package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
listen: 127.0.0.1:8443
tls_cert_file: /etc/i/server.pem
tls_key_file: /etc/i/server-key.pem
client_ca_file: /etc/i/ca.pem
readers: ["spiffe://example.com/port49d"]
syncers: ["user:alice@example.com"]
signing_key_file: /etc/i/signing.key
policy_file: /etc/i/policy.yaml
state_dir: /var/lib/port49-inventory
sync:
  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}
`

func loadString(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49-inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestTheMinimalConfigLoadsWithItsDefaults(t *testing.T) {
	c, err := loadString(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	if c.MetricsListen != ":9050" || c.Interval != 10*time.Minute || c.MaxRemovedPercent != 10 ||
		c.Bounds()["lab_file"] != 10 || c.MirrorDir != "" || c.SyncTimeout != 5*time.Minute ||
		len(c.VerifyKeyFiles) != 0 {
		t.Fatalf("%+v", c)
	}
}

// Spec §10: each source syncs on its own interval, defaulting to the
// top-level one.
func TestAPerSourceIntervalOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5m}", 1))
	if err != nil || c.Sync[0].Interval != 5*time.Minute {
		t.Fatalf("%+v %v", c.Sync, err)
	}
	c, err = loadString(t, minimalConfig)
	if err != nil || c.Sync[0].Interval != 10*time.Minute {
		t.Fatalf("the default: %+v %v", c.Sync, err)
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, interval: 5s}", 1)); err == nil ||
		!strings.Contains(err.Error(), "sync[0].interval must be between 1m and 24h") {
		t.Fatalf("got %v", err)
	}
}

func TestASourceBoundOverridesTheDefault(t *testing.T) {
	c, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, safety: {max_removed_percent: 30}}", 1)+"safety: {max_removed_percent: 5}\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxRemovedPercent != 5 || c.Bounds()["lab_file"] != 30 {
		t.Fatalf("%+v", c)
	}
}

// A source without its own bound takes the top-level one, not the default.
func TestASourceInheritsTheTopLevelBound(t *testing.T) {
	c, err := loadString(t, minimalConfig+"safety: {max_removed_percent: 5}\n")
	if err != nil || c.Bounds()["lab_file"] != 5 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestVerifyKeyFilesAreRead(t *testing.T) {
	c, err := loadString(t, minimalConfig+"verify_key_files: [/etc/i/old-signing.pub, /etc/i/older-signing.pub]\n")
	if err != nil || len(c.VerifyKeyFiles) != 2 || c.VerifyKeyFiles[0] != "/etc/i/old-signing.pub" ||
		c.VerifyKeyFiles[1] != "/etc/i/older-signing.pub" {
		t.Fatalf("%+v %v", c.VerifyKeyFiles, err)
	}
}

// A mirror_dir beside state_dir, not inside it, is fine; a sibling with
// state_dir's name as a prefix is not inside it.
func TestAMirrorDirBesideStateDirLoads(t *testing.T) {
	c, err := loadString(t, minimalConfig+"mirror_dir: /var/lib/port49-inventory-mirror\n")
	if err != nil || c.MirrorDir != "/var/lib/port49-inventory-mirror" {
		t.Fatalf("%+v %v", c, err)
	}
}

// A mirror_dir whose name is a prefix of state_dir's does not hold it.
func TestAStateDirBesideMirrorDirLoads(t *testing.T) {
	c, err := loadString(t, minimalConfig+"mirror_dir: /var/lib/port49\n")
	if err != nil || c.MirrorDir != "/var/lib/port49" {
		t.Fatalf("%+v %v", c, err)
	}
}

// A trailing empty document is still a second document.
func TestATrailingEmptyDocumentIsRefused(t *testing.T) {
	_, err := loadString(t, minimalConfig+"---\n")
	if err == nil || !strings.Contains(err.Error(), "one YAML document") {
		t.Fatalf("got %v", err)
	}
}

// A second document is refused in fixed text: none of its values are echoed.
func TestASecondDocumentIsRefusedWithoutItsText(t *testing.T) {
	_, err := loadString(t, minimalConfig+"---\nsigning_key: SECRET\n")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "one YAML document") {
		t.Fatalf("got %v", err)
	}
}

// A path is named by its key, never quoted: a mis-pasted secret is not echoed.
func TestABadPathIsNamedWithoutItsText(t *testing.T) {
	_, err := loadString(t, minimalConfig+"verify_key_files: [SECRET]\n")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("got %v", err)
	}
}

// A secret pasted under a mistyped key is not echoed: the line and a
// category (yamlfault).
func TestAnUnknownKeyIsNamedByLineWithoutItsText(t *testing.T) {
	_, err := loadString(t, minimalConfig+"signing_key: \"-----BEGIN PRIVATE KEY-----SECRET\"\n")
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "an unknown field") {
		t.Fatalf("got %v", err)
	}
}

func TestWhatTheServiceCannotRunWithoutIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ from, to, want string }{
		"no state_dir":      {"state_dir: /var/lib/port49-inventory\n", "", "state_dir is required"},
		"no signing key":    {"signing_key_file: /etc/i/signing.key\n", "", "signing_key_file is required"},
		"nobody may read":   {"readers: [\"spiffe://example.com/port49d\"]\nsyncers: [\"user:alice@example.com\"]\n", "", "readers or syncers"},
		"no source":         {"sync:\n  - {name: lab_file, type: file, path: /etc/i/inventory.yaml}\n", "", "at least one sync source"},
		"netbox":            {"type: file", "type: netbox", "path is for a file source; a netbox source reads url"},
		"an unknown type":   {"type: file", "type: infrahub", "type must be file, netbox or nautobot"},
		"bad source name":   {"name: lab_file", "name: Lab-File", "sync[0].name"},
		"file with no path": {", path: /etc/i/inventory.yaml", "", "sync[0] (lab_file): path is required"},
		"bound over 100":    {"state_dir:", "safety: {max_removed_percent: 101}\nstate_dir:", "between 0 and 100"},
		"a bad identity":    {`"user:alice@example.com"`, `"alice"`, "syncers[0]"},
		"interval too fast": {"state_dir:", "interval: 10s\nstate_dir:", "interval must be between 1m and 24h"},
		"sync_timeout":      {"state_dir:", "sync_timeout: 2h\nstate_dir:", "sync_timeout must be between 10s and 1h"},
		"no listen":         {"listen: 127.0.0.1:8443\n", "", "listen is required"},
		"no tls_cert_file":  {"tls_cert_file: /etc/i/server.pem\n", "", "tls_cert_file is required"},
		"no tls_key_file":   {"tls_key_file: /etc/i/server-key.pem\n", "", "tls_key_file is required"},
		"no client_ca_file": {"client_ca_file: /etc/i/ca.pem\n", "", "client_ca_file is required"},
		"no policy_file":    {"policy_file: /etc/i/policy.yaml\n", "", "policy_file is required"},
		"source bound over 100": {"path: /etc/i/inventory.yaml}", "path: /etc/i/inventory.yaml, safety: {max_removed_percent: 101}}",
			"sync[0].safety.max_removed_percent must be between 0 and 100"},
		"negative bound": {"state_dir:", "safety: {max_removed_percent: -1}\nstate_dir:",
			"safety.max_removed_percent must be between 0 and 100"},
		"duplicate source": {"path: /etc/i/inventory.yaml}\n", "path: /etc/i/inventory.yaml}\n" +
			"  - {name: lab_file, type: file, path: /etc/i/other.yaml}\n", "sync[1].name must be unique"},
		"control character in an identity": {`"user:alice@example.com"`, `"user:al\x1bice@example.com"`, "syncers[0]"},
		"DEL in an identity":               {`"spiffe://example.com/port49d"`, `"spiffe://example.com/port\x7f49d"`, "readers[0]"},
		"relative state_dir":               {"state_dir: /var/lib/port49-inventory", "state_dir: var/lib/port49-inventory", "state_dir must be an absolute path"},
		"relative tls_cert_file":           {"tls_cert_file: /etc/i/server.pem", "tls_cert_file: server.pem", "tls_cert_file must be an absolute path"},
		"relative tls_key_file":            {"tls_key_file: /etc/i/server-key.pem", "tls_key_file: server-key.pem", "tls_key_file must be an absolute path"},
		"relative client_ca_file":          {"client_ca_file: /etc/i/ca.pem", "client_ca_file: ca.pem", "client_ca_file must be an absolute path"},
		"relative signing_key_file":        {"signing_key_file: /etc/i/signing.key", "signing_key_file: signing.key", "signing_key_file must be an absolute path"},
		"relative policy_file":             {"policy_file: /etc/i/policy.yaml", "policy_file: policy.yaml", "policy_file must be an absolute path"},
		"relative mirror_dir":              {"state_dir:", "mirror_dir: mirror\nstate_dir:", "mirror_dir must be an absolute path"},
		"relative source path":             {"path: /etc/i/inventory.yaml}", "path: inventory.yaml}", "sync[0].path must be an absolute path"},
		"empty verify_key_files entry":     {"state_dir:", "verify_key_files: [\"/etc/i/old.pub\", \"\"]\nstate_dir:", "verify_key_files[1] must be an absolute path"},
		"relative verify_key_files entry":  {"state_dir:", "verify_key_files: [old.pub]\nstate_dir:", "verify_key_files[0] must be an absolute path"},
		"listen with no port":              {"listen: 127.0.0.1:8443", "listen: \"8443\"", "listen must be host:port"},
		"listen with an empty port":        {"listen: 127.0.0.1:8443", "listen: \"127.0.0.1:\"", "listen must be host:port"},
		"metrics_listen with no port":      {"state_dir:", "metrics_listen: localhost\nstate_dir:", "metrics_listen must be host:port"},
		"mirror_dir is state_dir":          {"state_dir:", "mirror_dir: /var/lib/port49-inventory/\nstate_dir:", "mirror_dir must be outside state_dir"},
		"mirror_dir inside state_dir":      {"state_dir:", "mirror_dir: /var/lib/port49-inventory/mirror\nstate_dir:", "mirror_dir must be outside state_dir"},
		"a second document":                {"state_dir:", "---\nstate_dir:", "one YAML document"},
		"state_dir inside mirror_dir":      {"state_dir:", "mirror_dir: /var/lib\nstate_dir:", "state_dir must be outside mirror_dir"},
	} {
		_, err := loadString(t, strings.Replace(minimalConfig, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// CallerOf names a person by a lower-cased email, so a `user:` entry with a
// capital would match nobody, silently: it is refused, by list and index,
// never quoting the value. A URI SAN is matched as written, capitals and all.
func TestAUserIdentityIsWrittenInLowerCase(t *testing.T) {
	for _, c := range []struct{ from, to, want string }{
		{`"user:alice@example.com"`, `"user:Alice@example.com"`, "syncers[0]"},
		{`"spiffe://example.com/port49d"`, `"user:bob@Example.COM"`, "readers[0]"},
	} {
		_, err := loadString(t, strings.Replace(minimalConfig, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "lower case") ||
			strings.Contains(err.Error(), "lice@") || strings.Contains(err.Error(), "bob@") {
			t.Errorf("%s: got %v", c.to, err)
		}
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "spiffe://example.com/port49d",
		"spiffe://example.com/Port49d", 1)); err != nil {
		t.Errorf("a URI SAN with a capital: %v", err)
	}
}

// netboxSource is a second source, under minimalConfig's sync:.
const netboxSource = `  - name: netbox_prod
    type: netbox
    url: https://netbox.example.com
    ca_file: /etc/i/netbox-ca.pem
    token_secret_env: PORT49_TEST_NETBOX_TOKEN
`

const testToken = "0123456789abcdef0123456789abcdef01234567"
const testHookSecret = "l33-unit-test-webhook-secret-0123456789"

func TestANetboxSourceLoadsWithItsDefaults(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	c, err := loadString(t, minimalConfig+netboxSource)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sync[1]
	if s.Type != "netbox" || s.URL != "https://netbox.example.com" || s.API != "auto" || s.PageSize != 500 ||
		s.Interval != 10*time.Minute || s.MaxRemovedPercent != 10 || s.Token.Reveal() != testToken ||
		!s.WebhookSecret.Empty() || strings.Join(s.Mapping.Filter.Status, ",") != "active" ||
		!s.Mapping.Addresses.Primary || s.Mapping.Map != nil {
		t.Fatalf("%+v", s)
	}
	// Decision 31: a config printed whole carries no secret.
	if out := fmt.Sprintf("%+v %#v", c, c); strings.Contains(out, testToken) {
		t.Fatalf("printed the token: %s", out)
	}
}

// Plan 6a Task 15: a secret's variable is named by its key, and its value
// never.
func TestASecretIsNamedByItsKey(t *testing.T) {
	_, err := loadString(t, minimalConfig+netboxSource)
	if err == nil || !strings.Contains(err.Error(), "sync[1].token_secret_env names an environment variable that is "+
		"unset or empty") || strings.Contains(err.Error(), "PORT49_TEST_NETBOX_TOKEN") {
		t.Fatalf("unset: %v", err)
	}
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", "Token "+testToken)
	if _, err := loadString(t, minimalConfig+netboxSource); err == nil ||
		!strings.Contains(err.Error(), "not 1 to 512 printable characters without a space") ||
		strings.Contains(err.Error(), testToken) {
		t.Fatalf("a space: %v", err)
	}
}

// Decision 31: a webhook secret is 32 to 255 printable characters, and a
// source with one needs webhook_listen, as webhook_listen needs a source.
func TestWebhookListenAndAWebhookSourceGoTogether(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret)
	hook := "    webhook_secret_env: PORT49_TEST_NETBOX_HOOK\n"
	if _, err := loadString(t, minimalConfig+netboxSource+hook); err == nil ||
		!strings.Contains(err.Error(), "sync[1] (netbox_prod): webhook_secret_env is set, and webhook_listen is not") {
		t.Fatalf("no listener: %v", err)
	}
	if _, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource); err == nil ||
		!strings.Contains(err.Error(), "webhook_listen is set, and no source has webhook_secret_env") {
		t.Fatalf("no source: %v", err)
	}
	c, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource+hook)
	if err != nil || c.WebhookSecrets()["netbox_prod"].Reveal() != testHookSecret ||
		strings.Join(c.WebhookSources(), ",") != "netbox_prod" || len(c.WebhookSecrets()) != 1 {
		t.Fatalf("%v %v", c.WebhookSources(), err)
	}
	if out := fmt.Sprintf("%+v %#v %v", c, c, c.Sync); strings.Contains(out, testHookSecret) {
		t.Fatal("printed the webhook secret")
	}
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret[:31])
	if _, err := loadString(t, "webhook_listen: 127.0.0.1:8444\n"+minimalConfig+netboxSource+hook); err == nil ||
		!strings.Contains(err.Error(), "sync[1].webhook_secret_env names a variable whose value is not 32 to 255") ||
		strings.Contains(err.Error(), testHookSecret[:31]) || strings.Contains(err.Error(), "PORT49_TEST_NETBOX_HOOK") {
		t.Fatalf("short: %v", err)
	}
}

func TestWhatANetboxSourceCannotHave(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	for name, c := range map[string]struct{ from, to, want string }{
		"http":                 {"url: https://", "url: http://", "url must be https://"},
		"a token in the url":   {"url: https://netbox.example.com", "url: https://netbox.example.com/?t=" + testToken, "a query"},
		"no ca_file":           {"    ca_file: /etc/i/netbox-ca.pem\n", "", "ca_file is required"},
		"no token_secret_env":  {"    token_secret_env: PORT49_TEST_NETBOX_TOKEN\n", "", "sync[1].token_secret_env is required"},
		"relative ca_file":     {"ca_file: /etc/i/netbox-ca.pem", "ca_file: netbox-ca.pem", "ca_file is required, an absolute path"},
		"a nautobot profile":   {"token_secret_env:", "profile: nautobot_2\n    token_secret_env:", "profile must be one of netbox_3_7, netbox_4"},
		"api":                  {"token_secret_env:", "api: soap\n    token_secret_env:", "api must be auto, graphql or rest"},
		"page_size":            {"token_secret_env:", "page_size: 5000\n    token_secret_env:", "page_size must be between 1 and 1000"},
		"map without platform": {"token_secret_env:", "map: {site: site.slug}\n    token_secret_env:", "map must name platform"},
		"map path":             {"token_secret_env:", "map: {platform: platform.slug, x: tenant.slug}\n    token_secret_env:", "map.x names no path a profile reads"},
		"map key name":         {"token_secret_env:", "map: {platform: platform.slug, name: site.slug}\n    token_secret_env:", "map has a key that is not an attribute name"},
		"both interface rules": {"token_secret_env:", "addresses: {interfaces: [Loopback0], all_interfaces: true}\n    token_secret_env:", "one or the other"},
		"no address":           {"token_secret_env:", "addresses: {primary: false}\n    token_secret_env:", "addresses gives no address"},
		"a status list that keeps nothing named": {"token_secret_env:", "filter: {status: []}\n    token_secret_env:",
			"filter.status is empty"},
		"two aliases alike in lower case": {"token_secret_env:",
			"platform_aliases: {EOS: arista_eos, eos: arista_eos}\n    token_secret_env:", "two entries for one slug"},
		"a pasted token": {"token_secret_env:", "token: " + testToken + "\n    token_secret_env:", "an unknown field"},
		"a netbox profile on nautobot": {"type: netbox", "type: nautobot\n    profile: netbox_4",
			"profile must be one of nautobot_1_6, nautobot_2"},
		"rest and interfaces": {"token_secret_env:", "api: rest\n    addresses: {all_interfaces: true}\n    token_secret_env:", "REST does not give"},
		"an alias":            {"token_secret_env:", "platform_aliases: {eos: Arista EOS}\n    token_secret_env:", "platform_aliases has an entry"},
		"a status":            {"token_secret_env:", "filter: {status: [\"act\\u001bive\"]}\n    token_secret_env:", "filter.status[0] is not a status name"},
	} {
		_, err := loadString(t, minimalConfig+strings.Replace(netboxSource, c.from, c.to, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := loadString(t, strings.Replace(minimalConfig, "path: /etc/i/inventory.yaml}",
		"path: /etc/i/inventory.yaml, url: https://x.example.com}", 1)); err == nil ||
		!strings.Contains(err.Error(), "are for netbox and nautobot sources") {
		t.Fatalf("a file source with url: %v", err)
	}
}

// Spec §10's example writes `filter: {status: active, has_primary_ip: true}`:
// a status is a string or a list.
func TestTheSpecExamplesFilterLoads(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	c, err := loadString(t, minimalConfig+netboxSource+"    filter: {status: Active, has_primary_ip: true}\n"+
		"    map: {platform: platform.slug, os_version: custom_fields.os_version}\n"+
		"    addresses: {interfaces: [Loopback0]}\n    platform_aliases: {EOS-Lab: arista_eos}\n")
	if err != nil {
		t.Fatal(err)
	}
	m := c.Sync[1].Mapping
	if strings.Join(m.Filter.Status, ",") != "active" || !m.Filter.HasPrimaryIP || m.Map["os_version"] != "custom_fields.os_version" ||
		!m.Addresses.Primary || m.Addresses.Interfaces[0] != "Loopback0" || m.Aliases["eos-lab"] != "arista_eos" {
		t.Fatalf("%+v", m)
	}
}

func TestANautobotSourceLoads(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	c, err := loadString(t, minimalConfig+strings.Replace(netboxSource, "type: netbox",
		"type: nautobot\n    profile: nautobot_2", 1))
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Sync[1]; s.Type != "nautobot" || s.Profile != "nautobot_2" || s.API != "auto" ||
		!s.Mapping.Addresses.Primary || strings.Join(s.Mapping.Filter.Status, ",") != "active" {
		t.Fatalf("%+v", s)
	}
}

func TestWhatAWebhookListenerCannotHave(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", testHookSecret)
	hooked := minimalConfig + netboxSource + "    webhook_secret_env: PORT49_TEST_NETBOX_HOOK\n"
	listen := "webhook_listen: 127.0.0.1:8444\n"
	cert, key := "webhook_tls_cert_file: /etc/i/hook.pem\n", "webhook_tls_key_file: /etc/i/hook-key.pem\n"
	for name, c := range map[string]struct{ body, want string }{
		"a cert without its key": {listen + cert + hooked, "webhook_tls_cert_file and webhook_tls_key_file go together"},
		"a relative cert": {listen + "webhook_tls_cert_file: hook.pem\n" + key + hooked,
			"webhook_tls_cert_file must be an absolute path"},
		"a cert without a listener": {cert + key + minimalConfig + netboxSource,
			"webhook_tls_cert_file is set, and webhook_listen is not"},
		"a listener that is not host:port": {"webhook_listen: \"8444\"\n" + hooked, "webhook_listen must be host:port"},
	} {
		if _, err := loadString(t, c.body); err == nil || !strings.Contains(err.Error(), c.want) ||
			strings.Contains(err.Error(), testHookSecret) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := loadString(t, listen+cert+key+hooked); err != nil {
		t.Fatalf("its own cert and key: %v", err)
	}
	// 255 is the products' secret field (L27, L30); one past it is refused.
	long := strings.Repeat("s", 255)
	t.Setenv("PORT49_TEST_NETBOX_HOOK", long)
	if _, err := loadString(t, listen+hooked); err != nil {
		t.Fatalf("255: %v", err)
	}
	t.Setenv("PORT49_TEST_NETBOX_HOOK", long+"s")
	if _, err := loadString(t, listen+hooked); err == nil || !strings.Contains(err.Error(), "not 32 to 255") ||
		strings.Contains(err.Error(), long) {
		t.Fatalf("256: %v", err)
	}
}
