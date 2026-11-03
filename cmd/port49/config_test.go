package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/internal/userconfig"
)

const configBroker = "https://broker.example:8443"

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002, the default on Ubuntu, a t.TempDir is
// group-writable, and port49 reads no config file below one
// (decision 42 ruling 6).
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// labConfig writes the lab PKI and a config.yaml naming it by relative path,
// in dir, and returns the config's path.
func labConfig(t *testing.T, dir, broker string) string {
	t.Helper()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := "broker: " + broker + "\nbroker_ca: " + testpki.LabCA + "\ncert: " + testpki.LabClientCert +
		"\nkey: " + testpki.LabClientKey + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// runningAgent is an agent socket whose session is the lab certificate's on
// configBroker, so login refreshes it rather than starting another.
func runningAgent(t *testing.T, dir string) (string, func() int32) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	p, n := countingRefreshStub(t, agent.Status{Broker: configBroker, CertFingerprint: agent.CertFingerprint(cert)},
		http.StatusOK, api.RefreshResponse{AuthTime: "2026-10-09T09:00:00Z", SessionEndsAt: "2026-10-09T21:00:00Z"})
	return p, n.Load
}

// login takes what its flags leave out from the config file, at the default
// path, ~/.port49/config.yaml, at $PORT49_CONFIG and at --config (decision 42
// ruling 6; decision 43 ruling 24).
func TestLoginTakesWhatItLacksFromTheConfigFile(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".port49")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	labConfig(t, dir, configBroker)
	other := privateDir(t)
	named := labConfig(t, other, configBroker)
	for _, c := range []struct {
		name, dir, env string
		args           []string
	}{
		{"the default path", dir, "", nil},
		{"$PORT49_CONFIG", other, named, nil},
		{"--config", other, "", []string{"--config", named}},
	} {
		// Each file names its own lab certificate, so only the file the
		// login should read matches the running agent's.
		t.Setenv(userconfig.EnvConfig, c.env)
		sock, refreshes := runningAgent(t, c.dir)
		var out, errb bytes.Buffer
		t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
		code := run(append([]string{"login"}, c.args...), &out, &errb)
		if code != 0 || refreshes() != 1 ||
			!strings.HasPrefix(out.String(), "port49: already logged in to "+configBroker+"; refreshing\n") {
			t.Errorf("%s: code %d stdout %q stderr %q", c.name, code, out.String(), errb.String())
		}
	}
}

// systemConfig stands path in for /etc/port49/config.yaml, and this user in
// for root, for the rest of the test, in this process and in a child it
// starts (TestMain reads testSystemConfig).
func systemConfig(t *testing.T, path string) {
	t.Helper()
	t.Setenv(testSystemConfig, path)
	oldPath, oldOwner := userconfig.SystemPath, userconfig.SystemOwner
	userconfig.SystemPath, userconfig.SystemOwner = path, uint32(os.Getuid())
	t.Cleanup(func() { userconfig.SystemPath, userconfig.SystemOwner = oldPath, oldOwner })
}

// The install's file is under the user's, key by key: a user who sets only
// broker keeps the system file's CA, certificate and key (decision 43
// ruling 24).
func TestTheSystemFileIsUnderYoursKeyByKey(t *testing.T) {
	sys := privateDir(t)
	systemConfig(t, labConfig(t, sys, "https://elsewhere.example:8443"))
	home := privateDir(t)
	t.Setenv("HOME", home)
	if err := userconfig.WritePrivate(filepath.Join(home, ".port49", "config.yaml"),
		[]byte("broker: "+configBroker+"\n"), "port49 config file"); err != nil {
		t.Fatal(err)
	}
	sock, refreshes := runningAgent(t, sys)
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	if code := run([]string{"login"}, &out, &errb); code != 0 || refreshes() != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A config file at plan 9a's place, with none at ~/.port49, is refused in
// one line naming the move, exit 2, and nothing is asked of the agent.
func TestAConfigFileAtPlan9asPlaceIsRefused(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	labConfig(t, filepath.Join(home, ".config", "port49"), configBroker)
	sock, refreshes := runningAgent(t, filepath.Join(home, ".config", "port49"))
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"login"}, &out, &errb)
	old, now := filepath.Join(home, ".config", "port49", "config.yaml"), filepath.Join(home, ".port49", "config.yaml")
	if code != 2 || refreshes() != 0 || strings.Count(errb.String(), "\n") != 1 ||
		!strings.Contains(errb.String(), "mkdir -m 700 -p "+filepath.Join(home, ".port49")+" && mv "+old+" "+now) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A flag overrides the file's key.
func TestAFlagOverridesTheConfigFile(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, "https://elsewhere.example:8443")
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"login", "--config", cfg, "--broker", configBroker}, &out, &errb)
	if code != 0 || refreshes() != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A config file others could write is refused, exit 2, and nothing is
// asked of the agent.
func TestAConfigFileOthersCanWriteIsRefused(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	if err := os.Chmod(cfg, 0o664); err != nil {
		t.Fatal(err)
	}
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"login", "--config", cfg}, &out, &errb)
	if code != 2 || refreshes() != 0 || !strings.HasPrefix(errb.String(), "port49 login: "+cfg+" is writable by ") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A --config that names no file is refused; the default path missing is no
// file, and the flags are asked for.
func TestAMissingConfigFile(t *testing.T) {
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", filepath.Join(t.TempDir(), "a.sock"))
	code := run([]string{"login", "--config", filepath.Join(t.TempDir(), "none.yaml")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "none.yaml: no such file") {
		t.Fatalf("a named file: code %d stderr %q", code, errb.String())
	}
	// Named, it is checked even when every flag is given.
	errb.Reset()
	t.Setenv("PORT49_TEST_AGENT_SOCKET", filepath.Join(t.TempDir(), "a.sock"))
	code = run([]string{"login", "--config", filepath.Join(t.TempDir(), "none.yaml"), "--broker", configBroker,
		"--broker-ca", "ca.pem", "--cert", "c.pem", "--key", "k.pem"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "none.yaml: no such file") {
		t.Fatalf("a named file beside every flag: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	t.Setenv("PORT49_TEST_AGENT_SOCKET", filepath.Join(t.TempDir(), "a.sock"))
	code = run([]string{"login"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "are all required") || !strings.Contains(errb.String(), "config.yaml") {
		t.Fatalf("the default path: code %d stderr %q", code, errb.String())
	}
}

// The config file's broker_ca is always required: a file naming no CA is a
// refusal, never a fall back to the system roots.
func TestAConfigFileWithNoBrokerCAIsRefused(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	body := "broker: " + configBroker + "\ncert: " + testpki.LabClientCert + "\nkey: " + testpki.LabClientKey + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", filepath.Join(t.TempDir(), "a.sock"))
	code := run([]string{"login", "--config", cfg}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "--broker-ca") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// method: oidc in the file makes a plain login an OIDC one: against a
// running agent holding another certificate it is refused, naming it.
func TestTheConfigFileCanChooseOIDC(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("method: oidc\n")
	f.Close()
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"login", "--config", cfg}, &out, &errb)
	if code != 1 || refreshes() != 0 || !strings.Contains(errb.String(), "with another certificate") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
