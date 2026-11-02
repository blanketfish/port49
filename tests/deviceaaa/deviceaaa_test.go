package deviceaaa

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const labKey = "lab-only-key-0123456789"

// platforms lists every reference file: platform, transport and the file's extension.
var platforms = []struct{ name, transport, ext string }{
	{"arista_eos", "tcp", ".cfg"}, {"arista_eos", "tls", ".cfg"},
	{"cisco_iosxe", "tcp", ".cfg"}, {"cisco_iosxe", "tls", ".cfg"},
	{"cisco_nxos", "tcp", ".cfg"}, {"cisco_nxos", "tls", ".cfg"},
	{"juniper_junos", "tcp", ".set"}, {"juniper_junos", "tls", ".set"},
	{"cisco_iosxr", "tcp", ".cfg"}, {"cisco_iosxr", "tls", ".cfg"},
	{"nokia_srlinux", "tcp", ".cli"},
}

func labValues() Values {
	return Values{
		Servers:         []string{"172.100.100.1", "172.100.100.2"},
		SourceInterface: "Loopback0",
		SourceAddress:   "172.100.100.250",
		MgmtVRF:         "management",
		BreakGlass:      "breakglass",
		TLSPort:         300,
		ServerName:      "tacacs.lab.example",
		CertID:          "port49-device",
	}
}

func path(name, transport, ext string) string {
	f := name + ext
	if transport == "tls" {
		f = name + "-tls" + ext
	}
	return filepath.Join("..", "..", "deploy", "device-aaa", f)
}

func raw(t *testing.T, name, transport, ext string) string {
	t.Helper()
	b, err := os.ReadFile(path(name, transport, ext))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func isComment(l string) bool {
	l = strings.TrimSpace(l)
	return l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "/*")
}

// commands is a file's lines with comments and blanks removed.
func commands(t *testing.T, name, transport, ext string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(raw(t, name, transport, ext), "\n") {
		if !isComment(l) {
			out = append(out, l)
		}
	}
	return out
}

func each(t *testing.T, fn func(t *testing.T, name, transport, ext string)) {
	t.Helper()
	for _, p := range platforms {
		t.Run(p.name+"/"+p.transport, func(t *testing.T) { fn(t, p.name, p.transport, p.ext) })
	}
}

func TestEveryReferenceRenders(t *testing.T) {
	each(t, func(t *testing.T, name, transport, _ string) {
		lines, err := Render(name, transport, labValues(), labKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) == 0 {
			t.Fatal("rendered nothing")
		}
		for _, l := range lines {
			if strings.ContainsAny(l, "<>") {
				t.Errorf("placeholder left in %q", l)
			}
		}
	})
}

func TestRenderRefusesWhatItCannotFill(t *testing.T) {
	v := labValues()
	v.SourceInterface = ""
	if _, err := Render("cisco_iosxe", "tcp", v, labKey); err == nil {
		t.Error("an empty source interface rendered")
	}
	v = labValues()
	v.Port = 6049
	if _, err := Render("cisco_iosxe", "tcp", v, labKey); err == nil {
		t.Error("a non-default plain port rendered; the references use 49")
	}
	if _, err := Render("nokia_srlinux", "tls", labValues(), labKey); err == nil {
		t.Error("SR Linux has no TLS reference")
	}
	if _, err := Render("cisco_iosxe", "tcp", labValues(), ""); err == nil {
		t.Error("an empty key rendered")
	}
}

func TestRenderNeverReturnsTheKeyInAnError(t *testing.T) {
	v := labValues()
	v.SourceInterface = ""
	_, err := Render("cisco_iosxe", "tcp", v, labKey)
	if err == nil || strings.Contains(err.Error(), labKey) {
		t.Fatalf("err = %v", err)
	}
}

var placeholder = regexp.MustCompile(`<[A-Z0-9_]+>`)

func TestOnlyClosedPlaceholders(t *testing.T) {
	want := []string{"<PORT49_1>", "<PORT49_2>", "<KEY>", "<SOURCE_INTERFACE>", "<SOURCE_ADDRESS>", "<MGMT_VRF>",
		"<BREAKGLASS_USER>", "<TLS_PORT>", "<SERVER_NAME>", "<CERT_ID>"}
	got := Placeholders()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Placeholders() = %v", got)
	}
	each(t, func(t *testing.T, name, transport, ext string) {
		for _, m := range placeholder.FindAllString(raw(t, name, transport, ext), -1) {
			if !slices.Contains(want, m) {
				t.Errorf("%s is not a placeholder", m)
			}
		}
	})
}

var secretForms = []*regexp.Regexp{
	regexp.MustCompile(`\$aes1\$`), regexp.MustCompile(`\$9\$`), regexp.MustCompile(`\$[156]\$`),
	regexp.MustCompile(`(?i)\b(key|secret|secret-key|password|encrypted-password)\s+7\s`),
}

var secretValue = regexp.MustCompile(`(?i)\b(?:key|secret|secret-key|password|encrypted-password)\s+(?:0\s+)?(\S+)`)

// literalSecret reports a key, secret or password word followed by anything but the <KEY> placeholder
// (after an optional cleartext type digit 0).
func literalSecret(l string) bool {
	if strings.HasPrefix(strings.TrimSpace(l), "certificate ") { // EOS: a file name, not a secret
		return false
	}
	l = strings.NewReplacer("<KEY>", "@K@", `"`, "").Replace(l)
	for _, m := range secretValue.FindAllStringSubmatch(l, -1) {
		if m[1] != "@K@" {
			return true
		}
	}
	return false
}

func TestNoReferenceCarriesAKey(t *testing.T) {
	each(t, func(t *testing.T, name, transport, ext string) {
		for _, l := range commands(t, name, transport, ext) {
			if literalSecret(l) {
				t.Errorf("%q holds a literal secret", l)
			}
			for _, re := range secretForms {
				if re.MatchString(l) {
					t.Errorf("%q looks like a literal secret", l)
				}
			}
		}
	})
	// The key is on every plain server and appears as <KEY> alone; an RFC 9887 server carries none.
	each(t, func(t *testing.T, name, transport, ext string) {
		has := strings.Contains(raw(t, name, transport, ext), "<KEY>")
		if has == (transport == "tls") {
			t.Errorf("<KEY> present = %v on a %s reference", has, transport)
		}
	})
}

func joined(t *testing.T, name, transport, ext string) string {
	return strings.Join(commands(t, name, transport, ext), "\n")
}

func TestNoReferenceFallsThroughOnAReject(t *testing.T) {
	each(t, func(t *testing.T, name, transport, ext string) {
		for _, l := range commands(t, name, transport, ext) {
			l = strings.TrimSpace(l)
			switch name {
			case "juniper_junos":
				if strings.Contains(l, "authentication-order") && l != "set system authentication-order tacplus" {
					t.Errorf("Junos authentication-order must be tacplus alone: %q", l)
				}
			case "cisco_iosxe", "cisco_nxos", "cisco_iosxr", "arista_eos":
				if strings.HasPrefix(l, "aaa ") &&
					(strings.HasSuffix(l, " none") || strings.Contains(l, " if-authenticated")) {
					t.Errorf("method list falls through: %q", l)
				}
			}
			if name == "cisco_nxos" && strings.Contains(l, "deadtime") {
				t.Errorf("NX-OS deadtime locks token logins out (L4): %q", l)
			}
		}
		all := joined(t, name, transport, ext)
		if name == "juniper_junos" && !strings.Contains(all, "set system authentication-order tacplus\n") &&
			!strings.HasSuffix(all, "set system authentication-order tacplus") {
			t.Error("Junos sets no authentication-order tacplus")
		}
		if name == "nokia_srlinux" && !strings.Contains(all, "exit-on-reject true") {
			t.Error("SR Linux without exit-on-reject true")
		}
	})
}

func TestEveryReferenceNamesTwoServers(t *testing.T) {
	each(t, func(t *testing.T, name, transport, ext string) {
		all := joined(t, name, transport, ext)
		for _, p := range []string{"<PORT49_1>", "<PORT49_2>"} {
			if !strings.Contains(all, p) {
				t.Errorf("no %s", p)
			}
		}
	})
	// L73: IOS XE cannot share one address between two tacacs server objects.
	all := joined(t, "cisco_iosxe", "tls", ".cfg")
	if n := strings.Count(all, "address ipv4 <PORT49_1>"); n != 1 {
		t.Errorf("IOS XE TLS: %d objects at <PORT49_1>, want 1", n)
	}
	if n := strings.Count(all, "address ipv4 <PORT49_2>"); n != 1 {
		t.Errorf("IOS XE TLS: %d objects at <PORT49_2>, want 1", n)
	}
}

func TestEveryReferencePinsItsSource(t *testing.T) {
	need := map[string][]string{
		"arista_eos":    {"<SOURCE_INTERFACE>", "<MGMT_VRF>"},
		"cisco_iosxe":   {"<SOURCE_INTERFACE>", "<MGMT_VRF>"},
		"cisco_nxos":    {"<SOURCE_INTERFACE>", "<MGMT_VRF>"},
		"cisco_iosxr":   {"<SOURCE_INTERFACE>", "<MGMT_VRF>"},
		"juniper_junos": {"<SOURCE_ADDRESS>", "<MGMT_VRF>"},
		"nokia_srlinux": {"<SOURCE_ADDRESS>", "<MGMT_VRF>"},
	}
	each(t, func(t *testing.T, name, transport, ext string) {
		all := joined(t, name, transport, ext)
		for _, p := range need[name] {
			if !strings.Contains(all, p) {
				t.Errorf("no %s", p)
			}
		}
	})
	// Junos pins it per server.
	for _, tr := range []string{"tcp", "tls"} {
		all := joined(t, "juniper_junos", tr, ".set")
		for _, s := range []string{"<PORT49_1>", "<PORT49_2>"} {
			if !strings.Contains(all, "tacplus-server "+s+" source-address <SOURCE_ADDRESS>") {
				t.Errorf("Junos %s: %s has no source-address", tr, s)
			}
		}
	}
	if !strings.Contains(joined(t, "arista_eos", "tcp", ".cfg"), "ip tacacs vrf <MGMT_VRF> source-interface <SOURCE_INTERFACE>") {
		t.Error("EOS pins no source interface")
	}
}

func TestTLSReferencesFollowL73(t *testing.T) {
	junos := joined(t, "juniper_junos", "tls", ".set")
	for _, s := range []string{"<PORT49_1>", "<PORT49_2>"} {
		for _, l := range []string{"tacplus-server " + s + " port <TLS_PORT>",
			"tacplus-server " + s + " tls mutual-authentication certificate-id <CERT_ID>"} {
			if !strings.Contains(junos, l) {
				t.Errorf("Junos TLS lacks %q", l)
			}
		}
	}
	nx := raw(t, "cisco_nxos", "tls", ".cfg")
	if !strings.Contains(nx, "port <TLS_PORT>") || !strings.Contains(strings.ToLower(nx), "rsa") {
		t.Error("NX-OS TLS lacks its port or an RSA key in its enrolment comment")
	}
	if !strings.Contains(joined(t, "arista_eos", "tls", ".cfg"), "port <TLS_PORT>") {
		t.Error("EOS TLS lacks its port")
	}
	for _, n := range []string{"cisco_iosxe", "cisco_iosxr", "arista_eos", "cisco_nxos"} {
		if !strings.Contains(joined(t, n, "tls", ".cfg"), "<TLS_PORT>") {
			t.Errorf("%s TLS lacks its port", n)
		}
	}
	each(t, func(t *testing.T, name, transport, ext string) {
		if transport != "tls" {
			return
		}
		all := joined(t, name, transport, ext)
		if !strings.Contains(all, "single-connection") {
			t.Error("no single-connection")
		}
		// No non-TLS server for the same host: a plain server needs a shared key, and the key check above
		// proves no TLS reference holds one. A TLS server never carries a key line either.
		for _, l := range commands(t, name, transport, ext) {
			l = strings.TrimSpace(l)
			if strings.Contains(l, "<KEY>") || strings.Contains(l, "secret") {
				t.Errorf("a TLS reference carries a shared key: %q", l)
			}
		}
	})
}

func TestTheSRLinuxReferenceFollowsL76(t *testing.T) {
	all := joined(t, "nokia_srlinux", "tcp", ".cli")
	if !strings.Contains(all, "priv-lvl-authorization true") {
		t.Error("no priv-lvl-authorization true")
	}
	for _, role := range []string{"p49-read", "p49-admin"} {
		body := all[strings.Index(all, "role "+role+" {\n                services"):]
		if end := strings.Index(body, "tacacs"); end < 0 || !strings.Contains(body[:end], "services [ cli ]") {
			t.Errorf("role %s lacks services [ cli ] before its tacacs block", role)
		}
	}
	m := regexp.MustCompile(`(?s)authentication-method \[\s*port49\s+local\s*\]`)
	if !m.MatchString(all) {
		t.Error("authentication-method is not port49 then local")
	}
	if !regexp.MustCompile(`(?s)user <BREAKGLASS_USER> \{\s*role \[\s*p49-admin\s*\]`).MatchString(all) {
		t.Error("break-glass is not mapped to p49-admin")
	}
}

func TestTheEOSTLSGroupMembersNameTLSAndThePort(t *testing.T) {
	n := 0
	for _, l := range commands(t, "arista_eos", "tls", ".cfg") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "server ") {
			n++
			if !strings.Contains(l, " tls port <TLS_PORT>") {
				t.Errorf("EOS TLS member %q lacks tls port (L73: a bare member is plain port 49)", l)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d EOS TLS members, want 2", n)
	}
}

func TestTheNXOSTLSReferenceTurnsTLSOn(t *testing.T) {
	if !slices.Contains(commands(t, "cisco_nxos", "tls", ".cfg"), "tacacs-server secure tls") {
		t.Error("no tacacs-server secure tls (L73 typed it; without it NX-OS speaks plain TACACS+)")
	}
}

func TestTheIOSXETLSReferenceNamesAServerTrustpoint(t *testing.T) {
	all := joined(t, "cisco_iosxe", "tls", ".cfg")
	if n := strings.Count(all, " tls trustpoint server port49-root"); n != 2 {
		t.Errorf("%d server trustpoints, want one per object", n)
	}
	if !strings.Contains(all, "crypto pki trustpoint port49-root") {
		t.Error("the root trustpoint is not defined")
	}
	if strings.Contains(joined(t, "cisco_nxos", "tls", ".cfg"), "server-trustpoint") {
		t.Error("NX-OS 10.6(2)F offered no server-trustpoint keyword")
	}
}

func TestRenderRefusesUnsafeValues(t *testing.T) {
	for _, mut := range []func(*Values){
		func(v *Values) { v.MgmtVRF = "mgmt\nreload" },
		func(v *Values) { v.Servers[1] = v.Servers[0] },
		func(v *Values) { v.Servers[0] = "" },
	} {
		v := labValues()
		mut(&v)
		if _, err := Render("cisco_iosxe", "tcp", v, labKey); err == nil {
			t.Errorf("rendered %+v", v)
		}
	}
	if _, err := Render("cisco_iosxe", "tcp", labValues(), "k\nreload"); err == nil {
		t.Error("a key with a line break rendered")
	}
}
