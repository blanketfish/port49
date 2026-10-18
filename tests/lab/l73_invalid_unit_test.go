//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL73InvalidScreenDropsPEM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-2", "Issuer: CN=L73\n-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ZZZZ") || !strings.Contains(string(b), "Issuer: CN=L73") {
		t.Fatal(string(b))
	}
}

func TestL73InvalidScreenMasksTheTacplusSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-3", "set system tacplus-server 172.100.100.1 port 300\n"+
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdefgh1234\"\n"+
		"set system tacplus-server 172.100.100.1 authentication-key \"$9$zzzzyyyy5678\"\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "$9$") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "zzzzyyyy") ||
		!strings.Contains(got, "tacplus-server 172.100.100.1 port 300") {
		t.Fatal(got)
	}
}

func TestJunosLineRefusal(t *testing.T) {
	ln := "set system tacplus-server 1.2.3.4 tls trusted-ca-group g"
	for name, c := range map[string]struct {
		ln, out string
		want    bool
	}{
		"clean set":                         {ln, ln + "\r\nbreakglass@srx1# ", false},
		"clean set as the image answers it": {ln, ln + " \r\n\r\n[edit]\r\nbreakglass@srx1#  " + ln + " \r\n\r\n[edit]\r\nbreakglass@srx1# ", false},
		"error then edit":                   {ln, ln + "\r\nerror: bad\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"syntax error then edit":            {ln, ln + "\r\n  ^\r\nsyntax error.\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"other words then edit":             {ln, ln + "\r\nwarning: odd\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"clean set at a level":              {ln, ln + "\r\n\r\n[edit system]\r\nbreakglass@srx1# ", false},
		"syntax error":                      {ln, ln + "\r\n                  ^\r\nsyntax error.\r\nbreakglass@srx1# ", true},
		"unknown command":                   {ln, ln + "\r\nunknown command.\r\nbreakglass@srx1# ", true},
		"error colon":                       {ln, ln + "\r\nerror: bad\r\nbreakglass@srx1# ", true},
		"missing argument":                  {ln, ln + "\r\nmissing argument.\r\nbreakglass@srx1# ", true},
		"set warning":                       {ln, ln + "\r\nwarning: something odd\r\nbreakglass@srx1# ", true},
		"delete not found":                  {"delete system tacplus-server", "delete system tacplus-server\r\nwarning: statement not found\r\nbreakglass@srx1# ", false},
		"delete real error":                 {"delete system tacplus-server", "delete system tacplus-server\r\nerror: bad\r\nbreakglass@srx1# ", true},
	} {
		if got := junosLineRefusal(c.ln, c.out) != ""; got != c.want {
			t.Errorf("%s: refusal %v want %v", name, got, c.want)
		}
	}
}

func TestL73ScrubLogMasksTheTacplusSecret(t *testing.T) {
	got := l73ScrubLog("set system tacplus-server 172.100.100.1 port 300\n" +
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdefgh1234\"\n" +
		"set system tacplus-server 172.100.100.1 authentication-key \"$9$zzzzyyyy5678\"\n")
	if strings.Contains(got, "$9$") || strings.Contains(got, "secret") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "zzzzyyyy") || !strings.Contains(got, "port 300") {
		t.Fatal(got)
	}
}

func TestL73InvalidScreenKeepsAPlainFilePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("configure", "File path '/var/db/certs/common/local/l73-trust' doesn't exists.\r\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-configure.txt"))
	if err != nil || !strings.Contains(string(b), "'/var/db/certs/common/local/l73-trust'") {
		t.Fatal(err, string(b))
	}
}

func TestL73InvalidScreenDropsEveryPrivateKeyBlock(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	var in strings.Builder
	in.WriteString("$ show crypto key mypubkey rsa\nkey label: l73-key\n")
	for i, kind := range []string{"RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		fmt.Fprintf(&in, "-----BEGIN %s-----\nPRIVBODY%d\n-----END %s-----\n", kind, i, kind)
	}
	e.invalidScreen("device-3", in.String())
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PRIVBODY") || strings.Contains(string(b), "PRIVATE KEY") || !strings.Contains(string(b), "key label: l73-key") {
		t.Fatal(string(b))
	}
}

func TestL73InvalidScreenMasksIOSXEServerKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-1", "tacacs server port49-host\r\n address ipv4 172.100.100.1\r\n key 0 PLAINKEY123\r\n"+
		"tacacs server l73\r\n tls port 300\r\n key 7 ENCRYPTED0822455D0A16\r\n key 6 TYPESIX\r\n"+
		"Server Address: 172.100.100.1 Key: SHOWNKEY999\r\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, leak := range []string{"PLAINKEY123", "ENCRYPTED0822", "TYPESIX", "SHOWNKEY999"} {
		if strings.Contains(got, leak) {
			t.Errorf("%s leaked:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "tls port 300") || !strings.Contains(got, "address ipv4 172.100.100.1") {
		t.Errorf("the configuration around the keys was lost:\n%s", got)
	}
}
