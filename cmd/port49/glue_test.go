package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A credential keyword glued to a value with any separator never carries the
// value to a line the printers write (issue 19): diff's widens, narrows and
// probe list (the lint findings and the logs are tested beside their writers).
func TestAGluedCredentialIsNeverPrinted(t *testing.T) {
	const lit = "fakesecret123"
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, permit string) string {
		path := filepath.Join(dir, name)
		body := "platform_set: 1.3.0\nscopes: [{name: all_devices, match: {}}]\n" +
			"roles: [{name: r, privilege: readonly, permit: [\"show **\"" + permit + "]}]\n" +
			"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n" +
			"grants: [{subject: noc, scope: all_devices, roles: [r]}]\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, sep := range []string{",", ":", "=", "+", "|", ";", "/"} {
		rule := `, "request password` + sep + lit + `"`
		for _, c := range []struct {
			name string
			args []string
		}{
			{"diff widens", []string{"policy", "diff", "--old", write("o.yaml", ""), "--new", write("n.yaml", rule), "--inventory", inv}},
			{"diff narrows", []string{"policy", "diff", "--old", write("o2.yaml", rule), "--new", write("n2.yaml", ""), "--inventory", inv}},
		} {
			var out, errb bytes.Buffer
			code := run(c.args, &out, &errb)
			if code == 2 {
				t.Fatalf("%s: usage:\n%s", c.name, errb.String())
			}
			if strings.Contains(out.String()+errb.String(), lit) {
				t.Errorf("sep %q: %s printed the literal:\n%s%s", sep, c.name, out.String(), errb.String())
			}
		}
	}
}
