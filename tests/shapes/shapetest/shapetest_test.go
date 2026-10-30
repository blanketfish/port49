package shapetest

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGaugeIn(t *testing.T) {
	expo := "# HELP port49_key_secret_files_changed x\nport49_key_secret_files_changed_total 9\nport49_key_secret_files_changed 2\nport49_x{a=\"b\"} 7\n"
	if v, err := gaugeIn(expo, "port49_key_secret_files_changed"); err != nil || v != 2 {
		t.Fatalf("gauge = %v, %v; want 2", v, err)
	}
	if _, err := gaugeIn(expo, "port49_x"); err == nil {
		t.Fatal("a labelled sample was read as an unlabelled one")
	}
	if _, err := gaugeIn(expo, "port49_absent"); err == nil {
		t.Fatal("an absent metric was read")
	}
}

// refuses is whether f, run on a throwaway T, fails it: a helper's refusal.
func refuses(f func(t *testing.T)) (refused bool) {
	inner := &testing.T{}
	done := make(chan struct{})
	go func() { defer close(done); f(inner) }()
	<-done
	return inner.Failed()
}

func TestFloorLine(t *testing.T) {
	members := []string{"https://etcd-1:2379", "https://etcd-2:2379", "https://etcd-3:2379"}
	good := "x\nport49d: store: etcd https://etcd-1:2379 3.6.15, https://etcd-2:2379 3.6.15, https://etcd-3:2379 3.6.15, at or above the floor (3.4.24, 3.5.8 or 3.6)\n"
	if refuses(func(t *testing.T) { FloorLine(t, good, members) }) {
		t.Fatal("the floor line naming every member was refused")
	}
	for name, log := range map[string]string{
		"a member missing": strings.Replace(good, "https://etcd-3:2379 3.6.15, ", "", 1),
		"a VIP":            strings.ReplaceAll(good, "https://etcd-", "https://vip-"),
		"no floor words":   strings.Replace(good, ", at or above the floor", "", 1),
		"empty":            "",
	} {
		if !refuses(func(t *testing.T) { FloorLine(t, log, members) }) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWithAcceptV2(t *testing.T) {
	base := []byte("keys:\n  k:\n    current: {version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}\nscopes: []\n")
	out, err := WithAcceptV2(base, "/run/port49/keys")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"accept:", "version: 2", "secret_ref: file:/run/port49/keys/tacacs_v2", "version: 1", "tacacs_v1", "scopes"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the policy with version 2 lacks %q:\n%s", want, out)
		}
	}
	if _, err := WithAcceptV2([]byte("keys: {}\n"), "/k"); err == nil {
		t.Error("a policy with no key set k was accepted")
	}
}

func TestAdminRender(t *testing.T) {
	broker := "broker:\n  listen: \":8443\"\n  client_ca_file: /etc/port49/broker/broker-ca.pem\n  policy_file: /p\n"
	out := AdminBroker(t, broker, "/etc/port49/broker/attestation-roots.pem")
	if strings.Contains(out, "client_ca_file") || !strings.Contains(out, "trust_anchor_file: /etc/port49/broker/broker-ca.pem") ||
		!strings.Contains(out, "attestation_roots_file: /etc/port49/broker/attestation-roots.pem") {
		t.Fatalf("the broker config is not rendered for the admin touch:\n%s", out)
	}
	if !refuses(func(t *testing.T) { AdminBroker(t, "broker: {}\n", "/r") }) {
		t.Error("a config with no client_ca_file was rendered")
	}
	pol := AdminPolicy(t, "subjects:\n  - {name: a}\ngrants:\n  - {}\n", "  - {name: operator}")
	if pol != "subjects:\n  - {name: a}\n  - {name: operator}\ngrants:\n  - {}\n" {
		t.Fatalf("the subject went to the wrong place:\n%s", pol)
	}
	if !refuses(func(t *testing.T) { AdminPolicy(t, "subjects: []\n", "x") }) {
		t.Error("a policy with no grants: line was rendered")
	}
}

// A shipped policy names one subject; the admin cells revoke and mint as a second, so the smoke adds
// that subject and its grant from this one helper rather than hand-copying the lines.
func TestWithGrantedSubject(t *testing.T) {
	base := "scopes: [{name: all_devices, match: {}}]\nsubjects:\n  - {name: alice, identity: [\"user:alice@example.com\"], username: alice}\ngrants:\n  - {subject: alice, scope: all_devices, roles: [network_admin]}\nkey_groups: []\n"
	got, err := WithGrantedSubject(base, "bob", "user:bob@example.com", "all_devices", "network_admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  - {name: bob, identity: [\"user:bob@example.com\"], username: bob, token_ttl: 15m}\ngrants:\n",
		"grants:\n  - {subject: bob, scope: all_devices, roles: [network_admin]}\n  - {subject: alice",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the policy lacks %q:\n%s", want, got)
		}
	}
	if _, err := WithGrantedSubject("subjects: []\n", "bob", "user:bob@example.com", "s", "r"); err == nil {
		t.Error("a policy with no grants: block was accepted")
	}
}

func TestFilteredDropsASecretAndKeepsTheRest(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	got := Filtered(root, "nothing was revoked: run it as the owner\npassword = hunter2\nlast line\n")
	if !strings.Contains(got, "nothing was revoked") || strings.Contains(got, "hunter2") || !strings.Contains(got, "last line") {
		t.Fatalf("got %q", got)
	}
	// A line the filter drops is said to be withheld, with its length: a failure never shows nothing.
	if !strings.Contains(got, "<line withheld: 18 bytes>") {
		t.Fatalf("the dropped line is not accounted for: %q", got)
	}
}
