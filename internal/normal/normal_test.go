package normal

import "testing"

func TestPrincipalIsTheFormTheBrokerCompares(t *testing.T) {
	for in, want := range map[string]string{
		"User:Alice@Example.COM":                "user:alice@example.com",
		"app:Port49-CI":                         "app:Port49-CI",
		"spiffe://corp.example.com/host/box-01": "spiffe://corp.example.com/host/box-01",
		"system:serviceaccount:netops:oxidized": "system:serviceaccount:netops:oxidized",
	} {
		if got, err := Principal(in); err != nil || got != want {
			t.Errorf("Principal(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "alice", "user:", "user:a b@example.com", "spiffe://", "user:\x01"} {
		if got, err := Principal(in); err == nil {
			t.Errorf("Principal(%q) = %q, want an error", in, got)
		}
	}
}

func TestUserRefusesAWorkload(t *testing.T) {
	if _, err := User("app:ci"); err == nil {
		t.Fatal("a workload is not a person")
	}
	if got, err := User("USER:Bob@Example.com"); err != nil || got != "user:bob@example.com" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestSerialIsLowerCaseHexWithoutPaddingOrColons(t *testing.T) {
	for in, want := range map[string]string{"0x1A:2b": "1a2b", "00ff": "ff", "0": "0", "-0x0": "0", "-0x1F": "-1f", "10": "10"} {
		if got, err := Serial(in); err != nil || got != want {
			t.Errorf("Serial(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "xyz", "0x", "-"} {
		if _, err := Serial(in); err == nil {
			t.Errorf("Serial(%q): want an error", in)
		}
	}
}

func TestIssuerRefusesControlAndFormCharacters(t *testing.T) {
	if err := Issuer("CN=Test CA"); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"CN=A\x1b[31m", "CN=A‮B", "\xff"} {
		if Issuer(in) == nil {
			t.Errorf("Issuer(%q): want an error", in)
		}
	}
}
