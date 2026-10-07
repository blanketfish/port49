package spiffe

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAccepts(t *testing.T) {
	for in, want := range map[string]ID{
		"spiffe://corp.example.com/host/oxidized-01":   {TrustDomain: "corp.example.com", Path: "/host/oxidized-01"},
		"spiffe://port49.test/ns/Netops/sa/Oxidized_2": {TrustDomain: "port49.test", Path: "/ns/Netops/sa/Oxidized_2"},
		"spiffe://a-b_c.d":                             {TrustDomain: "a-b_c.d"},
	} {
		got, err := Parse(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

// Each is refused, never folded or trimmed into an ID (decision 40 ruling 4):
// the path is case-sensitive, so folding would make two IDs one.
func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"SPIFFE://corp.example.com/x",
		"spiffe://Corp.example.com/x",
		"spiffe:///x",
		"spiffe://corp.example.com/x/",
		"spiffe://corp.example.com//x",
		"spiffe://corp.example.com/a/../b",
		"spiffe://corp.example.com/./b",
		"spiffe://corp.example.com/a%2fb",
		"spiffe://user@corp.example.com/x",
		"spiffe://corp.example.com:8443/x",
		"spiffe://corp.example.com/x?q=1",
		"spiffe://corp.example.com/x#f",
		"spiffe://corp.example.com/a b",
		"https://corp.example.com/x",
		"spiffe://corp.example.com/" + strings.Repeat("a", MaxLen),
	} {
		if id, err := Parse(in); err == nil || !errors.Is(err, ErrNotSPIFFE) {
			t.Errorf("Parse(%q) = %+v, %v; want ErrNotSPIFFE", in, id, err)
		}
	}
}

// A workload's ID has a path: the bare trust domain names the domain itself,
// not a workload (decision 40 ruling 3).
func TestParseWorkloadNeedsAPath(t *testing.T) {
	if _, err := ParseWorkload("spiffe://corp.example.com"); err == nil ||
		!strings.Contains(err.Error(), "names the trust domain itself, not a workload") {
		t.Fatalf("got %v", err)
	}
	if id, err := ParseWorkload("spiffe://corp.example.com/host/oxidized-01"); err != nil || id.Path != "/host/oxidized-01" {
		t.Fatalf("got %+v %v", id, err)
	}
}

func TestCheckTrustDomain(t *testing.T) {
	for td, ok := range map[string]bool{"corp.example.com": true, "a_b-c": true, "": false, "Corp.example.com": false,
		"corp.example.com/x": false, "corp example": false, strings.Repeat("a", MaxLen): false} {
		if err := CheckTrustDomain(td); (err == nil) != ok {
			t.Errorf("CheckTrustDomain(%q) = %v", td, err)
		}
	}
}
