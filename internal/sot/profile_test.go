package sot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// statusOf is the body of /api/status/ as L30 recorded it for stack.
func statusOf(t *testing.T, stack string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "lab", "sot", "l30", stack, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.Body
}

// L27 and L30: the release is read from /api/status/, and every release they
// measured has its profile.
func TestEachMeasuredReleaseHasItsProfile(t *testing.T) {
	for stack, want := range map[string]string{"netbox-3.7": NetBox37, "netbox-4": NetBox4,
		"nautobot-1.6": Nautobot16, "nautobot-2": Nautobot2, "nautobot-3": Nautobot2} {
		product := strings.SplitN(stack, "-", 2)[0]
		v, err := versionOf(statusOf(t, stack), product)
		if err != nil {
			t.Fatalf("%s: %v", stack, err)
		}
		p, measured, err := Detect(v, "")
		if err != nil || p.Name != want || !measured || p.Product != product {
			t.Errorf("%s (%s): %s measured=%v %v", stack, v.Text, p.Name, measured, err)
		}
	}
}

func TestAnUnmeasuredMinorIsReadWithItsMajorsProfile(t *testing.T) {
	for _, c := range []struct {
		v    Version
		want string
	}{
		{Version{"netbox", "4.6.2", 4, 6}, NetBox4},
		{Version{"nautobot", "2.3.1", 2, 3}, Nautobot2},
		{Version{"nautobot", "3.0.0", 3, 0}, Nautobot2},
	} {
		p, measured, err := Detect(c.v, "")
		if err != nil || p.Name != c.want || measured {
			t.Errorf("%s: %s measured=%v %v", c.v.Text, p.Name, measured, err)
		}
	}
}

// Spec §10: an explicit override is available; without it, a major no lab
// run measured is refused.
func TestAnUnmeasuredMajorIsRefusedUnlessAProfileIsNamed(t *testing.T) {
	for _, v := range []Version{{"netbox", "3.6.9", 3, 6}, {"netbox", "5.0.0", 5, 0}, {"nautobot", "1.5.20", 1, 5},
		{"nautobot", "4.0.0", 4, 0}} {
		if _, _, err := Detect(v, ""); err == nil || !strings.Contains(err.Error(), "no lab run measured") ||
			!strings.Contains(err.Error(), "set profile") {
			t.Errorf("%s: %v", v.Text, err)
		}
	}
	p, measured, err := Detect(Version{"netbox", "3.6.9", 3, 6}, NetBox37)
	if err != nil || p.Name != NetBox37 || measured {
		t.Fatalf("override: %s %v %v", p.Name, measured, err)
	}
	if _, _, err := Detect(Version{"netbox", "4.7.1", 4, 7}, Nautobot2); err == nil ||
		!strings.Contains(err.Error(), "is not a netbox profile") {
		t.Fatalf("a Nautobot profile for NetBox: %v", err)
	}
}

func TestTheStatusMustNameTheProduct(t *testing.T) {
	if _, err := versionOf(statusOf(t, "nautobot-2"), "netbox"); err == nil ||
		!strings.Contains(err.Error(), "answers as Nautobot, and the source's type is netbox") {
		t.Fatalf("got %v", err)
	}
	if _, err := versionOf(map[string]any{}, "netbox"); err == nil || !strings.Contains(err.Error(), "netbox-version") {
		t.Fatalf("got %v", err)
	}
	// A version is the source's text: one that is not a version is refused
	// without being printed.
	if _, err := versionOf(map[string]any{"netbox-version": "4.7.1\x1b[2J"}, "netbox"); err == nil ||
		strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("got %v", err)
	}
}

// Decision 31: the map's vocabulary is what L27 and L30 recorded.
func TestTheVocabularyIsWhatWasRecorded(t *testing.T) {
	for path, ok := range map[string]bool{"site.slug": true, "role.slug": true, "platform.slug": true,
		"platform.network_driver": true, "location.name": true, "role.name": true, "platform.name": true,
		"status": true, "custom_fields.os_version": true, "custom_fields.Asset_Tag_2": true,
		"tenant.slug": false, "site.name": false, "custom_fields.": false, "custom_fields.a-b": false, "name": false} {
		if ValidPath(path) != ok {
			t.Errorf("%s: %v", path, !ok)
		}
	}
	if p := profiles[NetBox4]; strings.Join(p.paths(), ",") != "platform.slug,role.slug,site.slug" {
		t.Fatalf("%v", p.paths())
	}
	if f := profiles[Nautobot16].fields["platform.network_driver"]; f.over("graphql") == nil || f.over("rest") != nil {
		t.Fatal("Nautobot 1.6 gives network_driver over GraphQL only (L27)")
	}
	if !KnownProfile("nautobot", Nautobot2) || KnownProfile("netbox", Nautobot2) || KnownProfile("netbox", "netbox_5") {
		t.Fatal("KnownProfile")
	}
}
