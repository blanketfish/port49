package keyring

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

func heldUnder(t *testing.T, secret string) *Held {
	t.Helper()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("x")}.Encode()
	h.Length = uint32(len(body))
	var held Held
	held.Put("leaf-19", netip.MustParseAddr("10.20.4.9"), h, wire.Obfuscate(h, []byte(secret), body),
		time.Date(2026, 9, 30, 11, 59, 30, 0, time.UTC))
	return &held
}

var sets = map[string]Set{
	"prod_key": {Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("new")}, {Number: 2, Secret: []byte("old"), Retired: true}}},
	"lab_key":  {Ref: "lab_key", Versions: []Version{{Number: 1, Secret: []byte("lab")}}},
}

// Spec §10: keys diagnose names the group and version that match, retired
// versions and other groups' material included, and says so plainly.
func TestDiagnoseNamesWhatTheDeviceHolds(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f, ok := Diagnose(heldUnder(t, "old"), sets, "leaf-19", "prod_key", now)
	if !ok || len(f.Matches) != 1 || f.Matches[0] != (Match{KeyRef: "prod_key", Version: 2, State: "retired"}) {
		t.Fatalf("%+v, %v", f, ok)
	}
	if s := f.Text(now); !strings.Contains(s, "packet held 30s ago") || !strings.Contains(s, "missed in the rotation") {
		t.Fatalf("%s", s)
	}
	f, _ = Diagnose(heldUnder(t, "lab"), sets, "leaf-19", "prod_key", now)
	if s := f.Text(now); !strings.Contains(s, "holds lab_key's key, another group's") {
		t.Fatalf("%s", s)
	}
	f, _ = Diagnose(heldUnder(t, "nothing"), sets, "leaf-19", "prod_key", now)
	if s := f.Text(now); !strings.Contains(s, "validates under nothing port49d holds") {
		t.Fatalf("%s", s)
	}
	if _, ok := Diagnose(heldUnder(t, "old"), sets, "spine-02", "prod_key", now); ok {
		t.Fatal("a device with no held packet was diagnosed")
	}
}

// A finding names versions, never material: no secret and no byte of the
// held body, obfuscated or not, reaches its text or its JSON.
func TestAFindingCarriesNoSecretAndNoBody(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	secrets := map[string]Set{
		"prod_key": {Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("S3CR3T-NEW")}, {Number: 2, Secret: []byte("S3CR3T-OLD"), Retired: true}}},
		"lab_key":  {Ref: "lab_key", Versions: []Version{{Number: 1, Secret: []byte("S3CR3T-LAB")}}},
	}
	for _, secret := range []string{"S3CR3T-OLD", "S3CR3T-LAB", "S3CR3T-NONE"} {
		held := heldUnder(t, secret)
		p, _ := held.Get("leaf-19")
		f, _ := Diagnose(held, secrets, "leaf-19", "prod_key", now)
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{f.Text(now), string(raw)} {
			if strings.Contains(s, "S3CR3T") || strings.Contains(s, string(p.Body)) ||
				strings.Contains(s, base64.StdEncoding.EncodeToString(p.Body)) {
				t.Fatalf("material in %q", s)
			}
		}
	}
}

// Two groups sharing a secret: the assigned group's retired version is the
// verdict, not "another group's" key.
func TestDiagnoseReadsTheAssignedGroupFirst(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	shared := map[string]Set{
		"a_key":    {Ref: "a_key", Versions: []Version{{Number: 1, Secret: []byte("old")}}},
		"prod_key": {Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("new")}, {Number: 2, Secret: []byte("old"), Retired: true}}},
	}
	f, _ := Diagnose(heldUnder(t, "old"), shared, "leaf-19", "prod_key", now)
	if s := f.Text(now); len(f.Matches) != 2 || !strings.Contains(s, "missed in the rotation") || strings.Contains(s, "another group's") {
		t.Fatalf("%s", s)
	}
}

// Put keeps a copy: a caller reusing its read buffer cannot rewrite what is
// held.
func TestHeldKeepsACopy(t *testing.T) {
	var held Held
	body := []byte{1, 2, 3}
	held.Put("leaf-19", netip.MustParseAddr("10.20.4.9"), wire.Header{}, body, time.Time{})
	body[0] = 9
	if p, _ := held.Get("leaf-19"); p.Body[0] != 1 {
		t.Fatalf("%v", p.Body)
	}
}
