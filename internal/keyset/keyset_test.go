package keyset

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const fakeKey = "Sx9-qT4v!Lm2@pR7zK0w#Yh5"

func v(n int, ref string) Version { return Version{Version: n, SecretRef: ref} }

// Keyring orders each set current, accept, retired, with RetireAt and the
// retired flag, and takes each secret by its version's reference.
func TestKeyring(t *testing.T) {
	sets, err := Check(map[string]Set{"k": {
		Current: Version{Version: 3, SecretRef: "env:K3"},
		Accept:  []Version{{Version: 2, SecretRef: "env:K2", RetireAfter: "2026-12-01"}},
		Retired: []Version{{Version: 1, SecretRef: "env:K1"}}}}, []byte("keys:\n  k: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ring := Keyring(sets, func(ref string) []byte { return []byte("s-" + ref) })
	vs := ring["k"].Versions
	if len(vs) != 3 || vs[0].Number != 3 || string(vs[0].Secret.Bytes()) != "s-env:K3" || vs[1].RetireAt.IsZero() ||
		!vs[2].Retired {
		t.Fatalf("got %d versions, wrong numbers, dates or flags (secrets not printed)", len(vs))
	}
}

func TestCheckRefusesWhatARotationCannotUse(t *testing.T) {
	cur := v(3, "env:A")
	for name, c := range map[string]struct {
		set  Set
		want string
	}{
		"version zero":  {Set{Current: v(0, "env:A")}, "1 or greater"},
		"twice":         {Set{Current: cur, Accept: []Version{v(3, "env:B")}}, "version 3 appears twice"},
		"no ref":        {Set{Current: v(3, "")}, "secret_ref is required"},
		"current dated": {Set{Current: Version{Version: 3, SecretRef: "env:A", RetireAfter: "2999-01-01"}}, "current version 3 has retire_after"},
		"retired dated": {Set{Current: cur, Retired: []Version{{Version: 1, SecretRef: "env:B", RetireAfter: "2999-01-01"}}}, "retired version 1 has retire_after"},
		"not a date":    {Set{Current: cur, Accept: []Version{{Version: 2, SecretRef: "env:B", RetireAfter: "soon"}}}, "retire_after is not a date"},
	} {
		_, err := Check(map[string]Set{"k": c.set}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		} else if strings.HasPrefix(err.Error(), "config:") {
			t.Errorf("%s: the refusal carries the caller's prefix: %v", name, err)
		}
	}
}

func TestCheckFillsRetireAtAsMidnightAfterTheDay(t *testing.T) {
	sets, err := Check(map[string]Set{"k": {Current: v(2, "env:A"),
		Accept: []Version{{Version: 1, SecretRef: "env:B", RetireAfter: "2000-01-01"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC); !sets["k"].Accept[0].RetireAt.Equal(want) {
		t.Fatalf("RetireAt %v", sets["k"].Accept[0].RetireAt)
	}
}

// A reference Parse refuses is ErrBadRef, and the refusal never carries it:
// it may be the secret itself.
func TestACheckedRefThatIsNoRefIsErrBadRefAndUnprinted(t *testing.T) {
	_, err := Check(map[string]Set{"k": {Current: v(1, fakeKey)}}, nil)
	if !errors.Is(err, ErrBadRef) {
		t.Fatalf("%v", err)
	}
	for i := 0; i+5 <= len(fakeKey); i++ {
		if strings.Contains(err.Error(), fakeKey[i:i+5]) {
			t.Fatalf("the refusal carries part of the secret: %v", err)
		}
	}
}

// A key that is no key_ref name is refused by its line in raw, never printed.
func TestACheckedKeyThatIsNoNameIsRefusedByLine(t *testing.T) {
	raw := "keys:\n  ok:\n    current: {version: 1, secret_ref: env:A}\n  " + fakeKey + ":\n    current: {version: 1, secret_ref: env:A}\n"
	_, err := Check(map[string]Set{"ok": {Current: v(1, "env:A")}, fakeKey: {Current: v(1, "env:A")}}, []byte(raw))
	if err == nil || !strings.Contains(err.Error(), "on line 4 is not a valid key_ref name") ||
		strings.Contains(err.Error(), fakeKey[:6]) {
		t.Fatalf("%v", err)
	}
}

func TestAllAndSortedAndNotices(t *testing.T) {
	s := Set{Current: v(3, "env:A"), Accept: []Version{v(2, "env:B")}, Retired: []Version{v(1, "env:C")}}
	if got := s.All(); len(got) != 3 || got[0].Version != 3 || got[1].Version != 2 || got[2].Version != 1 {
		t.Fatalf("All: %+v", got)
	}
	if got := Sorted(map[string]Set{"b": {}, "a": {}, "c": {}}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("Sorted: %v", got)
	}
	past := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)
	got := Notices(map[string]Set{"k": {Current: v(3, "env:A"), Accept: []Version{
		v(2, "env:B"), {Version: 1, SecretRef: "env:C", RetireAfter: "2000-01-01", RetireAt: past}}}}, time.Now())
	if len(got) != 2 || !strings.Contains(got[0], "key k version 2 has no retire_after") ||
		!strings.Contains(got[1], "retire_after 2000-01-01 has passed") {
		t.Fatalf("%q", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	s := Set{Current: v(3, "env:A"), Accept: []Version{v(2, "env:B")}, Retired: []Version{v(1, "env:C")}}
	c := s.Clone()
	c.Accept[0].Version, c.Retired[0].Version = 9, 9
	if s.Accept[0].Version != 2 || s.Retired[0].Version != 1 {
		t.Fatal("Clone shares its lists with the original")
	}
}

// single_device is the label the key series report every single-device key
// under, so no key may be named it.
func TestTheReservedKeyRefIsRefused(t *testing.T) {
	raw := "keys:\n  ok:\n    current: {version: 1, secret_ref: env:A}\n  single_device:\n    current: {version: 1, secret_ref: env:A}\n"
	_, err := Check(map[string]Set{"ok": {Current: v(1, "env:A")}, "single_device": {Current: v(1, "env:A")}}, []byte(raw))
	if err == nil || !strings.Contains(err.Error(), "on line 4") || !strings.Contains(err.Error(), "reserved name single_device") {
		t.Fatalf("%v", err)
	}
}
