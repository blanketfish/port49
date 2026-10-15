package directory

import (
	"errors"
	"strings"
	"testing"
)

func adCfg() Config {
	return Config{BaseDN: "DC=corp", GroupsBaseDN: "OU=G,DC=corp", UserFilter: "(objectClass=person)",
		GroupFilter: "(objectClass=group)", PrincipalAttribute: "userPrincipalName", UsernameAttribute: "sAMAccountName",
		GroupNameAttribute: "cn", MemberAttribute: "member", MaxDepth: 16}
}

// A zero mapping asks for no attribute named "": some directories refuse
// the whole search for it.
func TestAZeroMappingAsksForNoEmptyAttribute(t *testing.T) {
	cfg := adCfg()
	cfg.Mapping = Mapping{}
	for _, a := range cfg.entryAttrs() {
		if a == "" {
			t.Fatalf("an empty attribute among %q", cfg.entryAttrs())
		}
	}
}

// Two entries for one certificate is identity_ambiguous with both DNs,
// never the first; none is identity_unmapped (Ruling 2).
func TestOneEntryOrNone(t *testing.T) {
	d := newFakeDir()
	f := "(&(objectClass=person)(mail=alice@corp.example.com))"
	d.on(f, entry("CN=Alice,OU=Staff,DC=corp", nil), entry("CN=Alice,OU=Contractors,DC=corp", nil))
	_, err := adCfg().oneEntry(d, f, nil)
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "OU=Staff") || !strings.Contains(err.Error(), "OU=Contractors") {
		t.Fatalf("%v", err)
	}
	if d.calls[0].SizeLimit != 2 || d.calls[0].BaseDN != "DC=corp" {
		t.Fatalf("the search: %+v", d.calls[0])
	}
	if _, err := adCfg().oneEntry(d, "(&(objectClass=person)(mail=nobody@corp))", nil); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
}

// The principal and username are derived and checked (Ruling 3), and the
// entry's immutable id is its pin: objectGUID, else entryUUID, else the DN.
func TestIdentityOfAnEntry(t *testing.T) {
	c := adCfg()
	id, err := c.identityOf(entry("CN=Alice,DC=corp", map[string][]string{"userPrincipalName": {"Alice@Corp.Example.com"},
		"sAMAccountName": {"Alice"}, "objectGUID": {"\x0a\x1b\x2c\x3d"}}))
	if err != nil || id.Principal != "user:alice@corp.example.com" || id.Username != "alice" || id.EntryID != "guid:0a1b2c3d" {
		t.Fatalf("%+v %v", id, err)
	}
	if got := entryID(entry("CN=B,DC=corp", map[string][]string{"entryUUID": {"5F0E-AB"}})); got != "uuid:5f0e-ab" {
		t.Fatalf("entryUUID: %s", got)
	}
	if got := entryID(entry("CN=B,DC=Corp", nil)); got != "dn:cn=b,dc=corp" {
		t.Fatalf("no id attribute: %s", got)
	}
	both := entry("CN=B,DC=corp", map[string][]string{"objectGUID": {"\x01"}, "entryUUID": {"AB"}})
	if got := entryID(both); got != "uuid:ab" {
		t.Fatalf("the server-assigned entryUUID wins over a possibly writable objectGUID: %s", got)
	}
	for name, attrs := range map[string]map[string][]string{
		"no upn":           {"sAMAccountName": {"alice"}},
		"two upns":         {"userPrincipalName": {"a@x", "b@x"}, "sAMAccountName": {"alice"}},
		"a upn with no @":  {"userPrincipalName": {"alice"}, "sAMAccountName": {"alice"}},
		"a reserved name":  {"userPrincipalName": {"r@x"}, "sAMAccountName": {"remote"}},
		"a p49- name":      {"userPrincipalName": {"r@x"}, "sAMAccountName": {"p49-admin"}},
		"a domain prefix":  {"userPrincipalName": {"r@x"}, "sAMAccountName": {`CORP\alice`}},
		"a non-ascii upn":  {"userPrincipalName": {"\u212aate@corp.example.com"}, "sAMAccountName": {"mallory"}}, // U+212A KELVIN SIGN
		"a non-ascii name": {"userPrincipalName": {"r@x"}, "sAMAccountName": {"\u0130van"}},
		"an unprintable":   {"userPrincipalName": {"r@x"}, "sAMAccountName": {"al\tice"}},
	} {
		if _, err := c.identityOf(entry("CN=X,DC=corp", attrs)); !errors.Is(err, ErrUnmapped) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A username another entry holds is username_collision, naming both DNs
// (Ruling 3): two people under one username share one context.
func TestAUsernameTwoEntriesHoldCollides(t *testing.T) {
	d := newFakeDir()
	d.on("(sAMAccountName=alice)", entry("CN=Alice,DC=corp", nil), entry("CN=Alice2,DC=corp", nil))
	err := adCfg().usernameUnique(d, Identity{DN: "CN=Alice,DC=corp", Username: "alice"})
	if !errors.Is(err, ErrUsernameTaken) || !strings.Contains(err.Error(), "CN=Alice2,DC=corp") {
		t.Fatalf("%v", err)
	}
	d.on("(sAMAccountName=bob)", entry("CN=Bob,DC=corp", nil))
	if err := adCfg().usernameUnique(d, Identity{DN: "cn=bob,dc=corp", Username: "bob"}); err != nil {
		t.Fatalf("the same DN in another case: %v", err)
	}
	if f := d.calls[0].Filter; strings.Contains(f, "objectClass") {
		t.Fatalf("the uniqueness search is narrowed by user_filter: %s (pre-flight M-5)", f)
	}
}

// A principal another entry holds is identity_ambiguous, naming both DNs
// (pre-flight C-2): a user who sets their own mail or UPN to a colleague's
// never becomes the colleague, and the colleague is refused too while the
// two collide. Searched without user_filter, which finds more.
func TestAPrincipalTwoEntriesHoldIsAmbiguous(t *testing.T) {
	d := newFakeDir()
	d.on("(userPrincipalName=victim@corp.example.com)", entry("CN=Victim,DC=corp", nil), entry("CN=Mallory,DC=corp", nil))
	for _, dn := range []string{"CN=Mallory,DC=corp", "CN=Victim,DC=corp"} {
		err := adCfg().principalUnique(d, Identity{DN: dn, Principal: "user:victim@corp.example.com"})
		if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "CN=Victim,DC=corp") ||
			!strings.Contains(err.Error(), "CN=Mallory,DC=corp") {
			t.Fatalf("%s: %v", dn, err)
		}
	}
	d.on("(userPrincipalName=bob@corp.example.com)", entry("CN=Bob,DC=corp", nil))
	if err := adCfg().principalUnique(d, Identity{DN: "cn=bob,dc=corp", Principal: "user:bob@corp.example.com"}); err != nil {
		t.Fatalf("one entry: %v", err)
	}
}

// The uniqueness searches escape the value they search: a UPN or username
// of filter metacharacters cannot widen them into a match of every entry.
func TestUniquenessSearchesEscapeTheirValue(t *testing.T) {
	d := newFakeDir()
	d.on(`(userPrincipalName=\2a\29\28uid=\2a@x)`, entry("CN=X,DC=corp", nil))
	d.on(`(sAMAccountName=a\2a)`, entry("CN=X,DC=corp", nil))
	if err := adCfg().principalUnique(d, Identity{DN: "CN=X,DC=corp", Principal: "user:*)(uid=*@x"}); err != nil {
		t.Fatal(err)
	}
	if err := adCfg().usernameUnique(d, Identity{DN: "CN=X,DC=corp", Username: "a*"}); err != nil {
		t.Fatal(err)
	}
	if f := d.calls[0].Filter; f != `(userPrincipalName=\2a\29\28uid=\2a@x)` {
		t.Fatalf("%s", f)
	}
	if f := d.calls[1].Filter; f != `(sAMAccountName=a\2a)` {
		t.Fatalf("%s", f)
	}
}

// Past the size limit with neither returned entry another's is still
// another entry: refused, never passed.
func TestSizeLimitWithOnlySelfIsStillCollision(t *testing.T) {
	d := newFakeDir()
	d.on("(sAMAccountName=alice)", entry("CN=Alice,DC=corp", nil), entry("CN=Alice,DC=corp", nil), entry("CN=Z,DC=corp", nil))
	err := adCfg().usernameUnique(d, Identity{DN: "CN=Alice,DC=corp", Username: "alice"})
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("%v", err)
	}
}

// A search error is returned, not read as "no collision".
func TestUniquenessSearchErrorFailsClosed(t *testing.T) {
	d := newFakeDir()
	d.err["(sAMAccountName=alice)"] = errors.New("boom")
	if err := adCfg().usernameUnique(d, Identity{DN: "CN=Alice,DC=corp", Username: "alice"}); err == nil {
		t.Fatal("a failed uniqueness search passed")
	}
}

// dn: entry ids are injective (review I-1): an escaped comma, an RDN
// boundary and a multi-valued RDN are three DNs, three ids.
func TestEntryIDDNIsInjective(t *testing.T) {
	a := entryID(entry(`CN=alice\,OU=admins,DC=corp`, nil))
	b := entryID(entry(`CN=alice,OU=admins,DC=corp`, nil))
	c := entryID(entry(`CN=alice+OU=admins,DC=corp`, nil))
	if a == b || b == c || a == c {
		t.Fatalf("%s %s %s", a, b, c)
	}
	if entryID(entry("CN=B,DC=Corp", nil)) != entryID(entry("cn=b, dc=corp", nil)) {
		t.Fatal("the same DN in another case or spacing is another id")
	}
}

// A uniqueness search that does not return this entry is refused, not
// passed (review M-2): the server's matching rule disagrees with the
// canonical value.
func TestUniquenessSearchThatMissesTheEntryItselfFailsClosed(t *testing.T) {
	d := newFakeDir()
	if err := adCfg().principalUnique(d, Identity{DN: "CN=A,DC=corp", Principal: "user:kate@corp"}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("%v", err)
	}
	if err := adCfg().usernameUnique(d, Identity{DN: "CN=A,DC=corp", Username: "kate"}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("%v", err)
	}
	if f := d.calls[0].Attributes; len(f) != 1 || f[0] != "1.1" {
		t.Fatalf("attributes: %v", f)
	}
}
