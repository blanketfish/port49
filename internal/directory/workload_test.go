package directory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	wlID     = "spiffe://corp.example.com/host/oxidized-01"
	wlDN     = "CN=svc-oxidized-01,OU=Workloads,DC=corp"
	gBackup  = "CN=backup-hosts,OU=G,DC=corp"
	wlFilter = "(&(objectClass=user)(uid=" + wlID + "))"
)

// wlEntry is the workload's service account holding uid.
func wlEntry(uid ...string) *ldap.Entry {
	return entry(wlDN, map[string][]string{"uid": uid, "sAMAccountName": {"svc-oxidized-01"},
		"objectGUID": {"\x01\x02"}})
}

// newWorkloadWorld is newWorld with a workload mapping by uid, pinned to the
// world's issuer, and the workload's entry in backup-hosts.
func newWorkloadWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	w.r.Cfg.Workload = &WorkloadMapping{Attribute: "uid", Issuers: pin, UserFilter: "(objectClass=user)",
		TrustDomains: []string{"corp.example.com"}}
	e := wlEntry(wlID)
	w.dir.on(wlFilter, e)
	w.dir.on("(uid="+wlID+")", e)                   // workloadUnique
	w.dir.on("(sAMAccountName=svc-oxidized-01)", e) // usernameUnique
	w.dir.on(memberFilter(wlDN), grp(gBackup, "backup-hosts"))
	w.dir.on(uniqueFilter("backup-hosts"), grp(gBackup, "backup-hosts"))
	return w
}

// A workload is verified by its SPIFFE ID (decision 41 ruling 2): one search
// under base_dn by the workload filter, size limit 2; the principal is the ID,
// the username the entry's, the groups its groups, the entry pinned; no
// mapping key is written.
func TestAWorkloadIsVerifiedByItsSPIFFEID(t *testing.T) {
	w := newWorkloadWorld(t)
	a, err := w.r.VerifyWorkload(context.Background(), wlID)
	if err != nil || a.Principal != wlID || a.Username != "svc-oxidized-01" || a.Source != Fresh ||
		!slices.Equal(a.GroupNames, []string{"backup-hosts"}) || a.EntryID != "guid:0102" || len(a.MapKeys) != 0 {
		t.Fatalf("%+v %v", a, err)
	}
	first := w.dir.calls[0]
	if first.Filter != wlFilter || first.SizeLimit != 2 || first.BaseDN != "DC=corp" {
		t.Fatalf("the search: %+v", first)
	}
	if m, err := w.st.GetMembership(context.Background(), wlID); err != nil || m.Refused || m.EntryID != "guid:0102" {
		t.Fatalf("stored %+v %v", m, err)
	}
}

// A directory's matching rule may ignore case; a SPIFFE ID's path does not
// (decision 40 ruling 4). The entry found must hold the ID byte for byte, as
// its one value, or the workload is refused identity_unmapped, and the
// refusal is stored (Review Focus 1).
func TestAWorkloadEntryMustHoldItsIDByteForByte(t *testing.T) {
	for name, vals := range map[string][]string{
		"another case": {"spiffe://corp.example.com/host/Oxidized-01"},
		"two values":   {wlID, "spiffe://corp.example.com/host/oxidized-02"},
		"no value":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorkloadWorld(t)
			w.dir.on(wlFilter, wlEntry(vals...))
			_, err := w.r.VerifyWorkload(context.Background(), wlID)
			if !errors.Is(err, ErrUnmapped) {
				t.Fatalf("%v", err)
			}
			if m, _ := w.st.GetMembership(context.Background(), wlID); !m.Refused {
				t.Fatalf("the refusal was not stored: %+v", m)
			}
		})
	}
	w := newWorkloadWorld(t)
	w.dir.on(wlFilter, wlEntry("spiffe://corp.example.com/host/Oxidized-01"))
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err == nil || !strings.Contains(err.Error(), "byte for byte") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// Two entries holding one SPIFFE ID, found by the uniqueness search with no
// user_filter, refuse it identity_ambiguous, never the first (decision 41
// ruling 2; Review Focus 1). Two cases: the twin holds the ID exactly, or
// another case of it that a case-insensitive matching rule returns for the
// ID. The search reads no values, so the variant is never waved through.
func TestTwoEntriesHoldingOneSPIFFEIDAreAmbiguous(t *testing.T) {
	for name, twin := range map[string]*ldap.Entry{
		"exact": entry("CN=alice,OU=Staff,DC=corp", map[string][]string{"uid": {wlID}}),
		"another case": entry("CN=svc-variant,OU=Staff,DC=corp",
			map[string][]string{"uid": {"spiffe://corp.example.com/host/Oxidized-01"}}),
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorkloadWorld(t)
			w.dir.on("(uid="+wlID+")", wlEntry(wlID), twin)
			if _, err := w.r.VerifyWorkload(context.Background(), wlID); !errors.Is(err, ErrAmbiguous) ||
				!strings.Contains(err.Error(), "OU=Staff") {
				t.Fatalf("%v", err)
			}
		})
	}
}

// One entry, one domain (decision 41 ruling 4; pre-flight I-2): a service
// account holding both a userPrincipalName and a SPIFFE ID in the workload
// attribute is the workload's alone. Verify refuses it as a person,
// identity_unmapped naming the attribute; VerifyWorkload accepts it. A
// person whose uid holds no SPIFFE ID stays a person.
func TestOneEntryIsOneDomain(t *testing.T) {
	w := newWorkloadWorld(t)
	both := entry(wlDN, map[string][]string{"uid": {wlID}, "userPrincipalName": {"svc-oxidized-01@corp.example.com"},
		"sAMAccountName": {"svc-oxidized-01"}, "objectGUID": {"\x01\x02"}})
	w.dir.on(wlFilter, both)
	w.dir.on("(uid="+wlID+")", both)
	w.dir.on("(sAMAccountName=svc-oxidized-01)", both)
	w.dir.on("(&(objectClass=person)(userPrincipalName=svc-oxidized-01@corp.example.com))", both)
	w.dir.on("(userPrincipalName=svc-oxidized-01@corp.example.com)", both)
	_, err := w.r.Verify(context.Background(), "user:svc-oxidized-01@corp.example.com")
	if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "the entry is a workload's (uid)") {
		t.Fatalf("as a person: %v", err)
	}
	if a, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil || a.Principal != wlID {
		t.Fatalf("as a workload: %+v %v", a, err)
	}
	// alice's uid is a login name, no SPIFFE ID: she is still a person.
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "uid": {"alice"}})
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatalf("alice: %v", err)
	}
	// The person search reads the workload attribute, or the check sees nothing.
	if !slices.ContainsFunc(w.dir.calls, func(c *ldap.SearchRequest) bool {
		return c.Filter == "(&(objectClass=person)(userPrincipalName=alice@corp.example.com))" &&
			slices.Contains(c.Attributes, "uid")
	}) {
		t.Fatal("the person search does not read the workload attribute")
	}
}

// With no server answering, a workload is served from the store within
// grace and refused past it (decision 38 ruling 10; decision 41 ruling 7).
func TestAWorkloadInGraceAndPastIt(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatal(err)
	}
	w.down()
	w.clk.Add(30 * time.Minute)
	a, err := w.r.CurrentWorkload(context.Background(), wlID)
	if err != nil || a.Source != Grace || !slices.Equal(a.GroupNames, []string{"backup-hosts"}) {
		t.Fatalf("within grace: %+v %v", a, err)
	}
	w.clk.Add(4 * time.Hour)
	if _, err := w.r.CurrentWorkload(context.Background(), wlID); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "past directory.grace") {
		t.Fatalf("past grace: %v", err)
	}
}

// A workload's principal is pinned to its entry (decision 38 ruling 3):
// another entry claiming the ID later is identity_unmapped, naming forget.
func TestAWorkloadIsPinnedToItsEntry(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatal(err)
	}
	moved := entry("CN=svc-new,OU=Workloads,DC=corp", map[string][]string{"uid": {wlID},
		"sAMAccountName": {"svc-new"}, "objectGUID": {"\x09\x09"}})
	w.dir.on(wlFilter, moved)
	w.dir.on("(uid="+wlID+")", moved)
	w.dir.on("(sAMAccountName=svc-new)", moved)
	_, err := w.r.VerifyWorkload(context.Background(), wlID)
	if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "port49 directory forget "+wlID) ||
		!strings.Contains(err.Error(), "a uid value moved") {
		t.Fatalf("%v", err)
	}
}

// The resolver leaves a workload's declared username to the broker (decision
// 41 ruling 4): a subject declaring the entry's username is no refusal here,
// fresh or in grace, since the subject may be the workload's own.
func TestTheResolverLeavesAWorkloadsDeclaredUsernameToTheBroker(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Declared = func() map[string]string { return map[string]string{"svc-oxidized-01": "svc_oxidized"} }
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	w.down()
	if _, err := w.r.CurrentWorkload(context.Background(), wlID); err != nil {
		t.Fatalf("grace: %v", err)
	}
}

// Only a SPIFFE ID under a mapping is a workload to verify; Verify still
// takes user: alone (pre-flight I-10).
func TestOnlyAWorkloadUnderTheMappingIsVerified(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), alicePrincipal); !errors.Is(err, ErrNotUser) {
		t.Fatalf("a person: %v", err)
	}
	if _, err := w.r.Verify(context.Background(), wlID); !errors.Is(err, ErrNotUser) {
		t.Fatalf("Verify of a workload: %v", err)
	}
	w.r.Cfg.Workload = nil
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); !errors.Is(err, ErrNotUser) {
		t.Fatalf("no mapping: %v", err)
	}
	if !IsWorkload(wlID) || IsWorkload(alicePrincipal) || IsWorkload("SPIFFE://corp.example.com/x") {
		t.Fatal("IsWorkload")
	}
}

// The issuer pin (decision 41 ruling 2; decision 38 ruling 1): the leaf's
// issuer, read from its DER, must be one pinned.
func TestTheWorkloadIssuerPin(t *testing.T) {
	m := &WorkloadMapping{Attribute: "uid", Issuers: pin}
	if err := m.Pinned(leaf(t, nil)); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	m.Issuers = []string{"CN=Other CA,DC=corp,DC=com"}
	if err := m.Pinned(leaf(t, nil)); err == nil || !strings.Contains(err.Error(), "is not one") {
		t.Fatalf("not pinned: %v", err)
	}
}

// The person path's prefix test is byte for byte (decision 41 ruling 4): a
// value in another case can never map a workload, so it does not make the
// entry a workload's.
func TestAnotherCaseOfTheSchemeIsNoWorkloadsEntry(t *testing.T) {
	w := newWorkloadWorld(t)
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "uid": {"SPIFFE://corp.example.com/host/x"}})
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatalf("%v", err)
	}
}
