package directory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
			// The uniqueness search reads no values (attribute 1.1), so a
			// variant is never compared and waved through.
			if !slices.ContainsFunc(w.dir.calls, func(c *ldap.SearchRequest) bool {
				return c.Filter == "(uid="+wlID+")" && slices.Equal(c.Attributes, []string{"1.1"})
			}) {
				t.Fatal("the uniqueness search does not request 1.1")
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
	// With no mapping, a SPIFFE value is only a value: alice stays a person.
	t.Run("no mapping", func(t *testing.T) {
		w := newWorkloadWorld(t)
		w.r.Cfg.Workload = nil
		a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
			"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "uid": {wlID}})
		w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
		if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
			t.Fatalf("%v", err)
		}
	})
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

// Pre-warm verifies a machine_group's members as workloads (decision 41
// ruling 6): the principal is the SPIFFE ID the member's attribute holds, in
// a listed trust domain, else the member is skipped and counted. A pre-warmed
// workload is served in an outage within grace though it never minted
// (Review Focus 4), and no mb/user: record is written for it (Review Focus 5).
func TestPrewarmVerifiesMachineGroupMembersAsWorkloads(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 10
	const stray = "CN=stray,OU=Workloads,DC=corp"
	w.dir.onBase(gBackup, "(objectClass=*)", entry(gBackup, map[string][]string{"member": {wlDN, stray}}))
	w.dir.onBase(wlDN, "(objectClass=user)", wlEntry(wlID))
	w.dir.onBase(stray, "(objectClass=user)", entry(stray, map[string][]string{
		"uid": {"spiffe://elsewhere.example/x"}, "sAMAccountName": {"stray"}}))
	rep, err := w.r.PrewarmAll(context.Background(), nil, []string{gBackup}, nil)
	if err != nil || rep.Groups != 1 || rep.Principals != 1 || rep.Failed != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryPrewarmPrincipals); v != 1 {
		t.Fatalf("port49_directory_prewarm_principals = %v", v)
	}
	if ps, _ := w.st.MembershipPrincipals(context.Background()); !slices.Equal(ps, []string{wlID}) {
		t.Fatalf("pre-warm wrote %v", ps)
	}
	w.clk.Add(time.Hour)
	w.down()
	a, err := w.r.CurrentWorkload(context.Background(), wlID)
	if err != nil || a.Source != Grace || !slices.Equal(a.GroupNames, []string{"backup-hosts"}) {
		t.Fatalf("%+v %v", a, err)
	}
}

// Without a workload mapping, neither machine groups nor workload identities
// are pre-warmed.
func TestPrewarmSkipsMachineGroupsWithoutAMapping(t *testing.T) {
	w := newWorld(t)
	rep, err := w.r.PrewarmAll(context.Background(), nil, []string{gBackup}, []string{wlID})
	if err != nil || rep.Groups != 0 || rep.Principals != 0 || len(w.dir.calls) != 0 {
		t.Fatalf("%+v %v %d searches", rep, err, len(w.dir.calls))
	}
}

// An identity-only workload, granted by its own spiffe:// subject and in no
// machine_group, is pre-warmed too (decision 41 ruling 6; pre-flight I-3):
// its last own verification is past grace, the pass verifies it, and it is
// served in an outage within grace of the pass. An identity outside the
// verifier's trust domains is not searched. The workloads share one
// prewarm.max_principals: past it the rest are capped.
func TestPrewarmVerifiesIdentityOnlyWorkloads(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 10
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil { // its own last mint
		t.Fatal(err)
	}
	w.clk.Add(5 * time.Hour) // past grace (4h)
	rep, err := w.r.PrewarmAll(context.Background(), nil, nil, []string{"spiffe://elsewhere.example/x", wlID})
	if err != nil || rep.Principals != 1 || rep.Failed != 0 || rep.Capped {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, c := range w.dir.calls {
		if strings.Contains(c.Filter, "elsewhere.example") {
			t.Fatalf("an identity outside the trust domains was searched: %s", c.Filter)
		}
	}
	w.clk.Add(time.Hour)
	w.down()
	if a, err := w.r.CurrentWorkload(context.Background(), wlID); err != nil || a.Source != Grace {
		t.Fatalf("in the outage: %+v %v", a, err)
	}
	// The budget: one principal, two workloads; the second (sorted) is capped.
	w = newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 1
	rep, err = w.r.PrewarmAll(context.Background(), nil, nil,
		[]string{"spiffe://corp.example.com/host/oxidized-02", wlID})
	if err != nil || rep.Principals != 1 || rep.Failed != 0 || !rep.Capped {
		t.Fatalf("capped: %+v %v", rep, err)
	}
}

// Pre-warm of a machine group's member fails, counted and skipped, when the
// member's attribute is not a SPIFFE ID in a listed trust domain (a value
// outside them, or not a SPIFFE ID at all), or when the entry is not under the
// workload user_filter; none of them is stored (Task 2 review Minor 2).
func TestPrewarmSkipsMachineGroupMembersThatAreNoWorkload(t *testing.T) {
	const bad = "CN=bad,OU=Workloads,DC=corp"
	for name, e := range map[string]*ldap.Entry{
		"outside the trust domains": entry(bad, map[string][]string{"uid": {"spiffe://elsewhere.example/x"}, "sAMAccountName": {"bad"}}),
		"malformed":                 entry(bad, map[string][]string{"uid": {"spiffe://corp.example.com"}, "sAMAccountName": {"bad"}}),
		"not a SPIFFE ID":           entry(bad, map[string][]string{"uid": {"bad"}, "sAMAccountName": {"bad"}}),
		"outside the user_filter":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorkloadWorld(t)
			w.r.Cfg.PrewarmMax = 10
			w.dir.onBase(gBackup, "(objectClass=*)", entry(gBackup, map[string][]string{"member": {bad}}))
			if e != nil {
				w.dir.onBase(bad, "(objectClass=user)", e)
			}
			rep, err := w.r.PrewarmAll(context.Background(), nil, []string{gBackup}, nil)
			if err != nil || rep.Groups != 1 || rep.Principals != 0 || rep.Failed != 1 {
				t.Fatalf("%+v %v", rep, err)
			}
			if ps, _ := w.st.MembershipPrincipals(context.Background()); len(ps) != 0 {
				t.Fatalf("pre-warm wrote %v", ps)
			}
		})
	}
}
