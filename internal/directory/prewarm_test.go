package directory

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// addUser registers one more user of the world: the searches Prewarm's
// classification and verification send for dn.
func addUser(w *world, dn, name string, groups ...*ldap.Entry) {
	mail := name + "@corp.example.com"
	e := entry(dn, map[string][]string{"userPrincipalName": {mail}, "sAMAccountName": {name}, "mail": {mail}})
	w.dir.onBase(dn, "(objectClass=person)", e)
	w.dir.on("(userPrincipalName="+mail+")", e)
	w.dir.on("(sAMAccountName="+name+")", e)
	w.dir.on(memberFilter(dn), groups...)
}

func memberEntry(dns ...string) *ldap.Entry {
	return entry(gOnCall, map[string][]string{"member": dns})
}

// Prewarm reads the group's member at base scope, verifies each user and
// stores them with their mapping keys: a later bind finds alice in grace.
func TestPrewarmStoresMembersByKey(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 10
	w.dir.onBase(gOnCall, "(objectClass=*)", memberEntry(alice, dave))
	addUser(w, alice, "alice", grp(gOnCall, "netops-oncall"))
	addUser(w, dave, "dave")
	rep, err := w.r.Prewarm(context.Background(), []string{gOnCall})
	if err != nil || rep.Groups != 1 || rep.Principals != 2 || rep.Failed != 0 || rep.Capped {
		t.Fatalf("%+v %v", rep, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryPrewarmPrincipals); v != 2 {
		t.Fatalf("port49_directory_prewarm_principals = %v", v)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryPrewarmLastSuccess); v != float64(w.clk.Now().Unix()) {
		t.Fatalf("last success = %v", v)
	}
	w.clk.Add(time.Hour)
	w.down()
	a, err := w.r.Map(context.Background(), aliceCert(t))
	if err != nil || a.Source != Grace || a.Principal != alicePrincipal || !slices.Equal(a.GroupNames, []string{"netops-oncall"}) {
		t.Fatalf("%+v %v", a, err)
	}
}

// A group named by its name is resolved to its one group; a member that is
// no user is counted failed and skipped.
func TestPrewarmResolvesANameAndSkipsANonUser(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 10
	w.dir.onBase(gOnCall, "(objectClass=*)", memberEntry(alice, "CN=Ghost,OU=Staff,DC=corp"))
	addUser(w, alice, "alice", grp(gOnCall, "netops-oncall"))
	rep, err := w.r.Prewarm(context.Background(), []string{"netops-oncall"})
	if err != nil || rep.Principals != 1 || rep.Failed != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// max_principals stops the pass at the limit and says so.
func TestPrewarmStopsAtMaxPrincipals(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 1
	w.dir.onBase(gOnCall, "(objectClass=*)", memberEntry(alice, dave))
	addUser(w, alice, "alice", grp(gOnCall, "netops-oncall"))
	addUser(w, dave, "dave")
	rep, err := w.r.Prewarm(context.Background(), []string{gOnCall})
	if err != nil || rep.Principals != 1 || !rep.Capped {
		t.Fatalf("%+v %v", rep, err)
	}
}

// A walk cut at max_depth is not the limit: it is counted apart, and the
// next group is still pre-warmed.
func TestPrewarmACutWalkDoesNotStopTheNextGroup(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 10
	w.r.Cfg.Nested, w.r.Cfg.MaxDepth = "recursive", 1
	w.dir.onBase(gMid, "(objectClass=*)", memberEntry(gLeaf))
	w.dir.onBase(gLeaf, "(objectClass=group)", grp(gLeaf, "g-leaf"))
	w.dir.onBase(gOnCall, "(objectClass=*)", memberEntry(alice))
	addUser(w, alice, "alice", grp(gOnCall, "netops-oncall"))
	w.dir.on(memberFilter(gOnCall))
	rep, err := w.r.Prewarm(context.Background(), []string{gMid, gOnCall})
	if err != nil || rep.Capped || rep.Principals != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryWalksTruncated); v != 1 {
		t.Fatalf("port49_directory_walks_truncated_total = %v, want 1", v)
	}
}

// With no server answering, the pass fails with ErrUnavailable and records
// no success.
func TestPrewarmInAnOutage(t *testing.T) {
	w := newWorld(t)
	w.down()
	if _, err := w.r.Prewarm(context.Background(), []string{gOnCall}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryPrewarmLastSuccess); v != 0 {
		t.Fatalf("last success = %v", v)
	}
}

// A member an earlier group already counted never counts again: with a
// limit of two, {alice} and {alice, dave} pre-warm both.
func TestPrewarmCountsDistinctUsersOnly(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 2
	w.dir.onBase(gMid, "(objectClass=*)", memberEntry(alice))
	w.dir.onBase(gOnCall, "(objectClass=*)", memberEntry(alice, dave))
	addUser(w, alice, "alice", grp(gOnCall, "netops-oncall"))
	addUser(w, dave, "dave")
	rep, err := w.r.Prewarm(context.Background(), []string{gMid, gOnCall})
	if err != nil || rep.Principals != 2 || rep.Capped {
		t.Fatalf("%+v %v", rep, err)
	}
}

// A name that matches no group, or two, is said.
func TestPrewarmSaysAGroupNameThatMatchesNoOne(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.PrewarmMax = 2
	if _, err := w.r.Prewarm(context.Background(), []string{"no-such-group"}); err != nil {
		t.Fatal(err)
	}
	if !w.say.has("no-such-group") {
		t.Fatalf("%v", w.say.l)
	}
}

// A policy group name that two groups share is skipped, and moves the
// ambiguous gauge; a name that matches no group does not.
func TestPrewarmASharedNameMovesTheAmbiguousGauge(t *testing.T) {
	w := newWorld(t)
	evil := "CN=shared,OU=Users-Can-Create,DC=corp"
	w.dir.on(uniqueFilter("shared"), grp(gOnCall, "shared"), grp(evil, "shared"))
	if _, err := w.r.Prewarm(context.Background(), []string{"nobody-has-this"}); err != nil {
		t.Fatal(err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryGroupNamesAmbiguous); v != 0 {
		t.Fatalf("a name matching no group: %v, want 0", v)
	}
	if _, err := w.r.Prewarm(context.Background(), []string{"shared"}); err != nil {
		t.Fatal(err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryGroupNamesAmbiguous); v != 1 {
		t.Fatalf("a shared name: %v, want 1", v)
	}
	w.clk.Add(time.Hour + time.Minute)
	if v := testutil.ToFloat64(w.r.M.DirectoryGroupNamesAmbiguous); v != 0 {
		t.Fatalf("an hour on: %v, want 0", v)
	}
}
