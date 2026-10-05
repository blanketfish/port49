package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func grp(dn, cn string) *ldap.Entry { return entry(dn, map[string][]string{"cn": {cn}}) }

const (
	gLeaf   = "CN=g-leaf,OU=G,DC=corp"
	gMid    = "CN=g-mid,OU=G,DC=corp"
	gOnCall = "CN=netops-oncall,OU=G,DC=corp"
	gLoopA  = "CN=g-loop-a,OU=G,DC=corp"
	gLoopB  = "CN=g-loop-b,OU=G,DC=corp"
	alice   = "CN=Alice,OU=Staff,DC=corp"
	dave    = "CN=Dave,OU=Staff,DC=corp"
)

func memberFilter(dns ...string) string {
	if len(dns) == 1 {
		return "(&(objectClass=group)(member=" + dns[0] + "))"
	}
	f := "(&(objectClass=group)(|"
	for _, d := range dns {
		f += "(member=" + d + ")"
	}
	return f + "))"
}

func uniqueFilter(name string) string { return "(&(objectClass=group)(cn=" + name + "))" }

// in_chain is one search with the matching rule under groups_base_dn.
func TestInChainIsOneSearch(t *testing.T) {
	d := newFakeDir()
	d.on("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+alice+"))", grp(gLeaf, "g-leaf"), grp(gMid, "g-mid"), grp(gOnCall, "netops-oncall"))
	for _, g := range []struct{ dn, cn string }{{gLeaf, "g-leaf"}, {gMid, "g-mid"}, {gOnCall, "netops-oncall"}} {
		d.on(uniqueFilter(g.cn), grp(g.dn, g.cn))
	}
	c := adCfg()
	c.Nested = "in_chain"
	got, err := c.groupsOf(d, alice)
	if err != nil || !slices.Equal(got.DNs, []string{gLeaf, gMid, gOnCall}) || !slices.Contains(got.Names, "netops-oncall") {
		t.Fatalf("%+v %v", got, err)
	}
	if d.calls[0].BaseDN != "OU=G,DC=corp" {
		t.Fatalf("searched under %s", d.calls[0].BaseDN)
	}
	n := 0
	for _, c := range d.calls {
		if strings.Contains(c.Filter, inChainOID) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the matching-rule search was sent %d times, want once (pre-flight M-10)", n)
	}
}

// recursive walks member upward: alice ∈ g-leaf ∈ g-mid ∈ netops-oncall.
func TestARecursiveWalkFindsEveryLevel(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	d.on(memberFilter(gMid), grp(gOnCall, "netops-oncall"))
	for _, g := range []struct{ dn, cn string }{{gLeaf, "g-leaf"}, {gMid, "g-mid"}, {gOnCall, "netops-oncall"}} {
		d.on(uniqueFilter(g.cn), grp(g.dn, g.cn))
	}
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, alice)
	if err != nil || !slices.Equal(got.DNs, []string{gLeaf, gMid, gOnCall}) || got.Truncated || got.Loops != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	c.Nested = "direct"
	if got, _ = c.groupsOf(d, alice); !slices.Equal(got.DNs, []string{gLeaf}) {
		t.Fatalf("direct: %+v", got)
	}
}

// A loop ends the walk at the first revisit, counted (Review Focus 3).
func TestARecursiveWalkEndsOnALoop(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(dave), grp(gLoopA, "g-loop-a"))
	d.on(memberFilter(gLoopA), grp(gLoopB, "g-loop-b"))
	d.on(memberFilter(gLoopB), grp(gLoopA, "g-loop-a"))
	d.on(uniqueFilter("g-loop-a"), grp(gLoopA, "g-loop-a"))
	d.on(uniqueFilter("g-loop-b"), grp(gLoopB, "g-loop-b"))
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, dave)
	if err != nil || !slices.Equal(got.DNs, []string{gLoopA, gLoopB}) || got.Loops != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if len(d.calls) > 10 {
		t.Fatalf("the walk did not end: %d searches", len(d.calls))
	}
}

// A chain deeper than max_depth keeps what it found, truncated, never
// more (Review Focus 3).
func TestAWalkAtMaxDepthKeepsWhatItFound(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	d.on(memberFilter(gMid), grp(gOnCall, "netops-oncall"))
	d.on(uniqueFilter("g-leaf"), grp(gLeaf, "g-leaf"))
	d.on(uniqueFilter("g-mid"), grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested, c.MaxDepth = "recursive", 2
	got, err := c.groupsOf(d, alice)
	if err != nil || !got.Truncated || !slices.Equal(got.DNs, []string{gLeaf, gMid}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// A name two groups share is dropped from Names, and its DN kept: a DN
// subject still matches, a name subject does not (Ruling 7).
func TestASharedGroupNameMatchesNoOne(t *testing.T) {
	d := newFakeDir()
	evil := "CN=netops-oncall,OU=Users-Can-Create,DC=corp"
	d.on(memberFilter(alice), grp(evil, "netops-oncall"))
	d.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"), grp(evil, "netops-oncall"))
	c := adCfg()
	c.Nested = "direct"
	got, err := c.groupsOf(d, alice)
	if err != nil || len(got.Names) != 0 || !slices.Equal(got.Ambiguous, []string{"netops-oncall"}) ||
		!slices.Equal(got.DNs, []string{evil}) {
		t.Fatalf("%+v %v", got, err)
	}
	// Three sharing it: the fake answers with the size-limit error, which is
	// ambiguous too, never an error and never unique.
	d.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"), grp(evil, "netops-oncall"),
		grp("CN=netops-oncall,OU=More,DC=corp", "netops-oncall"))
	got, err = c.groupsOf(d, alice)
	if err != nil || len(got.Names) != 0 || !slices.Equal(got.Ambiguous, []string{"netops-oncall"}) {
		t.Fatalf("size limit: %+v %v", got, err)
	}
}

// A name whose uniqueness search finds no group is dropped and reported,
// never silently (pre-flight M-9).
func TestANameNoGroupAnswersIsReported(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf")) // uniqueFilter("g-leaf") unregistered: no group
	c := adCfg()
	c.Nested = "direct"
	got, err := c.groupsOf(d, alice)
	if err != nil || len(got.Names) != 0 || !slices.Equal(got.Unfound, []string{"g-leaf"}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// in_chain pre-warm asks for one more than the limit and stops there
// (pre-flight M-8): a 50,000-member group is never paged in whole.
func TestMembersOfInChainStopsPastTheLimit(t *testing.T) {
	d := newFakeDir()
	f := "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=" + gOnCall + "))"
	d.on(f, entry("CN=A,DC=corp", nil), entry("CN=B,DC=corp", nil), entry("CN=C,DC=corp", nil))
	c := adCfg()
	c.Nested = "in_chain"
	got, truncated, cut, err := c.membersOf(d, gOnCall, 2)
	if err != nil || !truncated || cut || len(got) != 2 || d.calls[0].SizeLimit != 3 {
		t.Fatalf("%v %v %v; size limit %d", got, truncated, err, d.calls[0].SizeLimit)
	}
}

// A DN spelled in another case is the same DN: the walk ends at it, never
// loops, never lists a group twice.
func TestARecursiveWalkComparesDNsCanonically(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(dave), grp(gLoopA, "g-loop-a"))
	d.on(memberFilter(gLoopA), grp(gLoopB, "g-loop-b"))
	d.on(memberFilter(gLoopB), grp("cn=G-LOOP-A, ou=g,dc=corp", "g-loop-a"))
	d.on(uniqueFilter("g-loop-a"), grp(gLoopA, "g-loop-a"))
	d.on(uniqueFilter("g-loop-b"), grp(gLoopB, "g-loop-b"))
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, dave)
	if err != nil || len(got.DNs) != 2 || got.Loops != 1 || got.Truncated {
		t.Fatalf("%+v %v", got, err)
	}
}

// A chain that ends exactly at max_depth is not truncated: nothing was left
// unasked.
func TestAWalkEndingAtMaxDepthIsNotTruncated(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	d.on(uniqueFilter("g-leaf"), grp(gLeaf, "g-leaf"))
	d.on(uniqueFilter("g-mid"), grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested, c.MaxDepth = "recursive", 2
	got, err := c.groupsOf(d, alice)
	if err != nil || got.Truncated || len(got.DNs) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
}

// A user DN with filter metacharacters is escaped in every filter.
func TestAGroupSearchEscapesTheDN(t *testing.T) {
	d := newFakeDir()
	evil := "CN=a)(cn=*,OU=Staff,DC=corp"
	c := adCfg()
	c.Nested = "direct"
	if _, err := c.groupsOf(d, evil); err != nil {
		t.Fatal(err)
	}
	if f := d.calls[0].Filter; f != `(&(objectClass=group)(member=CN=a\29\28cn=\2a,OU=Staff,DC=corp))` {
		t.Fatalf("%s", f)
	}
}

// A walk past the node bound keeps the groups it reached, truncated, and
// grants no more.
func TestAWalkPastTheNodeBoundIsTruncated(t *testing.T) {
	d := newFakeDir()
	var es []*ldap.Entry
	for i := 0; i < maxWalkNodes+5; i++ {
		es = append(es, grp(fmt.Sprintf("CN=g%d,OU=G,DC=corp", i), fmt.Sprintf("g%d", i)))
	}
	d.on(memberFilter(alice), es...)
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, alice)
	if err != nil || !got.Truncated || len(got.DNs) != maxWalkNodes {
		t.Fatalf("%d DNs, truncated %v, %v", len(got.DNs), got.Truncated, err)
	}
}

// in_chain past the node bound is truncated too.
func TestAnInChainAnswerPastTheNodeBoundIsTruncated(t *testing.T) {
	d := newFakeDir()
	var es []*ldap.Entry
	for i := 0; i < maxWalkNodes+5; i++ {
		es = append(es, grp(fmt.Sprintf("CN=g%d,OU=G,DC=corp", i), fmt.Sprintf("g%d", i)))
	}
	d.on("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+alice+"))", es...)
	c := adCfg()
	c.Nested = "in_chain"
	got, err := c.groupsOf(d, alice)
	if err != nil || !got.Truncated || len(got.DNs) != maxWalkNodes {
		t.Fatalf("%d DNs, truncated %v, %v", len(got.DNs), got.Truncated, err)
	}
}

// A search failing mid-walk returns nothing: never a partial membership.
func TestAWalkThatFailsMidwayReturnsNoGroups(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.err[memberFilter(gLeaf)] = ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, alice)
	if err == nil || len(got.DNs) != 0 || len(got.Names) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// The same for the uniqueness search.
	d = newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.err[uniqueFilter("g-leaf")] = ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	c.Nested = "direct"
	if got, err = c.groupsOf(d, alice); err == nil || len(got.DNs) != 0 || len(got.Names) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

const (
	uIn  = "CN=u-in,OU=G,DC=corp" // inside groups_base_dn: classified by a search
	anyF = "(objectClass=*)"
	isGF = "(objectClass=group)"
)

// members registers groupDN's member attribute for a base-scope read.
func members(d *fakeDir, groupDN string, ms ...string) {
	d.onBase(groupDN, anyF, entry(groupDN, map[string][]string{"member": ms}))
}

func isGroupSearches(d *fakeDir) int {
	n := 0
	for _, r := range d.calls {
		if r.Scope == ldap.ScopeBaseObject && r.Filter == isGF {
			n++
		}
	}
	return n
}

func TestMembersOfRecursiveListsNestedUsers(t *testing.T) {
	d := newFakeDir()
	members(d, gOnCall, gMid, alice, uIn)
	members(d, gMid, dave, gOnCall) // a loop back to the start
	d.onBase(gMid, isGF, grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested = "recursive"
	got, capped, cut, err := c.membersOf(d, gOnCall, 10)
	if err != nil || capped || cut || !slices.Equal(got, []string{alice, uIn, dave}) {
		t.Fatalf("%v %v %v %v", got, capped, cut, err)
	}
	// gMid and uIn are in groups_base_dn and asked about once each; alice
	// and dave are outside it and never searched.
	if n := isGroupSearches(d); n != 2 {
		t.Fatalf("%d isGroup searches, want 2", n)
	}
}

func TestMembersOfLimitIsCappedNotCut(t *testing.T) {
	d := newFakeDir()
	members(d, gOnCall, alice, dave, "CN=Eve,OU=Staff,DC=corp")
	c := adCfg()
	c.Nested = "recursive"
	got, capped, cut, err := c.membersOf(d, gOnCall, 2)
	if err != nil || !capped || cut || len(got) != 2 {
		t.Fatalf("%v %v %v %v", got, capped, cut, err)
	}
}

// A chain deeper than max_depth is cut, never capped: pre-warm goes on to
// the next group (review I-1).
func TestMembersOfDeeperThanMaxDepthIsCutNotCapped(t *testing.T) {
	d := newFakeDir()
	members(d, gOnCall, gMid)
	members(d, gMid, dave)
	d.onBase(gMid, isGF, grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested, c.MaxDepth = "recursive", 1
	got, capped, cut, err := c.membersOf(d, gOnCall, 10)
	if err != nil || capped || !cut || len(got) != 0 {
		t.Fatalf("%v %v %v %v", got, capped, cut, err)
	}
}

func TestMembersOfDirectDoesNotDescend(t *testing.T) {
	d := newFakeDir()
	members(d, gOnCall, gMid, alice)
	members(d, gMid, dave)
	d.onBase(gMid, isGF, grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested = "direct"
	got, capped, cut, err := c.membersOf(d, gOnCall, 10)
	if err != nil || capped || cut || !slices.Equal(got, []string{alice}) {
		t.Fatalf("%v %v %v %v", got, capped, cut, err)
	}
	for _, r := range d.calls {
		if r.BaseDN == gMid && r.Filter == anyF {
			t.Fatal("direct read the nested group's members")
		}
	}
}
