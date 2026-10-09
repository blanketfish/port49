package policy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const machineYAML = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: backup, privilege: admin, permit: ["show running-config"]}
subjects:
  - {name: netops_ro, group: netops-ro, token_ttl: 15m}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 15m}
  - {name: backup_dn, machine_group: "CN=Backup-DN,OU=G,DC=corp", token_ttl: 15m}
  - {name: shared_people, group: shared, token_ttl: 15m}
  - {name: shared_hosts, machine_group: shared, token_ttl: 15m}
grants:
  - {subject: netops_ro, scope: all_devices, roles: [ro]}
  - {subject: backup_hosts, scope: all_devices, roles: [backup]}
  - {subject: backup_dn, scope: all_devices, roles: [backup]}
  - {subject: shared_people, scope: all_devices, roles: [ro]}
  - {subject: shared_hosts, scope: all_devices, roles: [backup]}
`

func loadWorkloadText(t *testing.T, body string, mode DirectoryMode) (*Policy, error) {
	t.Helper()
	e := env()
	e.Directory, e.WorkloadDirectory = DirectoryOn, mode
	return Parse([]byte(body), e)
}

func machinePolicy(t *testing.T, mode DirectoryMode) *Policy {
	t.Helper()
	p, err := loadWorkloadText(t, machineYAML, mode)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const wlPrincipal = "spiffe://corp.example.com/host/oxidized-01"

// everyGroup is in every group the policy names, by name and by DN.
func everyGroup(m Member) Member {
	m.GroupNames = []string{"backup-hosts", "netops-ro", "shared"}
	m.GroupDNs = []string{"cn=backup-dn,ou=G,dc=corp"}
	return m
}

// A machine_group subject matches a workload resolved through the mapping,
// and a group subject a person; never across (decision 41 ruling 5; Review
// Focus 3). One group named both ways matches each in its own domain.
func TestAMachineGroupMatchesAWorkloadAlone(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	wl := everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc"})
	if got := p.SubjectsOf(wl); !slices.Equal(got, []string{"backup_dn", "backup_hosts", "shared_hosts"}) {
		t.Fatalf("the workload: %v", got)
	}
	person := everyGroup(Member{Principal: "user:alice@corp.example.com", Directory: true, Username: "alice"})
	if got := p.SubjectsOf(person); !slices.Equal(got, []string{"netops_ro", "shared_people"}) {
		t.Fatalf("the person: %v", got)
	}
	// A domain the principal's form contradicts matches nothing, either way.
	for _, m := range []Member{
		everyGroup(Member{Principal: wlPrincipal, Domain: DomainHumans, Directory: true}),
		everyGroup(Member{Principal: wlPrincipal, Directory: true}),
		everyGroup(Member{Principal: "user:alice@corp.example.com", Domain: DomainMachines, Directory: true}),
		everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines}),
	} {
		if got := p.SubjectsOf(m); len(got) != 0 {
			t.Fatalf("%+v matched %v", m, got)
		}
	}
}

// With the mapping off, no machine_group subject matches anyone.
func TestNoMachineGroupMatchesWithTheMappingOff(t *testing.T) {
	p := machinePolicy(t, DirectoryOff)
	wl := everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc"})
	if got := p.SubjectsOf(wl); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// A workload resolves with the username its member carries, and the
// machine_group's grants.
func TestAMachineGroupResolvesWithItsMembersUsername(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	wl := Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc-oxidized-01",
		GroupNames: []string{"backup-hosts"}}
	res, err := p.ResolveMember(wl, device(t, p, "leaf-01"), now)
	if err != nil || res.Subject != "backup_hosts" || res.Username != "svc-oxidized-01" || !slices.Equal(res.Roles, []string{"backup"}) {
		t.Fatalf("%+v %v", res, err)
	}
	wl.Username = ""
	if _, err := p.ResolveMember(wl, device(t, p, "leaf-01"), now); !errors.Is(err, ErrNoUsername) {
		t.Fatalf("no username: %v", err)
	}
}

func TestOneSubjectOfBothDomainsIsALoadError(t *testing.T) {
	for name, c := range map[string]struct{ subject, want string }{
		"both keys": {`{name: a, group: g, machine_group: g, token_ttl: 5m}`,
			"group names people and machine_group names workloads; a subject is one trust domain"},
		"a machine_group and identities": {`{name: a, machine_group: g, identity: ["spiffe://corp.example.com/x"], token_ttl: 5m}`,
			"a subject is a group or a list of identities, not both"},
		"a username on a machine_group": {`{name: a, machine_group: g, username: svc, token_ttl: 5m}`,
			"a machine_group's members take the username their identity subject declares, or their entry's"},
		"an equals sign that is no DN": {`{name: a, machine_group: "CN=a,,", token_ttl: 5m}`,
			`machine_group "CN=a,," holds = but is not a DN`},
	} {
		_, err := loadWorkloadText(t, "subjects: ["+c.subject+"]\n"+minimalGrant, DirectoryOn)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// A machine_group subject is a machines subject: attached_roles.machines
// reach it. Pre-warm and the start read the two kinds apart (Review Focus 5).
func TestAMachineGroupIsAMachinesSubject(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	s, _ := p.Subject("backup_hosts")
	if s.Domain != DomainMachines || s.GroupKey() != "machine_group" {
		t.Fatalf("%+v", s)
	}
	if h, _ := p.Subject("netops_ro"); h.GroupKey() != "group" {
		t.Fatalf("%+v", h)
	}
	if !slices.Equal(p.GroupValues(), []string{"netops-ro", "shared"}) ||
		!slices.Equal(p.MachineGroupValues(), []string{"CN=Backup-DN,OU=G,DC=corp", "backup-hosts", "shared"}) ||
		!slices.Equal(p.GroupSubjects(), []string{"netops_ro", "shared_people"}) ||
		!slices.Equal(p.MachineGroupSubjects(), []string{"backup_dn", "backup_hosts", "shared_hosts"}) {
		t.Fatalf("%v %v %v %v", p.GroupValues(), p.MachineGroupValues(), p.GroupSubjects(), p.MachineGroupSubjects())
	}
}

// DeclaredFor is the username the identity subject listing a principal
// declares (decision 41 ruling 4).
func TestDeclaredFor(t *testing.T) {
	p, err := loadWorkloadText(t, `subjects: [{name: a, identity: ["`+wlPrincipal+`"], username: svc-oxidized, token_ttl: 5m}]`+
		"\n"+minimalGrant, DirectoryOn)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeclaredFor(wlPrincipal) != "svc-oxidized" || p.DeclaredFor("spiffe://corp.example.com/other") != "" {
		t.Fatal("DeclaredFor")
	}
}

// Under the mapping, a spiffe://-only subject takes its entry's username and
// need not declare one; an app: identity still must (decision 41 ruling 4).
func TestASPIFFEOnlySubjectNeedsNoUsernameUnderTheMapping(t *testing.T) {
	spiffeOnly := `subjects: [{name: a, identity: ["` + wlPrincipal + `"], token_ttl: 5m}]` + "\n" + minimalGrant
	for _, mode := range []DirectoryMode{DirectoryOn, DirectoryUnknown} {
		if _, err := loadWorkloadText(t, spiffeOnly, mode); err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
	}
	if _, err := loadWorkloadText(t, spiffeOnly, DirectoryOff); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("off: %v", err)
	}
	withApp := `subjects: [{name: a, identity: ["` + wlPrincipal + `", "app:oxidized"], token_ttl: 5m}]` + "\n" + minimalGrant
	if _, err := loadWorkloadText(t, withApp, DirectoryOn); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("an app: identity: %v", err)
	}
}

// A changed machine_group fails the gate until a session test names the
// subject; a new one is gated; a group moved to machine_group with one value
// is a change (decision 41 ruling 8; Review Focus 3).
func TestAChangedMachineGroupIsGated(t *testing.T) {
	before := loadDiff(t, `subjects: [{name: oncall, machine_group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	after := loadDiff(t, `subjects: [{name: oncall, machine_group: other-hosts, token_ttl: 5m}]`+grantOnCall)
	if d := Compare(before, after, noon); d.UnacknowledgedPrincipals() != 1 {
		t.Fatalf("%+v", d.Subjects)
	}
	tested := loadDiff(t, `subjects: [{name: oncall, machine_group: other-hosts, token_ttl: 5m}]`+grantOnCall+
		"\ntests: [{subject: oncall, device: leaf-01, level: readonly}]")
	if d := Compare(before, tested, noon); d.UnacknowledgedPrincipals() != 0 {
		t.Fatalf("acknowledged: %+v", d.Subjects)
	}
}

func TestAGroupMovedToMachineGroupIsGated(t *testing.T) {
	before := loadDiff(t, `subjects: [{name: oncall, group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	after := loadDiff(t, `subjects: [{name: oncall, machine_group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	d := Compare(before, after, noon)
	if d.UnacknowledgedPrincipals() != 1 || len(d.Subjects) != 1 || d.Subjects[0].OldGroupKey != "group" ||
		d.Subjects[0].NewGroupKey != "machine_group" {
		t.Fatalf("%+v", d.Subjects)
	}
	// An identity subject added is still gated by its principals, not as a group.
	added := loadDiff(t, `subjects: [{name: oncall, group: backup-hosts, token_ttl: 5m}, {name: x, identity: ["app:x"], username: x, token_ttl: 5m}]`+grantOnCall)
	for _, s := range Compare(before, added, noon).Subjects {
		if s.Subject == "x" {
			t.Fatalf("an identity subject reported as a group change: %+v", s)
		}
	}
}
