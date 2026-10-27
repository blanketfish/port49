package port49d

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
)

func workloadMapping() *directory.WorkloadMapping {
	return &directory.WorkloadMapping{Attribute: "uid", Issuers: []string{"CN=Workloads Issuing CA,O=Corp"},
		UserFilter: "(objectClass=user)", TrustDomains: []string{"corp.example.com"}}
}

// The start says the mapping, what every workload of the verifier then needs
// (ruling Q2; pre-flight I-4), its 3am cost with the two clocks apart
// (pre-flight M-1) and its ACL requirement (decision 41 rulings 2, 7 and 10),
// never the fact L50 measures.
func TestTheWorkloadMappingStartLines(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.Directory.Workload = workloadMapping()
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var out syncBuffer
	announceDirectory(&out, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
	got := out.String()
	for _, want := range []string{
		"port49-broker: directory: workload certificates map by spiffe_id (weak, pinned to CN=Workloads Issuing CA,O=Corp) " +
			"through uid under (objectClass=user); every workload this verifier accepts must have exactly one entry " +
			"holding its SPIFFE ID: none is refused identity_unmapped, two or more identity_ambiguous, and while the " +
			"directory is down past grace it is refused directory_unavailable; username from the identity subject listing the SPIFFE ID, else from " +
			"sAMAccountName; an entry holding a SPIFFE ID in uid is never a person's; machine_group subjects match " +
			"them, group subjects never\n",
		"port49-broker: directory: a mapped workload mints only while a server answers or its membership was verified " +
			"within grace (4h0m0s): past it its mints are refused directory_unavailable (port49 workload exits 75); its " +
			"live device sessions go unstamped from the first scheduled refresh that cannot verify it, and deny " +
			"context_stale once port49d's session.staleness_ceiling has passed since the last one that did; pre-warm " +
			"every 1h0m0s keeps mapped workloads verified (machine_group members and each spiffe:// identity a subject " +
			"lists, up to prewarm.max_principals (10000) besides the people's)\n",
		"port49-broker: directory: uid must be writable only by directory administrators: whoever can write it on an " +
			"entry chooses which workload takes that entry's groups\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start lines lack %q:\n%s", want, got)
		}
	}
	cfg.Broker.Directory.PrewarmInterval = 0
	var off syncBuffer
	announceDirectory(&off, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
	if !strings.Contains(off.String(), "; pre-warm is off, so a workload that has not minted within grace is refused in an outage\n") {
		t.Errorf("pre-warm off is not said:\n%s", off.String())
	}
}

// On AD the entry itself writes wWWHomePage and url whatever the OU's ACL (L50;
// decision 41 ruling 10), so the start says so for either, in any case, and
// stays quiet for an attribute the entry cannot write.
func TestTheWorkloadMappingStartSaysSelfWrittenAttributes(t *testing.T) {
	const selfWritten = "port49-broker: directory: on Active Directory the entry itself can write %s whatever the " +
		"OU's ACL (lab L50, measured on a service account's entry), so an entry under the workload user_filter " +
		"can put another workload's SPIFFE ID on itself; use uid or description\n"
	for _, tc := range []struct {
		attribute string
		said      bool
	}{
		{"wWWHomePage", true},
		{"URL", true},
		{"uid", false},
	} {
		cfg := brokerConfig(t, directoryPolicy)
		cfg.Broker.Directory = directoryCfg("gssapi")
		cfg.Broker.Directory.Workload = workloadMapping()
		cfg.Broker.Directory.Workload.Attribute = tc.attribute
		var out syncBuffer
		announceDirectory(&out, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
		got := out.String()
		if has := strings.Contains(got, fmt.Sprintf(selfWritten, tc.attribute)); has != tc.said {
			t.Errorf("attribute %s: the self-written line present = %v, want %v:\n%s", tc.attribute, has, tc.said, got)
		}
	}
}

// machine_group subjects with no mapping mint for no one, and the start names
// them (decision 41 ruling 5); with no broker.directory too.
func TestMachineGroupSubjectsWithoutAMappingAreSaid(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 5m}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: backup_hosts, scope: all_devices, roles: [r]}]
` + runKeys
	want := "port49d: policy: 1 machine_group subjects (backup_hosts) mint for no one: no " +
		"broker.identity.machines[].directory is configured\n"
	cfg := brokerConfig(t, body)
	var out syncBuffer
	announceDirectory(&out, "port49d", cfg, buildPolicy(t, cfg, body))
	if out.String() != want {
		t.Fatalf("no directory: got %q, want %q", out.String(), want)
	}
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var dir syncBuffer
	announceDirectory(&dir, "port49d", cfg, buildPolicy(t, cfg, strings.Replace(body,
		`identity: ["user:alice@example.com"], username: alice,`, `identity: ["user:alice@example.com"],`, 1)))
	if !strings.Contains(dir.String(), want) {
		t.Fatalf("a directory, no mapping:\n%s", dir.String())
	}
}

// policyEnv says whether the workload verifier maps (decision 41 ruling 1).
func TestPolicyEnvSaysTheWorkloadMapping(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	if e := policyEnv(cfg); e.Directory != policy.DirectoryOff || e.WorkloadDirectory != policy.DirectoryOff {
		t.Fatalf("no directory: %+v", e)
	}
	cfg.Broker.Directory = directoryCfg("gssapi")
	if e := policyEnv(cfg); e.Directory != policy.DirectoryOn || e.WorkloadDirectory != policy.DirectoryOff {
		t.Fatalf("a directory: %+v", e)
	}
	cfg.Broker.Directory.Workload = workloadMapping()
	if e := policyEnv(cfg); e.WorkloadDirectory != policy.DirectoryOn {
		t.Fatalf("a mapping: %+v", e)
	}
}

// The resolver port49d builds carries the workload mapping of the config, so a
// mapped verifier's mints are resolved through it (Task 5 review m-1).
func TestTheResolverCarriesTheWorkloadMapping(t *testing.T) {
	t.Setenv("T_DIR_BIND_PW", secretBindValue)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("simple")
	live := policy.NewLive(buildPolicy(t, cfg, directoryPolicy))
	open := func() *directory.Resolver {
		r, err := openDirectory(cfg, nil, live, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
		if err != nil || r == nil {
			t.Fatalf("%v %v", r, err)
		}
		return r
	}
	if w := open().Cfg.Workload; w != nil {
		t.Fatalf("a mapping without one configured: %+v", w)
	}
	cfg.Broker.Directory.Workload = workloadMapping()
	w := open().Cfg.Workload
	if w == nil || w.Attribute != "uid" || len(w.Issuers) != 1 || w.Issuers[0] != "CN=Workloads Issuing CA,O=Corp" {
		t.Fatalf("the resolver's mapping: %+v", w)
	}
}
