//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/projection"
	"github.com/rhwendt/port49/internal/testpki"
)

// TestProjectionDifferential is spec §8's differential test of decision
// 22's projection: the reference configuration `platform export --classes`
// renders for set 1.1.0 is applied to the device, and for each rule shape the
// generator produces, a policy pinning 1.1.0 is minted through the broker, the
// token logs in, and every probe's outcome on the device is compared with
// port49's own decision on the command as the device expands it. The device
// running a command port49 denies fails the test; the device refusing one
// port49 permits must be what the projection itself predicts (a permit beyond
// the level's bits, say), or it fails too. A shape the generator cannot carry
// gets that subject the fail-closed reply (decision 26): the session opens,
// and the device runs no more than the allows the generator proved. Nothing
// quarantines the device.
//
// The probes type what the projection could let past: each denied command
// abbreviated, in upper case and piped; the commands a class with no bits
// runs; and configuration mode (plan 5b pre-flight I15). Every command typed
// has junosPer's deadline; a prompt that does not come back is not observed,
// and fails.

// projectionProbe is a command as typed and as the device expands it, without
// its pipeline: port49 is asked about the second, since a session-only device
// decides on it and the engine strips a pipeline before matching.
type projectionProbe struct {
	junosProbe
	canonical string
}

const hostEvidence = "host-name " + junosHost

// The `op url` probes run the staged script (stageOpScript), whose output
// carries the host name only where jcs:invoke was answered. The first is the
// canonical form; the second is its abbreviation, which the entry deny must
// refuse too (L26c: "with their abbreviations"). The control row's run of the
// canonical form is the positive control (opControlMissing).
const (
	opURLCmd      = "op url " + junosEntryOpPath
	opAbbrevCmd   = "op ur " + junosEntryOpPath
	opURLEvidence = "P49OP-VERSION " + junosHost
)

// opControlMissing reports whether row is set 1.2.0's control, whose reply
// carries no entry deny, and the canonical `op url` did not run in it: every
// `op` refusal in the other rows is then unisolated, and the run is INVALID.
func opControlMissing(set, row, cmd string, ran bool) bool {
	return (set == "1.2.0" || set == "1.3.0") && row == "operator, all it reaches" && cmd == opURLCmd && !ran
}

var projectionProbes = []projectionProbe{
	{junosProbe{cmd: "show version"}, "show version"},
	{junosProbe{cmd: "show system uptime"}, "show system uptime"},
	{junosProbe{cmd: "show interfaces terse"}, "show interfaces terse"},
	{junosProbe{cmd: "sh int ter"}, "show interfaces terse"},
	{junosProbe{cmd: "SHOW INTERFACES TERSE"}, "show interfaces terse"},
	{junosProbe{cmd: "show interfaces terse | no-more"}, "show interfaces terse"},
	{junosProbe{cmd: "show interfaces fxp0 terse"}, "show interfaces fxp0 terse"},
	{junosProbe{cmd: "show interfaces lo0 terse"}, "show interfaces lo0 terse"},
	{junosProbe{cmd: "show configuration system host-name", evidence: hostEvidence}, "show configuration system host-name"},
	{junosProbe{cmd: "sh conf sys host-name", evidence: hostEvidence}, "show configuration system host-name"},
	{junosProbe{cmd: "SHOW CONFIGURATION SYSTEM HOST-NAME", evidence: hostEvidence}, "show configuration system host-name"},
	{junosProbe{cmd: "show configuration system host-name | display set", evidence: hostEvidence},
		"show configuration system host-name"},
	{junosProbe{cmd: "   show configuration system host-name   ", evidence: hostEvidence},
		"show configuration system host-name"},
	{junosProbe{cmd: "show route summary"}, "show route summary"},
	// An enumerated value: the keyword tree must not prove `static` a keyword
	// unless Junos matches a deny against it (decision 27).
	{junosProbe{cmd: "show route protocol static"}, "show route protocol static"},
	{junosProbe{cmd: "clear interfaces statistics fxp0"}, "clear interfaces statistics fxp0"},
	{junosProbe{cmd: "ping 127.0.0.1 count 1 rapid"}, "ping 127.0.0.1 count 1 rapid"},
	{junosProbe{cmd: "sh ver"}, "show version"},
	{junosProbe{cmd: "SHOW VERSION"}, "show version"},
	// What a class with no bits runs (the adapter's baseline).
	{junosProbe{cmd: "set cli screen-width 200"}, "set cli screen-width 200"},
	{junosProbe{cmd: "show cli"}, "show cli"},
	{junosProbe{cmd: "file list /var/tmp"}, "file list /var/tmp"},
	// The op script's jcs:invoke RPCs are an entry past the CLI deny: set 1.2.0's
	// `op **` entry deny must refuse them (decision 44 ruling 2; L26c).
	{junosProbe{cmd: opURLCmd, evidence: opURLEvidence}, opURLCmd},
	{junosProbe{cmd: opAbbrevCmd, evidence: opURLEvidence}, opURLCmd},
	{junosProbe{cmd: "request system reboot", complete: true}, "request system reboot"},
	{junosProbe{cmd: "restart routing", complete: true}, "restart routing"},
	// The readings (projectionReadings): what a readonly's grant deny and its
	// allows beyond `view` do on the device.
	// Each is typed `| no-more`: a session without `set cli screen-length 0`
	// (the narrow readonly's) pages a long output, and the next probe's first
	// letter would go to the pager (HALT 2: `show log messages` is 1050 lines).
	{junosProbe{cmd: "show security zones | no-more"}, "show security zones"},
	{junosProbe{cmd: "show security policies | no-more"}, "show security policies"},
	// `show log messages` prints the syslog, which in a lab that has just refused
	// a stream of commands holds the refusal words: it is read by `| count`, whose
	// "Count: " line proves the command ran and which cannot page (review I2).
	{junosProbe{cmd: "show log messages | count", evidence: "Count: "}, "show log messages"},
	{junosProbe{cmd: "show firewall | no-more"}, "show firewall"},
	{junosProbe{cmd: "show policer | no-more"}, "show policer"},
	// Configuration mode, typed last: a statement there is governed by the
	// class's configuration permissions, which no command regex reaches.
	{junosProbe{cmd: "configure"}, "configure"},
	{junosProbe{cmd: "edit"}, "edit"},
}

// projectionReadings are probes the run reads rather than gates on the
// device's side: `show security` (the "readonly denying show security" row's
// grant deny), and the allows of view-configuration's carve-outs `show log`,
// `show firewall` and `show policer` that a readonly's reply sends beyond
// `view`. An image may lack the command (a security hierarchy on
// vJunos-router) or hold the allow narrower than port49 does; either is
// recorded in the note as the device's shortfall, not a failure. A device that
// runs what port49 denies, or what the model says it refuses, still fails.
// Only `show log messages` can print a refusal word on a command that ran (it
// is the syslog), so it alone is read by evidence (`| count`); the others print
// zone, policy, filter and policer configuration, which holds none, and an
// empty output is a command that ran.
var projectionReadings = map[string]bool{
	"show security zones | no-more": true, "show security policies | no-more": true, "show log messages | count": true,
	"show firewall | no-more": true, "show policer | no-more": true,
}

// upperCaseTyped reports whether cmd was typed with an upper-case letter. The
// Junos CLI is case-sensitive, so the device refuses it where port49 matches
// case-insensitively: narrower than port49, the fail-closed direction, which
// L12-projection already records. The device-refused check skips such a probe;
// the fail-open check does not.
func upperCaseTyped(cmd string) bool { return cmd != strings.ToLower(cmd) }

// configEntry reports whether cmd enters configuration mode.
func configEntry(cmd string) bool { return cmd == "configure" || cmd == "edit" }

// projectionShapes are the rule shapes the generator produces, and the one
// no measurement lets it carry. Each is the roles block of a policy pinning
// set 1.1.0. Which shape a composition renders to is the generator's, from
// the facts the binary ships, and the note records it; the test asserts the
// shape each renders to under set 1.1.0 as shipped, both ways, so a shape that
// silently fails closed, or stops failing closed, fails the run (Task 19
// review, finding 3).
var projectionShapes = []struct {
	name, roles, want string
}{
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
	{"readonly, a deny aligned with a bit", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeFailClosed},
	{"a permit beneath a deny", `  - {name: r, privilege: readonly, permit: ["show **", "show configuration system host-name"], deny: ["show configuration **"]}`, projection.ShapeFailClosed},
	{"an exact deny", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces terse"]}`, projection.ShapeFailClosed},
	{"narrow", `  - {name: r, privilege: readonly, permit: ["show version", "show interfaces **"]}`, projection.ShapeNarrow},
	{"a class term", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces @management **"]}`, projection.ShapeFailClosed},
	{"a permit beyond the bits", `  - {name: r, privilege: readonly, permit: ["show **", "clear interfaces statistics **"]}`, projection.ShapeNarrow},
	{"operator", `  - {name: r, privilege: operator, permit: ["show **", "clear **", "ping **"]}`, projection.ShapeNarrow},
	{"admin", `  - {name: r, privilege: admin, permit: ["**"]}`, projection.ShapeCapability},
	// The capability shapes carrying a keyword deny, and bits short of `all`:
	// the only shapes set 1.1.0 renders that put a deny regex on the wire
	// beside the bits (Task 19 review, finding 1). `restart` is a keyword on
	// both images, and no sent bit reaches it.
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"operator, a capability with a keyword deny", `  - {name: r, privilege: operator, permit: ["**"], deny: ["restart **"]}`,
		projection.ShapeCapability},
	{"operator, a capability with a keyword deny and allows", `  - {name: r, privilege: operator, permit: ["show **", ` +
		`"clear **", "ping **", "traceroute **", "restart **", "request **", "test **", "monitor **", "file **", ` +
		`"help **", "set **", "start **", "op **", "save **", "load **", "scp **", "ssh **", "telnet **", ` +
		`"mtrace **", "quit **", "exit **", "junoscript **", "xml-mode **"], deny: ["restart **"]}`,
		projection.ShapeCapability},
	// Two keyword denies alternated in one regex, the form every deny list of
	// more than one command renders to (Task 19 re-review).
	{"operator, a capability with two keyword denies", `  - {name: r, privilege: operator, permit: ["**"], ` +
		`deny: ["restart **", "configure **"]}`, projection.ShapeCapability},
	// Under 1.1.0's keyword tree nothing under `request` is proven, so this
	// deny fails closed (re-pre-flight R-M2); the operator shapes below carry
	// the capability shape with a deny on the device.
	{"admin with a deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["request system reboot **"]}`, projection.ShapeFailClosed},
	// An admin keeping a keyword deny under `show` (re-pre-flight minor):
	// with the bits that enter configuration mode dropped, the reply carries
	// the deny, the device refuses the configuration in every form typed and
	// over NETCONF, runs everything else the model says it runs, and never
	// enters configure or edit. Under set 1.1.0's facts as shipped
	// (DenyBindsRPCs false: a deny beneath a sent bit guards the CLI alone,
	// option C) it is the fail-closed reply, where the same refusals hold.
	{"admin keeping a keyword deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["show configuration **"]}`, projection.ShapeFailClosed},
	{"the refused shape", `  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}`, projection.ShapeFailClosed},
	// Junos matches keywords only (decision 27): a deny naming an argument
	// fails closed, an allow naming one is not sent, and a deny naming an
	// enumerated value runs only if the keyword tree proved it a keyword, which
	// the fail-open check then tests on the device.
	{"a deny naming an argument", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces fxp0 **"]}`, projection.ShapeFailClosed},
	{"an allow naming an argument", `  - {name: r, privilege: readonly, permit: ["show version", "show interfaces fxp0 **"]}`, projection.ShapeNarrow},
	{"a deny naming an enumerated value", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show route protocol static"]}`, projection.ShapeFailClosed},
	// A value under a command with no RPC, and one under a command that still
	// needs another argument: neither is proven a keyword (pre-flight A1), so
	// each deny fails closed and fails CI. Nothing here streams: the
	// fail-closed reply refuses `monitor` and `ping` outright.
	{"a deny of a value under a command with no RPC", `  - {name: r, privilege: operator, permit: ["show **", "monitor **"], deny: ["monitor traffic interface fxp0 **"]}`, projection.ShapeFailClosed},
	{"a deny of a value under an incomplete command", `  - {name: r, privilege: operator, permit: ["show **", "ping **"], deny: ["ping routing-instance mgmt_junos **"]}`, projection.ShapeFailClosed},
}

// projectionShapes120 are cell (c): set 1.2.0's answer for a deny beneath a
// sent bit. The first two carry a deny of `show configuration` beneath their
// bits and every baseline word permitted, so the only deny beneath is the
// grant's and the reply fits: the capability shape with the entry deny, the
// CLI refusing `show configuration`, NETCONF refused. "operator, all it
// reaches" has no deny beneath and keeps NETCONF: the control. The readonly
// rows are decision 44 ruling 10: `view`, the baseline's denies in one
// alternative with `junoscript` (`xml-mode` sent as nothing, refused through
// it), and allows of view-configuration's carve-outs the deny does not hold,
// sent beyond the bits, whose runs the note records as the device's
// shortfall; "readonly" alone keeps 1.1.0's narrow reply.
var projectionShapes120 = []struct{ name, roles, want string }{
	{"operator, a deny of show configuration beneath its bits", `  - {name: r, privilege: operator, permit: ["show **", ` +
		`"clear **", "ping **", "traceroute **", "request **", "test **", "monitor **", "file **", "help **", "set **", ` +
		`"start **", "op **", "save **", "load **", "scp **", "ssh **", "telnet **", "mtrace **", "probe **", "quit **", ` +
		`"exit **", "junoscript **", "xml-mode **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"admin keeping a keyword deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"readonly denying show configuration", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"readonly denying show security", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
}

// projectionShapes130 are set 1.3.0's (plan 9g; L68). The readonly denying
// `show security` now gets `view view-configuration` with `monitor **`
// denied, and its `show configuration` must run; so must the operator's, at
// `clear view view-configuration` (pre-flight I6). The readonly denying `show
// configuration` keeps 1.2.0's reply; the operator control keeps NETCONF.
var projectionShapes130 = []struct{ name, roles, want string }{
	{"readonly denying show security", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"operator denying show security", `  - {name: r, privilege: operator, permit: ["show **", "clear **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"readonly denying show configuration", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
}

// projectionProbes130 are typed in set 1.3.0's rows besides projectionProbes:
// view-configuration's other reach as commands that run in the control
// ("operator, all it reaches"), so a reply that let one through is seen. The
// `request` words, which run in no row, are Task 1's (L68), with their
// isolation.
var projectionProbes130 = []projectionProbe{
	{junosProbe{cmd: "monitor list"}, "monitor list"},
	{junosProbe{cmd: "mon list"}, "monitor list"},
	{junosProbe{cmd: "monitor list | no-more"}, "monitor list"},
}

// viewConfigurationRows130 are the set 1.3.0 rows sent view-configuration for
// `show configuration`: the device refusing it there is a STOP, since that
// delivery is plan 9g's point (pre-flight I2).
var viewConfigurationRows130 = []string{"readonly denying show security", "operator denying show security"}

// TestProjectionDifferential runs the differential once per set
// PORT49_LAB_PROJECTION_SETS names (comma-separated, default 1.1.0,1.2.0):
// 1.1.0 with projectionShapes into L12-projection, 1.2.0 with
// projectionShapes120 into L26c-projected (plan 9b1 Task 9, cell c).
func TestProjectionDifferential(t *testing.T) {
	sets := os.Getenv("PORT49_LAB_PROJECTION_SETS")
	if sets == "" {
		sets = "1.1.0,1.2.0"
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		for _, v := range strings.Split(sets, ",") {
			l.projectionSet(t, strings.TrimSpace(v))
		}
	})
}

// projectionSet is one set's run. Its NETCONF switch, capture and restore are
// its own, so 1.1.0's deleted `netconf ssh` is back before 1.2.0 starts.
func (l *lab) projectionSet(t *testing.T, v string) {
	t.Helper()
	shapes, entry := projectionShapes, "L12-projection"
	capName := map[string]string{"1.1.0": "projection", "1.2.0": "L26c-projected", "1.3.0": "L68-projected"}[v]
	if capName == "" {
		t.Fatalf("INVALID: no capture name for set %s; L12's evidence must not be overwritten", v)
	}
	if v == "1.2.0" {
		shapes, entry = projectionShapes120, "L26c-projected"
	}
	probes := projectionProbes
	if v == "1.3.0" {
		shapes, entry = projectionShapes130, "L68-projected"
		probes = slices.Concat(projectionProbes, projectionProbes130)
	}
	port49 := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(port49); err != nil {
		t.Fatalf("%s is missing: run `make build` first (%v)", port49, err)
	}
	set, ok := adapter.Set(v)
	if !ok || !set["juniper_junos"].Projected() {
		t.Fatalf("set %s does not project juniper_junos (plan 5b, Task 14)", v)
	}
	reference, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stop := l.capture(t, capName)
	defer stop()
	l.junosConfigureAdmin(t, reference)
	defer l.junosConfigureAdmin(t, projectionRestore(reference))
	// The `op url` probes run this script; the control row's run is their
	// positive control (opControlMissing).
	l.stageOpScript(t)
	// Where set 1.1.0 requires NETCONF disabled (plan 5b Task 14, branch
	// M), the run disables it as the operator must, and puts the lab's
	// `netconf ssh` back after.
	netconfOff := netconfForbidden(set["juniper_junos"])
	if netconfOff {
		l.junosConfigureAdmin(t, []string{"delete system services netconf"})
		defer l.junosConfigureAdmin(t, []string{"set system services netconf ssh"})
	}
	pki := filepath.Join(root, slicePKIDir)
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if std, err := l.configPath(); err == nil {
			if err := l.restart(std); err != nil {
				t.Errorf("could not put port49d back on the lab config: %v", err)
			}
		}
	}()
	var b strings.Builder
	fmt.Fprintf(&b, "The reference configuration applied, as `port49 platform export --classes` prints it for set "+
		"%s with a 12h max_session_age:\n\n```\n%s\n```\n", v, strings.Join(reference, "\n"))
	fmt.Fprintf(&b, "\nThe binary's JunosFacts: %+v.\n", projection.JunosFacts)
	var rendered []string
	for _, shape := range shapes {
		fmt.Fprintf(&b, "\n### %s\n\n", shape.name)
		b.WriteString(l.projectionShape(t, v, port49, pki, inv.Devices, shape.name, shape.roles, shape.want,
			netconfOff, probes, &rendered))
	}
	b.WriteString("\n### the commit checker (L9)\n\n")
	b.WriteString(l.projectionCommitCheck(t, rendered))
	claim := "Decisions 22 and 26's projection, differentially: for each rule shape the " +
		"generator produces, what the device runs under the reply port49 renders, typed as an operator might " +
		"type it — abbreviated, in upper case, piped — compared with port49's own decision on the command as the " +
		"device expands it: never more; and, for a composition the projection cannot carry, that the subject " +
		"gets the fail-closed reply and the device is not quarantined (spec §8, \"Verification\"; §13 decisions " +
		"22 and 26; §15 L9, L12)."
	if v == "1.2.0" {
		claim = "Set 1.2.0's projection end to end (plan 9b1 Task 9, cell c): for each shape, the reply port49 " +
			"renders carrying the entry deny (`junoscript **`, `op **`) beside the grant's deny, what the CLI " +
			"runs and refuses, whether `xml-mode`, `xml-mode netconf`, port 830 and the port-22 NETCONF " +
			"subsystem are refused under port49's rendered reply, and the shipped readonly's nested deny " +
			"(decision 44 rulings 1, 4 and 10; spec §15 L26c, L58)."
	}
	if v == "1.3.0" {
		claim = "Set 1.3.0's projection end to end (plan 9g Task 6; L68): for each shape, the reply port49 " +
			"renders, the readonly and the operator denying `show security` sent view-configuration with " +
			"`monitor **` denied (decision 48), what the CLI runs and refuses, `show configuration` running " +
			"where it is sent, and the XML entries and NETCONF under port49's rendered reply (spec §15 L68)."
	}
	// entryResult writes no note after a failed or INVALID run, and withholds
	// one that holds a pool token: a note under either set is a valid run's.
	l.entryResult(t, entry, claim, b.String())
}

// projectionShape runs one shape and renders its section of the note.
func (l *lab) projectionShape(t *testing.T, set, port49, pki string, devices []admission.Device, name, roles string,
	want string, netconfOff bool, probes []projectionProbe, rendered *[]string) string {
	t.Helper()
	// The lab's rules before each row: the STOP sentinel and the disk floor.
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("%v", err)
	}
	body := "platform_set: " + set + "\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n" + roles + "\n" +
		"subjects:\n  - {name: slice_operator, identity: [\"" + slicePrincipal + "\"], username: " + sliceUser +
		", enable: none, token_ttl: 60s}\ngrants:\n  - {subject: slice_operator, scope: all_devices, roles: [r]}\n"
	path := filepath.Join(root, "tests", "lab", "logs", "projection-"+l16Slug(name)+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: devices})
	if err != nil {
		t.Fatalf("%s: the shape's policy does not load: %v", name, err)
	}
	device, _ := pol.Device(l.p.node)
	_, quarantined := pol.Quarantined(device.Name, time.Now())
	brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	broker := strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml", path, 1)
	cfg, err := l.derivedConfig("projection-"+l16Slug(name), `[]`, broker)
	if err == nil {
		err = l.restart(cfg)
	}
	if err != nil {
		t.Fatalf("%s: port49d: %v", name, err)
	}
	sockDir, err := os.MkdirTemp("", "p49proj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "a", "agent.sock")
	out, err := withAgent(exec.Command(port49, "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
		"--broker-ca", filepath.Join(pki, testpki.LabCA)), sock).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: port49 login: %v\n%s", name, err, out)
	}
	defer stopSliceAgent(t, string(out))
	var b strings.Builder
	if quarantined {
		// A projection never quarantines: a composition it cannot carry is
		// that subject's fail-closed reply (decision 26).
		t.Errorf("%s: port49 quarantined %s", name, l.p.node)
		return "port49 quarantined the device, which a projection never does.\n"
	}
	res, err := pol.ResolveSubject("slice_operator", device, time.Now())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	got := res.Projection.Shape
	if res.Projection.FailClosed != "" {
		got = projection.ShapeFailClosed
	}
	if got != want {
		t.Errorf("%s: expected the %s shape, and port49 rendered %s (%s)", name, want, got, res.Projection.FailClosed)
	}
	*rendered = append(*rendered, res.Blob.Attributes...)
	tok := sliceToken(t, port49, sock, l.p.node)
	c, err := l.sshCLI(sliceUser, tok)
	if err == nil {
		if _, err = c.expect(90*time.Second, junosOpPrompt); err != nil {
			c.Close()
		}
	}
	if err != nil {
		t.Errorf("%s: the session did not open: %v", name, err)
		return "The session did not open: " + oneLine(err.Error()) + "\n"
	}
	defer c.Close()
	if err := junosPrepare(c); err != nil {
		t.Errorf("%s: set cli screen-length 0 not observed: %v", name, err)
	}
	auth, err := c.sendExpect("show cli authorization", junosPer, junosOpPrompt)
	if err != nil {
		t.Errorf("%s: show cli authorization not observed within %s: %v", name, junosPer, err)
		return "`show cli authorization` was not observed: " + oneLine(err.Error()) + "\n"
	}
	shape := res.Projection.Shape
	if res.Projection.FailClosed != "" {
		shape += ", " + res.Projection.FailClosed
	}
	fmt.Fprintf(&b, "Reply `%s` (%s). `show cli authorization`:\n\n```\n%s\n```\n\n", strings.Join(res.Blob.Attributes,
		"`, `"), shape, precReply(l16TrimEcho(auth, "show cli authorization")))
	b.WriteString("| typed | port49 on | port49 | projection predicts | device | agrees |\n|---|---|---|---|---|---|\n")
	var shortfalls []string
	for _, p := range probes {
		devOut, err := l.junosProbe(c, p.junosProbe)
		if err != nil {
			t.Errorf("%s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
			fmt.Fprintf(&b, "| `%s` | | | | not observed | |\n", p.cmd)
			break
		}
		r := junosRun{outs: map[string]string{p.cmd: devOut}}
		ran := r.runs(p.junosProbe)
		if p.complete {
			ran = r.completes(p.junosProbe)
		}
		if configEntry(p.cmd) && strings.Contains(devOut, "configuration mode") {
			ran = true
			if _, err := c.sendExpect("exit configuration-mode", junosPer, junosOpPrompt); err != nil {
				t.Errorf("%s: leaving configuration mode not observed within %s: %v", name, junosPer, err)
			}
		}
		_, o, err := pol.Decide("slice_operator", "", device, p.canonical, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		predicts := res.Projection.Device(strings.Fields(p.canonical))
		if opControlMissing(set, name, p.cmd, ran) {
			t.Errorf("INVALID: %s: the control's `%s` did not run the script, so no `op` refusal in the other "+
				"rows is isolated; no note is written: %s", name, p.cmd, oneLine(devOut))
		}
		// The proof rests on the model holding every command the device runs:
		// a command it runs and the model says it refuses is a model defect
		// even where port49 permits it. The device refusing what the model
		// says it runs is narrower, which fails closed, and is recorded.
		keepsDeny := name == "admin keeping a keyword deny"
		switch {
		case keepsDeny && configEntry(p.cmd) && ran:
			t.Errorf("%s: the device entered configuration mode by %q under a reply that carries a deny", name, p.cmd)
		case keepsDeny && res.Projection.FailClosed == "" && predicts && o.Permit && !ran && !p.complete &&
			!configEntry(p.cmd) && !projectionReadings[p.cmd] && !upperCaseTyped(p.cmd):
			t.Errorf("%s: the device refused %q, which port49 permits and the reply was proven to let run", name, p.cmd)
		case set == "1.3.0" && slices.Contains(viewConfigurationRows130, name) && p.evidence == hostEvidence &&
			!upperCaseTyped(p.cmd) && predicts && o.Permit && !ran:
			t.Errorf("STOP: %s: the device refused %q under set 1.3.0's reply, which sends view-configuration "+
				"so that it runs: the reply does not deliver what plan 9g ships; report to the controller", name, p.cmd)
		case ran && !o.Permit:
			t.Errorf("%s: the device ran %q, which port49 denies (%s): the projection fails open", name, p.cmd, o.Reason)
		case ran && !predicts:
			t.Errorf("%s: the device ran %q, and the projection's model says it refuses it: the model the proof "+
				"rests on is short of the device", name, p.cmd)
		}
		// The entry deny is the projection's alone: port49's decision on `op url`
		// is the role's (a permit where it permits `op **`), and the model is
		// what predicts the refusal, so a run past it is `ran && !predicts`.
		expected := o.Permit
		if p.canonical == opURLCmd {
			expected = o.Permit && predicts
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s | %s |\n", p.cmd, p.canonical, verdictWord(o.Permit),
			verb(predicts), verb(ran), yesNo(ran == expected))
		switch {
		case upperCaseTyped(p.cmd) && o.Permit && !ran:
			shortfalls = append(shortfalls, fmt.Sprintf("reading: `%s`: Junos's CLI is case-sensitive; the device refuses "+
				"the uppercase form; recorded, not a failure; see L12-projection.", p.cmd))
		case projectionReadings[p.cmd] && o.Permit && !ran:
			shortfalls = append(shortfalls, fmt.Sprintf("reading: `%s` did not run on this image (a refusal word, or the "+
				"probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the "+
				"command), recorded, not a failure.", p.cmd))
		}
	}
	for _, s := range shortfalls {
		fmt.Fprintf(&b, "\n%s\n", s)
	}
	// Where the set keeps NETCONF configured, the reply's `junoscript` deny
	// is what refuses the XML entries: "refused" where the reply carries it
	// (the entry deny, the narrow shape's `.*`, or the fail-closed reply),
	// else "open", the control.
	netconf := "open"
	switch {
	case netconfOff:
		netconf = "disabled"
	case res.Projection.NetconfClosed() || res.Projection.FailClosed != "":
		netconf = "refused"
	}
	if netconf != "disabled" {
		readonly := strings.Contains(roles, "privilege: readonly")
		b.WriteString(l.projectionXMLMode(t, name, c, netconf == "refused", readonly))
		if readonly && strings.Contains(roles, "deny:") && res.Projection.FailClosed == "" {
			b.WriteString(projectionNestedDeny(t, name, res.Blob.Attributes))
		}
	}
	b.WriteString(l.projectionNetconf(t, name, pol, device, tok, netconf))
	return b.String()
}

// projectionXMLMode types the XML entries at the CLI after the probes. A
// readonly row types bare `xml-mode` first (L58's cell, under the shipped
// nested deny), and every row types `xml-mode netconf need-trailer` last,
// through entryXMLMode, since a greeting leaves the session in XML mode. Under
// a reply that refuses `junoscript` a greeting, or an entry the device did not
// answer, fails the shape.
func (l *lab) projectionXMLMode(t *testing.T, name string, c *cliConn, refuses, readonly bool) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n| CLI entry | cell |\n|---|---|\n")
	check := func(entry, cell string) {
		fmt.Fprintf(&b, "| `%s` | %s |\n", entry, cell)
		if refuses && cell != "refused" {
			t.Errorf("%s: `%s` was %s under a reply that refuses junoscript", name, entry, cell)
		}
	}
	if readonly {
		from := len(c.out.String())
		cell := "not observed"
		if err := c.send("xml-mode"); err == nil {
			out, err := c.expectFrom(from, junosPer, "<junoscript", "</hello>", junosOpPrompt)
			if err == nil && !strings.Contains(out, "<junoscript") && !strings.Contains(out, "</hello>") {
				junosSettle(c)
				out = c.out.String()[from:]
			}
			if err == nil {
				cell = l58EntryCell(out)
			}
		}
		check("xml-mode", cell)
		if cell != "refused" {
			// The session may be in XML mode: the next entry would read
			// the XML protocol, not the CLI.
			b.WriteString("| `xml-mode netconf need-trailer` | not typed: the session is no longer at the CLI |\n")
			return b.String()
		}
	}
	r := newL26cRun()
	entryXMLMode(c, r)
	cell := r.cells["entry: xml-mode netconf need-trailer"]
	check("xml-mode netconf need-trailer", cell)
	if !refuses && cell != "hello" {
		t.Errorf("INVALID: %s: the control's `xml-mode netconf need-trailer` was %s, so the refusals in the other rows "+
			"are not isolated", name, cell)
	}
	if cell == "hello" {
		fmt.Fprintf(&b, "\n`get-configuration`: %s\n", r.cells["xml-mode netconf need-trailer: get-configuration"])
	}
	return b.String()
}

// projectionNestedDeny writes the rendered deny-commands of a readonly row
// that carries a deny of its own, and fails the shape unless it is the nested
// form, `^( … )$` holding the alternative that names `save` and `junoscript`:
// the regex the row's `xml-mode` cells are typed under (decision 44 ruling 10).
func projectionNestedDeny(t *testing.T, name string, attrs []string) string {
	t.Helper()
	for _, a := range attrs {
		v, ok := strings.CutPrefix(a, "deny-commands=")
		if !ok {
			continue
		}
		if !strings.HasPrefix(v, "^(") || !strings.HasSuffix(v, ")$") || !strings.Contains(v, "save") ||
			!strings.Contains(v, "junoscript") {
			t.Errorf("%s: the readonly's deny is not the nested form naming save and junoscript: %s", name, v)
		}
		return "\nRendered `deny-commands=` (the regex the `xml-mode` cells above are typed under): `" +
			tableCell(v) + "`\n"
	}
	t.Errorf("%s: the readonly's reply carries no deny-commands: %q", name, attrs)
	return "\nNo `deny-commands=` in the reply.\n"
}

// netconfForbidden reports whether check-config fails a device of d for
// serving NETCONF, so the run disables it as the operator must: under set
// 1.1.0 it does (plan 5b Task 14, branch M); under set 1.2.0 the reply's
// `junoscript` deny closes NETCONF per subject and the device keeps it
// (decision 44 rulings 1 and 6; platform.NetconfForbidden).
func netconfForbidden(d adapter.Dialect) bool { return adapter.NetconfForbidden(d) }

// projectionNetconf opens NETCONF with the shape's token, which gets the same
// reply, and sends the RPC equivalents of `show configuration` and `show
// version` (TestL12JunosNetconf's): an RPC the device runs where port49
// denies its command fails the test, as the CLI's fail-open check does (plan
// 5b pre-flight B1). want is "disabled" (the set requires NETCONF off, so the
// session must not open), "refused" (the reply denies junoscript, so ports 830
// and 22 must refuse) or "open" (the control). Each RPC has its deadline; a reply that is neither output
// nor an `<rpc-error>` is not observed.
func (l *lab) projectionNetconf(t *testing.T, name string, pol *policy.Policy, device admission.Device, tok string,
	want string) string {
	t.Helper()
	switch want {
	case "disabled":
		n, _, err := l.netconfDial(sliceUser, tok)
		if err == nil {
			n.Close()
			t.Errorf("%s: NETCONF opened, and the reply runs on a set that requires it disabled", name)
			return "\nNETCONF opened, which the set requires disabled.\n"
		}
		return "\nNETCONF disabled, as the set requires: `" + oneLine(err.Error()) + "`\n"
	case "refused":
		// The reply is port49's rendered one, so this is where ruling 1's
		// port 830 and port-22 subsystem cells are measured against what
		// port49 sends. A refusal counts only with the device's word and
		// port49's permit in the decision log, as entryNetconf reads it.
		var b strings.Builder
		for _, port := range []string{"830", "22"} {
			off := l.mark()
			n, _, err := l.netconfDialPort(sliceUser, tok, port)
			switch {
			case err == nil:
				n.Close()
				t.Errorf("%s: NETCONF on port %s opened under a reply that denies junoscript", name, port)
				fmt.Fprintf(&b, "\nNETCONF on port %s opened, which the reply's junoscript deny should refuse.\n", port)
			case isAuthRejection(err) || !entryErrRefusal(err) || !sessionPermitted(l.drainRecords(off, 10*time.Second)):
				t.Errorf("%s: NETCONF on port %s not observed: no device refusal after port49's permit: %v", name, port, err)
				fmt.Fprintf(&b, "\nNETCONF on port %s: not observed, `%s`\n", port, oneLine(err.Error()))
			default:
				fmt.Fprintf(&b, "\nNETCONF on port %s refused under the rendered reply: `%s`\n", port, oneLine(err.Error()))
			}
		}
		return b.String()
	}
	// "open", the control: the port-22 subsystem opens too, since a refusal
	// under the deny says nothing unless the same subsystem opens without it.
	var b strings.Builder
	if n22, _, err22 := l.netconfDialPort(sliceUser, tok, "22"); err22 != nil {
		t.Errorf("INVALID: %s: the control's port-22 NETCONF subsystem did not open: %v", name, err22)
	} else {
		n22.Close()
		b.WriteString("\nNETCONF on port 22 opened (control)\n")
	}
	n, hello, err := l.netconfDial(sliceUser, tok)
	if err != nil {
		t.Errorf("%s: the NETCONF session did not open: %v (%s)", name, err, oneLine(hello))
		return b.String() + "\nNETCONF: not observed, `" + oneLine(err.Error()) + "`\n"
	}
	defer n.Close()
	fmt.Fprintf(&b, "\nNETCONF on port %s opened (control)\n", netconfPort(l.p))
	b.WriteString("\n| NETCONF RPC | as the command | port49 | device |\n|---|---|---|---|\n")
	for k, r := range junosNetconfRPCs {
		reply, err := n.rpc(k+1, r.rpc)
		cell := netconfCell(reply, r.evidence)
		if err != nil || cell == "not observed" {
			t.Errorf("%s: %s not observed: %v %s", name, r.rpc, err, oneLine(reply))
			cell = "not observed"
		}
		_, o, err := pol.Decide("slice_operator", "", device, r.command, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cell == "ran" && !o.Permit {
			t.Errorf("%s: over NETCONF the device ran %s, and port49 denies %q (%s): the projection fails open "+
				"over RPC", name, r.rpc, r.command, o.Reason)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", r.rpc, r.command, verdictWord(o.Permit), cell)
	}
	return b.String()
}

func verb(ran bool) string {
	if ran {
		return "runs"
	}
	return "refuses"
}

func verdictWord(permit bool) string {
	if permit {
		return "permit"
	}
	return "deny"
}

// projectionRestore is what puts the lab's own configuration back after the
// reference configuration, which replaced the startup config's remote user
// and p49-readonly class: both rebuilt as tests/lab/configs/vjunos-startup.conf
// writes them, uid 2001 included, every other class and user the reference
// added deleted, and strict-authorization removed.
func projectionRestore(reference []string) []string {
	out := []string{"delete system tacplus-options strict-authorization",
		"delete system login user remote", "set system login user remote uid 2001",
		"set system login user remote class p49-readonly", "delete system login class p49-readonly",
		"set system login class p49-readonly permissions view",
		"set system login class p49-readonly permissions view-configuration"}
	seen := map[string]bool{"userremote": true, "classp49-readonly": true}
	for _, line := range reference {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "set" || f[1] != "system" || f[2] != "login" {
			continue
		}
		kind, name := f[3], f[4]
		if seen[kind+name] {
			continue
		}
		seen[kind+name] = true
		out = append(out, "delete system login "+kind+" "+name)
	}
	return out
}

// projectionCommitForms are wire regexes set 1.1.0 renders only under a
// policy's own platforms: block, where a privilege's ceiling drops `view` and
// a multi-word deny reaches the wire: the ` +` between its words, alone and
// alternated (Task 19 re-review 2). The commit check commits them beside the
// shapes' own.
var projectionCommitForms = []string{
	`deny-commands=^ *show +version *(\|.*)?$`,
	`deny-commands=^( *restart( .*)? *(\|.*)?| *show +version *(\|.*)?)$`,
}

// projectionCommitCheck commits each deny-commands and allow-commands regex
// the shapes rendered as a login class's own, over the break-glass CLI, reads
// it back and deletes the class: spec §15 L9's "whether the commit checker
// takes, as class configuration, every wire regex shape the projection
// renders" (Task 19 review, finding 2). A rejected one fails the test.
func (l *lab) projectionCommitCheck(t *testing.T, rendered []string) string {
	seen := map[string]bool{}
	var checks [][2]string
	for _, a := range append(rendered, projectionCommitForms...) {
		name, value, ok := strings.Cut(a, "=")
		if !ok || (name != "deny-commands" && name != "allow-commands") || seen[a] {
			continue
		}
		seen[a] = true
		checks = append(checks, [2]string{name, value})
	}
	var b strings.Builder
	b.WriteString("| attribute | regex | commit | read back |\n|---|---|---|---|\n")
	const class = "p49-l9-commit"
	for _, c := range checks {
		var out, back string
		var cerr error
		l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
			return l.junosCLI(breakglassUser, breakglassPassword)
		}, func(cli *cliConn) error {
			out, cerr = junosConfigure(cli, "set system login class "+class+" permissions view",
				"set system login class "+class+" "+c[0]+" \""+c[1]+"\"")
			if cerr == nil {
				back, _ = cli.sendExpect("show configuration system login class "+class+" | display set",
					junosPer, junosOpPrompt)
			}
			if _, derr := junosConfigure(cli, "delete system login class "+class); derr != nil {
				t.Errorf("could not delete the scratch class %s: %v", class, derr)
			}
			return nil
		})
		verdict := "accepted"
		if cerr != nil {
			verdict = "rejected: " + oneLine(cerr.Error()+" "+out)
			t.Errorf("the commit checker rejected %s %q: %v", c[0], c[1], cerr)
		}
		var kept string
		for _, line := range strings.Split(back, "\n") {
			if strings.Contains(line, " "+c[0]+" ") {
				kept = strings.TrimSpace(line)
			}
		}
		if cerr == nil && kept != "set system login class "+class+" "+c[0]+" \""+c[1]+"\"" {
			verdict += ", read back changed"
			t.Errorf("%s %q read back as %q", c[0], c[1], kept)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", c[0], strings.ReplaceAll(c[1], "|", "\\|"), verdict,
			strings.ReplaceAll(kept, "|", "\\|"))
	}
	return b.String()
}
