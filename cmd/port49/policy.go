package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/replay"
)

// policyFiles are the two files every policy tool reads: the policy and the
// inventory it is checked against (spec §10, §12). The tools run offline, as
// CI runs them; they never ask a broker.
type policyFiles struct{ policy, inventory string }

func (f *policyFiles) register(fs *flag.FlagSet) {
	fs.StringVar(&f.policy, "policy", "", "the policy file")
	fs.StringVar(&f.inventory, "inventory", "", "the inventory file the daemon admits from (inventory_file)")
}

func (f *policyFiles) load() (*policy.Policy, error) {
	if f.policy == "" || f.inventory == "" {
		return nil, fmt.Errorf("--policy and --inventory are both required")
	}
	inv, err := admission.LoadFile(f.inventory)
	if err != nil {
		return nil, err
	}
	return policy.Load(f.policy, policy.Env{Devices: inv.Devices})
}

// explainCmd resolves a hypothetical decision and prints exactly one reason
// (spec §12). It exits 0 whether the answer is permit or deny: the answer is
// the output, and an error is a policy or a name that did not load.
func explainCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject, by its name in the policy")
	principal := fs.String("principal", "", "or the principal, e.g. user:alice@example.com")
	device := fs.String("device", "", "the device, by its inventory name")
	command := fs.String("command", "", "the command line, quoted; omit it to see the session")
	attrs := fs.Bool("show-attributes", false, "show the session attributes and where each came from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*subject == "") == (*principal == "") || *device == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e, err := p.Explain(*subject, *principal, *device, *command, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e.Render(stdout, *attrs)
	return 0
}

// policyCmd runs `port49 policy SUBCOMMAND`.
func policyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "test":
		return policyTest(args[1:], stdout, stderr)
	case "replay":
		return policyReplay(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// policyTest is the CI gate (spec §11, §12): it loads the policy against the
// inventory — every load-time check is a failure here — prints what CI must
// report without refusing, then runs the file's tests. It exits 1 if the
// policy does not load or any test fails.
func policyTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy test:", err)
		return 1
	}
	now := time.Now()
	// A quarantined device is reported, not a failure of its own: the policy
	// loaded, and decision 20 exists so one device cannot block the rest. A
	// test on it fails in the ordinary way, as device_quarantined. An entry an
	// expiry will bring on is reported too, so CI sees it before it lands.
	for _, q := range p.Quarantines(now) {
		for _, e := range q.Entries {
			fmt.Fprintf(stdout, "quarantine: %s (%s): %s\n", q.Device, q.Platform, e.Message(now))
		}
	}
	for _, f := range p.Lint() {
		fmt.Fprintf(stdout, "report: %s: %s\n", f.Kind, f.Message)
	}
	results := p.RunTests(now)
	failed := 0
	for _, r := range results {
		who := r.Test.Subject
		if who == "" {
			who = r.Test.Principal
		}
		got := "deny"
		if r.Permit {
			got = "permit"
		}
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed++
		}
		line := fmt.Sprintf("%s %s on %s: %q -> %s %s", status, who, r.Test.Device, r.Test.Command, got, r.Reason)
		if r.Err != nil {
			line = fmt.Sprintf("%s %s on %s: %q -> error: %v", status, who, r.Test.Device, r.Test.Command, r.Err)
		} else if !r.Pass {
			want := r.Test.Expect
			if r.Test.Reason != "" {
				want += " " + r.Test.Reason
			}
			line += ", want " + want
		}
		fmt.Fprintln(stdout, line)
		for _, c := range r.Caveats {
			fmt.Fprintf(stdout, "     note: %s\n", c)
		}
	}
	fmt.Fprintf(stdout, "%d tests, %d failed\n", len(results), failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// policyReplay re-evaluates a decision log against the blobs it carries
// (spec §5.7, "Replay"): an auditor's reconstruction, a regression check of a
// captured corpus against this build, and an integrity check of the log. It
// prints every record that did not agree and exits 1 if any did not; with
// --line it replays that one record and prints it either way.
func policyReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 policy replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	only := fs.Int("line", 0, "replay only the record on this line of the log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	in := io.Reader(os.Stdin)
	if name := fs.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(stderr, "port49 policy replay:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	results, err := replay.Replay(in, *only)
	if err != nil {
		fmt.Fprintln(stderr, "port49 policy replay:", err)
		return 1
	}
	counts := map[replay.Status]int{}
	for _, r := range results {
		counts[r.Status]++
		if r.Status != replay.Agree || *only != 0 {
			fmt.Fprintf(stdout, "line %d %s: %s %s\n", r.Line, r.Event, r.Status, r.Detail)
		}
	}
	fmt.Fprintf(stdout, "replayed %d records: %d agree, %d diverge, %d unverifiable\n", len(results),
		counts[replay.Agree], counts[replay.Diverge], counts[replay.Unverifiable])
	if *only != 0 && len(results) == 0 {
		fmt.Fprintf(stderr, "port49 policy replay: line %d is not an authorization record that consulted a blob\n", *only)
		return 1
	}
	if counts[replay.Diverge]+counts[replay.Unverifiable] > 0 {
		return 1
	}
	return 0
}
