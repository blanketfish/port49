package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	daemonconfig "github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/username"
)

// checkConfig is `port49 devices check-config` (spec §5.6, §6): a device's
// configuration, as `show running-config` prints it, read against the
// policy's adapter for its platform. A device-local account named as a
// username port49 serves on that device is a collision the spec forbids —
// such a session's commands arrive under the same username and are
// authorized at the level port49 granted that username there — each line
// the adapter's checks name is one the spec says the device must not carry,
// and each device_config line the configuration lacks is one the adapter's
// renderings depend on (IOS-XE's level-7 command method list, spec §6). The
// set's lines and checks are the floor under a `platforms:` block's
// (Policy.ConfigDialect). It exits 1 on any of them. port49 never logs into a
// device; this reads a file a compliance tool fetched (spec §8,
// "Verification").
//
// --batch is the CI form: each CONFIGFILE is read against the inventory device
// its file name names, as it is (Oxidized writes an FQDN) or less its last
// extension (srx-01.conf is srx-01), every file is checked whatever one before
// it found, and the exit is the worst any file's check exits, with a summary
// line of the files checked and failed (decision 44 ruling 8). Its --config
// is the whole run's: a projected device reads it (and without it exits 2), a
// device on a platform that projects nothing ignores it, so a mixed fleet
// passes in one run.
//
// On a projected platform it also reads the configuration, as
// platform.ConfigCapture prints it, groups' statements expanded where they
// land, against the reference `platform export --classes` writes, whose
// idle-timeout comes from --config's port49d.yaml, which is then required:
// every reference line the device lacks, and every line under a template
// class or user the reference does not write and that is not harmless
// (templateCheck; plan 5b pre-flight I8; decision 44 rulings 7 and 9). A
// class carrying more than the reference is every subject at that template
// running more than port49 proved, so it fails, as does a capture it cannot
// read or one taken without `display inheritance`. A management service
// whose RPCs a deny does not bind is a finding too, read from the same
// capture (platform.CheckServices).
//
// A device's configuration is full of secrets — communities, keys, enable
// secrets, a URL's password — so every line of it this prints is redacted by
// every pattern that applies under the policy, and a line that could not be
// read is never quoted (spec §5.8).
func checkConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 devices check-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	device := fs.String("device", "", "the device the configuration is from, by its inventory name")
	cfgPath := fs.String("config", "", "port49d.yaml, whose session.max_session_age_default is the template "+
		"classes' idle-timeout (required on a projected platform; under --batch, ignored by the others)")
	batch := fs.Bool("batch", false, "check each CONFIGFILE against the inventory device its file name names, "+
		"as it is or less its last extension (srx-01.conf is srx-01): the CI form")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || *batch && (*device != "" || fs.NArg() == 0) || !*batch && (*device == "" || fs.NArg() != 1) {
		fmt.Fprint(stderr, usage)
		return 2
	}
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stdout, stderr = out, errOut
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	out.learn(p)
	errOut.learn(p)
	c := checkRun{p: p, files: files, cfgPath: *cfgPath, batch: *batch, stdout: stdout, stderr: stderr}
	if !*batch {
		return c.one(*device, fs.Arg(0))
	}
	// Every file is checked whatever one before it found (decision 44
	// ruling 8): a CI run reports the fleet, not its first failure.
	worst, checked := 0, 0
	var failed []string
	seen := map[string]bool{}
	for _, file := range fs.Args() {
		// A path given twice is one capture; two paths that name the same
		// device are two.
		if seen[file] {
			continue
		}
		seen[file] = true
		checked++
		// The name as it is where the inventory has it (Oxidized's files,
		// an FQDN), else less its last extension.
		asIs := filepath.Base(file)
		name := asIs
		if _, ok := p.Device(name); !ok {
			name = strings.TrimSuffix(asIs, filepath.Ext(asIs))
		}
		code := 0
		if _, ok := p.Device(name); !ok {
			tried := fmt.Sprintf("%q", asIs)
			if name != asIs {
				tried += fmt.Sprintf(" or %q", name)
			}
			fmt.Fprintf(stderr, "port49 devices check-config: %s: no inventory device %s\n", file, tried)
			code = 1
		} else {
			code = c.one(name, file)
		}
		if code != 0 {
			failed = append(failed, file)
		}
		worst = max(worst, code)
	}
	fmt.Fprintf(stdout, "batch: %d configurations checked, %d failed\n", checked, len(failed))
	if len(failed) > 0 {
		fmt.Fprintf(stdout, "batch: failed: %s\n", strings.Join(failed, " "))
	}
	return worst
}

// checkRun is what every file of one check-config run is read against.
type checkRun struct {
	p              *policy.Policy
	files          policyFiles
	cfgPath        string
	batch          bool // --config is the run's, so a device that projects nothing ignores it
	stdout, stderr io.Writer
}

// one checks file as device's configuration and prints its findings: 0 clean,
// 1 a finding or a file it could not read, 2 a usage or nothing-checked
// outcome, as a single check-config exits.
func (c checkRun) one(device, file string) int {
	p, stdout, stderr := c.p, c.stdout, c.stderr
	rules := p.Redactions()
	redact := func(line string) string { return platform.RedactConfigLine(rules, line) }
	d, ok := p.Device(device)
	if !ok {
		fmt.Fprintf(stderr, "port49 devices check-config: device %q is not in the inventory\n", device)
		return 1
	}
	config, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	// Under --batch every line about a file names it: in a CI log of a fleet
	// a line that does not is one nobody can place.
	who := "port49 devices check-config:"
	if c.batch {
		who += " " + file + ":"
	}
	served, groups, err := p.ServedUsernames(device, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, who, err)
		return 1
	}
	dialect, err := p.ConfigDialect(d.Platform)
	if err != nil {
		fmt.Fprintln(stderr, who, err)
		return 1
	}
	switch {
	case dialect.Projected() && c.cfgPath == "":
		fmt.Fprintf(stderr, "%s %s projects the policy into its session reply, so its "+
			"template classes are checked against the reference, whose idle-timeout is port49d.yaml's "+
			"session.max_session_age_default: pass --config\n", who, d.Platform)
		return 2
	case !dialect.Projected() && c.cfgPath != "" && !c.batch:
		fmt.Fprint(stderr, usage)
		return 2
	}
	// An adapter with nothing to read a configuration against — the generic
	// one an unknown platform gets, as the daemon resolves it — would report
	// every device clean: at 3am "0 findings" reads as no collision, where
	// nothing was looked for (final review I4).
	if len(dialect.LocalAccounts) == 0 && len(dialect.DeviceConfig) == 0 && len(dialect.ConfigChecks) == 0 {
		fmt.Fprintf(stderr, "%s nothing checked: %s has no config checks: its adapter has "+
			"no local_accounts, device_config or config_checks, so no collision or forbidden line could be found; "+
			"give the platform a platforms: block that says how its configuration names an account (spec §5.6)\n",
			who, d.Platform)
		return 2
	}
	accounts, findings, err := dialect.ReadConfig(config)
	if err != nil {
		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", file, err)
		return 1
	}
	missing, err := platform.Missing(config, dialect.DeviceConfig)
	if err != nil {
		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", file, err)
		return 1
	}
	var templateMissing []string
	var drift, services []platform.ConfigFinding
	if dialect.Projected() {
		if templateMissing, drift, err = templateCheck(dialect, c.cfgPath, file, config); err != nil {
			// The error leads with the file (or port49d.yaml), so it takes
			// no file prefix of its own.
			fmt.Fprintln(stderr, "port49 devices check-config:", err)
			return 1
		}
		// Where a deny does not bind the RPCs a management service serves,
		// every such service but the CLI's fails the device (plan 5b
		// Task 14, branch M).
		if services, err = platform.CheckServices(dialect, config); err != nil {
			fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", file, err)
			return 1
		}
	}
	failed := 0
	for _, line := range templateMissing {
		failed++
		fmt.Fprintf(stdout, "TEMPLATE: %s: %s: the configuration does not carry this line of the reference "+
			"(port49 platform export --classes): a session under that template is not what the projection "+
			"proved (spec §8)\n", file, line)
	}
	for _, f := range drift {
		failed++
		fmt.Fprintf(stdout, "TEMPLATE: %s:%d: %s: %s\n", file, f.Line, redact(f.Text), f.Says)
	}
	for _, f := range services {
		failed++
		fmt.Fprintf(stdout, "SERVICE: %s:%d: %s: %s\n", file, f.Line, redact(f.Text), f.Says)
	}
	for _, a := range accounts {
		// The daemon looks a context up by the canonical form of the username
		// the device sends (spec §2), so a local NOC, CORP\noc or noc@corp
		// reaches the port49 noc's context as a local noc would.
		if subject, ok := served[username.Canonical(strings.Trim(a.Name, `"`))]; ok {
			failed++
			fmt.Fprintf(stdout, "COLLISION: %s:%d: a device-local account %q is the username port49 serves subject %s "+
				"on %s: a session under it inherits that context's level, and the spec forbids the collision (spec "+
				"§5.6); rename the local account\n", file, a.Line, a.Name, subject, device)
		}
	}
	for _, f := range findings {
		failed++
		check := dialect.ConfigChecks[f.Check]
		if platform.ShippedConfigCheck(check) {
			// A set's check reads a method list or an authentication order:
			// the line is echoed, redacted.
			fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", file, f.Line, redact(f.Text), check.Says)
			continue
		}
		// A block's check may match any line, and the patterns are
		// best-effort: the line is not echoed, and the check is named by its
		// key and index in the block's list. The operator has the file.
		key := fmt.Sprintf("platforms.%s.config_checks[%d]", d.Platform,
			slices.Index(p.Dialect(d.Platform).ConfigChecks, check))
		fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", file, f.Line, key,
			platform.RedactConfigCheck(rules, check).Says)
	}
	for _, line := range missing {
		failed++
		fmt.Fprintf(stdout, "MISSING: %s: %s: the configuration does not carry this line, and the %s adapter's "+
			"renderings depend on it: without it a level is not what the adapter says it is (spec §6; %s)\n",
			file, redact(line), d.Platform, whereWritten(c.files, p.PlatformSet(), d.Platform, line))
	}
	// A partial capture, `| section aaa`, reads every line outside it as
	// missing (task 17 review, parked). A whole running-config names its
	// host; one that does not is said to be possibly partial.
	if len(missing)+len(templateMissing) > 0 && !hasHostname(config) {
		fmt.Fprintf(stdout, "note: the configuration has no hostname line, so it may be a partial capture (| section "+
			"...): a MISSING line may be in the part left out; check-config reads the whole show running-config\n")
	}
	// Half an adapter checks half: what it could not look for is said, so
	// the summary line is not read as covering it.
	if len(dialect.LocalAccounts) == 0 {
		fmt.Fprintf(stdout, "note: local-account collisions were not checked: the %s adapter has no local_accounts, "+
			"so how its configuration names an account is unknown\n", d.Platform)
	}
	if len(dialect.DeviceConfig) == 0 && len(dialect.ConfigChecks) == 0 {
		fmt.Fprintf(stdout, "note: no configuration line was checked: the %s adapter has no device_config or "+
			"config_checks\n", d.Platform)
	}
	for _, g := range groups {
		fmt.Fprintf(stdout, "note: subject %s reaches %s; its usernames come from its directory entries, "+
			"so they are not checked\n", g, device)
	}
	fmt.Fprintf(stdout, "%d local accounts, %d usernames served on %s (%s), %d findings\n", len(accounts), len(served),
		device, d.Platform, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// templateCheck is check-config's reading of a projected platform's
// configuration against the reference (platform.TemplateDrift), at the
// idle-timeout cfgPath's session.max_session_age_default gives: the reference
// lines the device lacks, and the lines under a template it does not write.
// The file is decoded as strictly as the daemon decodes it and no key or
// secret is resolved, so none is needed (config.MaxSessionAge; spec §13,
// decision 21). Anything it cannot read is an error, never a clean device.
func templateCheck(dialect platform.Dialect, cfgPath, configName string, config []byte) ([]string,
	[]platform.ConfigFinding, error) {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	age, err := daemonconfig.MaxSessionAge(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cfgPath, err)
	}
	missing, drift, err := platform.TemplateDrift(config, dialect, age)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", configName, err)
	}
	return missing, drift, nil
}

// whereWritten is where a device_config line check-config requires can be
// read: a line the platform set holds the device to is in the set's adapter,
// which `platform show --policy` does not print where a block replaced its
// device_config; any other is the policy's block's (final review M7).
func whereWritten(files policyFiles, version, platformName, line string) string {
	if set, ok := platform.Set(version); ok {
		names := sortedNames(set)
		if i := slices.Index(names, platformName); i > 0 {
			names[0], names[i] = names[i], names[0]
		}
		for _, name := range names {
			if slices.Contains(set[name].DeviceConfig, line) {
				return fmt.Sprintf("the platform set's line: port49 platform show --set %s %s", version, name)
			}
		}
	}
	return fmt.Sprintf("the policy's platforms: block's line: port49 platform show --policy %s --inventory %s %s",
		files.policy, files.inventory, platformName)
}

// hasHostname reports whether config has a top-level hostname line, as a
// whole running-config on every platform with an adapter prints one set in
// the lab: `hostname leaf1`, or Junos's `host-name`.
func hasHostname(config []byte) bool {
	for _, line := range strings.Split(string(config), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "hostname" || f[0] == "host-name" || len(f) > 3 && f[0] == "set" &&
			f[1] == "system" && f[2] == "host-name") {
			return true
		}
	}
	return false
}
