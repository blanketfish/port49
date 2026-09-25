package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/platform"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || *device == "" || fs.NArg() != 1 {
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
	rules := p.Redactions()
	out.learn(p)
	errOut.learn(p)
	redact := func(line string) string { return platform.RedactConfigLine(rules, line) }
	d, ok := p.Device(*device)
	if !ok {
		fmt.Fprintf(stderr, "port49 devices check-config: device %q is not in the inventory\n", *device)
		return 1
	}
	config, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	served, groups, err := p.ServedUsernames(*device, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	dialect, err := p.ConfigDialect(d.Platform)
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	// An adapter with nothing to read a configuration against — the generic
	// one an unknown platform gets, as the daemon resolves it — would report
	// every device clean: at 3am "0 findings" reads as no collision, where
	// nothing was looked for (final review I4).
	if len(dialect.LocalAccounts) == 0 && len(dialect.DeviceConfig) == 0 && len(dialect.ConfigChecks) == 0 {
		fmt.Fprintf(stderr, "port49 devices check-config: nothing checked: %s has no config checks: its adapter has "+
			"no local_accounts, device_config or config_checks, so no collision or forbidden line could be found; "+
			"give the platform a platforms: block that says how its configuration names an account (spec §5.6)\n",
			d.Platform)
		return 2
	}
	accounts, findings, err := dialect.ReadConfig(config)
	if err != nil {
		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
		return 1
	}
	missing, err := platform.Missing(config, dialect.DeviceConfig)
	if err != nil {
		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
		return 1
	}
	failed := 0
	for _, a := range accounts {
		// The daemon looks a context up by the canonical form of the username
		// the device sends (spec §2), so a local NOC, CORP\noc or noc@corp
		// reaches the port49 noc's context as a local noc would.
		if subject, ok := served[username.Canonical(strings.Trim(a.Name, `"`))]; ok {
			failed++
			fmt.Fprintf(stdout, "COLLISION: %s:%d: a device-local account %q is the username port49 serves subject %s "+
				"on %s: a session under it inherits that context's level, and the spec forbids the collision (spec "+
				"§5.6); rename the local account\n", fs.Arg(0), a.Line, a.Name, subject, *device)
		}
	}
	for _, f := range findings {
		failed++
		check := dialect.ConfigChecks[f.Check]
		if platform.ShippedConfigCheck(check) {
			// A set's check reads a method list or an authentication order:
			// the line is echoed, redacted.
			fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", fs.Arg(0), f.Line, redact(f.Text), check.Says)
			continue
		}
		// A block's check may match any line, and the patterns are
		// best-effort: the line is not echoed, and the check is named by its
		// key and index in the block's list. The operator has the file.
		key := fmt.Sprintf("platforms.%s.config_checks[%d]", d.Platform,
			slices.Index(p.Dialect(d.Platform).ConfigChecks, check))
		fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", fs.Arg(0), f.Line, key,
			platform.RedactConfigCheck(rules, check).Says)
	}
	for _, line := range missing {
		failed++
		fmt.Fprintf(stdout, "MISSING: %s: %s: the configuration does not carry this line, and the %s adapter's "+
			"renderings depend on it: without it a level is not what the adapter says it is (spec §6; %s)\n",
			fs.Arg(0), redact(line), d.Platform, whereWritten(files, p.PlatformSet(), d.Platform, line))
	}
	// A partial capture, `| section aaa`, reads every line outside it as
	// missing (task 17 review, parked). A whole running-config names its
	// host; one that does not is said to be possibly partial.
	if len(missing) > 0 && !hasHostname(config) {
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
		fmt.Fprintf(stdout, "note: group subject %s reaches %s; its members' usernames come from the directory "+
			"(plan 7), so they are not checked\n", g, *device)
	}
	fmt.Fprintf(stdout, "%d local accounts, %d usernames served on %s (%s), %d findings\n", len(accounts), len(served),
		*device, d.Platform, failed)
	if failed > 0 {
		return 1
	}
	return 0
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
