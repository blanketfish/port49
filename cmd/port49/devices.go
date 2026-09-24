package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// checkConfig is `port49 devices check-config` (spec §5.6, §6): a device's
// configuration, as `show running-config` prints it, read against the
// policy's adapter for its platform. A device-local account named as a
// username port49 serves on that device is a collision the spec forbids —
// such a session's commands arrive under the same username and are
// authorized at the level port49 granted that username there — and each line
// the adapter's checks name is one the spec says the device must not carry.
// It exits 1 on either. port49 never logs into a device; this reads a file a
// compliance tool fetched (spec §8, "Verification").
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
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
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
	accounts, findings, err := p.Dialect(d.Platform).ReadConfig(config)
	if err != nil {
		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
		return 1
	}
	failed := 0
	for _, a := range accounts {
		if subject, ok := served[a.Name]; ok {
			failed++
			fmt.Fprintf(stdout, "COLLISION: %s:%d: a device-local account %q is the username port49 serves subject %s "+
				"on %s: a session under it inherits that context's level, and the spec forbids the collision (spec "+
				"§5.6); rename the local account\n", fs.Arg(0), a.Line, a.Name, subject, *device)
		}
	}
	for _, f := range findings {
		failed++
		fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", fs.Arg(0), f.Line, strings.TrimSpace(f.Text), f.Says)
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
