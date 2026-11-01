package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/keyset"
	"github.com/blanketfish/port49/internal/keystatus"
)

// keysNow is the clock the key commands read a version's state by; tests
// fix it.
var keysNow = time.Now

// keysCmd is `port49 keys` (spec §12): status and show read files and the
// log offline; diagnose is port49d's (refused here).
func keysCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return keysStatus(args[1:], stdout, stderr)
		case "show":
			return keysShow(args[1:], stdout, stderr)
		case "diagnose":
			return keysDiagnose(args[1:], stdout, stderr)
		}
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// statusKeys is each key's versions in the roles they hold at now.
func statusKeys(sets map[string]keyset.Set, now time.Time) []keystatus.Key {
	var out []keystatus.Key
	for _, ref := range keyset.Sorted(sets) {
		ks := sets[ref]
		k := keystatus.Key{Ref: ref, Versions: []keystatus.Version{{Number: ks.Current.Version, State: "current"}}}
		for _, v := range ks.Accept {
			state := "accept"
			if !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
				state = "retired"
			}
			k.Versions = append(k.Versions, keystatus.Version{Number: v.Version, State: state, RetireAt: v.RetireAt})
		}
		for _, v := range ks.Retired {
			k.Versions = append(k.Versions, keystatus.Version{Number: v.Version, State: "retired"})
		}
		out = append(out, k)
	}
	return out
}

// keysStatus is `port49 keys status` (spec §10, §12).
func keysStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 keys status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	since := fs.Duration("since", 0, "read only the records within this long of the newest one (default: all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || fs.NArg() == 0 || *since < 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys status:", err)
		return 1
	}
	if !p.KeysDeclared() {
		fmt.Fprintln(stderr, "port49 keys status: the policy declares no keys: block; a port49d with no policy keeps "+
			"its keys in port49d.yaml, and keys status reads only a policy's")
		return 1
	}
	recs, unread, err := readLogs(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys status:", err)
		return 1
	}
	opt := keystatus.Options{Now: keysNow()}
	if *since > 0 && len(recs) > 0 {
		newest := recs[0].TS
		for _, r := range recs {
			if r.TS.After(newest) {
				newest = r.TS
			}
		}
		opt.From = newest.Add(-*since)
	}
	var devices []keystatus.Device
	for _, d := range p.Devices() {
		if d.EffectiveTransport() == admission.TransportTLS {
			continue // no key to phase out (decision 50 ruling 3)
		}
		r, _ := p.Admitted(d.Name)
		devices = append(devices, keystatus.Device{Name: d.Name, KeyRef: r.KeyRef, Addresses: d.Addresses})
	}
	keystatus.Infer(recs, devices, statusKeys(p.KeySets(), opt.Now), opt).Write(stdout, opt.Now)
	if unread > 0 {
		fmt.Fprintf(stderr, "port49 keys status: %d line(s) could not be read as records and were skipped\n", unread)
	}
	return 0
}

// keysShow is `port49 keys show` (spec §12): which key_ref a device matches,
// by which tier and group, and which version to provision. It never renders
// the secret.
func keysShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 keys show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys show:", err)
		return 1
	}
	if !p.KeysDeclared() {
		fmt.Fprintln(stderr, "port49 keys show: the policy declares no keys: block, so port49d refuses it "+
			"(decision 53 ruling 3); add the key sets beside key_groups, or `keys: {}` for a fleet all on TLS")
	}
	name := fs.Arg(0)
	r, ok := p.Admitted(name)
	if !ok {
		fmt.Fprintf(stderr, "port49 keys show: device %q is not in the inventory\n", name)
		return 1
	}
	if r.Refused != "" {
		fmt.Fprintf(stdout, "%s: refused admission: %s\n", name, r.Refused)
		return 1
	}
	if r.Device.EffectiveTransport() == admission.TransportTLS {
		fmt.Fprintf(stdout, "%s: transport tls (RFC 9887): no shared key; its credential is its certificate\n", name)
		return 0
	}
	as, _ := p.KeyAssignment(name)
	fmt.Fprintf(stdout, "%s: key_ref %s, by the %s tier (%s)\n", name, r.KeyRef, as.Tier, as.Group)
	if ks, ok := p.KeySets()[r.KeyRef]; ok {
		fmt.Fprintf(stdout, "  provision version %d (current)\n", ks.Current.Version)
		now := keysNow()
		for _, v := range ks.Accept {
			if !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
				fmt.Fprintf(stdout, "  version %d retired: retire_after %s has passed, so it admits none\n",
					v.Version, v.RetireAfter)
				continue
			}
			line := fmt.Sprintf("  also accepted: version %d", v.Version)
			if v.RetireAfter != "" {
				line += ", retire_after " + v.RetireAfter
			}
			fmt.Fprintln(stdout, line)
		}
	}
	fmt.Fprintln(stdout, "  the secret is not shown: rendering it is a separately authorized operation this build "+
		"does not offer (spec §12)")
	return 0
}

// keysDiagnose is `port49 keys diagnose`, which is gone (spec §12): it asked
// port49d's admin socket, and the sockets are removed. The same diagnosis runs
// offline from a capture, on the host that holds port49d's keys.
func keysDiagnose(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "port49 keys diagnose was removed with the admin socket: run port49d keys-diagnose "+
		"--device DEVICE --capture FILE on the host that holds the keys")
	return 2
}
