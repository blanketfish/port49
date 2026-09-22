// Command redact-pcap turns the lab's packet captures into evidence that can
// be committed.
//
// `tests/lab/captures/` is git-ignored, because a capture holds the lab tokens
// and the breakglass password — obfuscated under a key this repository
// publishes, which is no protection at all. But a results note that points at a
// git-ignored file points at nothing for everyone but the machine that ran the
// lab, so every register row closed so far rests on evidence only one person
// can open.
//
// So: for each capture, keep the TACACS+ traffic, overwrite every credential
// byte with `x` of the same length, leave everything else byte-identical, and
// prove it. The output goes to `tests/lab/evidence/`, which is committed, and
// Wireshark decodes it with the same published key.
//
//	go run ./tests/lab/cmd/redact-pcap              # captures/ -> evidence/
//	go run ./tests/lab/cmd/redact-pcap -scan        # report, write nothing
//
// `make evidence` is the first of those.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rhwendt/port49/tests/lab/labcreds"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "redact-pcap:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	in := flag.String("in", filepath.Join(root, "tests", "lab", "captures"), "directory of captures to read")
	out := flag.String("out", filepath.Join(root, "tests", "lab", "evidence"), "directory to write redacted evidence to")
	labYAML := flag.String("lab-config", filepath.Join(root, "tests", "lab", "port49d-lab.yaml"),
		"the daemon config naming lab.seed_token_file, where the credentials to verify against were written")
	seeds := flag.String("seed-tokens", "",
		"the seed-token file port49d wrote for this run; defaults to the -lab-config's lab.seed_token_file")
	// The default is the published lab key; PORT49_LAB_KEY overrides it the
	// same way it overrides the harness's.
	key := flag.String("key", envOr("PORT49_LAB_KEY", labcreds.Key), "TACACS+ shared secret the captures were taken under")
	// tests/lab/harness_test.go labSubnet. A packet to or from here is never
	// dropped: results notes quote a count of them.
	subnet := flag.String("subnet", "172.100.100.0/24", "lab management subnet; a packet to or from it may never be dropped")
	scan := flag.Bool("scan", false, "report which body fields hold a lab credential, and write nothing")
	flag.Parse()

	_, sn, err := net.ParseCIDR(*subnet)
	if err != nil {
		return err
	}
	// The credentials are the ones the daemon minted for this run, so they come
	// from the file it wrote rather than from the config. A run whose token
	// file is gone cannot have its captures verified — redacting against
	// another run's tokens would report every file clean.
	seedPath := *seeds
	if seedPath == "" {
		if seedPath, err = labcreds.SeedTokenFile(*labYAML); err != nil {
			return err
		}
	}
	secrets, err := labcreds.Secrets(seedPath)
	if err != nil {
		return fmt.Errorf("%w; the captures and the seed-token file come from one `make lab` run, so "+
			"redact them before the next run truncates it, or pass -seed-tokens", err)
	}
	opt := labpcap.Options{Key: *key, Secrets: secrets, Subnet: sn}

	if *scan {
		return runScan(*in, opt)
	}

	res, err := labpcap.RedactDir(*in, *out, opt)
	if err != nil {
		return err
	}
	if len(res) == 0 {
		return fmt.Errorf("no *.pcap in %s; captures are git-ignored, so a checkout that has not run the lab has none", *in)
	}
	var failed int
	for _, r := range res {
		if r.Err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", r.Name, r.Err)
			continue
		}
		fmt.Printf("%-34s %s\n", r.Name, r.Stats)
	}
	fmt.Printf("\n%d of %d capture(s) written to %s and verified against %d lab credential string(s)\n",
		len(res)-failed, len(res), *out, len(secrets))
	if failed > 0 {
		return fmt.Errorf("%d capture(s) produced no evidence file", failed)
	}
	return nil
}

// runScan answers the question the redaction policy rests on: which fields can
// carry a credential? Not which ones the protocol says can — which ones, in
// these captures, actually do. A hit on a field this package does not treat as
// a credential is a bug in the field list, and this is how it is found.
func runScan(in string, opt labpcap.Options) error {
	names, err := filepath.Glob(filepath.Join(in, "*.pcap"))
	if err != nil {
		return err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no *.pcap in %s", in)
	}
	hits := map[string]int{}    // field name -> packets holding a credential
	all := map[string]int{}     // field name -> packets carrying the field
	unclean := map[string]int{} // field name -> hits in a field not marked Credential
	var packets, files int
	for _, n := range names {
		raw, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		f, err := labpcap.Parse(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(n), err)
			continue
		}
		d, err := f.Decode(opt.Key, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(n), err)
			continue
		}
		fields, err := d.Fields()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(n), err)
			continue
		}
		files++
		packets += len(d.Packets)
		for _, fd := range fields {
			name := generalize(fd.Name)
			all[name]++
			if len(labcreds.Contains(fd.Bytes(d.Packets[fd.Packet].Body), opt.Secrets)) == 0 {
				continue
			}
			hits[name]++
			if !fd.Credential {
				unclean[name]++
			}
		}
	}
	var names2 []string
	for k := range all {
		names2 = append(names2, k)
	}
	sort.Strings(names2)
	fmt.Printf("%d file(s), %d TACACS+ packet(s)\n\n%-32s %8s %8s\n", files, packets, "field", "seen", "with a credential")
	for _, k := range names2 {
		mark := ""
		if unclean[k] > 0 {
			mark = "  <-- NOT REDACTED BY THIS TOOL"
		}
		fmt.Printf("%-32s %8d %8d%s\n", k, all[k], hits[k], mark)
	}
	if len(unclean) > 0 {
		return fmt.Errorf("%d field name(s) hold a lab credential and are not marked as credential fields", len(unclean))
	}
	return nil
}

// generalize collapses arg[0], arg[1], ... so the scan reports one row per
// field rather than one per argument position.
func generalize(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		return name[:i] + "[]"
	}
	return name
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// repoRoot walks up from the working directory to the module root, so the tool
// works from anywhere in the tree.
func repoRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no go.mod above %s; run this from inside the repository", d)
		}
		d = parent
	}
}
