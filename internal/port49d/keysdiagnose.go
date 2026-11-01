package port49d

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/keyring"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// keysDiagnoseCmd is `port49d keys-diagnose --device NAME --capture FILE|-
// [--config FILE]` (spec §10, "Cross-group probing is manual"). It reads a
// capture taken at the device's side (tcpdump -w, the classic format), takes the
// first packet the device sent to port 49, and tries each version of every
// group's secret that port49d holds on it, retired ones and other groups' included. It starts
// nothing and holds no packet: port49d itself keeps none.
//
// The answer is the group and version that validate the packet, one line each,
// or that none does. It prints no byte of the packet and no key. Exit 0 when a
// key validates, 1 when none does or the capture holds no packet from the
// device, 2 on usage.
func keysDiagnoseCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49d keys-diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	device := fs.String("device", "", "the device's name in the inventory")
	capture := fs.String("capture", "", "a classic pcap file taken at the device's side, or - for standard input")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *device == "" || *capture == "" {
		fmt.Fprintln(stderr, "usage: port49d keys-diagnose --device NAME --capture FILE|- [--config FILE]")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d keys-diagnose:", err)
		return 1
	}
	var addrs []netip.Addr
	for _, d := range cfg.Inventory.Devices {
		if d.Name == *device {
			addrs = d.Addresses
		}
	}
	if len(addrs) == 0 {
		fmt.Fprintf(stderr, "port49d keys-diagnose: %s is not a device in the inventory port49d.yaml reads (inventory_file); "+
			"with an inventory service, the inventory_file is the copy this reads\n", printsafe.Line(*device, 80))
		return 1
	}
	sets, err := diagnoseKeys(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "port49d keys-diagnose:", err)
		return 1
	}
	in := stdin
	if *capture != "-" {
		f, err := os.Open(*capture)
		if err != nil {
			fmt.Fprintln(stderr, "port49d keys-diagnose:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	from := func(a netip.Addr) bool {
		for _, d := range addrs {
			if d == a {
				return true
			}
		}
		return false
	}
	p, found, err := firstPacketFrom(in, from, 49)
	if err != nil {
		fmt.Fprintln(stderr, "port49d keys-diagnose:", err)
		return 1
	}
	if !found {
		fmt.Fprintf(stderr, "port49d keys-diagnose: the capture holds no whole TACACS+ packet from %s to port 49; "+
			"capture at the device's side with the full packet (tcpdump -s 0 -w FILE 'tcp dst port 49 and src host %s')\n",
			printsafe.Line(*device, 80), addrs[0])
		return 1
	}
	if p.hdr.Flags&wire.FlagUnencrypted != 0 { // from the header alone, never the body
		fmt.Fprintln(stderr, "port49d keys-diagnose: the device sent this packet unencrypted, so no key applies")
	}
	matches := keyring.Try(p.hdr, p.body, sets, time.Now())
	if len(matches) == 0 {
		fmt.Fprintln(stdout, "no key port49d holds validates this packet")
		return 1
	}
	for _, m := range matches {
		fmt.Fprintf(stdout, "group %s version %d validates this packet\n", m.KeyRef, m.Version)
	}
	return 0
}

// diagnoseKeys is the key sets port49d would hold: the policy's, read as a
// start reads them, or with no policy port49d.yaml's own.
func diagnoseKeys(cfg config.Config) (map[string]keyring.Set, error) {
	if cfg.Policy == nil {
		return cfg.Keyring(), nil
	}
	pol, err := loadPolicy(cfg, "inventory_file "+cfg.InventoryFile)
	if err != nil {
		return nil, err
	}
	b, err := newLiveKeys(cfg.Secrets, cfg.KeySecretRefs).build(pol)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, err)
	}
	return b.sets, nil
}
