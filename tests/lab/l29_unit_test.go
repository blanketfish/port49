//go:build lab

package lab

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/policy"
)

// l29KeyRefs are the key_refs the run's port49d.yaml defines (serviceConfig):
// the lab key, and the rotation key the rekeyed phase pins a device onto.
var l29KeyRefs = []string{"lab_key", "lab_key2"}

var l29Nodes = map[string]string{"leaf1": "arista_eos", "srx1": "juniper_junos", "vsrx1": "juniper_junos",
	"nx1": "cisco_nxos", "xe1": "cisco_iosxe"}

// Every reload phase's edit, on every node of the real lab inventory, yields
// an inventory that parses, that the service would publish (no device
// problem), that port49d loads against the run's policy and takes under its
// default 10% bound, and that changes the node's admission the way the phase
// is named for; and the rekeyed phase's pin (pre-flight M9) parses as the
// policy's third key group and moves the node, alone, onto lab_key2. A run
// whose phase changed nothing, or changed it another way, would measure the
// wrong reload.
func TestL29EditsOnTheRealLabInventory(t *testing.T) {
	raw, err := os.ReadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := os.ReadFile(filepath.Join("l29", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := labSource(string(raw))
	load := func(what, body string, policyRaw []byte) *policy.Policy {
		t.Helper()
		inv, err := admission.ParseFile([]byte(body), "")
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		for _, d := range inv.Devices {
			if why := bundle.DeviceProblem(d); why != "" {
				t.Fatalf("%s: %s %s", what, d.Name, why)
			}
		}
		p, err := bundle.Parse(policyRaw, inv, policy.Env{KeyRefs: l29KeyRefs})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return p
	}
	base := load("the lab source", src, pol)
	if refused := base.AdmissionRefusals(); len(refused) != 0 {
		t.Fatalf("the lab source under l29/policy.yaml refuses %d device(s): %+v", len(refused), refused)
	}
	if got := len(labLine.FindAllString(src, -1)); got != 15 {
		t.Fatalf("labLine finds %d devices in the lab source, want the 5 lab devices and 10 dummies", got)
	}
	for node, platform := range l29Nodes {
		if got := labPlatformOf(src, node); got != platform {
			t.Fatalf("%s: platform %q, want %q", node, got, platform)
		}
		addr := l29Address(t, src, node)
		was, ok := base.Admission().Lookup(addr)
		if !ok || was.Device.Name != node || was.KeyRef != "lab_key" {
			t.Fatalf("%s: before any phase, admitted %v as %+v", node, ok, was)
		}
		for _, phase := range []string{"removed", "renamed", "replatformed", "refused"} {
			what := node + " " + phase
			body, err := l29Edit(src, node, phase)
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			next := load(what, body, pol)
			if n := strings.Count(body, "\n  - {name: "); phase == "removed" && n != 14 || phase != "removed" && n != 15 {
				t.Fatalf("%s: %d devices", what, n)
			}
			if err := bundle.Check(base, next, 10); err != nil {
				t.Fatalf("%s: port49d's default bound refuses it: %v", what, err)
			}
			now, found := next.Admission().Lookup(addr)
			var changed bool
			switch phase {
			case "removed":
				changed = !found
			case "renamed":
				changed = found && now.Refused == "" && now.Device.Name == node+"-b"
			case "replatformed":
				changed = found && now.Refused == "" && now.Device.Name == node && now.Device.Platform != platform
			case "refused":
				changed = found && now.Refused != ""
			}
			if !changed {
				t.Fatalf("%s: the node's admission after the edit is %v %+v", what, found, now)
			}
			for _, other := range l29Admitted(t, next, body) {
				if other.Device.Name != node && other.Device.Name != node+"-b" && other.Refused != "" {
					t.Fatalf("%s: refuses %s too: %s", what, other.Device.Name, other.Refused)
				}
			}
		}
		pinned := load(node+" rekeyed", src, []byte(l29Pin(string(pol), node)))
		if n := strings.Count(l29Pin(string(pol), node), "key_ref:"); n != 3 {
			t.Fatalf("%s rekeyed: %d key groups", node, n)
		}
		if err := bundle.CheckAdmission(base, pinned, 10); err != nil {
			t.Fatalf("%s rekeyed: port49d's policy reload refuses it: %v", node, err)
		}
		for _, r := range l29Admitted(t, pinned, src) {
			want := "lab_key"
			if r.Device.Name == node {
				want = "lab_key2"
			}
			if r.Refused != "" || r.KeyRef != want {
				t.Fatalf("%s rekeyed: %s is admitted under %q (refused %q), want %q", node, r.Device.Name, r.KeyRef,
					r.Refused, want)
			}
		}
	}
}

// Conflict scan F5: the quarantine-sync policy quarantines each of the five
// lab devices, whatever its platform, and none of the dummies; fixed.yaml
// quarantines none. Checked on the exact source each platform's run syncs,
// as port49d parses it, before any lab night is spent on it.
func TestQuarantineSyncPolicyQuarantinesEveryLabNode(t *testing.T) {
	raw, err := os.ReadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for node := range l29Nodes {
		body, err := quarantineSource(string(raw), node)
		if err != nil {
			t.Fatal(err)
		}
		inv, err := admission.ParseFile([]byte(body), "")
		if err != nil {
			t.Fatalf("%s: %v", node, err)
		}
		before, err := admission.ParseFile([]byte(quarantineDummies), "")
		if err != nil {
			t.Fatalf("the dummies: %v", err)
		}
		for file, want := range map[string][]string{"policy.yaml": {node}, "fixed.yaml": nil} {
			polRaw, err := os.ReadFile(filepath.Join("quarantine-sync", file))
			if err != nil {
				t.Fatal(err)
			}
			for what, i := range map[string]admission.Inventory{"the dummies": before, "the sync": inv} {
				p, err := bundle.Parse(polRaw, i, policy.Env{KeyRefs: l29KeyRefs})
				if err != nil {
					t.Fatalf("%s, %s under %s: %v", node, what, file, err)
				}
				if refused := p.AdmissionRefusals(); len(refused) != 0 {
					t.Fatalf("%s, %s under %s refuses %+v", node, what, file, refused)
				}
				var names []string
				for _, q := range p.Quarantines(time.Now()) {
					names = append(names, q.Device)
				}
				expect := want
				if what == "the dummies" {
					expect = nil
				}
				if !slices.Equal(names, expect) {
					t.Fatalf("%s, %s under %s quarantines %v, want %v", node, what, file, names, expect)
				}
			}
		}
	}
}

// The capture reading each reload note rests on (ruling 1: the capture, not
// the record, tells a reset mid-connection from a first-packet miss), over a
// capture built a packet at a time in the shape `tcpdump -i any` writes:
// little-endian pcap, LINUX_SLL2 frames.
func TestL29ConnectionsReadsEachConnectionsReset(t *testing.T) {
	const dev, srv = "172.100.100.11", "172.100.100.1"
	base := time.Unix(1_790_000_000, 0)
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 262144)
	binary.LittleEndian.PutUint32(buf[20:24], 276)
	seg := func(sec int, src, dst string, sport, dport uint16, flags byte, payload int) {
		tcp := make([]byte, 20+payload)
		binary.BigEndian.PutUint16(tcp[0:2], sport)
		binary.BigEndian.PutUint16(tcp[2:4], dport)
		tcp[12], tcp[13] = 5<<4, flags
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
		copy(ip[12:16], net.ParseIP(src).To4())
		copy(ip[16:20], net.ParseIP(dst).To4())
		sll := make([]byte, 20)
		binary.BigEndian.PutUint16(sll[0:2], 0x0800)
		pkt := append(append(sll, ip...), tcp...)
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(base.Unix())+uint32(sec))
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(pkt)))
		buf = append(append(buf, hdr...), pkt...)
	}
	const syn, ack, psh, rst = 0x02, 0x10, 0x08, 0x04
	// 40001: open across the change, reset at its first packet after it.
	seg(1, dev, srv, 40001, 49, syn, 0)
	seg(2, dev, srv, 40001, 49, psh|ack, 40)
	seg(12, dev, srv, 40001, 49, psh|ack, 40)
	seg(12, srv, dev, 49, 40001, rst|ack, 0)
	// 40002: opened after the change, reset at its first packet.
	seg(13, dev, srv, 40002, 49, syn, 0)
	seg(13, dev, srv, 40002, 49, psh|ack, 40)
	seg(13, srv, dev, 49, 40002, rst|ack, 0)
	// 40003: reset before the device sent on it.
	seg(14, dev, srv, 40003, 49, syn, 0)
	seg(14, srv, dev, 49, 40003, rst|ack, 0)
	// 40004: served before the change, never reset.
	seg(3, dev, srv, 40004, 49, psh|ack, 40)
	// Traffic that is not the device's is not read.
	seg(4, "172.100.100.41", srv, 40005, 49, psh|ack, 40)
	path := filepath.Join(t.TempDir(), "c.pcap")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	got, mid := l29Connections(path, dev, base.Add(10*time.Second))
	if mid != 1 {
		t.Errorf("%d connection(s) counted as reset mid-connection, want 1 (40001)", mid)
	}
	// The quarantine test's premise reads the same capture: packets the
	// device sent at or after an instant.
	if n, err := l29DeviceSent(path, dev, base.Add(10*time.Second)); err != nil || n != 4 {
		t.Errorf("l29DeviceSent after the change: %d, %v; want 4 (40001's packet, 40002's SYN and packet, "+
			"40003's SYN)", n, err)
	}
	for port, want := range map[string]string{"40001": "**reset mid-connection**", "40002": "reset at its first packet",
		"40003": "reset before the device sent on it", "40004": "not reset by port49d"} {
		var row string
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, "| "+port+" |") {
				row = line
			}
		}
		if !strings.Contains(row, want) {
			t.Errorf("connection %s: want %q in its row, got %q\n%s", port, want, row, got)
		}
	}
	if strings.Contains(got, "40005") {
		t.Errorf("another device's connection was read:\n%s", got)
	}
}

// The premise readers over the texts and records they are given: l28Live's
// slow success is a success (review I2), and only port49d's record of a
// reset of an open connection, with the phase's diagnosis, counts (I1).
func TestL29PremiseReaders(t *testing.T) {
	for live, want := range map[string]bool{
		"Before this phase, with port49d validating the device's key: the first probe login reached port49 (3s).": true,
		"Before this phase, with port49d validating the device's key: no probe login reached port49 until probe " +
			"attempt 3; why is not established (41s).": true,
		"Before this phase: **no probe login reached port49 in 152s**.": false,
	} {
		if got := l28Reached(live); got != want {
			t.Errorf("l28Reached(%q) = %v, want %v", live, got, want)
		}
	}
	if l29SingleSet("not available at `x`: ...\nThe phases run on whatever connections the device opens") ||
		!l29SingleSet("on: `tacacs-server host 172.100.100.1 single-connection`") {
		t.Error("l29SingleSet misreads singleConnection's line")
	}
	firstPacket := map[string]any{"event": "unvalidated", "unvalidated": map[string]any{"diagnosis": "admission_withdrawn",
		"type": float64(2)}}
	otherDiag := map[string]any{"event": "unvalidated", "reason": "device_unknown",
		"unvalidated": map[string]any{"diagnosis": "unadmitted_source", "type": float64(2)}}
	open := map[string]any{"event": "unvalidated", "reason": "device_unknown",
		"unvalidated": map[string]any{"diagnosis": "admission_withdrawn", "type": float64(3)}}
	if l29Withdrawn([]map[string]any{firstPacket, otherDiag}, "admission_withdrawn") != nil {
		t.Error("l29Withdrawn took a record without reason=device_unknown, or with another diagnosis")
	}
	r := l29Withdrawn([]map[string]any{firstPacket, otherDiag, open}, "admission_withdrawn")
	if r == nil || l29Type(r) != "acct" {
		t.Errorf("l29Withdrawn = %v (type %q), want the device_unknown admission_withdrawn record, type acct", r, l29Type(r))
	}
}

// l29Admitted is how p admits each device of src, by its first address.
func l29Admitted(t *testing.T, p *policy.Policy, src string) []admission.Resolved {
	t.Helper()
	inv, err := admission.ParseFile([]byte(src), "")
	if err != nil {
		t.Fatal(err)
	}
	var out []admission.Resolved
	for _, d := range inv.Devices {
		r, ok := p.Admission().Lookup(d.Addresses[0])
		if !ok {
			t.Fatalf("%s at %s is not in the admission trie", d.Name, d.Addresses[0])
		}
		out = append(out, r)
	}
	return out
}

// l29Address is node's first address in src.
func l29Address(t *testing.T, src, node string) netip.Addr {
	t.Helper()
	inv, err := admission.ParseFile([]byte(src), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range inv.Devices {
		if d.Name == node && len(d.Addresses) > 0 {
			return d.Addresses[0]
		}
	}
	t.Fatalf("no address for %s", node)
	return netip.Addr{}
}
