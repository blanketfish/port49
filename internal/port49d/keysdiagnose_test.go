package port49d

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// The keys are obviously fake and live only in this process's environment.
const (
	diagProdV3 = "fake-key-prod-v3"
	diagLabV1  = "fake-key-lab-v1"
	diagOldV1  = "fake-key-old-v1"
	diagNobody = "fake-key-nobody-has-this"
)

// diagConfig writes a port49d.yaml with no policy: two key groups (prod, and
// old with a retired version 1), a device in the inventory, and the keys in
// the environment.
func diagConfig(t *testing.T) string {
	t.Helper()
	t.Setenv("T_DIAG_PROD_V3", diagProdV3)
	t.Setenv("T_DIAG_LAB_V1", diagLabV1)
	t.Setenv("T_DIAG_OLD_V1", diagOldV1)
	t.Setenv("T_DIAG_OLD_V2", "fake-key-old-v2")
	t.Setenv("T_DIAG_ENC", "33333333333333333333333333333333")
	dir := safeDir(t)
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9]}
  - {name: spine-02, platform: arista_eos, addresses: [10.20.4.10]}
key_groups:
  - {match: {cidr: 10.20.0.0/16}, key_ref: prod}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`
listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
encryption:
  current: {id: v1, secret_ref: env:T_DIAG_ENC}
accounting: {spool_path: %s}
keys:
  prod:
    current: {version: 3, secret_ref: env:T_DIAG_PROD_V3}
  lab:
    current: {version: 1, secret_ref: env:T_DIAG_LAB_V1}
  old:
    current: {version: 2, secret_ref: env:T_DIAG_OLD_V2}
    accept: [{version: 1, secret_ref: env:T_DIAG_OLD_V1, retire_after: 2020-01-01}]
`, inv, filepath.Join(dir, "acct.jsonl"))), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// diagSegment is one TCP segment of a synthetic capture.
type diagSegment struct {
	src      [4]byte
	sport    uint16
	dport    uint16
	flags    byte
	seq      uint32
	payload  []byte
	vlan     bool
	truncate int // bytes of the segment's payload cut from the record, as a short snaplen does
}

// diagPcap is segments written as a classic little-endian pcap of Ethernet,
// IPv4 and TCP records.
func diagPcap(segs []diagSegment) []byte {
	var out bytes.Buffer
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:], 2)
	binary.LittleEndian.PutUint16(gh[6:], 4)
	binary.LittleEndian.PutUint32(gh[16:], 65535)
	binary.LittleEndian.PutUint32(gh[20:], 1)
	out.Write(gh)
	for _, s := range segs {
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:], s.sport)
		binary.BigEndian.PutUint16(tcp[2:], s.dport)
		binary.BigEndian.PutUint32(tcp[4:], s.seq)
		tcp[12], tcp[13] = 5<<4, s.flags
		tcp = append(tcp, s.payload...)
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		copy(ip[12:], s.src[:])
		copy(ip[16:], []byte{10, 1, 1, 1})
		eth := make([]byte, 12)
		if s.vlan {
			eth = append(eth, 0x81, 0x00, 0x00, 0x05, 0x08, 0x00)
		} else {
			eth = append(eth, 0x08, 0x00)
		}
		rec := append(append(eth, ip...), tcp...)
		kept := rec[:len(rec)-s.truncate]
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[8:], uint32(len(kept)))
		binary.LittleEndian.PutUint32(rh[12:], uint32(len(rec)))
		out.Write(rh)
		out.Write(kept)
	}
	return out.Bytes()
}

// diagLogin is a device's connection: a SYN, then its first authentication
// packet obfuscated under key, in two segments (so reassembly is exercised).
// A real login's first packet is an authentication START.
func diagLogin(src [4]byte, key string) []diagSegment {
	h := wire.Header{MajorVersion: wire.MajorVersion, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("fake-user"), Data: []byte("fake-credential")}.Encode()
	h.Length = uint32(len(body))
	pkt := append(h.Encode(), wire.Obfuscate(h, []byte(key), body)...)
	return []diagSegment{
		{src: src, sport: 40001, dport: 49, flags: 0x02, seq: 1000},
		{src: src, sport: 40001, dport: 49, flags: 0x18, seq: 1001, payload: pkt[:15]},
		{src: src, sport: 40001, dport: 49, flags: 0x18, seq: 1001 + 15, payload: pkt[15:]},
	}
}

func writeCapture(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func diagRun(t *testing.T, stdin string, args ...string) (code int, out, errs string) {
	t.Helper()
	var o, e bytes.Buffer
	code = keysDiagnoseCmd(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

var leaf19 = [4]byte{10, 20, 4, 9}

// A packet under a retired version of another group is named by its group and
// version, and nothing else is printed (spec §10).
func TestDiagnoseNamesTheMatchingGroup(t *testing.T) {
	cfg := diagConfig(t)
	capture := writeCapture(t, diagPcap(diagLogin(leaf19, diagOldV1)))
	code, out, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
	if code != 0 || out != "group old version 1 validates this packet\n" || errs != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// The assigned group's own current key.
	capture = writeCapture(t, diagPcap(diagLogin(leaf19, diagProdV3)))
	code, out, _ = diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
	if code != 0 || out != "group prod version 3 validates this packet\n" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	// Another host's packet in the same capture is not the device's, and a
	// VLAN-tagged frame is read.
	segs := diagLogin([4]byte{10, 20, 4, 77}, diagLabV1)
	segs = append(segs, diagLogin(leaf19, diagLabV1)...)
	for i := range segs {
		segs[i].vlan = true
	}
	capture = writeCapture(t, diagPcap(segs))
	code, out, _ = diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
	if code != 0 || out != "group lab version 1 validates this packet\n" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
}

func TestDiagnoseNamesNone(t *testing.T) {
	cfg := diagConfig(t)
	capture := writeCapture(t, diagPcap(diagLogin(leaf19, diagNobody)))
	code, out, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
	if code != 1 || out != "no key port49d holds validates this packet\n" || errs != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

// Nothing of the packet is printed, in any encoding, and no key is.
func TestDiagnosePrintsNoPacketByte(t *testing.T) {
	cfg := diagConfig(t)
	for name, key := range map[string]string{"matching": diagOldV1, "none": diagNobody} {
		t.Run(name, func(t *testing.T) {
			segs := diagLogin(leaf19, key)
			var pkt []byte
			for _, s := range segs {
				pkt = append(pkt, s.payload...)
			}
			capture := writeCapture(t, diagPcap(segs))
			_, out, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
			all := out + errs
			body := pkt[wire.HeaderLen:]
			for _, p := range []struct{ what, text string }{
				{"hex", hex.EncodeToString(body[:8])}, {"base64", base64.StdEncoding.EncodeToString(body[:9])},
				{"raw", string(body[:8])}, {"credential", "fake-credential"}, {"user", "fake-user"},
				{"prod key", diagProdV3}, {"lab key", diagLabV1}, {"old key", diagOldV1}, {"nobody key", diagNobody},
			} {
				if strings.Contains(all, p.text) || strings.Contains(strings.ToLower(all), strings.ToLower(p.text)) {
					t.Errorf("the output holds the packet's or a key's %s", p.what)
				}
			}
		})
	}
}

func TestDiagnoseRefusesAPcapng(t *testing.T) {
	cfg := diagConfig(t)
	ng := append([]byte{0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 28, 0, 0, 0)
	capture := writeCapture(t, ng)
	code, out, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", capture)
	if code != 1 || out != "" || !strings.Contains(errs, "pcapng") || !strings.Contains(errs, "tcpdump -w") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// Not a capture at all.
	code, out, errs = diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", writeCapture(t, []byte("not a capture, just text in a file")))
	if code != 1 || out != "" || !strings.Contains(errs, "not a pcap file") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

func TestDiagnoseReadsStandardInput(t *testing.T) {
	cfg := diagConfig(t)
	raw := diagPcap(diagLogin(leaf19, diagOldV1))
	_, fromFile, _ := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", writeCapture(t, raw))
	code, fromStdin, errs := diagRun(t, string(raw), "--config", cfg, "--device", "leaf-19", "--capture", "-")
	if code != 0 || fromStdin == "" || fromStdin != fromFile || errs != "" {
		t.Fatalf("exit %d: stdin %q, file %q, stderr %q", code, fromStdin, fromFile, errs)
	}
}

// Exit codes: 1 for a capture with no packet from the device and for a device
// not in the inventory, 2 for usage.
func TestDiagnoseExitCodes(t *testing.T) {
	cfg := diagConfig(t)
	other := writeCapture(t, diagPcap(diagLogin([4]byte{10, 20, 4, 77}, diagOldV1)))
	if code, out, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", other); code != 1 || out != "" ||
		!strings.Contains(errs, "no whole TACACS+ packet from leaf-19") {
		t.Fatalf("no packet from the device: exit %d, %q, %q", code, out, errs)
	}
	// A packet cut short by the snaplen is not a whole packet.
	segs := diagLogin(leaf19, diagOldV1)
	segs[2].truncate = 3
	if code, _, errs := diagRun(t, "", "--config", cfg, "--device", "leaf-19", "--capture", writeCapture(t, diagPcap(segs))); code != 1 ||
		!strings.Contains(errs, "no whole TACACS+ packet") {
		t.Fatalf("a short snaplen: exit %d, %q", code, errs)
	}
	if code, _, errs := diagRun(t, "", "--config", cfg, "--device", "nope", "--capture", other); code != 1 || !strings.Contains(errs, "not a device") {
		t.Fatalf("an unknown device: exit %d, %q", code, errs)
	}
	for _, args := range [][]string{{}, {"--device", "leaf-19"}, {"--capture", "-"}, {"--device", "leaf-19", "--capture", "-", "extra"}} {
		if code, _, _ := diagRun(t, "", append([]string{"--config", cfg}, args...)...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
