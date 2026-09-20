//go:build lab

package lab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

// capture runs tcpdump around a test.
//
// Two flags and two probes, and each one is here because its absence cost a
// measurement. `--immediate-mode` is the important one: without it libpcap
// hands tcpdump the kernel's ring buffer on a one-second read timeout, so a
// test that stops the capture within a second of its last packet loses that
// packet. That is exactly what happened to the first vEOS run — L10's whole
// exchange lasted 263ms and was never written, leaving a 24-byte file beside a
// results note that claimed a measurement, and L6 and L8 each lost their
// accounting tail the same way. `-U` then flushes each packet to the file as it
// is written, so the file is complete even if tcpdump is killed rather than
// interrupted.
//
// The probes turn "tcpdump is running" into "this file is capturing". One at
// the start must appear in the file before the test is allowed to generate
// traffic; one at the end must appear before tcpdump is stopped, which proves
// by ordering that everything the test produced is already on disk. They are
// loopback packets, so they never appear in the device-packet count a results
// note reports.
func (l *lab) capture(t *testing.T, name string) func() {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "captures")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("captures directory: %v", err)
	}
	abs := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", name, l.p.name))
	l.capPath = filepath.Join("tests/lab/captures", filepath.Base(abs))
	l.capAbs = abs

	// tcpdump runs as root under sudo and drops privileges to its own user, so
	// it cannot be signalled directly and its pid is not the pid of sudo. The
	// shell wrapper writes the pid the harness must signal. Matching on the
	// command line instead would be one typo away from a capture that is never
	// stopped and a run that waits on it forever.
	pidPath := abs + ".pid"
	os.Remove(pidPath)
	os.Remove(abs)
	script := fmt.Sprintf("echo $$ > %s; exec tcpdump --immediate-mode -i any -U -n -s 0 -w %s 'tcp port 49'",
		shellQuote(pidPath), shellQuote(abs))
	cmd := exec.Command("sudo", "-n", "sh", "-c", script)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	// A test that runs without a live capture measures without evidence, and a
	// results note may not point at a capture that holds nothing, so this is
	// fatal rather than a warning. Kill tcpdump first: it runs as root under
	// sudo and nothing else in this function will ever stop it — the stop
	// closure below has not been returned yet — so failing without this leaves a
	// privileged process and its pid file behind for the rest of the run.
	if err := waitCaptureLive(abs); err != nil {
		signalCapture(pidPath, "-KILL")
		cmd.Wait()
		os.Remove(pidPath)
		t.Fatalf("the capture for %s never became live, so this test would measure without evidence: %v\ntcpdump said: %s",
			abs, err, errBuf.String())
	}

	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		l.flushCapture(t)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		signalCapture(pidPath, "-INT")
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			signalCapture(pidPath, "-KILL")
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				// -U wrote every packet through as it arrived, so the file is
				// complete and readable whatever this process is now doing.
				t.Logf("WARNING: tcpdump for %s did not exit; the capture is still valid but a process was left behind", abs)
			}
		}
		// tcpdump wrote the file as its own dropped-privilege user.
		_ = exec.Command("sudo", "-n", "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), abs).Run()
		os.Remove(pidPath)
		total, device, err := pcapCounts(abs)
		if err != nil {
			t.Logf("could not read the capture %s back (%v); tcpdump said: %s", abs, err, errBuf.String())
			return
		}
		t.Logf("capture %s: %d packets, %d of them between the device and port49d", abs, total, device)
		if device == 0 {
			t.Logf("WARNING: the capture %s holds no TACACS packet to or from %s; tcpdump said: %s",
				abs, labSubnet, errBuf.String())
		}
	}
}

// flushCapture makes tcpdump prove it has written everything the test produced,
// by sending a probe and waiting for it to reach the file. Packets are written
// in the order they arrive, so a probe that is on disk means every earlier
// packet is too. It is called both before the capture is stopped and before a
// results note quotes the capture, and is safe to call repeatedly.
func (l *lab) flushCapture(t *testing.T) {
	t.Helper()
	if l.capAbs == "" {
		return
	}
	before := pcapSize(l.capAbs)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		capProbe()
		for i := 0; i < 10 && time.Now().Before(deadline); i++ {
			if pcapSize(l.capAbs) > before {
				// A short settle: the probe's own RST follows its SYN.
				time.Sleep(200 * time.Millisecond)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Logf("WARNING: the capture %s did not grow when probed, so its tail may be short", l.capAbs)
}

// waitCaptureLive blocks until a probe packet has reached the capture file,
// which is the only proof that tcpdump has its socket open, its filter set, and
// its savefile written to. A running tcpdump process is not that proof.
func waitCaptureLive(path string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		capProbe()
		for i := 0; i < 10 && time.Now().Before(deadline); i++ {
			if pcapSize(path) > pcapHeaderSize {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return fmt.Errorf("no probe packet reached %s within 30s", path)
}

// capProbe generates the two loopback packets that prove a capture is live: a
// SYN to a port nothing listens on, and the kernel's RST.
func capProbe() {
	c, err := net.DialTimeout("tcp", capProbeAddr, 500*time.Millisecond)
	if err == nil {
		c.Close()
	}
}

func pcapSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// pcapCounts reads a capture back and returns how many packets it holds and how
// many of those are to or from the lab management subnet. The second number is
// the one a results note may rest on: it excludes the harness's own loopback
// liveness probes, so a note that quotes a capture is quoting device traffic.
//
// The parser handles only what this harness produces — a little-endian pcap of
// `-i any`, which on Linux is LINUX_SLL2 — and reports what it cannot read
// rather than guessing.
func pcapCounts(path string) (total, device int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	if len(raw) < pcapHeaderSize {
		return 0, 0, fmt.Errorf("%s is %d bytes, shorter than a pcap file header", path, len(raw))
	}
	magic := binary.LittleEndian.Uint32(raw[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		return 0, 0, fmt.Errorf("%s: unexpected pcap magic %#x; this parser reads only little-endian pcap", path, magic)
	}
	link := binary.LittleEndian.Uint32(raw[20:24])
	// snaplen bounds every record's inclLen by construction: tcpdump never
	// stores more of a packet than it captured. A larger value is corruption
	// in the middle of the file, not the truncated tail handled below, and a
	// results note must not quote a count taken from a corrupt capture.
	snaplen := int(binary.LittleEndian.Uint32(raw[16:20]))

	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return 0, 0, err
	}

	for off := pcapHeaderSize; off+16 <= len(raw); {
		inclLen := int(binary.LittleEndian.Uint32(raw[off+8 : off+12]))
		off += 16
		if snaplen > 0 && inclLen > snaplen {
			return 0, 0, fmt.Errorf("%s: record at offset %d claims %d bytes, more than the file's snaplen of %d; the capture is corrupt",
				path, off-16, inclLen, snaplen)
		}
		if off+inclLen > len(raw) {
			// A short tail is not corruption, it is a snapshot. Notes are written
			// while tcpdump is still running, so a read can land between the
			// record header and its bytes. Erroring here turned that race into a
			// red test on a run where the device behaved perfectly. Every whole
			// record before this point is counted and returned; the partial one
			// is simply not one of them.
			return total, device, nil
		}
		total++
		if src, dst, ok := ipv4Of(link, raw[off:off+inclLen]); ok && (subnet.Contains(src) || subnet.Contains(dst)) {
			device++
		}
		off += inclLen
	}
	return total, device, nil
}

// ipv4Of pulls the source and destination address out of one captured packet.
func ipv4Of(link uint32, b []byte) (src, dst net.IP, ok bool) {
	var hdr int
	var proto uint16
	switch link {
	case 276: // LINUX_SLL2, what `-i any` produces on Linux
		hdr, proto = 20, 0
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[0:2])
	case 113: // LINUX_SLL
		hdr = 16
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[14:16])
	case 1: // Ethernet
		hdr = 14
		if len(b) < hdr {
			return nil, nil, false
		}
		proto = binary.BigEndian.Uint16(b[12:14])
	default:
		return nil, nil, false
	}
	if proto != 0x0800 || len(b) < hdr+20 {
		return nil, nil, false
	}
	ip := b[hdr:]
	if ip[0]>>4 != 4 {
		return nil, nil, false
	}
	return net.IP(ip[12:16]), net.IP(ip[16:20]), true
}

func signalCapture(pidPath, sig string) {
	out, err := exec.Command("sudo", "-n", "cat", pidPath).Output()
	if err != nil {
		return
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" {
		return
	}
	// The shell exec'd into tcpdump, so this pid is tcpdump's own.
	_ = exec.Command("sudo", "-n", "kill", sig, pid).Run()
}

// shellQuote wraps a path for the `sudo sh -c` wrapper above.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
