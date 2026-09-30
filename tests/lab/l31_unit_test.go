//go:build lab

package lab

import (
	"testing"
	"time"
)

// The bar a declined phase's break-glass is held to: the same run's rekeyed
// control plus 1.5 s, and never 5 s or more, the devices' own AAA timeout.
func TestL31Bar(t *testing.T) {
	for _, c := range []struct{ control, want time.Duration }{
		{1530 * time.Millisecond, 3030 * time.Millisecond},
		{2600 * time.Millisecond, 4100 * time.Millisecond},
		{4 * time.Second, 5 * time.Second},
	} {
		if got := l31Bar(c.control); got != c.want {
			t.Errorf("l31Bar(%s) = %s, want %s", c.control, got, c.want)
		}
	}
}

// The capture readers, on committed evidence whose answers are known.
// Counted with tcpdump on 2026-09-30, keyed by the device's address and port
// (SYN from the device, RST from port49d, no device payload): the rekeyed
// phase's retries were refused at Accept, 13 connections on NX-OS and 10 on
// IOS-XE, and the refused phase's never were, 0 on both. The 2026-09-30 L29
// captures carry the single-connect flag, and L28's do not
// (tests/lab/results/L31-breakglass-cisco-singleconnection.md).
func TestL31CaptureReaders(t *testing.T) {
	for _, c := range []struct {
		addr, platform string
		rekeyed        int
	}{
		{"172.100.100.31", "cisco_nxos", 13},
		{"172.100.100.41", "cisco_iosxe", 10},
	} {
		rekeyed, err := l31RefusedAtAccept("evidence/L29-reload-rekeyed-"+c.platform+".pcap", c.addr, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		refused, err := l31RefusedAtAccept("evidence/L29-reload-refused-"+c.platform+".pcap", c.addr, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if rekeyed != c.rekeyed || refused != 0 {
			t.Errorf("%s refused at Accept: rekeyed %d (tcpdump: %d), refused %d (tcpdump: 0)",
				c.platform, rekeyed, c.rekeyed, refused)
		}
	}
	const nx = "172.100.100.31"
	if set, _, err := l31SingleConnect("evidence/L29-reload-refused-cisco_nxos.pcap", nx, time.Time{}); err != nil || set == 0 {
		t.Fatalf("L29 refused capture: %d packets with the single-connect flag, %v", set, err)
	}
	if set, unset, err := l31SingleConnect("evidence/L28-cisco_nxos.pcap", nx, time.Time{}); err != nil || set != 0 || unset == 0 {
		t.Fatalf("L28 capture: single-connect set on %d, unset on %d, %v", set, unset, err)
	}
}
