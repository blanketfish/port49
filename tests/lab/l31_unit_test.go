//go:build lab

package lab

import (
	"errors"
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
		rekeyed, err := l31RefusedAtAccept("evidence/L29-reload-rekeyed-"+c.platform+".pcap", c.addr, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		refused, err := l31RefusedAtAccept("evidence/L29-reload-refused-"+c.platform+".pcap", c.addr, time.Time{}, time.Time{})
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

// The interval readers count only inside [since, until], so a premise read
// over the break-glass session is not met by the token login before it. On
// the committed NX-OS rekeyed capture, whose device SYNs run from
// 1790803873.37 to 1790803896.68 (tcpdump -tt): an interval before the first
// SYN or after the last brackets nothing, and two intervals split between
// the retries at 1790803894.10 and 1790803894.20 count the 13 refusals
// between them.
func TestL31IntervalReaders(t *testing.T) {
	const path, nx = "evidence/L29-reload-rekeyed-cisco_nxos.pcap", "172.100.100.31"
	before, mid, after := time.Unix(1790803873, 0), time.Unix(1790803894, 150_000_000), time.Unix(1790803900, 0)
	for _, c := range []struct {
		name         string
		since, until time.Time
	}{
		{"before the first SYN", time.Time{}, before},
		{"after the last SYN", after, time.Time{}},
	} {
		refused, errR := l31RefusedAtAccept(path, nx, c.since, c.until)
		opened, errO := l31Opened(path, nx, c.since, c.until)
		if err := errors.Join(errR, errO); err != nil {
			t.Fatal(err)
		}
		if refused != 0 || opened != 0 {
			t.Errorf("%s: refused at Accept %d, opened %d; want 0 and 0", c.name, refused, opened)
		}
	}
	first, errF := l31RefusedAtAccept(path, nx, time.Time{}, mid)
	second, errS := l31RefusedAtAccept(path, nx, mid, time.Time{})
	opened, errO := l31Opened(path, nx, time.Time{}, time.Time{})
	if err := errors.Join(errF, errS, errO); err != nil {
		t.Fatal(err)
	}
	if first+second != 13 || first == 0 || second == 0 {
		t.Errorf("split at %s: refused at Accept %d before and %d after; want both nonzero, summing to 13",
			mid.UTC(), first, second)
	}
	if opened < 13 {
		t.Errorf("the whole capture: %d connections opened, fewer than the 13 refused at Accept", opened)
	}
}

// A break-glass session ran its commands only if it logged in, all of them
// answered, and none answered with the platform's refusal text: a session
// refused every command, quickly, is the regression L31 most needs to catch.
func TestBreakglassRan(t *testing.T) {
	ver := "show version\nCisco IOS XE Software, Version 17.12.01\n"
	for _, c := range []struct {
		name, platform string
		outs           []string
		err            error
		cell           string
		ok             bool
	}{
		{"ran them", "cisco_iosxe", []string{ver, ver, ver}, nil, "logged in and ran them", true},
		{"IOS-XE refused", "cisco_iosxe", []string{ver, "show version\n% Authorization failed.\n", ver}, nil,
			"refused: % Authorization failed.", false},
		{"NX-OS refused", "cisco_nxos", []string{"Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)"},
			nil, "refused: Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)", false},
		{"EOS refused", "arista_eos", []string{ver, ver, "% Authorization denied for command 'show version': port49: x"},
			nil, "refused: % Authorization denied for command 'show version': port49: x", false},
		{"two of three", "cisco_nxos", []string{ver, ver}, nil, "ran 2 of 3", false},
		{"no login", "cisco_nxos", nil, errors.New("ssh: handshake failed"), "not observed: ssh: handshake failed", false},
	} {
		cell, ok := breakglassRan(c.platform, c.outs, c.err, 3)
		if cell != c.cell || ok != c.ok {
			t.Errorf("%s: breakglassRan = %q, %v; want %q, %v", c.name, cell, ok, c.cell, c.ok)
		}
	}
}
