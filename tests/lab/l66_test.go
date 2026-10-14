//go:build lab

package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

// L66 (plan 9d, Task 12): the Ansible lookup `port49.client.token` over `ansible.netcommon.network_cli`,
// and the host keys of the connection plugins around it, against each platform. Spec §15 L66 is the claim.
//
// One capture for the run. Every cell counts TACACS+ packets in its own window, and a good login's window
// in the same capture is the positive control for every zero. A cell is PASS, FAIL, INVALID (it could not
// measure what it claims: no note is written for a run with one) or OBSERVED (it records what happens, and
// no answer was claimed). Nothing here reads, prints or stores a token: the decision log's hashes are what
// a token is looked for by.

// ---------------------------------------------------------------------------
// Readers: pure, and unit-tested in l66_unit_test.go
// ---------------------------------------------------------------------------

var (
	l66RecapRe = regexp.MustCompile(`(?m)^(\S+)\s*:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)` +
		`(?:\s+skipped=(\d+))?(?:\s+rescued=(\d+))?(?:\s+ignored=(\d+))?`)
)

// l66Recap is one host's line of the PLAY RECAP.
type l66Recap struct{ OK, Changed, Unreachable, Failed, Skipped, Rescued, Ignored int }

// Passed is a host that ran something and had nothing fail or go unreachable.
func (r l66Recap) Passed() bool { return r.OK > 0 && r.Failed == 0 && r.Unreachable == 0 }

// l66ReadRecap reads the PLAY RECAP of an ansible-playbook run, by host.
func l66ReadRecap(out string) map[string]l66Recap {
	recaps := map[string]l66Recap{}
	for _, m := range l66RecapRe.FindAllStringSubmatch(out, -1) {
		n := make([]int, 8)
		for i := 2; i < len(m); i++ {
			n[i-2], _ = strconv.Atoi(m[i])
		}
		recaps[m[1]] = l66Recap{OK: n[0], Changed: n[1], Unreachable: n[2], Failed: n[3], Skipped: n[4], Rescued: n[5], Ignored: n[6]}
	}
	return recaps
}

// l66ErrorText is the first `fatal:` block of a run on one line, cut to max: the text of the error a task
// failed with. "" when no task failed.
func l66ErrorText(out string, max int) string {
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(ln, "fatal: [") {
			continue
		}
		parts := []string{strings.TrimSpace(ln)}
		if strings.HasSuffix(strings.TrimSpace(ln), "{") {
			for _, nx := range lines[i+1:] {
				parts = append(parts, strings.TrimSpace(nx))
				if strings.TrimSpace(nx) == "}" {
					break
				}
			}
		}
		s := strings.Join(parts, " ")
		if len(s) > max {
			s = s[:max] + "..."
		}
		return s
	}
	return ""
}

// l66WarningLines are the `[WARNING]:` lines of a run: ansible-core 2.16 to 2.18 show a failed no_log
// task's message only there.
func l66WarningLines(out string) []string { return l66TaggedLines(out, "[WARNING]:") }

// l66ErrorLines are the `[ERROR]:` lines of a run. no_log censors a failed task's `fatal:` result but not
// this line, so for a censored task it is the only text that says why it failed.
func l66ErrorLines(out string) []string { return l66TaggedLines(out, "[ERROR]:") }

func l66TaggedLines(out, tag string) []string {
	var w []string
	for _, ln := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(ln); strings.HasPrefix(s, tag) {
			w = append(w, s)
		}
	}
	return w
}

// l66Counts is what a window of the decision log says about mints and redeems.
type l66Counts struct {
	Mints, MintDenies, Redeems int
	MintReasons, RedeemReasons map[string]int
	// Other is every event but mint, blob and redeem, in order: a login's accounting and authorization.
	Other []string
}

func l66CountRecords(recs []map[string]any) l66Counts {
	c := l66Counts{MintReasons: map[string]int{}, RedeemReasons: map[string]int{}}
	for _, r := range recs {
		switch ev := str(r, "event"); ev {
		case "mint":
			c.Mints++
			c.MintReasons[str(r, "reason")]++
			if str(r, "verdict") == "deny" {
				c.MintDenies++
			}
		case "redeem":
			c.Redeems++
			c.RedeemReasons[str(r, "reason")]++
		case "blob":
		default:
			c.Other = append(c.Other, ev)
		}
	}
	return c
}

func (c l66Counts) String() string {
	return fmt.Sprintf("%d mint records (%d denied; reasons %v), %d redeem records (reasons %v)", c.Mints, c.MintDenies,
		c.MintReasons, c.Redeems, c.RedeemReasons)
}

// l66TokenHashes are the SHA-256 hashes of every token the window's records name: the mints' token_sha256
// and the redeems' credential_sha256. A token is looked for by these, never by its text.
func l66TokenHashes(recs []map[string]any) map[string]bool {
	h := map[string]bool{}
	for _, r := range recs {
		for _, s := range strs(sub(r, "mint"), "token_sha256") {
			h[s] = true
		}
		if s := str(sub(r, "auth"), "credential_sha256"); s != "" {
			h[s] = true
		}
	}
	return h
}

func l66Base62(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// l66HasToken is whether any tokLen window of any base62 run of s hashes to one of hashes. A token is not
// delimited in an Ansible log (it sits in a `password=` argument, a repr, a URL), so every window of a run
// is hashed, as the lab's own note audit does.
func l66HasToken(s string, hashes map[string]bool, tokLen int) bool {
	for i := 0; i < len(s); {
		if !l66Base62(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && l66Base62(s[j]) {
			j++
		}
		for k := i; k+tokLen <= j; k++ {
			if hashes[sha(s[k:k+tokLen])] {
				return true
			}
		}
		i = j
	}
	return false
}

// l66FindTokens is the 1-based line numbers of text that hold a token one of hashes names. It never returns,
// and never needs, the token.
func l66FindTokens(text string, hashes map[string]bool, tokLen int) []int {
	var lines []int
	if len(hashes) == 0 || tokLen <= 0 {
		return lines
	}
	for i, ln := range strings.Split(text, "\n") {
		if l66HasToken(ln, hashes, tokLen) {
			lines = append(lines, i+1)
		}
	}
	return lines
}

// l66Scrub is text with every token one of hashes names replaced by "[token]": what a note may quote of a
// run's output.
func l66Scrub(text string, hashes map[string]bool, tokLen int) string {
	if len(hashes) == 0 || tokLen <= 0 {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		if !l66Base62(text[i]) {
			b.WriteByte(text[i])
			i++
			continue
		}
		j := i
		for j < len(text) && l66Base62(text[j]) {
			j++
		}
		run := text[i:j]
		for k := 0; k < len(run); {
			if k+tokLen <= len(run) && hashes[sha(run[k:k+tokLen])] {
				b.WriteString("[token]")
				k += tokLen
				continue
			}
			b.WriteByte(run[k])
			k++
		}
		i = j
	}
	return b.String()
}

// l66KHLine is one key line of a known_hosts file.
type l66KHLine struct{ Marker, Hosts, Type, Blob string }

// Short is the line without its whole key: the marker, the hosts, the type and the key's first characters.
func (l l66KHLine) Short() string {
	blob := l.Blob
	if len(blob) > 16 {
		blob = blob[:16] + "..."
	}
	s := l.Hosts + " " + l.Type + " " + blob
	if l.Marker != "" {
		s = l.Marker + " " + s
	}
	return s
}

// l66ParseKH reads the key lines of a known_hosts file; comments and blank lines are not key lines.
func l66ParseKH(content string) []l66KHLine {
	var out []l66KHLine
	for _, ln := range strings.Split(content, "\n") {
		if l, ok := l66ParseKHLine(ln); ok {
			out = append(out, l)
		}
	}
	return out
}

func l66ParseKHLine(ln string) (l66KHLine, bool) {
	f := strings.Fields(ln)
	if len(f) == 0 || strings.HasPrefix(f[0], "#") {
		return l66KHLine{}, false
	}
	var l l66KHLine
	if strings.HasPrefix(f[0], "@") {
		l.Marker, f = f[0], f[1:]
	}
	if len(f) < 3 {
		return l66KHLine{}, false
	}
	l.Hosts, l.Type, l.Blob = f[0], f[1], f[2]
	return l, true
}

// l66KHChange is what a run did to a known_hosts file.
type l66KHChange struct {
	// Mode is unchanged, appended (everything that was there is still there, in place) or rewritten.
	Mode           string
	Added, Removed []l66KHLine
	// LostComments and LostMarkers are the comment lines and the @revoked/@cert-authority lines of the file
	// before that the file after does not hold, verbatim.
	LostComments, LostMarkers []string
}

func l66DiffKH(before, after string) l66KHChange {
	var c l66KHChange
	switch b := before; {
	case before == after:
		c.Mode = "unchanged"
	case func() bool {
		if b != "" && !strings.HasSuffix(b, "\n") {
			b += "\n"
		}
		return strings.HasPrefix(after, b)
	}():
		c.Mode = "appended"
	default:
		c.Mode = "rewritten"
	}
	bl, al := l66ParseKH(before), l66ParseKH(after)
	for _, l := range al {
		if !slices.Contains(bl, l) {
			c.Added = append(c.Added, l)
		}
	}
	for _, l := range bl {
		if !slices.Contains(al, l) {
			c.Removed = append(c.Removed, l)
		}
	}
	afterLines := map[string]bool{}
	for _, ln := range strings.Split(after, "\n") {
		afterLines[strings.TrimSpace(ln)] = true
	}
	for _, ln := range strings.Split(before, "\n") {
		s := strings.TrimSpace(ln)
		if afterLines[s] {
			continue
		}
		if strings.HasPrefix(s, "#") {
			c.LostComments = append(c.LostComments, s)
		} else if strings.HasPrefix(s, "@") {
			c.LostMarkers = append(c.LostMarkers, s)
		}
	}
	return c
}

// l66ReplaceBlob swaps the key of the first line of content that is line, keeping the rest of the file as
// it was. ok is false when no line matches.
func l66ReplaceBlob(content string, line l66KHLine, blob string) (string, bool) {
	lines := strings.Split(content, "\n")
	for i, ln := range lines {
		if l, ok := l66ParseKHLine(ln); ok && l == line {
			lines[i] = strings.Replace(ln, " "+line.Blob, " "+blob, 1)
			return strings.Join(lines, "\n"), true
		}
	}
	return content, false
}

// l66BaselineKH is the known_hosts file (c) starts from: a comment, an @revoked line and an
// @cert-authority line, all for patterns unrelated to the lab, so that what a client does to them is seen.
func l66BaselineKH(blobRevoked, blobCA string) string {
	return "# L66 baseline: a comment line a client that rewrites this file may drop\n" +
		"@revoked unrelated.l66.invalid ssh-ed25519 " + blobRevoked + "\n" +
		"@cert-authority *.unrelated.l66.invalid ssh-ed25519 " + blobCA + "\n"
}

// l66StandinEvent is one line of the stand-in sshd's log. A password is its length and its hash, never its
// text.
type l66StandinEvent struct {
	Event   string `json:"event"`
	User    string `json:"user"`
	Remote  string `json:"remote"`
	KeyType string `json:"key_type"`
	SHA256  string `json:"sha256"`
	Len     int    `json:"len"`
	// HostKeys are the stand-in's key fingerprints, on its ready event.
	HostKeys []string `json:"host_keys"`
}

func l66ParseStandin(log string) []l66StandinEvent {
	var es []l66StandinEvent
	for _, ln := range strings.Split(log, "\n") {
		var e l66StandinEvent
		if json.Unmarshal([]byte(strings.TrimSpace(ln)), &e) == nil && e.Event != "" {
			es = append(es, e)
		}
	}
	return es
}

// l66StandinTally is what the stand-in saw: connections, and the passwords and keyboard-interactive answers
// it was offered, by hash.
type l66StandinTally struct {
	Connects, Passwords, Kbdint int
	Hashes                      []string
}

func l66TallyStandin(es []l66StandinEvent) l66StandinTally {
	var t l66StandinTally
	for _, e := range es {
		switch e.Event {
		case "connect":
			t.Connects++
		case "password_attempt":
			t.Passwords++
			t.Hashes = append(t.Hashes, e.SHA256)
		case "kbdint_attempt":
			t.Kbdint++
			t.Hashes = append(t.Hashes, e.SHA256)
		}
	}
	return t
}

// Presented is whether any attempt the stand-in logged was one of the tokens hashes names.
func (t l66StandinTally) Presented(hashes map[string]bool) bool {
	return slices.ContainsFunc(t.Hashes, func(h string) bool { return hashes[h] })
}

// l66Seg is one TCP segment the device sent to port 49 with a payload.
type l66Seg struct {
	At      time.Time
	SrcPort uint16
	Seq     uint32
	Payload []byte
}

// l66AuthStarts counts TACACS+ authentication starts (header type 1, sequence number 1) the device sent in
// the window [from, to]: one per segment, however many interfaces `tcpdump -i any` saw it on. A start is
// read from the header at the front of a segment's payload; a segment that carries a packet's tail or two
// packets is not looked into.
func l66AuthStarts(segs []l66Seg, from, to time.Time) int {
	type key struct {
		port uint16
		seq  uint32
	}
	seen := map[key]bool{}
	n := 0
	for _, s := range segs {
		k := key{s.SrcPort, s.Seq}
		if seen[k] {
			continue
		}
		seen[k] = true
		if s.At.Before(from) || s.At.After(to) || len(s.Payload) < 12 {
			continue
		}
		if s.Payload[1] == 0x01 && s.Payload[2] == 0x01 {
			n++
		}
	}
	return n
}

// l66LoadSegs reads the capture at path for every segment with a payload that the device at addr sent to
// port 49.
func l66LoadSegs(path, addr string) ([]l66Seg, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return nil, err
	}
	var segs []l66Seg
	for i, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok || fl.Src.String() != addr || fl.DstPort != 49 || fl.PayloadLen == 0 {
			continue
		}
		segs = append(segs, l66Seg{At: f.TimeOf(i), SrcPort: fl.SrcPort, Seq: fl.Seq, Payload: slices.Clone(f.Payload(r, fl))})
	}
	return segs, nil
}

// l66Result is one cell's row.
type l66Result = l64Result

// l66Outcome is a cell's verdict. kind is claim (ok is whether the claim held), refusal (a claim whose
// zero needs the positive control) or record (it records what happens: ok is only whether the thing could
// be observed). A refusal that passes without a good control, a record that could not be observed, and any
// cell whose count could not be read are INVALID, never PASS or OBSERVED.
func l66Outcome(kind string, ok, timedOut, controlOK, unread bool) string {
	switch {
	case timedOut:
		return "TIMEOUT"
	case unread:
		return "INVALID"
	case kind == "record" && (!ok || !controlOK):
		return "INVALID"
	case kind == "refusal" && ok && !controlOK:
		return "INVALID"
	case !ok:
		return "FAIL"
	case kind == "record":
		return "OBSERVED"
	}
	return "PASS"
}

// l66WhyInvalid is the sentence a note gives for an INVALID cell, from the same facts l66Outcome read.
func l66WhyInvalid(kind string, ok, controlOK, unread bool) string {
	switch {
	case unread:
		return "a TACACS+ count could not be read, so a zero here is not a measurement"
	case !controlOK && (kind == "refusal" || kind == "record"):
		return "the positive control failed: no good login's window in this cell held TACACS+ packets and a redeem, so a zero here is a zero of a counter that does not count"
	case kind == "record" && !ok:
		return "the cell could not observe what it records"
	}
	return ""
}

// l66Writable is whether a run's note may be written: an INVALID cell measured nothing, and an INCOMPLETE
// one (skipped for the test's deadline) leaves the run short, so either writes no note. A NOT RUN cell, blocked
// by a client behaviour another cell measured, does not stop it.
func l66Writable(rs []l66Result) (bool, string) {
	if len(rs) == 0 {
		return false, "no cell ran"
	}
	var bad []string
	for _, r := range rs {
		if r.outcome == "INVALID" || strings.HasPrefix(r.outcome, "INCOMPLETE") {
			bad = append(bad, r.id+" "+strings.SplitN(r.outcome, " ", 2)[0])
		}
	}
	if len(bad) > 0 {
		return false, "cells that stop the note: " + strings.Join(bad, ", ")
	}
	return true, ""
}

// l66Platform names what a platform's Ansible collection calls things.
type l66Platform struct{ NetworkOS, Module, Collection string }

var l66Platforms = map[string]l66Platform{
	"arista_eos":            {"arista.eos.eos", "arista.eos.eos_command", "arista.eos"},
	"cisco_nxos":            {"cisco.nxos.nxos", "cisco.nxos.nxos_command", "cisco.nxos"},
	"cisco_iosxe":           {"cisco.ios.ios", "cisco.ios.ios_command", "cisco.ios"},
	"juniper_vjunos-router": {"junipernetworks.junos.junos", "junipernetworks.junos.junos_command", "junipernetworks.junos"},
	"juniper_vsrx":          {"junipernetworks.junos.junos", "junipernetworks.junos.junos_command", "junipernetworks.junos"},
}

// l66DeniedNode is a node of port49d's inventory the run's policy grants nothing on: the (d) cell's device.
func l66DeniedNode(node string) string {
	if node == "srx1" {
		return "vsrx1"
	}
	return "srx1"
}

// l66Policy is the broker's policy for a run: the slice operator may do everything on the one node, and
// nothing on any other.
func l66Policy(node string) string {
	return "# L66's lab policy: the slice's operator on one node, and no grant on any other (cell d).\n" +
		"scopes:\n" +
		"  - {name: this_node, match: {name: [" + node + "]}}\n" +
		"roles:\n" +
		"  - {name: network_admin, privilege: admin, permit: [\"**\"]}\n" +
		"subjects:\n" +
		"  - {name: slice_operator, identity: [\"user:" + sliceEmail + "\"], username: slice01,\n" +
		"     enable: token, token_ttl: 60s}\n" +
		"grants:\n" +
		"  - {subject: slice_operator, scope: this_node, roles: [network_admin], max_privilege: admin}\n"
}

const l66MintFact = `"{{ lookup('port49.client.token', p49_name, field='all', socket=p49_socket, port49=p49_bin) }}"`

// l66Playbook renders a play: kind ten (n commands, the lookup in the connection variables mints), once (a
// no_log mint in pre_tasks, then n commands), gap (the mint, one command, the between task, then n commands)
// or raw (the mint, then n `raw` tasks, for the plain ssh connection).
func l66Playbook(kind string, p l66Platform, n int, between string) string {
	var b strings.Builder
	b.WriteString("---\n- name: L66 " + kind + "\n  hosts: all\n  gather_facts: false\n")
	if kind != "ten" {
		b.WriteString("  pre_tasks:\n    - name: mint once\n      ansible.builtin.set_fact:\n        p49: " + l66MintFact + "\n      no_log: true\n")
	}
	b.WriteString("  tasks:\n")
	task := func(i int) {
		fmt.Fprintf(&b, "    - name: show version %d\n", i)
		if kind == "raw" {
			b.WriteString("      ansible.builtin.raw: show version\n")
			return
		}
		fmt.Fprintf(&b, "      %s:\n        commands: show version\n", p.Module)
	}
	first := 1
	if kind == "gap" {
		task(1)
		for _, ln := range strings.Split(strings.TrimRight(between, "\n"), "\n") {
			b.WriteString("    " + ln + "\n")
		}
		first = 2
	}
	for i := 0; i < n; i++ {
		task(first + i)
	}
	return b.String()
}

// l66Host is an inventory name and the address Ansible connects to.
type l66Host struct{ Name, Address string }

// l66InvSpec is one inventory.
type l66InvSpec struct {
	Hosts []l66Host
	// P49Name is the port49 device every host's lookup asks for; "" asks for the inventory name.
	P49Name     string
	Socket, Bin string
	Platform    l66Platform
	Conn        string // network_cli, or ssh for ansible.builtin.ssh
	SSHType     string // libssh or paramiko, for network_cli
	// Mode is lookup (the lookups sit in ansible_user and ansible_password, cell a) or fact (they read the
	// fact the play's pre_tasks minted).
	Mode           string
	LibsshConfig   string
	ConnectTimeout int
	SSHCommonArgs  string
	SSHExtraArgs   string
}

func l66Inventory(s l66InvSpec) string {
	q := func(v string) string { return strconv.Quote(v) }
	var b strings.Builder
	b.WriteString("all:\n  hosts:\n")
	for _, h := range s.Hosts {
		b.WriteString("    " + h.Name + ":\n      ansible_host: " + q(h.Address) + "\n")
		if s.P49Name != "" {
			b.WriteString("      p49_name: " + q(s.P49Name) + "\n")
		} else {
			b.WriteString("      p49_name: \"{{ inventory_hostname }}\"\n")
		}
	}
	b.WriteString("  vars:\n")
	b.WriteString("    p49_socket: " + q(s.Socket) + "\n    p49_bin: " + q(s.Bin) + "\n")
	if s.Conn == "ssh" {
		b.WriteString("    ansible_connection: ssh\n")
	} else {
		b.WriteString("    ansible_connection: ansible.netcommon.network_cli\n")
		b.WriteString("    ansible_network_os: " + q(s.Platform.NetworkOS) + "\n")
		b.WriteString("    ansible_network_cli_ssh_type: " + s.SSHType + "\n")
		b.WriteString("    ansible_look_for_keys: false\n")
	}
	if s.Mode == "lookup" {
		b.WriteString("    ansible_user: \"{{ lookup('port49.client.token', p49_name, field='username', socket=p49_socket, port49=p49_bin) }}\"\n")
		b.WriteString("    ansible_password: \"{{ lookup('port49.client.token', p49_name, socket=p49_socket, port49=p49_bin) }}\"\n")
	} else {
		// ansible-core templates these into remote_user and password for the mint's set_fact too, before the
		// fact exists; without the default every fact play fails at its mint (the collection README's pattern).
		b.WriteString("    ansible_user: \"{{ p49.username | default(omit) }}\"\n    ansible_password: \"{{ p49.login | default(omit) }}\"\n")
	}
	if s.LibsshConfig != "" {
		b.WriteString("    ansible_libssh_config_file: " + q(s.LibsshConfig) + "\n")
	}
	if s.ConnectTimeout > 0 {
		b.WriteString("    ansible_connect_timeout: " + strconv.Itoa(s.ConnectTimeout) + "\n")
	}
	if s.SSHCommonArgs != "" {
		b.WriteString("    ansible_ssh_common_args: " + q(s.SSHCommonArgs) + "\n")
	}
	if s.SSHExtraArgs != "" {
		b.WriteString("    ansible_ssh_extra_args: " + q(s.SSHExtraArgs) + "\n")
	}
	return b.String()
}

// l66ConnLookups is how many port49.client.token lookups an inventory puts in its connection variables
// (ansible_*): what L66a's note says each evaluation of them costs, read from the inventory it ran.
func l66ConnLookups(inv string) int {
	n := 0
	for _, ln := range strings.Split(inv, "\n") {
		if s := strings.TrimSpace(ln); strings.HasPrefix(s, "ansible_") {
			n += strings.Count(s, "lookup('port49.client.token'")
		}
	}
	return n
}

// l66Collections are the collections a run needs, in the order its install command names them. port49.client
// is the tree's own (clients/ansible); the rest are installed once into the private directory.
var l66Collections = []string{"ansible.netcommon", "arista.eos", "cisco.nxos", "cisco.ios", "junipernetworks.junos", "port49.client"}

// l66ParseGalaxy reads `ansible-galaxy collection list --format json`: collection name to version, over
// every path it lists.
func l66ParseGalaxy(js string) (map[string]string, error) {
	var byPath map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(js), &byPath); err != nil {
		return nil, fmt.Errorf("the collection list is not JSON: %w", err)
	}
	have := map[string]string{}
	for _, cs := range byPath {
		for name, c := range cs {
			have[name] = c.Version
		}
	}
	return have, nil
}

// l66Missing is the collections of l66Collections that have lists no version of.
func l66Missing(have map[string]string) []string {
	var miss []string
	for _, c := range l66Collections {
		if _, ok := have[c]; !ok {
			miss = append(miss, c)
		}
	}
	return miss
}

// l66InstallCommand is the command that puts the Galaxy collections into dir.
func l66InstallCommand(dir string) string {
	var names []string
	for _, c := range l66Collections {
		if c != "port49.client" {
			names = append(names, c)
		}
	}
	return filepath.Join(filepath.Dir(venvPython), "ansible-galaxy") + " collection install -p " + dir + " " + strings.Join(names, " ")
}

// l66Snap is a file as it was: the operator's own known_hosts, which a client that reads the home from the
// passwd entry rather than $HOME (libssh) could write. A run that finds it changed is INVALID and says what
// was added; the file is left as it is, since it may hold the operator's own additions made meanwhile.
type l66Snap struct {
	Path   string
	Exists bool
	Data   []byte
}

func l66Snapshot(path string) (l66Snap, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l66Snap{Path: path}, nil
	}
	if err != nil {
		return l66Snap{}, err
	}
	return l66Snap{Path: path, Exists: true, Data: data}, nil
}

// Changed is whether the file differs from the snapshot: another content, created, or gone.
func (s l66Snap) Changed() (bool, error) {
	now, err := l66Snapshot(s.Path)
	if err != nil {
		return false, err
	}
	return now.Exists != s.Exists || !bytes.Equal(now.Data, s.Data), nil
}

// Diff is what the file holds now against the snapshot, key lines and comments.
func (s l66Snap) Diff() (l66KHChange, error) {
	now, err := l66Snapshot(s.Path)
	if err != nil {
		return l66KHChange{}, err
	}
	return l66DiffKH(string(s.Data), string(now.Data)), nil
}

// l66ClientSums is the SHA-256 of each .py file directly in dir, by name.
func l66ClientSums(dir string) (map[string]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sums := map[string]string{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".py") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sums[e.Name()] = sha(string(b))
	}
	return sums, nil
}

// l66ParseSums reads "name sha256" lines.
func l66ParseSums(out string) map[string]string {
	sums := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) == 2 && len(f[1]) == 64 {
			sums[f[0]] = f[1]
		}
	}
	return sums
}

// l66DiffFileSums names what the installed copy lacks or has different from the tree's. A file only the
// installed copy holds is not stale code and is not named.
func l66DiffFileSums(tree, installed map[string]string) []string {
	var diff []string
	for _, name := range slices.Sorted(maps.Keys(tree)) {
		got, ok := installed[name]
		switch {
		case !ok:
			diff = append(diff, name+" missing")
		case got != tree[name]:
			diff = append(diff, name+" differs")
		}
	}
	return diff
}

// ---------------------------------------------------------------------------
// The lab side
// ---------------------------------------------------------------------------

const (
	l66Budget     = 10 * time.Minute
	l66Grace      = time.Minute
	l66PlayBudget = 4 * time.Minute
	// l66Reserve is what a cell leaves of the test's deadline for the teardown; l66MinCell is the least a
	// cell is given.
	l66Reserve = 5 * time.Minute
	l66MinCell = 2 * time.Minute
	// l66RestartMax is the most a cell's restart of port49d takes: on IOS-XE a 20 s stop, 30 s for the socket
	// to clear, a 60 s start and up to 3 min of awaitTACACS. Seconds on EOS and NX-OS.
	l66RestartMax  = 5 * time.Minute
	l66StandinName = "l66-standin"
	l66StandinAddr = "172.100.100.250"
	l66DockerNet   = "port49-lab"
	// l66Gap is how long the idle-gap cell sleeps, past l66ShortIdle (persistent_connect_timeout).
	l66Gap = 20
	// l66ShortIdle is persistent_connect_timeout, in seconds, for every run but (a) and (b), so that a play's
	// persistent connection is gone soon after the play and the next window starts quiet. (a) and (b) run
	// with the default, l66DefaultIdle.
	l66ShortIdle   = 10
	l66DefaultIdle = 30
)

var (
	l66Venv     = filepath.Dir(venvPython)
	l66Once     sync.Once
	l66Versions string
	l66CollDir  string
	l66NSSLib   string
	// l66NSSDirs are where libnss_wrapper.so is looked for.
	l66NSSDirs = []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib"}
)

// l66StandinImage is the stand-in's base image, which the preflight finds locally rather than pulling mid-run.
const l66StandinImage = "alpine:3.22"

func l66Start(platform, cell string, budget time.Duration) string {
	return labStart("L66", platform, cell, budget)
}

func l66Stage(platform, cell, stage string) string { return labStage("L66", platform, cell, stage) }

func l66Progress(platform, cell, outcome string, d time.Duration) string {
	return labProgress("L66", platform, cell, outcome, d)
}

// l66PyProbe is what the lab venv's Python prints: the versions of what the cells use, and the SHA-256 of each
// .py file of the installed port49 library, so that a venv that holds another commit's library is found.
const l66PyProbe = `import hashlib, importlib.metadata as m, os, sys
try:
    import port49, pylibsshext
except ImportError as e:
    print("IMPORT_ERROR " + str(e.name))
    sys.exit(3)
print("VERSIONS python %s ansible-core %s ansible-pylibssh %s (libssh %s) paramiko %s port49 %s" % (
    sys.version.split()[0], m.version("ansible-core"), m.version("ansible-pylibssh"), pylibsshext.__libssh_version__,
    m.version("paramiko"), m.version("port49")))
d = os.path.dirname(port49.__file__)
for n in sorted(os.listdir(d)):
    if n.endswith(".py"):
        print(n, hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest())
`

// l66Preflight checks everything a run needs and installs nothing: the venv's Python with the port49 library
// of this tree and ansible-pylibssh, the collections in their private directory, libnss_wrapper, docker and the
// stand-in's image. It returns the versions line for the note and the collections directory. A missing piece
// is a Fatal that names the command that installs it. Every Ansible command runs with a private HOME, so none
// of them touches the operator's ~/.ansible.
func l66Preflight(t *testing.T) (versions, collDir string) {
	t.Helper()
	l66Once.Do(func() {
		l66CollDir = filepath.Join(root, "tests", "lab", "l66", ".collections")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		pre, err := os.MkdirTemp("", "p49l66pre")
		if err != nil {
			l66Versions = "PREFLIGHT FAILED: " + err.Error()
			return
		}
		defer os.RemoveAll(pre)
		env := append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "HOME="+pre)
		fail := func(f string, a ...any) { l66Versions = "PREFLIGHT FAILED: " + fmt.Sprintf(f, a...) }
		for _, tool := range []string{"docker", "go", "ssh", "ssh-keygen"} {
			if _, err := exec.LookPath(tool); err != nil {
				fail("%s is not on PATH", tool)
				return
			}
		}
		lib, found := l66FindNSSWrapper(l66NSSDirs)
		if !found {
			fail("libnss_wrapper.so is not under %s: libssh reads the home from the passwd entry, and this gives it the private one. "+
				"Install it with: sudo apt install libnss-wrapper", strings.Join(l66NSSDirs, ", "))
			return
		}
		l66NSSLib = lib
		// docker runs in the same environment startStandin uses, so both talk to the same daemon.
		if _, se, exit, err := l64Run(ctx, os.Environ(), root, "docker", "image", "inspect", l66StandinImage); err != nil || exit != 0 {
			fail("the stand-in's image %s is not local (%s): docker pull %s", l66StandinImage, trimForNote(se), l66StandinImage)
			return
		}
		// Python and every Ansible command run in the plays' kind of environment: the private HOME, and a
		// passwd entry that agrees with it, so nothing is created under the operator's ~/.ansible.
		u, uerr := user.Current()
		if uerr != nil {
			fail("%v", uerr)
			return
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		pw, gr := filepath.Join(pre, "nss_passwd"), filepath.Join(pre, "nss_group")
		if werr := errors.Join(os.WriteFile(pw, []byte(l66NSSPasswd(u.Username, uid, gid, pre, "/bin/sh")), 0o600),
			os.WriteFile(gr, []byte(l66NSSGroup(u.Username, gid)), 0o600)); werr != nil {
			fail("%v", werr)
			return
		}
		penv := l66PreflightEnv(os.Environ(), pre, lib)
		out, se, exit, err := l64Run(ctx, penv, root, venvPython, "-I", "-B", "-c", l66PyProbe)
		if err != nil || exit != 0 {
			fail("the lab venv cannot import port49 and pylibsshext (exit %d %v %s%s): pip install ansible-pylibssh ./clients/python "+
				"into %s", exit, err, trimForNote(out), trimForNote(se), filepath.Dir(l66Venv))
			return
		}
		var vline string
		installed := map[string]string{}
		for _, ln := range strings.Split(out, "\n") {
			if rest, ok := strings.CutPrefix(ln, "VERSIONS "); ok {
				vline = rest
			}
		}
		for n, s := range l66ParseSums(out) {
			installed[n] = s
		}
		tree, err := l66ClientSums(filepath.Join(root, "clients", "python", "src", "port49"))
		if err != nil {
			fail("reading clients/python: %v", err)
			return
		}
		if diff := l66DiffFileSums(tree, installed); len(diff) > 0 {
			fail("the lab venv's port49 library is not this tree's (%s): pip install --force-reinstall ./clients/python", strings.Join(diff, ", "))
			return
		}
		cenv := append(slices.Clone(penv), "ANSIBLE_COLLECTIONS_PATH="+filepath.Join(root, "clients", "ansible")+":"+l66CollDir,
			"ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false")
		gout, gerr, gexit, err := l64Run(ctx, cenv, root, filepath.Join(l66Venv, "ansible-galaxy"), "collection", "list", "--format", "json")
		if err != nil || gexit != 0 {
			fail("ansible-galaxy collection list: exit %d %v %s", gexit, err, trimForNote(gerr))
			return
		}
		have, err := l66ParseGalaxy(gout)
		if err != nil {
			fail("%v", err)
			return
		}
		if miss := l66Missing(have); len(miss) > 0 {
			fail("collections missing: %s. Install them with: %s", strings.Join(miss, ", "), l66InstallCommand(l66CollDir))
			return
		}
		var cols []string
		for _, n := range slices.Sorted(maps.Keys(have)) {
			if slices.Contains(l66Collections, n) {
				cols = append(cols, n+" "+have[n])
			}
		}
		pv, _, _, _ := l64Run(ctx, penv, root, filepath.Join(l66Venv, "ansible-playbook"), "--version")
		// OpenSSH prints its version on stderr.
		_, sv, _, _ := l64Run(ctx, env, root, "ssh", "-V")
		sha, _, _, _ := l64Run(ctx, env, root, "git", "-C", root, "rev-parse", "HEAD")
		l66Versions = fmt.Sprintf("%s; %s; collections: %s; %s; nss_wrapper %s; ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass; "+
			"tree commit %s", strings.TrimSpace(vline), strings.TrimSpace(strings.SplitN(pv, "\n", 2)[0]), strings.Join(cols, ", "),
			strings.TrimSpace(sv), lib, strings.TrimSpace(sha))
	})
	if strings.HasPrefix(l66Versions, "PREFLIGHT FAILED") {
		t.Fatalf("%s", l66Versions)
	}
	fmt.Fprintf(os.Stdout, "L66 versions: %s\n", l66Versions)
	return l66Versions, l66CollDir
}

// l66Env is one platform's run: a private home, the agent, the daemon, one capture, the cells' results. It
// reuses L64's environment (the private HOME, the agent, the counters) and adds Ansible's.
type l66Env struct {
	*l64Env

	work, collDir string
	versions      string
	idleNote      string

	results   []l66Result
	controlOK bool
	cellID    string
	// hashes are the SHA-256 of every token any window of the run minted or redeemed: what the run's output
	// is searched and scrubbed by.
	hashes map[string]bool

	// nssLib is libnss_wrapper.so: every ansible-playbook runs under it, with a passwd file whose entry for the
	// current uid has the private home (libssh takes its home from the passwd entry). realKH are the operator's
	// own files, checked around every play; fatal is set when one changed and ends the run.
	nssLib string
	realKH []l66Snap
	fatal  string
	// notRun is set by a cell that cannot run because of a client behaviour another cell measured.
	notRun string
	// deadline is the test's, for the cells' budgets.
	deadline    time.Time
	hasDeadline bool

	standin     bool
	standinKeys []string

	// What (c)'s first contact left, by ssh type, for its changed-key cell.
	cAfter map[string]string
	cAdded map[string][]l66KHLine
	// cNoFile[sshType] is set when the latest first-contact cell of that type measured a play that passed
	// and logged in without filing a key: the only measurement a later cell may be NOT RUN on.
	cNoFile map[string]bool
	// cfgRaised is the daemon config with token.candidate_cap raised (daemonCfg is the default cap's). The
	// token store is in memory, so a restart empties it; every cell starts on a restarted daemon.
	cfgRaised string
	// freshChecked is whether the cell's first mint has been read for candidate_cap_reached.
	freshChecked bool
}

func (e *l66Env) path(parts ...string) string {
	return filepath.Join(append([]string{e.work}, parts...)...)
}

// restart puts the daemon on an empty token store under the cap the cell runs under, so every cell starts
// with zero unspent tokens for its device and username. The store is in memory (the lab config has no
// store block), so a restart is a fresh store. The decision log is appended to, so window offsets hold.
func (e *l66Env) restart(cap int) error {
	cfg := e.daemonCfg
	if cap > 0 {
		cfg = e.cfgRaised
	}
	if err := e.l.stopDaemon(); err != nil {
		return err
	}
	if err := e.l.startDaemonWith(cfg, true); err != nil {
		return err
	}
	return e.l.awaitTACACS()
}

func (e *l66Env) addInvalid(msg string) {
	if e.invalid != "" {
		e.invalid += "; "
	}
	e.invalid += msg
}

// l66Opts is how one ansible-playbook run differs from another.
type l66Opts struct {
	pb, inv string
	verbose string // -vvv, -vvvv
	forks   int
	// hostKeys sets host_key_checking and host_key_auto_add to true; otherwise host_key_checking is false and
	// the connection plugin reads and writes no known_hosts file.
	hostKeys bool
	// idle is persistent_connect_timeout in seconds; 0 is l66ShortIdle.
	idle       int
	logPath    string
	persistLog bool
}

func (e *l66Env) ansibleEnv(o l66Opts) []string {
	idle := o.idle
	if idle == 0 {
		idle = l66ShortIdle
	}
	checking, auto := "False", "False"
	if o.hostKeys {
		checking, auto = "True", "True"
	}
	env := l66PrivateEnv(e.env(), e.home, e.nssLib, e.path("nss_passwd"), e.path("nss_group"))
	env = append(env,
		"PATH="+l66Venv+":"+filepath.Join(root, "bin")+":"+os.Getenv("PATH"),
		"ANSIBLE_CONFIG="+e.path("ansible.cfg"),
		"ANSIBLE_COLLECTIONS_PATH="+filepath.Join(root, "clients", "ansible")+":"+e.collDir,
		"ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false",
		"ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0",
		"ANSIBLE_HOST_KEY_CHECKING="+checking,
		"ANSIBLE_HOST_KEY_AUTO_ADD="+auto,
		"ANSIBLE_LIBSSH_HOST_KEY_AUTO_ADD="+auto,
		"ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD="+auto,
		"ANSIBLE_LIBSSH_LOOK_FOR_KEYS=False", "ANSIBLE_PARAMIKO_LOOK_FOR_KEYS=False",
		"ANSIBLE_PERSISTENT_CONNECT_TIMEOUT="+strconv.Itoa(idle),
		"ANSIBLE_SSH_CONTROL_PATH_DIR="+e.path("cp"),
		// ansible.builtin.ssh logs in with a password through SSH_ASKPASS; sshpass is not used.
		"ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass",
	)
	if o.logPath != "" {
		env = append(env, "ANSIBLE_LOG_PATH="+o.logPath)
	}
	if o.persistLog {
		env = append(env, "ANSIBLE_PERSISTENT_LOG_MESSAGES=True")
	}
	return env
}

// waitPersistentGone waits for the persistent connections of the private home to end, so that the next
// window starts quiet and a lingering session's accounting is not counted in it. It returns what it found if
// one is still open after 90s.
func (e *l66Env) waitPersistentGone(ctx context.Context) string {
	dir := filepath.Join(e.home, ".ansible", "pc")
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if ents, _ := os.ReadDir(dir); len(ents) == 0 {
			return ""
		}
		time.Sleep(time.Second)
	}
	return "a persistent connection was still open 90s after the play ended, so its teardown may fall in a later window"
}

// closeMasters ends every ControlPersist master the plain ssh connection left in the private control path
// directory. Exact sockets, by path; nothing is matched by name.
func (e *l66Env) closeMasters() {
	ents, _ := os.ReadDir(e.path("cp"))
	for _, en := range ents {
		sock := e.path("cp", en.Name())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _, _, _ = l64Run(ctx, e.env(), e.home, "ssh", "-F", "/dev/null", "-O", "exit", "-S", sock, "l66")
		cancel()
		_ = os.Remove(sock)
	}
}

// snapReal takes the snapshot of the operator's own known_hosts that a run is checked against. Under
// nss_wrapper no client should reach it; this is the check that says so if one does.
//
// A guard that cannot be set ends the run: a play must not start unwatched.
func (e *l66Env) snapReal() error {
	e.realKH = nil
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("the operator's home cannot be found, so the guard on their known_hosts cannot be set: %w", err)
	}
	for _, name := range []string{"known_hosts"} {
		s, err := l66Snapshot(filepath.Join(u.HomeDir, ".ssh", name))
		if err != nil {
			return fmt.Errorf("the operator's %s cannot be read, so the guard on it cannot be set: %w", name, err)
		}
		e.realKH = append(e.realKH, s)
	}
	return nil
}

// realChanged says whether a run wrote the operator's own known_hosts, and what it added. The file is left
// as the client wrote it. A change ends the run on the spot (see cell): the private passwd home did not hold.
func (e *l66Env) realChanged() string {
	var msgs []string
	for _, s := range e.realKH {
		ch, err := s.Changed()
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s could not be re-read: %v", s.Path, err))
			continue
		}
		if !ch {
			continue
		}
		d, _ := s.Diff()
		var added []string
		for _, l := range d.Added {
			added = append(added, l.Short())
		}
		msgs = append(msgs, fmt.Sprintf("the operator's own %s was written during the run (%s; added: %s), so the private passwd "+
			"home did not hold. The file has not been touched by the harness: remove those lines by hand", s.Path,
			d.Mode, strings.Join(added, " | ")))
	}
	return strings.Join(msgs, "; ")
}

// l66Run is one ansible-playbook run and its window.
type l66Run struct {
	stdout, stderr string
	exit           int
	err            error
	recap          map[string]l66Recap
	recs           []map[string]any
	counts         l66Counts
	hashes         map[string]bool
	packets        int
	starts         int
}

func (r l66Run) text() string { return r.stdout + "\n" + r.stderr }

// good is a run whose host passed and whose window shows a login that reached port49d.
func (r l66Run) good(host string) bool {
	return r.err == nil && r.recap[host].Passed() && l64ControlOK(r.packets, r.counts.Redeems)
}

func (r l66Run) summary(host string) string {
	s := fmt.Sprintf("ansible-playbook exit %d, `%s` recap %+v; %s; %d TACACS+ packets and %d TACACS+ authentication starts in "+
		"the window; records other than mint, blob and redeem: %v", r.exit, host, r.recap[host], r.counts, r.packets, r.starts, r.counts.Other)
	if t := l66ErrorText(r.text(), 500); t != "" {
		s += "; the error: `" + t + "`"
	}
	for i, ln := range l66ErrorLines(r.text()) {
		if i == 3 {
			break
		}
		if len(ln) > 300 {
			ln = ln[:300] + "..."
		}
		s += "; ansible: `" + ln + "`"
	}
	for i, w := range l66WarningLines(r.text()) {
		if i == 3 {
			break
		}
		s += "; warning: `" + w + "`"
	}
	if r.err != nil {
		s += fmt.Sprintf("; **the run ended abnormally: %v**", r.err)
	}
	return s
}

// runPlay renders a play and an inventory, runs ansible-playbook on them in the private home, and reads the
// window: the decision log, the capture, the PLAY RECAP.
func (e *l66Env) runPlay(ctx context.Context, name, kind string, n int, between string, s l66InvSpec, o l66Opts) (l66Run, error) {
	var r l66Run
	// Once the operator's own known_hosts was found written (or its guard could not be set), no further play
	// starts, in this cell or after it.
	if e.fatal != "" {
		return r, errors.New(e.fatal)
	}
	o.pb, o.inv = e.path("play", name+".yml"), e.path("inv", name+".yml")
	if err := os.WriteFile(o.pb, []byte(l66Playbook(kind, s.Platform, n, between)), 0o600); err != nil {
		return r, err
	}
	if err := os.WriteFile(o.inv, []byte(l66Inventory(s)), 0o600); err != nil {
		return r, err
	}
	fmt.Fprintln(os.Stdout, l66Stage(e.l.p.name, e.cellID, "ansible-playbook "+name))
	if err := e.snapReal(); err != nil {
		e.fatal = err.Error()
		return r, err
	}
	args := []string{"-i", o.inv}
	if o.verbose != "" {
		args = append(args, o.verbose)
	}
	if o.forks > 0 {
		args = append(args, "--forks", strconv.Itoa(o.forks))
	}
	args = append(args, o.pb)
	off, from := e.l.mark(), time.Now()
	pctx, cancel := context.WithTimeout(ctx, l66PlayBudget)
	r.stdout, r.stderr, r.exit, r.err = l64Run(pctx, e.ansibleEnv(o), e.work, filepath.Join(l66Venv, "ansible-playbook"), args...)
	cancel()
	if left := e.waitPersistentGone(ctx); left != "" {
		e.addInvalid(left)
	}
	e.closeMasters()
	r.recs = e.l.drainRecords(off, 6*time.Second)
	to := time.Now()
	r.packets = e.tacacsIn(from, to)
	if segs, err := l66LoadSegs(e.l.capAbs, e.l.p.addr); err != nil {
		e.unread, r.starts = true, -1
	} else {
		r.starts = l66AuthStarts(segs, from, to)
	}
	r.recap = l66ReadRecap(r.stdout)
	r.counts = l66CountRecords(r.recs)
	if !e.freshChecked && r.counts.Mints > 0 {
		e.freshChecked = true
		if l66MintRefusedByCap(r.recs) {
			e.addInvalid("the cell's first mint was refused with candidate_cap_reached after a restart, so the token store was not fresh")
		}
	}
	r.hashes = l66TokenHashes(r.recs)
	maps.Copy(e.hashes, r.hashes)
	if msg := e.realChanged(); msg != "" {
		e.fatal = msg
		return r, errors.New(msg)
	}
	return r, nil
}

// spec is the inventory of the one node, over network_cli with the given ssh type.
func (e *l66Env) spec(mode, sshType string) l66InvSpec {
	return l66InvSpec{Hosts: []l66Host{{e.node, e.l.p.addr}}, Socket: e.sock, Bin: filepath.Join(root, "bin", "port49"),
		Platform: l66Platforms[e.l.p.name], Conn: "network_cli", SSHType: sshType, Mode: mode}
}

// libsshAliasConf writes an ssh_config that sets a HostKeyAlias of the node's name and names it to libssh
// with `ansible_libssh_config_file`. pylibssh 1.4.0 passes no config file to libssh, so the expected answer is
// that the alias is never honoured; the L66e-libssh-alias cell measures it. It returns the path.
func (e *l66Env) libsshAliasConf() string {
	p := e.path("libssh_alias.conf")
	_ = os.WriteFile(p, []byte("Host *\n  HostKeyAlias "+e.node+"\n"), 0o600)
	return p
}

// sshSpec is the inventory for ansible.builtin.ssh: the private ssh_config, and the extra args the collection's
// README recommends. Each host's ssh writes its own debug log (-E, DEBUG3): ansible-core passes -v to ssh only
// from its own `verbosity` option, and tags what it prints with the address, so the host's lines are read
// from its file.
func (e *l66Env) sshSpec(hosts []l66Host, p49 string) l66InvSpec {
	cfg := e.path("ssh_config")
	_ = os.WriteFile(cfg, []byte("Host *\n  UserKnownHostsFile "+e.khPath+"\n  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys yes\n"), 0o600)
	return l66InvSpec{Hosts: hosts, P49Name: p49, Socket: e.sock, Bin: filepath.Join(root, "bin", "port49"),
		Platform: l66Platforms[e.l.p.name], Conn: "ssh", Mode: "fact", SSHCommonArgs: "-F " + cfg,
		SSHExtraArgs: "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new -o LogLevel=DEBUG3 -E " +
			e.path("ssh-{{ inventory_hostname }}.log")}
}

// sshLog is what the host's ssh wrote to its -E file; clearSSHLogs empties them before a play.
func (e *l66Env) sshLog(host string) string {
	b, _ := os.ReadFile(e.path("ssh-" + host + ".log"))
	return string(b)
}

func (e *l66Env) clearSSHLogs() {
	logs, _ := filepath.Glob(e.path("ssh-*.log"))
	for _, p := range logs {
		_ = os.Remove(p)
	}
}

// cell runs fn under its own budget and records its row. fn returns whether the cell's claim held (or, for a
// record cell, whether it could observe) and what it observed; it never calls t. A cell that has not returned
// a minute after its budget ends the platform's run. It is not l64Env.cell because the outcomes differ: kinds,
// NOT RUN, INCOMPLETE and a fatal that ends the run.
//
// A `go test` timeout panics without running a defer or a Cleanup (the stand-in container, the agent, port49d
// on L66's config would stay), so a cell does not start when the test's deadline would cut it, and its budget
// is capped to leave l66Reserve for the teardown; a skipped cell makes the run INCOMPLETE and writes no note.
func (e *l66Env) cell(id, kind string, budget time.Duration, fn func(ctx context.Context) (bool, string)) bool {
	start := time.Now()
	e.cellID = id
	tooNear := func() bool {
		obs := fmt.Sprintf("**Not started: the test's deadline is too near** (less than %s would remain for it after %s kept for "+
			"the teardown).", l66MinCell, l66Reserve)
		e.results = append(e.results, l66Result{id, "INCOMPLETE (deadline)", obs, 0})
		fmt.Fprintln(os.Stdout, l66Progress(e.l.p.name, id, "INCOMPLETE", 0))
		return false
	}
	// Every cell starts on a restarted daemon, so its (device, username) has no unspent token left by an
	// earlier cell; 16 cells per platform restart (a, b, b2 x2, d, d2, c x5, e x4 and e2). The restart comes
	// before the budget is computed, so its time comes out of the cell's share of the deadline, never out of
	// l66Reserve; it starts only when its worst case and the least budget fit.
	if _, ok := l66CellBudget(budget, e.deadline, e.hasDeadline, start, l66Reserve+l66RestartMax, l66MinCell); !ok {
		return tooNear()
	}
	cap := l66CellCap(id)
	if err := e.restart(cap); err != nil {
		e.t.Fatalf("%s: could not restart port49d on an empty token store, so nothing from here is a measurement: %v", id, err)
	}
	b, ok := l66CellBudget(budget, e.deadline, e.hasDeadline, time.Now(), l66Reserve, l66MinCell)
	if !ok {
		return tooNear()
	}
	budget = b
	fmt.Fprintln(os.Stdout, l66Start(e.l.p.name, id, budget))
	e.unread, e.invalid, e.controlOK, e.notRun = false, "", false, ""
	e.freshChecked = false
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	type done struct {
		ok  bool
		obs string
	}
	ch := make(chan done, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- done{false, fmt.Sprintf("the cell panicked: %v", p)}
			}
		}()
		ok, obs := fn(ctx)
		ch <- done{ok, obs}
	}()
	var d done
	select {
	case d = <-ch:
	case <-time.After(budget + l66Grace):
		fmt.Fprintln(os.Stdout, l66Progress(e.l.p.name, id, "STUCK", time.Since(start)))
		e.t.Fatalf("cell %s did not return %s after its %s budget; the platform's run ends here", id, l66Grace, budget)
	}
	outcome := l66Outcome(kind, d.ok, ctx.Err() != nil, e.controlOK, e.unread)
	// An invalid or a fatal set in the cell outranks NOT RUN (l66Settle): a cell that could not measure must
	// not read as one that was blocked.
	outcome = l66Settle(outcome, e.fatal, e.invalid, e.notRun)
	switch {
	case outcome == "TIMEOUT":
		d.obs = "**The cell's budget ran out.** " + d.obs
	case e.fatal != "":
		d.obs = "**INVALID: " + e.fatal + ".** " + d.obs
	case e.invalid != "":
		d.obs = "**INVALID: " + e.invalid + ".** " + d.obs
	case e.notRun != "":
		d.obs = "**Not run: " + e.notRun + ".** " + d.obs
	case outcome == "INVALID":
		d.obs = "**INVALID: " + l66WhyInvalid(kind, d.ok, e.controlOK, e.unread) + ".** " + d.obs
	}
	d.obs += " " + l66CapNote(cap)
	d.obs = l66Scrub(d.obs, e.hashes, labcreds.TokenLen)
	elapsed := time.Since(start)
	e.results = append(e.results, l66Result{id, outcome, d.obs, elapsed})
	fmt.Fprintln(os.Stdout, l66Progress(e.l.p.name, id, outcome, elapsed))
	e.t.Logf("%s: %s", id, d.obs)
	if e.fatal != "" {
		e.t.Fatalf("%s: %s", id, e.fatal)
	}
	return outcome == "PASS" || outcome == "OBSERVED"
}

// control is the positive control: one good login through the lookup, whose window must hold TACACS+ packets
// and a redeem. It runs at the head of every refusal cell, so that the zero that follows is the zero of a
// counter that counts.
func (e *l66Env) control(ctx context.Context) (l66Run, string) {
	r, err := e.runPlay(ctx, "control", "once", 1, "", e.spec("fact", "libssh"), l66Opts{})
	if err != nil {
		e.addInvalid("the control play could not be written: " + err.Error())
		return r, ""
	}
	e.controlOK = r.good(e.node)
	return r, fmt.Sprintf("The positive control, a good login through the lookup just before: %s (control %v).", r.summary(e.node), e.controlOK)
}

// baseline writes the known_hosts file a cell starts from and returns it: a comment line alone, or, when
// markers is true, with an @revoked and an @cert-authority line (L66c1). Paramiko 5.0 cannot read the second
// kind (c1 records that), and (e) is about an address that moved, so those cells start from the comment.
func (e *l66Env) baseline(ctx context.Context, markers bool) (string, error) {
	kh := l66CommentKH()
	if markers {
		a, err := e.freshKey(ctx, "ssh-ed25519")
		if err != nil {
			return "", err
		}
		b, err := e.freshKey(ctx, "ssh-ed25519")
		if err != nil {
			return "", err
		}
		kh = l66BaselineKH(a, b)
	}
	return kh, os.WriteFile(e.khPath, []byte(kh), 0o600)
}

func l66Shorts(ls []l66KHLine) string {
	if len(ls) == 0 {
		return "none"
	}
	var s []string
	for _, l := range ls {
		s = append(s, "`"+l.Short()+"`")
	}
	return strings.Join(s, ", ")
}

// l66Verbatim is a known_hosts file for a note: comments as they are, key lines with their keys shortened.
func l66Verbatim(content string) string {
	var out []string
	for _, ln := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if l, ok := l66ParseKHLine(ln); ok {
			out = append(out, l.Short())
		} else {
			out = append(out, ln)
		}
	}
	return "```\n" + strings.Join(out, "\n") + "\n```"
}

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

func (e *l66Env) cellA() {
	e.cell("L66a", "claim", l66Budget, func(ctx context.Context) (bool, string) {
		s := e.spec("lookup", "libssh")
		r, err := e.runPlay(ctx, "a", "ten", 10, "", s, l66Opts{idle: l66DefaultIdle})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		// Under the default cap the play may fail at a task, and that is the measurement: the first task's
		// good login is the control (l66GradeCap), not the whole play passing.
		outcome, _, reading := l66GradeCap(l66CapIn{Recap: r.recap[e.node], Counts: r.counts, Starts: r.starts,
			FirstMintRefused: l66MintRefusedByCap(r.recs), ConnLookups: l66ConnLookups(l66Inventory(s))})
		e.controlOK = outcome == "PASS"
		if outcome != "PASS" {
			e.addInvalid(reading)
		}
		return outcome == "PASS", fmt.Sprintf("A ten-task play (each task a `%s` of `show version`) with "+
			"`ansible_password: \"{{ lookup('port49.client.token', ...) }}\"` and `ansible_user` from a second lookup with "+
			"`field='username'`. **%s** %s.", l66Platforms[e.l.p.name].Module, reading, r.summary(e.node))
	})
}

func (e *l66Env) cellB() {
	e.cell("L66b", "record", l66Budget, func(ctx context.Context) (bool, string) {
		r, err := e.runPlay(ctx, "b", "once", 10, "", e.spec("fact", "libssh"), l66Opts{idle: l66DefaultIdle})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r.good(e.node)
		return r.recap[e.node].Passed(), fmt.Sprintf("The same play minting once in `pre_tasks` (`set_fact`, `field='all'`, `no_log`): "+
			"**%d mint records, %d redeem records, %d TACACS+ authentication starts** in the capture for ten tasks on one host. %s. This "+
			"run is a good login, so its window is its own positive control: %v.", r.counts.Mints, r.counts.Redeems, r.starts,
			r.summary(e.node), e.controlOK)
	})
}

// cellGap is (b2): the minted-once play, then something that ends the persistent connection between two
// tasks. Whether the next task logs in again with the spent token, and how that fails, are recorded.
func (e *l66Env) cellGap(id, what, between string) {
	e.cell(id, "record", l66Budget, func(ctx context.Context) (bool, string) {
		s := e.spec("fact", "libssh")
		s.ConnectTimeout = l66ShortIdle
		r, err := e.runPlay(ctx, id, "gap", 2, between, s, l66Opts{idle: l66ShortIdle})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r.packets > 0 && r.counts.Redeems > 0
		again := l66GradeGap(r.starts, r.counts.Redeems)
		// ok: the first login worked, so the gap had a connection to end (mint + the first task passed).
		return r.recap[e.node].OK >= 2, fmt.Sprintf("The minted-once play with %s (persistent_connect_timeout %ds in the inventory "+
			"and the environment). **The next task logged in again: %v** (%d TACACS+ authentication starts, %d redeem records with "+
			"reasons %v, for %d mint records). %s.", what, l66ShortIdle, again, r.starts, r.counts.Redeems, r.counts.RedeemReasons,
			r.counts.Mints, r.summary(e.node))
	})
}

// cellD is (d): a denied device, the error text, and no token in -vvv output.
func (e *l66Env) cellD() {
	e.cell("L66d", "refusal", l66Budget, func(ctx context.Context) (bool, string) {
		_, ctlNote := e.control(ctx)
		quiet := e.waitQuiet(ctx) // the control's late accounting must not fall in the denied window
		denied := l66DeniedNode(e.node)
		ds := e.spec("fact", "libssh")
		ds.Hosts = []l66Host{{denied, e.l.p.addr}}
		dr, err := e.runPlay(ctx, "d-denied", "once", 1, "", ds, l66Opts{verbose: "-vvv"})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		quiet += " " + e.waitQuiet(ctx)
		gr, err := e.runPlay(ctx, "d-good", "once", l66LogTasks, "", e.spec("fact", "libssh"), l66Opts{verbose: "-vvv"})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		deniedHits := l66FindTokens(dr.text(), e.hashes, labcreds.TokenLen)
		goodHits := l66FindTokens(gr.text(), e.hashes, labcreds.TokenLen)
		if len(gr.hashes) == 0 {
			e.addInvalid("the good run's records name no minted token, so there is no hash to look for in its -vvv output")
		}
		pass, why := l66GradeDenied(l66DeniedIn{
			Failed: !dr.recap[denied].Passed() && dr.recap[denied].Failed > 0, Named: strings.Contains(dr.text(), "no_grants_matched"),
			GoodRunGood: gr.good(e.node), MintDenies: dr.counts.MintDenies, DeniedPackets: dr.packets, Other: dr.counts.Other,
			DeniedHits: deniedHits, GoodHits: goodHits})
		if why != "" {
			why = " **Not as claimed:** " + why + "."
		}
		return pass, fmt.Sprintf("%s\n\nA device with no grant (`%s`, which the policy grants nothing on), `-vvv`: "+
			"the output names `no_grants_matched`: %v; %s. The token was searched for in clear text, by hash: words of its output "+
			"that hash to a minted token's `credential_sha256`: %d (lines %v); the harness knows %d token hashes from this run.\n\nA "+
			"good login (`%s`), a %d-task play, `-vvv`, searched the same way: %d words hash to a minted token (lines %v); %d token "+
			"hashes in its own window.%s %s %s", ctlNote, denied, strings.Contains(dr.text(), "no_grants_matched"), dr.summary(denied),
			len(deniedHits), deniedHits, len(e.hashes), e.node, l66LogTasks, len(goodHits), goodHits, len(gr.hashes), why, quiet,
			gr.summary(e.node))
	})
}

// cellD2 is (d2): -vvvv and the persistent connection's log hold no token.
func (e *l66Env) cellD2() {
	e.cell("L66d2", "claim", l66Budget, func(ctx context.Context) (bool, string) {
		logPath := e.path("ansible-d2.log")
		_ = os.Remove(logPath)
		r, err := e.runPlay(ctx, "d2", "once", l66LogTasks, "", e.spec("fact", "libssh"),
			l66Opts{verbose: "-vvvv", logPath: logPath, persistLog: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		logBytes, lerr := os.ReadFile(logPath)
		if lerr != nil {
			e.addInvalid(fmt.Sprintf("the persistent connection's log (%s) is unreadable: %v", logPath, lerr))
		}
		if len(r.hashes) == 0 {
			e.addInvalid("the run's records name no minted token, so there is no hash to look for")
		}
		outHits := l66FindTokens(r.stdout, e.hashes, labcreds.TokenLen)
		errHits := l66FindTokens(r.stderr, e.hashes, labcreds.TokenLen)
		logHits := l66FindTokens(string(logBytes), e.hashes, labcreds.TokenLen)
		e.controlOK = r.good(e.node)
		requests, setOptions := l66JSONRPC(string(logBytes))
		pass, invalid, why := l66GradeLogSearch(l66LogSearchIn{RunGood: r.good(e.node), Log: string(logBytes),
			OutHits: outHits, ErrHits: errHits, LogHits: logHits})
		if invalid != "" {
			e.addInvalid(invalid)
		}
		if why != "" {
			why = " **Not as claimed:** " + why + ". Never enable `persistent_log_messages` with the lookup."
		}
		return pass, fmt.Sprintf("A good login, a %d-task play, with `-vvvv`, `ANSIBLE_PERSISTENT_LOG_MESSAGES=True` and "+
			"`ANSIBLE_LOG_PATH` a private file (%d bytes, %d lines, holding %d `jsonrpc request:` lines, one of them a set_options: "+
			"%v; the persistent socket carries the connection's options, password included, to the process on every task after "+
			"the first, so a log that holds those lines is one a token could be in). The token was searched for in clear text: each "+
			"word of stdout (%d lines), stderr (%d lines) and the log was hashed and compared with the %d token hashes the decision "+
			"log names (`credential_sha256` and the mint's `token_sha256`). Words that match: stdout %d (lines %v), stderr %d "+
			"(lines %v), log %d (lines %v).%s %s", l66LogTasks, len(logBytes), strings.Count(string(logBytes), "\n"), requests,
			setOptions, strings.Count(r.stdout, "\n"), strings.Count(r.stderr, "\n"), len(e.hashes), len(outHits), outHits,
			len(errHits), errHits, len(logHits), logHits, why, r.summary(e.node))
	})
}

// cellC is (c) for one ssh type: a first contact from a file of a comment, an @revoked and an @cert-authority
// line, then that line's key replaced by a fresh key of its type. Paramiko 5.0 cannot read a file with those
// marker lines (InvalidHostKey, which its loader does not catch), so for it the first contact is a record of
// that refusal, and the claim is measured again from a file of a comment alone (c1b); the changed-key cell
// runs from whichever first contact filed a line.
func (e *l66Env) cellC(sshType string) {
	e.cellFirstContact("L66c1-"+sshType, sshType, true)
	if sshType == "paramiko" {
		e.cellFirstContact("L66c1b-"+sshType, sshType, false)
	}
	e.cellChanged("L66c2-"+sshType, sshType)
}

func (e *l66Env) cellFirstContact(id, sshType string, markers bool) {
	// Paramiko refusing the markers is a measured client behaviour, so that cell records it; every other
	// first contact claims the play passes and files a line.
	kind := "claim"
	if sshType == "paramiko" && markers {
		kind = "record"
	}
	e.cell(id, kind, l66Budget, func(ctx context.Context) (bool, string) {
		base, err := e.baseline(ctx, markers)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		delete(e.cAdded, sshType)
		r, err := e.runPlay(ctx, id, "once", 1, "", e.spec("fact", sshType), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		after := e.readKnownHosts()
		d := l66DiffKH(base, after)
		if len(d.Added) > 0 {
			e.cAfter[sshType], e.cAdded[sshType] = after, d.Added
		}
		e.cNoFile[sshType] = r.recap[e.node].Passed() && r.counts.Redeems > 0 && len(d.Added) == 0
		e.controlOK = r.good(e.node)
		if kind == "record" && !r.recap[e.node].Passed() && l66ParamikoRefusedMarkers(r.text()) {
			_, ctlNote := e.control(ctx)
			return true, fmt.Sprintf("%s\n\n**Paramiko refused to read the known_hosts file it was given** (`InvalidHostKey`): it holds an "+
				"`@revoked` line and an `@cert-authority` line for unrelated patterns, which paramiko's loader takes for a key line of the type "+
				"`unrelated.l66.invalid`. The play failed before any TACACS+ traffic (%d packets in its window). %s\n\nThe file, keys "+
				"shortened:\n\n%s", ctlNote, r.packets, r.summary(e.node), l66Verbatim(after))
		}
		where := "the private known_hosts (`~/.ssh/known_hosts` of the run's home)"
		if sshType == "libssh" {
			where += ", which libssh reads because the harness gives the user that home in the passwd entry (nss_wrapper); libssh " +
				"takes its home from there, not from $HOME"
		}
		what := "a comment line, an `@revoked` line and an `@cert-authority` line for unrelated patterns"
		if !markers {
			what = "a comment line alone"
		}
		rewrote := ""
		if d.Mode == "rewritten" {
			rewrote = " **The file was rewritten**"
			if len(d.LostComments)+len(d.LostMarkers) > 0 {
				rewrote += fmt.Sprintf(" **without %d comment line(s) and %d marker line(s) it held**", len(d.LostComments), len(d.LostMarkers))
			}
			rewrote += "."
		}
		return r.recap[e.node].Passed() && len(d.Added) > 0, fmt.Sprintf("`ansible_network_cli_ssh_type: %s`, `ANSIBLE_HOST_KEY_CHECKING=True`, "+
			"`ANSIBLE_HOST_KEY_AUTO_ADD=True`, from a known_hosts holding %s. The play passed: %v. The file changed in: %s. Mode: **%s**.%s "+
			"Lines added: %s; lines gone: %s; comment lines lost: %q; marker lines lost: %q. %s\n\nBefore (keys shortened to their first "+
			"16 characters):\n\n%s\n\nAfter:\n\n%s", sshType, what, r.recap[e.node].Passed(), where, d.Mode, rewrote, l66Shorts(d.Added),
			l66Shorts(d.Removed), d.LostComments, d.LostMarkers, r.summary(e.node), l66Verbatim(base), l66Verbatim(after))
	})
}

// cellChanged is (c)'s second half: the key the first contact filed is replaced by a fresh key of its type,
// and the play must end at the key exchange with the client's own words and not a TACACS+ packet.
func (e *l66Env) cellChanged(id2, sshType string) {
	e.cell(id2, "refusal", l66Budget, func(ctx context.Context) (bool, string) {
		added := e.cAdded[sshType]
		if len(added) == 0 {
			// NOT RUN only if the first-contact cell of this run measured the client passing without filing a
			// key; any other reason (the play failed, no login) means nothing was measured.
			verdict, why := l66GradeStepOne(l66StepOneIn{Passed: true, LoggedIn: true, MeasuredNoFile: e.cNoFile[sshType]})
			if verdict == "not run" {
				e.notRun = "the first-contact cell of " + sshType + " measured a login that filed no key line, so there is none to replace"
			} else {
				e.addInvalid("the first-contact cell of " + sshType + " filed no key line and did not measure that as a passing login (" + why + ")")
			}
			return false, ""
		}
		_, ctlNote := e.control(ctx)
		content := e.cAfter[sshType]
		var replaced []string
		for _, l := range added {
			blob, err := e.freshKey(ctx, l.Type)
			if err != nil {
				e.addInvalid(err.Error())
				return false, ctlNote
			}
			var ok bool
			if content, ok = l66ReplaceBlob(content, l, blob); !ok {
				e.addInvalid("the line to replace is not in the file")
				return false, ctlNote
			}
			replaced = append(replaced, l.Short())
		}
		if err := os.WriteFile(e.khPath, []byte(content), 0o600); err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		quiet := e.waitQuiet(ctx)
		r, err := e.runPlay(ctx, id2, "once", 1, "", e.spec("fact", sshType), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		d := l66DiffKH(content, e.readKnownHosts())
		refused := !r.recap[e.node].Passed()
		pass, why := l66GradeChanged(l66ChangedIn{SSHType: sshType, Failed: refused, Packets: r.packets, Redeems: r.counts.Redeems,
			Other: r.counts.Other, ErrText: l66ErrorText(r.text(), 2000)})
		if why != "" {
			why = " **Not as claimed:** " + why + "."
		}
		if !refused {
			// A client that logs in after its filed key was replaced is a result, not a broken run: it is graded
			// FAIL with this evidence. A redeem record carries auth.credential_sha256 and names the token the
			// device presented; the decision log is what says it was presented.
			why += fmt.Sprintf(" **%s accepted the changed key and logged in.** The token was presented to the device: %v (%d redeem "+
				"records in the window, each with the `credential_sha256` of a token this run minted; %d such hashes known).",
				sshType, r.counts.Redeems > 0, r.counts.Redeems, len(r.hashes))
		}
		return pass, fmt.Sprintf("%s\n\n`%s`: the key of each line the first contact filed (%s) replaced by a fresh key of its type, the "+
			"other lines left. %s. The play was refused (did not pass): %v; **%d TACACS+ packets**, **%d TACACS+ "+
			"authentication starts**, records other than mint and blob: %v (the token was never presented if there are none).%s The file "+
			"after the refused run: %s, added %s, gone %s. %s", ctlNote, sshType, strings.Join(replaced, ", "), quiet, refused, r.packets,
			r.starts, r.counts.Other, why, d.Mode, l66Shorts(d.Added), l66Shorts(d.Removed), r.summary(e.node))
	})
}

// l66ECase is one path (e) is measured on.
type l66ECase struct {
	id, desc, sshType string
	alias, plain      bool
}

// cellE is (e): after a run that filed the device's key, the inventory's address is changed to the stand-in.
func (e *l66Env) cellE(c l66ECase) {
	e.cell(c.id, "record", l66Budget, func(ctx context.Context) (bool, string) {
		base, err := e.baseline(ctx, false)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		kind := "once"
		mk := func(addr string) l66InvSpec {
			if c.plain {
				return e.sshSpec([]l66Host{{e.node, addr}}, "")
			}
			s := e.spec("fact", c.sshType)
			s.Hosts[0].Address = addr
			if c.alias {
				s.LibsshConfig = e.libsshAliasConf()
			}
			return s
		}
		if c.plain {
			kind = "raw"
		}
		e.clearSSHLogs()
		r1, err := e.runPlay(ctx, c.id+"-device", kind, 1, "", mk(e.l.p.addr), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = l64ControlOK(r1.packets, r1.counts.Redeems)
		kh1 := e.readKnownHosts()
		d1 := l66DiffKH(base, kh1)
		if c.plain {
			if why := l66GradeNames(map[string]string{e.node: e.sshLog(e.node)}); why != "" {
				e.addInvalid("step 1: " + why)
			}
		}
		// The premise of the move is an earlier login that filed the device's key. A client that logs in and
		// files none, which the first-contact cell of this run measured, leaves nothing to compare (NOT RUN);
		// any other failure measured nothing (INVALID).
		sshType := c.sshType
		if c.plain {
			sshType = "ssh"
		}
		verdict, why := l66GradeStepOne(l66StepOneIn{Passed: r1.recap[e.node].Passed(), LoggedIn: r1.counts.Redeems > 0,
			Filed: len(d1.Added), MeasuredNoFile: e.cNoFile[sshType]})
		switch verdict {
		case "not run":
			e.notRun = "step 1, at the device's address, logged in and filed no key, as " + sshType + "'s first-contact cell measured, so there is no earlier contact to move away from"
			return false, fmt.Sprintf("Step 1, at the device's address: %s. Lines added: %s.", r1.summary(e.node), l66Shorts(d1.Added))
		case "invalid":
			e.addInvalid("step 1: " + why)
			return false, fmt.Sprintf("Step 1, at the device's address: %s. Lines added: %s.", r1.summary(e.node), l66Shorts(d1.Added))
		}
		if err := e.startStandin(ctx); err != nil {
			e.addInvalid("the stand-in sshd could not be started: " + err.Error())
			return false, ""
		}
		mark := len(l66ParseStandin(e.standinLog(ctx)))
		quiet := e.waitQuiet(ctx)
		e.clearSSHLogs()
		r2, err := e.runPlay(ctx, c.id+"-standin", kind, 1, "", mk(l66StandinAddr), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		d2 := l66DiffKH(kh1, e.readKnownHosts())
		tally := l66TallyStandin(l66ParseStandin(e.standinLog(ctx))[mark:])
		invalid, presented := l66GradeMoved(tally, e.hashes, r2.hashes)
		if invalid != "" {
			e.addInvalid(invalid)
		}
		extra := ""
		if c.alias {
			honoured := slices.ContainsFunc(d1.Added, func(l l66KHLine) bool { return l.Hosts == e.node })
			extra = fmt.Sprintf(" **`ansible_libssh_config_file` naming `HostKeyAlias %s` was honoured (step 1 filed the key under that "+
				"name): %v.**", e.node, honoured)
		}
		if c.plain {
			if why := l66GradeNames(map[string]string{e.node: e.sshLog(e.node)}); why != "" {
				e.addInvalid("step 2: " + why)
			}
			a := l66ReadAlias(e.sshLog(e.node), e.node)
			extra = fmt.Sprintf(" Step 2's own ssh log: a connection of its own %v, looked the alias up %v, filed a key under it %v.%s",
				a.Connected, a.AliasUsed, a.Filed, l66AliasQuote(a.Lines))
		}
		return true, fmt.Sprintf("**%s.**%s Step 1, at the device's address `%s`: %s. File after step 1: mode %s, added %s.\n\n"+
			"Step 2, `ansible_host` changed to the stand-in (`%s`, a throwaway sshd container on the lab bridge with its own host keys %s; "+
			"it refuses every login and logs a password's length and hash only). %s. **The stand-in's key was auto-added: %v** (mode %s, "+
			"added %s, gone %s). The stand-in saw %d connection(s), %d password attempt(s) and %d keyboard-interactive answer(s); "+
			"**the minted token was presented to it: %v** (an attempt's hash is one of the token hashes the run's mint and redeem records "+
			"name).", c.desc, extra, e.l.p.addr, r1.summary(e.node), d1.Mode, l66Shorts(d1.Added), l66StandinAddr,
			strings.Join(e.standinKeys, ", "), quiet+" "+r2.summary(e.node), len(d2.Added) > 0, d2.Mode, l66Shorts(d2.Added),
			l66Shorts(d2.Removed), tally.Connects, tally.Passwords, tally.Kbdint, presented)
	})
}

// cellE2 is (e2): two inventory names at one address, over ansible.builtin.ssh.
func (e *l66Env) cellE2() {
	e.cell("L66e2-names", "record", l66Budget, func(ctx context.Context) (bool, string) {
		if _, err := e.baseline(ctx, false); err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		hosts := []l66Host{{"l66a", e.l.p.addr}, {"l66b", e.l.p.addr}}
		s := e.sshSpec(hosts, e.node)
		e.clearSSHLogs()
		r, err := e.runPlay(ctx, "e2", "raw", 1, "", s, l66Opts{hostKeys: true, forks: 1})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r.packets > 0 && r.counts.Redeems > 0
		logs := map[string]string{}
		for _, h := range hosts {
			logs[h.Name] = e.sshLog(h.Name)
		}
		if why := l66GradeNames(logs); why != "" {
			e.addInvalid(why)
		}
		kh := e.readKnownHosts()
		d := l66DiffKH(l66CommentKH(), kh)
		var per []string
		for _, h := range hosts {
			a := l66ReadAlias(logs[h.Name], h.Name)
			per = append(per, fmt.Sprintf("`%s`: recap %+v; opened a connection of its own: %v; authenticated on it: %v; reused an open "+
				"master: %v; ssh looked its alias up in known_hosts: %v; ssh filed a key under its alias: %v%s", h.Name, r.recap[h.Name],
				a.Connected, a.Authenticated, a.Muxed, a.AliasUsed, a.Filed, l66AliasQuote(a.Lines)))
		}
		var names []string
		for _, l := range l66ParseKH(kh) {
			names = append(names, l.Hosts)
		}
		return r.recap[hosts[0].Name].Passed(), fmt.Sprintf("Two inventory names (`l66a`, `l66b`) at one address (%s), `ansible.builtin.ssh` with "+
			"`-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new -o LogLevel=DEBUG3 -E <a file per host>`, one "+
			"fork, from a known_hosts holding a comment only. Per host, from its own ssh log: %s. The known_hosts file after the run holds "+
			"key lines for: %v (filed by the run: %s). %s", e.l.p.addr, strings.Join(per, "; "), names, l66Shorts(d.Added),
			r.summary(hosts[0].Name))
	})
}

func l66AliasQuote(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > 6 {
		lines = lines[:6]
	}
	return ":\n\n```\n" + strings.Join(lines, "\n") + "\n```\n"
}

// ---------------------------------------------------------------------------
// The stand-in sshd
// ---------------------------------------------------------------------------

// startStandin builds cmd/standin, starts it in a throwaway container on the lab bridge, and removes the
// container when the test ends. It is started once per platform run.
func (e *l66Env) startStandin(ctx context.Context) error {
	if e.standin {
		return nil
	}
	bin := e.path("standin")
	benv := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if _, se, exit, err := l64Run(ctx, benv, root, "go", "build", "-o", bin, "./tests/lab/l66/standin"); err != nil || exit != 0 {
		return fmt.Errorf("building the stand-in: exit %d %v %s", exit, err, trimForNote(se))
	}
	rm := func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _, _, _ = l64Run(c, os.Environ(), root, "docker", "rm", "-f", l66StandinName)
	}
	rm() // a leftover of an aborted run of this harness, by its exact name
	e.t.Cleanup(rm)
	if _, se, exit, err := l64Run(ctx, os.Environ(), root, "docker", "run", "-d", "--name", l66StandinName, "--network", l66DockerNet,
		"--ip", l66StandinAddr, "-v", bin+":/standin:ro", l66StandinImage, "/standin", "-listen", ":22"); err != nil || exit != 0 {
		return fmt.Errorf("docker run: exit %d %v %s", exit, err, trimForNote(se))
	}
	e.standin = true
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		for _, ev := range l66ParseStandin(e.standinLog(ctx)) {
			if ev.Event == "ready" {
				e.standinKeys = ev.HostKeys
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("the stand-in did not log ready within 30s")
}

// standinLog is the stand-in's stdout so far.
func (e *l66Env) standinLog(ctx context.Context) string {
	out, _, _, _ := l64Run(ctx, os.Environ(), root, "docker", "logs", l66StandinName)
	return out
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

// TestL66 measures L66 (the Ansible lookup and the host keys of its connection plugins) on each selected
// platform. It touches nothing but the device, the stand-in container and a private home: the operator's own
// known_hosts is checked before and after every run.
func TestL66(t *testing.T) {
	if os.Getenv("PORT49_LAB_ANSIBLE") != "1" {
		t.Skip("L66 drives the lab devices through Ansible: run it with `make lab-ansible` (PORT49_LAB_ANSIBLE=1)")
	}
	if _, err := os.Stat(venvPython); err != nil {
		t.Skipf("no client venv at %s: %v", venvPython, err)
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		if _, ok := l66Platforms[l.p.name]; !ok {
			t.Fatalf("no Ansible collection is named for %s", l.p.name)
		}
		versions, collDir := l66Preflight(t)
		if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		polRel := filepath.Join("tests", "lab", "logs", "l66-policy-"+l.p.name+".yaml")
		if err := os.MkdirAll(filepath.Join(root, "tests", "lab", "logs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, polRel), []byte(l66Policy(l.p.node)), 0o600); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(brokerYAML), "tests/lab/slice/policy.yaml") {
			t.Fatal("slice/broker.yaml no longer names tests/lab/slice/policy.yaml, so L66's policy cannot be put in its place")
		}
		extra := strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml", polRel, 1)
		cfg, err := l.derivedConfig("l66", platformSessionAttributes[l.p.name], extra)
		if err != nil {
			t.Fatal(err)
		}
		// Two configs: port49's default cap for L66a, which measures it, and a raised cap for every other cell.
		raisedExtra, err := l66CapConfig(extra, l66CellCap("L66b"))
		if err != nil {
			t.Fatal(err)
		}
		cfgRaised, err := l.derivedConfig("l66cap", platformSessionAttributes[l.p.name], raisedExtra)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		// The restore is registered before the restart it undoes, so a restart that fails still puts the lab
		// config back.
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the broker daemon: %v", err)
				return
			}
			std, err := l.configPath()
			if err != nil {
				t.Fatalf("derive this platform's daemon config: %v", err)
			}
			if err := l.startDaemonWith(std, true); err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker block, so nothing was measured: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}

		work, err := os.MkdirTemp("", "p49l66")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(work)
		home := filepath.Join(work, "home")
		sshDir, keyDir := filepath.Join(home, ".ssh"), filepath.Join(work, "keys")
		for _, d := range []string{home, sshDir, keyDir, filepath.Join(work, "play"), filepath.Join(work, "inv"), filepath.Join(work, "cp")} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		e := &l66Env{
			l64Env: &l64Env{t: t, l: l, node: l.p.node, home: home, keyDir: keyDir, daemonCfg: cfg,
				khPath: filepath.Join(sshDir, "known_hosts"), cfgPath: filepath.Join(sshDir, "config")},
			work: work, collDir: collDir, versions: versions, hashes: map[string]bool{}, nssLib: l66NSSLib,
			cAfter: map[string]string{}, cAdded: map[string][]l66KHLine{}, cNoFile: map[string]bool{},
			cfgRaised: cfgRaised,
		}
		e.deadline, e.hasDeadline = t.Deadline()
		if err := os.WriteFile(e.path("ansible.cfg"), []byte("[defaults]\ninterpreter_python = auto_silent\nretry_files_enabled = False\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := e.writeNSS(); err != nil {
			t.Fatal(err)
		}
		if err := e.checkHome(); err != nil {
			t.Fatalf("%v", err)
		}
		if e.sock, e.stopAgent, err = e.newAgent(); err != nil {
			t.Fatal(err)
		}
		defer func() { e.stopAgent() }()

		stopCap := l.capture(t, "L66")
		defer stopCap()
		runL66(e)
	})
}

// writeNSS writes the passwd and group files nss_wrapper is given, whose entry for the current uid has the
// private home.
func (e *l66Env) writeNSS() error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.WriteFile(e.path("nss_passwd"), []byte(l66NSSPasswd(u.Username, uid, gid, e.home, "/bin/sh")), 0o600); err != nil {
		return err
	}
	return os.WriteFile(e.path("nss_group"), []byte(l66NSSGroup(u.Username, gid)), 0o600)
}

// checkHome proves, before any play, that the venv's Python sees the private home as this user's home under
// exactly the environment ansible-playbook runs in. libssh takes its home from the same passwd lookup: if
// this does not hold, a libssh play would read and write the operator's own ~/.ssh.
func (e *l66Env) checkHome() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, se, exit, err := l64Run(ctx, e.ansibleEnv(l66Opts{}), e.work, venvPython, "-I", "-B", "-c",
		"import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)")
	if err != nil || exit != 0 || strings.TrimSpace(out) != e.home {
		return fmt.Errorf("under nss_wrapper (%s) the passwd home is %q, not the private home %s (exit %d %v %s): libssh would use the "+
			"operator's own ~/.ssh, so nothing is run", e.nssLib, strings.TrimSpace(out), e.home, exit, err, trimForNote(se))
	}
	return nil
}

// runL66 runs the cells in order and writes the note.
func runL66(e *l66Env) {
	{
		from, off := time.Now(), e.l.mark()
		time.Sleep(10 * time.Second)
		e.idleNote = fmt.Sprintf("The 10s before the first cell: %d decision records and %d TACACS+ packets to or from the device.",
			len(e.l.recordsSince(off)), e.tacacsIn(from, time.Now()))
	}
	e.cellA()
	e.cellB()
	e.cellGap("L66b2-idle", fmt.Sprintf("an idle gap of %ds between two tasks", l66Gap),
		fmt.Sprintf("- name: idle past persistent_connect_timeout\n  ansible.builtin.pause:\n    seconds: %d\n", l66Gap))
	e.cellGap("L66b2-reset", "`meta: reset_connection` between two tasks", "- name: reset the connection\n  meta: reset_connection\n")
	e.cellD()
	e.cellD2()
	e.cellC("libssh")
	e.cellC("paramiko")
	for _, c := range []l66ECase{
		{id: "L66e-libssh", desc: "libssh", sshType: "libssh"},
		{id: "L66e-paramiko", desc: "paramiko", sshType: "paramiko"},
		{id: "L66e-libssh-alias", desc: "libssh with `ansible_libssh_config_file` naming an ssh_config with `HostKeyAlias` (is that file honoured at all?)", sshType: "libssh", alias: true},
		{id: "L66e-ssh", desc: "ansible.builtin.ssh with `-o HostKeyAlias={{ inventory_hostname }}` (the `raw` module)", plain: true},
	} {
		e.cellE(c)
	}
	e.cellE2()
	l66WriteNotes(e)
}

// l66WriteNotes writes results/L66-<platform>.md from the cells, unless a cell was INVALID.
func l66WriteNotes(e *l66Env) {
	t, l := e.t, e.l
	if ok, why := l66Writable(e.results); !ok {
		fmt.Fprintf(os.Stdout, "L66 %s NO_NOTE %s\n", l.p.name, why)
		t.Errorf("%s: the run is INVALID, so no note is written (%s)", l.p.name, why)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Versions in this run: %s.\n\n%s\n\n", e.versions, e.idleNote)
	b.WriteString("| cell | outcome | elapsed |\n|---|---|---|\n")
	for _, r := range e.results {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.id, r.outcome, r.elapsed.Round(100*time.Millisecond))
	}
	for _, r := range e.results {
		fmt.Fprintf(&b, "\n### %s: %s\n\n%s\n", r.id, r.outcome, r.observation)
	}
	claim := "The Ansible lookup `port49.client.token` over `ansible.netcommon.network_cli` against " + l.p.name + " (policy engine spec " +
		"§15, L66): (a) mints per host for a ten-task play with the lookup in `ansible_password`; (b) the same play minting once, and " +
		"(b2) an idle gap or `meta: reset_connection` after it; (c) host keys under `host_key_checking` and `host_key_auto_add` for " +
		"`libssh` and `paramiko`, and a changed key; (d) a denied device, and no token in `-vvv` output, in `-vvvv` output or in the " +
		"persistent connection's log; (e) an address moved in the inventory, for `libssh`, `paramiko`, `libssh` with a `HostKeyAlias`, " +
		"and `ansible.builtin.ssh`, and (e2) two inventory names at one address over `ansible.builtin.ssh`."
	l.result(t, "L66", claim, l66Scrub(b.String(), e.hashes, labcreds.TokenLen))
}
