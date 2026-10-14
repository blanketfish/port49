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
	l66HostTagRe = regexp.MustCompile(`^<([^>\s]+)> `)
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
func l66WarningLines(out string) []string {
	var w []string
	for _, ln := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(ln); strings.HasPrefix(s, "[WARNING]:") {
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

// l66HostSection is the lines of an `ansible-playbook -vvv` output that belong to host: from a line tagged
// `<host> ` to the next line tagged for another host. Untagged lines belong to the host before them.
func l66HostSection(text, host string) string {
	var keep []string
	cur := ""
	for _, ln := range strings.Split(text, "\n") {
		if m := l66HostTagRe.FindStringSubmatch(ln); m != nil {
			cur = m[1]
		}
		if cur == host {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\n")
}

// l66AliasRead is what one host's ssh -vvv output says about its HostKeyAlias.
type l66AliasRead struct {
	// Lines are the lines that name the alias in a known_hosts lookup or a filed key.
	Lines []string
	// Muxed: the connection reused an open master. NewConnection: it authenticated afresh. KeyChecked: ssh
	// compared a server key it was sent.
	Muxed, NewConnection, KeyChecked bool
}

var l66AliasLineRe = regexp.MustCompile(`hostkeys_foreach|load_hostkeys|record_hostkey|is known and matches|Permanently added|known hosts|Host '`)

func l66ReadAlias(section, alias string) l66AliasRead {
	var r l66AliasRead
	// Ansible shows ssh's stderr inside a bytes repr, newlines escaped.
	s := strings.ReplaceAll(section, `\n`, "\n")
	word := regexp.MustCompile(`\b` + regexp.QuoteMeta(alias) + `\b`)
	for _, ln := range strings.Split(s, "\n") {
		if word.MatchString(ln) && l66AliasLineRe.MatchString(ln) {
			r.Lines = append(r.Lines, strings.TrimSpace(ln))
		}
	}
	r.Muxed = strings.Contains(s, "auto-mux: Trying existing master") || strings.Contains(s, "mux_client_request_session: master session id")
	r.NewConnection = strings.Contains(s, "Authenticated to ")
	r.KeyChecked = strings.Contains(s, "Server host key:") || strings.Contains(s, "is known and matches")
	return r
}

// l66Result is one cell's row.
type l66Result struct {
	id, outcome, observation string
	elapsed                  time.Duration
}

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

// l66Writable is whether a run's note may be written: an INVALID cell measured nothing, so the run writes
// none.
func l66Writable(rs []l66Result) (bool, string) {
	if len(rs) == 0 {
		return false, "no cell ran"
	}
	var bad []string
	for _, r := range rs {
		if r.outcome == "INVALID" {
			bad = append(bad, r.id)
		}
	}
	if len(bad) > 0 {
		return false, "INVALID cells: " + strings.Join(bad, ", ")
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
		b.WriteString("    ansible_user: \"{{ p49.username }}\"\n    ansible_password: \"{{ p49.login }}\"\n")
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
	l66Budget      = 10 * time.Minute
	l66Grace       = time.Minute
	l66PlayBudget  = 4 * time.Minute
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
)

func l66Start(platform, cell string, budget time.Duration) string {
	return fmt.Sprintf("L66 %s %s START budget %s", platform, cell, budget)
}

func l66Stage(platform, cell, stage string) string {
	return fmt.Sprintf("L66 %s %s STAGE %s", platform, cell, stage)
}

func l66Progress(platform, cell, outcome string, d time.Duration) string {
	return fmt.Sprintf("L66 %s %s %s %s", platform, cell, outcome, d.Round(100*time.Millisecond))
}

// l66PyProbe is what the lab venv's Python prints: the versions of what the cells use, and the SHA-256 of each
// .py file of the installed port49 library, so that a venv that holds another commit's library is found.
const l66PyProbe = `import hashlib, importlib.metadata as m, os, sys
try:
    import port49, pylibsshext
except ImportError as e:
    print("IMPORT_ERROR " + str(e.name))
    sys.exit(3)
print("VERSIONS python %s ansible-core %s ansible-pylibssh %s paramiko %s port49 %s" % (
    sys.version.split()[0], m.version("ansible-core"), m.version("ansible-pylibssh"), m.version("paramiko"),
    m.version("port49")))
d = os.path.dirname(port49.__file__)
for n in sorted(os.listdir(d)):
    if n.endswith(".py"):
        print(n, hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest())
`

// l66Preflight checks everything a run needs and installs nothing: the venv's Python with the port49 library
// of this tree and ansible-pylibssh, the collections in their private directory, sshpass, docker. It returns
// the versions line for the note and the collections directory. A missing piece is a Fatal that names the
// command that installs it.
func l66Preflight(t *testing.T) (versions, collDir string) {
	t.Helper()
	l66Once.Do(func() {
		l66CollDir = filepath.Join(root, "tests", "lab", "l66", ".collections")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		env := append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		fail := func(f string, a ...any) { l66Versions = "PREFLIGHT FAILED: " + fmt.Sprintf(f, a...) }
		for _, tool := range []string{"sshpass", "docker", "go", "ssh", "ssh-keygen"} {
			if _, err := exec.LookPath(tool); err != nil {
				hint := ""
				if tool == "sshpass" {
					hint = " (ansible.builtin.ssh logs in with a password only through sshpass; `sudo apt install sshpass`)"
				}
				fail("%s is not on PATH%s", tool, hint)
				return
			}
		}
		out, se, exit, err := l64Run(ctx, env, root, venvPython, "-I", "-B", "-c", l66PyProbe)
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
		cenv := append(os.Environ(), "ANSIBLE_COLLECTIONS_PATH="+filepath.Join(root, "clients", "ansible")+":"+l66CollDir,
			"ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false", "HOME="+os.TempDir())
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
		pv, _, _, _ := l64Run(ctx, env, root, filepath.Join(l66Venv, "ansible-playbook"), "--version")
		sv, _, _, _ := l64Run(ctx, env, root, "ssh", "-V")
		sha, _, _, _ := l64Run(ctx, env, root, "git", "-C", root, "rev-parse", "HEAD")
		l66Versions = fmt.Sprintf("%s; %s; collections: %s; %s; tree commit %s", strings.TrimSpace(vline),
			strings.TrimSpace(strings.SplitN(pv, "\n", 2)[0]), strings.Join(cols, ", "), strings.TrimSpace(sv), strings.TrimSpace(sha))
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

	realHome bool // PORT49_LAB_L66_REAL_HOME=1: libssh runs without a config file redirecting its known_hosts
	realKH   []l66Snap

	standin     bool
	standinKeys []string

	// What (c)'s first contact left, by ssh type, for its changed-key cell.
	cAfter map[string]string
	cAdded map[string][]l66KHLine
}

func (e *l66Env) path(parts ...string) string {
	return filepath.Join(append([]string{e.work}, parts...)...)
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
	env := slices.DeleteFunc(e.env(), func(kv string) bool { return strings.HasPrefix(kv, "ANSIBLE_") })
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
		_, _, _, _ = l64Run(ctx, e.env(), e.home, "ssh", "-O", "exit", "-S", sock, "l66")
		cancel()
		_ = os.Remove(sock)
	}
}

// snapReal takes the snapshot of the operator's own known_hosts that a run is checked against: libssh reads
// the home from the passwd entry, not from $HOME.
func (e *l66Env) snapReal() {
	e.realKH = nil
	u, err := user.Current()
	if err != nil {
		return
	}
	for _, name := range []string{"known_hosts"} {
		if s, err := l66Snapshot(filepath.Join(u.HomeDir, ".ssh", name)); err == nil {
			e.realKH = append(e.realKH, s)
		}
	}
}

// realChanged says whether a run wrote the operator's own known_hosts, and what it added. The file is left
// as the client wrote it.
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
		msgs = append(msgs, fmt.Sprintf("the operator's own %s was written during the run (%s; added: %s). libssh reads its "+
			"home from the passwd entry, not $HOME. The file has not been touched by the harness: remove those lines by hand", s.Path,
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
	o.pb, o.inv = e.path("play", name+".yml"), e.path("inv", name+".yml")
	if err := os.WriteFile(o.pb, []byte(l66Playbook(kind, s.Platform, n, between)), 0o600); err != nil {
		return r, err
	}
	if err := os.WriteFile(o.inv, []byte(l66Inventory(s)), 0o600); err != nil {
		return r, err
	}
	fmt.Fprintln(os.Stdout, l66Stage(e.l.p.name, e.cellID, "ansible-playbook "+name))
	e.snapReal()
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
	r.hashes = l66TokenHashes(r.recs)
	maps.Copy(e.hashes, r.hashes)
	if msg := e.realChanged(); msg != "" {
		e.addInvalid(msg)
	}
	return r, nil
}

// spec is the inventory of the one node, over network_cli with the given ssh type.
func (e *l66Env) spec(mode, sshType string) l66InvSpec {
	s := l66InvSpec{Hosts: []l66Host{{e.node, e.l.p.addr}}, Socket: e.sock, Bin: filepath.Join(root, "bin", "port49"),
		Platform: l66Platforms[e.l.p.name], Conn: "network_cli", SSHType: sshType, Mode: mode}
	if sshType == "libssh" && !e.realHome {
		s.LibsshConfig = e.libsshConf(false)
	}
	return s
}

// libsshConf writes the ssh_config libssh is given: its known_hosts is the private file and no other (libssh
// reads the home from the passwd entry, which is the operator's), with a HostKeyAlias of the node's name
// when alias is true. It returns the path.
func (e *l66Env) libsshConf(alias bool) string {
	name := "libssh.conf"
	cfg := "Host *\n  UserKnownHostsFile " + e.khPath + "\n  GlobalKnownHostsFile /dev/null\n"
	if alias {
		name, cfg = "libssh_alias.conf", cfg+"  HostKeyAlias "+e.node+"\n"
	}
	p := e.path(name)
	_ = os.WriteFile(p, []byte(cfg), 0o600)
	return p
}

// sshSpec is the inventory for ansible.builtin.ssh: the private ssh_config, and the extra args the collection's
// README recommends.
func (e *l66Env) sshSpec(hosts []l66Host, p49 string) l66InvSpec {
	cfg := e.path("ssh_config")
	_ = os.WriteFile(cfg, []byte("Host *\n  UserKnownHostsFile "+e.khPath+"\n  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys yes\n"), 0o600)
	return l66InvSpec{Hosts: hosts, P49Name: p49, Socket: e.sock, Bin: filepath.Join(root, "bin", "port49"),
		Platform: l66Platforms[e.l.p.name], Conn: "ssh", Mode: "fact", SSHCommonArgs: "-F " + cfg,
		SSHExtraArgs: "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new"}
}

// cell runs fn under its own budget and records its row. fn returns whether the cell's claim held (or, for a
// record cell, whether it could observe) and what it observed; it never calls t. A cell that has not returned
// a minute after its budget ends the platform's run.
func (e *l66Env) cell(id, kind string, budget time.Duration, fn func(ctx context.Context) (bool, string)) bool {
	start := time.Now()
	e.cellID = id
	fmt.Fprintln(os.Stdout, l66Start(e.l.p.name, id, budget))
	e.unread, e.invalid, e.controlOK = false, "", false
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
	switch {
	case outcome == "TIMEOUT":
		d.obs = "**The cell's budget ran out.** " + d.obs
	case e.invalid != "":
		outcome, d.obs = "INVALID", "**INVALID: "+e.invalid+".** "+d.obs
	case outcome == "INVALID":
		d.obs = "**INVALID: " + l66WhyInvalid(kind, d.ok, e.controlOK, e.unread) + ".** " + d.obs
	}
	d.obs = l66Scrub(d.obs, e.hashes, labcreds.TokenLen)
	elapsed := time.Since(start)
	e.results = append(e.results, l66Result{id, outcome, d.obs, elapsed})
	fmt.Fprintln(os.Stdout, l66Progress(e.l.p.name, id, outcome, elapsed))
	e.t.Logf("%s: %s", id, d.obs)
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

// readKH is the private known_hosts file as it is now.
func (e *l66Env) readKH() string {
	b, _ := os.ReadFile(e.khPath)
	return string(b)
}

// baseline writes the known_hosts file (c) and (e) start from and returns it.
func (e *l66Env) baseline(ctx context.Context) (string, error) {
	a, err := e.freshKey(ctx, "ssh-ed25519")
	if err != nil {
		return "", err
	}
	b, err := e.freshKey(ctx, "ssh-ed25519")
	if err != nil {
		return "", err
	}
	kh := l66BaselineKH(a, b)
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
	e.cell("L66a", "record", l66Budget, func(ctx context.Context) (bool, string) {
		r, err := e.runPlay(ctx, "a", "ten", 10, "", e.spec("lookup", "libssh"), l66Opts{idle: l66DefaultIdle})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r.good(e.node)
		return r.recap[e.node].Passed(), fmt.Sprintf("A ten-task play (each task a `%s` of `show version`) with "+
			"`ansible_password: \"{{ lookup('port49.client.token', ...) }}\"` and `ansible_user` from a second lookup with "+
			"`field='username'`: **%d mint records for the run** (%d redeem records, %d TACACS+ authentication starts) for ten tasks "+
			"on one host. %s. This run is a good login, so its window is the positive control for its own counts: %v.",
			l66Platforms[e.l.p.name].Module, r.counts.Mints, r.counts.Redeems, r.starts, r.summary(e.node), e.controlOK)
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
		again := r.starts > 1 || r.counts.Redeems > 1
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
		ctl, ctlNote := e.control(ctx)
		_ = ctl
		denied := l66DeniedNode(e.node)
		ds := e.spec("fact", "libssh")
		ds.Hosts = []l66Host{{denied, e.l.p.addr}}
		dr, err := e.runPlay(ctx, "d-denied", "once", 1, "", ds, l66Opts{verbose: "-vvv"})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		gr, err := e.runPlay(ctx, "d-good", "once", 1, "", e.spec("fact", "libssh"), l66Opts{verbose: "-vvv"})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ctlNote
		}
		named := strings.Contains(dr.text(), "no_grants_matched")
		failed := !dr.recap[denied].Passed() && dr.recap[denied].Failed > 0
		deniedHits := l66FindTokens(dr.text(), e.hashes, labcreds.TokenLen)
		goodHits := l66FindTokens(gr.text(), e.hashes, labcreds.TokenLen)
		if len(gr.hashes) == 0 {
			e.addInvalid("the good run's records name no minted token, so there is no hash to look for in its -vvv output")
		}
		pass := failed && named && dr.counts.MintDenies > 0 && len(deniedHits) == 0 && len(goodHits) == 0 && gr.good(e.node) &&
			dr.packets == 0 && len(dr.counts.Other) == 0
		return pass, fmt.Sprintf("%s\n\nA device with no grant (`%s`, which the policy grants nothing on), `-vvv`: the task failed: %v; "+
			"the output names `no_grants_matched`: %v; %s. Token-shaped words in its output that hash to a minted token's "+
			"`credential_sha256`: %d (lines %v); the harness knows %d token hashes from this run.\n\nA good login (`%s`), `-vvv`, "+
			"searched the same way: %d words hash to a minted token (lines %v); %d of this run's token hashes were known to search "+
			"for. %s", ctlNote, denied, failed, named, dr.summary(denied), len(deniedHits), deniedHits, len(e.hashes), e.node,
			len(goodHits), goodHits, len(gr.hashes), gr.summary(e.node))
	})
}

// cellD2 is (d2): -vvvv and the persistent connection's log hold no token.
func (e *l66Env) cellD2() {
	e.cell("L66d2", "claim", l66Budget, func(ctx context.Context) (bool, string) {
		logPath := e.path("ansible-d2.log")
		_ = os.Remove(logPath)
		r, err := e.runPlay(ctx, "d2", "once", 1, "", e.spec("fact", "libssh"),
			l66Opts{verbose: "-vvvv", logPath: logPath, persistLog: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		logBytes, lerr := os.ReadFile(logPath)
		if lerr != nil || len(logBytes) == 0 {
			e.addInvalid(fmt.Sprintf("the persistent connection's log (%s) is empty or unreadable (%v), so its search proves nothing", logPath, lerr))
		}
		if len(r.hashes) == 0 {
			e.addInvalid("the run's records name no minted token, so there is no hash to look for")
		}
		outHits := l66FindTokens(r.stdout, e.hashes, labcreds.TokenLen)
		errHits := l66FindTokens(r.stderr, e.hashes, labcreds.TokenLen)
		logHits := l66FindTokens(string(logBytes), e.hashes, labcreds.TokenLen)
		e.controlOK = r.good(e.node)
		return r.good(e.node) && len(outHits)+len(errHits)+len(logHits) == 0, fmt.Sprintf("A good login with `-vvvv`, "+
			"`ANSIBLE_PERSISTENT_LOG_MESSAGES=True` and `ANSIBLE_LOG_PATH` a private file (%d bytes, %d lines): each word of stdout "+
			"(%d lines), stderr (%d lines) and the log was hashed and compared with the %d token hashes the decision log names "+
			"(`credential_sha256` and the mint's `token_sha256`). Words that match: stdout %d (lines %v), stderr %d (lines %v), "+
			"log %d (lines %v). %s", len(logBytes), strings.Count(string(logBytes), "\n"), strings.Count(r.stdout, "\n"),
			strings.Count(r.stderr, "\n"), len(e.hashes), len(outHits), outHits, len(errHits), errHits, len(logHits), logHits, r.summary(e.node))
	})
}

// cellC is (c) for one ssh type: a first contact from a file of a comment, an @revoked and an @cert-authority
// line, then that line's key replaced by a fresh key of its type.
func (e *l66Env) cellC(sshType string) {
	id1, id2 := "L66c1-"+sshType, "L66c2-"+sshType
	e.cell(id1, "claim", l66Budget, func(ctx context.Context) (bool, string) {
		base, err := e.baseline(ctx)
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		r, err := e.runPlay(ctx, id1, "once", 1, "", e.spec("fact", sshType), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		after := e.readKH()
		d := l66DiffKH(base, after)
		e.cAfter[sshType], e.cAdded[sshType] = after, d.Added
		e.controlOK = r.good(e.node)
		where := "the private known_hosts (`~/.ssh/known_hosts` of the run's home)"
		if sshType == "libssh" && e.realHome {
			where += ", or the operator's own file if libssh wrote that (the run is then INVALID)"
		} else if sshType == "libssh" {
			where += ", named to libssh by `ansible_libssh_config_file` (`UserKnownHostsFile`), since libssh reads the home from the passwd entry"
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
			"`ANSIBLE_HOST_KEY_AUTO_ADD=True`, from a known_hosts holding a comment line, an `@revoked` line and an `@cert-authority` line "+
			"for unrelated patterns. The play passed: %v. The file changed in: %s. Mode: **%s**.%s Lines added: %s; lines gone: %s; "+
			"comment lines lost: %q; marker lines lost: %q. %s\n\nBefore (keys shortened to their first 16 characters):\n\n%s\n\nAfter:\n\n%s",
			sshType, r.recap[e.node].Passed(), where, d.Mode, rewrote, l66Shorts(d.Added), l66Shorts(d.Removed), d.LostComments,
			d.LostMarkers, r.summary(e.node), l66Verbatim(base), l66Verbatim(after))
	})
	e.cell(id2, "refusal", l66Budget, func(ctx context.Context) (bool, string) {
		added := e.cAdded[sshType]
		if len(added) == 0 {
			e.addInvalid("the first-contact cell filed no key line, so there is none to replace")
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
		d := l66DiffKH(content, e.readKH())
		refused := !r.recap[e.node].Passed()
		pass := refused && r.packets == 0 && len(r.counts.Other) == 0 && r.counts.Redeems == 0
		return pass, fmt.Sprintf("%s\n\n`%s`: the key of each line the first contact filed (%s) replaced by a fresh key of its type, the "+
			"comment and marker lines left. %s. The play was refused (did not pass): %v; **%d TACACS+ packets**, **%d TACACS+ "+
			"authentication starts**, records other than mint and blob: %v (the token was never presented if there are none). The file "+
			"after the refused run: %s, added %s, gone %s. %s", ctlNote, sshType, strings.Join(replaced, ", "), quiet, refused, r.packets,
			r.starts, r.counts.Other, d.Mode, l66Shorts(d.Added), l66Shorts(d.Removed), r.summary(e.node))
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
		base, err := e.baseline(ctx)
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
				s.LibsshConfig = e.libsshConf(true)
			}
			return s
		}
		if c.plain {
			kind = "raw"
		}
		r1, err := e.runPlay(ctx, c.id+"-device", kind, 1, "", mk(e.l.p.addr), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r1.good(e.node)
		kh1 := e.readKH()
		d1 := l66DiffKH(base, kh1)
		if !r1.recap[e.node].Passed() || len(d1.Added) == 0 {
			e.addInvalid("the run at the device's address did not pass and file its key, so there is no earlier contact for the move to be compared with")
			return false, fmt.Sprintf("Step 1, at the device's address: %s. Lines added: %s.", r1.summary(e.node), l66Shorts(d1.Added))
		}
		if err := e.startStandin(ctx); err != nil {
			e.addInvalid("the stand-in sshd could not be started: " + err.Error())
			return false, ""
		}
		mark := len(l66ParseStandin(e.standinLog(ctx)))
		quiet := e.waitQuiet(ctx)
		r2, err := e.runPlay(ctx, c.id+"-standin", kind, 1, "", mk(l66StandinAddr), l66Opts{hostKeys: true})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		d2 := l66DiffKH(kh1, e.readKH())
		tally := l66TallyStandin(l66ParseStandin(e.standinLog(ctx))[mark:])
		presented := tally.Presented(r2.hashes)
		return true, fmt.Sprintf("**%s.** Step 1, at the device's address `%s`: %s. File after step 1: mode %s, added %s.\n\n"+
			"Step 2, `ansible_host` changed to the stand-in (`%s`, a throwaway sshd container on the lab bridge with its own host keys %s; "+
			"it refuses every login and logs a password's length and hash only). %s. **The stand-in's key was auto-added: %v** (mode %s, "+
			"added %s, gone %s). The stand-in saw %d connection(s), %d password attempt(s) and %d keyboard-interactive answer(s); "+
			"**the minted token was presented to it: %v** (an attempt's hash is one of the %d token hashes this step's mint records name).",
			c.desc, e.l.p.addr, r1.summary(e.node), d1.Mode, l66Shorts(d1.Added), l66StandinAddr, strings.Join(e.standinKeys, ", "), quiet+
				" "+r2.summary(e.node), len(d2.Added) > 0, d2.Mode, l66Shorts(d2.Added), l66Shorts(d2.Removed), tally.Connects,
			tally.Passwords, tally.Kbdint, presented, len(r2.hashes))
	})
}

// cellE2 is (e2): two inventory names at one address, over ansible.builtin.ssh.
func (e *l66Env) cellE2() {
	e.cell("L66e2-names", "record", l66Budget, func(ctx context.Context) (bool, string) {
		if _, err := e.baseline(ctx); err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		hosts := []l66Host{{"l66a", e.l.p.addr}, {"l66b", e.l.p.addr}}
		s := e.sshSpec(hosts, e.node)
		r, err := e.runPlay(ctx, "e2", "raw", 1, "", s, l66Opts{hostKeys: true, forks: 1, verbose: "-vvv"})
		if err != nil {
			e.addInvalid(err.Error())
			return false, ""
		}
		e.controlOK = r.packets > 0 && r.counts.Redeems > 0
		kh := e.readKH()
		d := l66DiffKH("", kh)
		var per []string
		for _, h := range hosts {
			a := l66ReadAlias(l66HostSection(r.text(), h.Name), h.Name)
			per = append(per, fmt.Sprintf("`%s`: recap %+v; new connection (ssh authenticated afresh): %v; reused an open master: %v; "+
				"ssh looked its alias up or filed it on %d line(s)%s", h.Name, r.recap[h.Name], a.NewConnection, a.Muxed, len(a.Lines),
				l66AliasQuote(a.Lines)))
		}
		var names []string
		for _, l := range l66ParseKH(kh) {
			names = append(names, l.Hosts)
		}
		return r.recap[hosts[0].Name].Passed(), fmt.Sprintf("Two inventory names (`l66a`, `l66b`) at one address (%s), `ansible.builtin.ssh` with "+
			"`-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new`, one fork, `-vvv`. Per host: %s. The "+
			"known_hosts file after the run holds key lines for: %v (filed by the run: %s). %s", e.l.p.addr, strings.Join(per, "; "),
			names, l66Shorts(d.Added), r.summary(hosts[0].Name))
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
		"--ip", l66StandinAddr, "-v", bin+":/standin:ro", "alpine:3.22", "/standin", "-listen", ":22"); err != nil || exit != 0 {
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
		cfg, err := l.derivedConfig("l66", platformSessionAttributes[l.p.name],
			strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml", polRel, 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker block, so nothing was measured: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}
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
			work: work, collDir: collDir, versions: versions, hashes: map[string]bool{},
			realHome: os.Getenv("PORT49_LAB_L66_REAL_HOME") == "1",
			cAfter:   map[string]string{}, cAdded: map[string][]l66KHLine{},
		}
		if err := os.WriteFile(e.path("ansible.cfg"), []byte("[defaults]\ninterpreter_python = auto_silent\nretry_files_enabled = False\n"), 0o600); err != nil {
			t.Fatal(err)
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
		{id: "L66e-libssh-alias", desc: "libssh with `HostKeyAlias` in `ansible_libssh_config_file`", sshType: "libssh", alias: true},
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
	if e.realHome {
		b.WriteString("`PORT49_LAB_L66_REAL_HOME=1`: libssh ran without a config file redirecting its known_hosts.\n\n")
	}
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
