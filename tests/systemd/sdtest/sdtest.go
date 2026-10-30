// Package sdtest is what the systemd smoke (plan 12b, Task 9) rewrites in the shipped files, and
// reads from systemd, as plain functions a unit test can hold without Docker. UNVERIFIED until the
// smoke runs: the shipped files are the input; nothing here has met a real systemd.
package sdtest

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func itoa(n int) string { return strconv.Itoa(n) }

// ClientPort and PeerPort are etcd member n's ports in the one container (n is 1 to 3):
// 2379/2380, 2479/2480, 2579/2580.
func ClientPort(n int) int { return 2379 + 100*(n-1) }
func PeerPort(n int) int   { return 2380 + 100*(n-1) }

// Member is deploy/systemd/examples/etcd-<n>.yaml for three members in one container: every
// example.com name becomes localhost (the member certificates answer to it) at the member's own
// port, and the 0.0.0.0 listeners become 127.0.0.1.
func Member(body string, n int) (string, error) {
	out := body
	for m := 1; m <= 3; m++ {
		host := "https://etcd-" + itoa(m) + ".example.com"
		out = strings.ReplaceAll(out, host+":2379", "https://localhost:"+itoa(ClientPort(m)))
		out = strings.ReplaceAll(out, host+":2380", "https://localhost:"+itoa(PeerPort(m)))
	}
	out = strings.ReplaceAll(out, "https://0.0.0.0:2379", "https://127.0.0.1:"+itoa(ClientPort(n)))
	out = strings.ReplaceAll(out, "https://0.0.0.0:2380", "https://127.0.0.1:"+itoa(PeerPort(n)))
	if out == body {
		return "", errors.New("sdtest: the etcd member file names nothing to rewrite")
	}
	return out, nil
}

// Endpoints is a port49d or broker config with its three example.com member URLs made the
// container's.
func Endpoints(body string) (string, error) {
	out := body
	for m := 1; m <= 3; m++ {
		out = strings.ReplaceAll(out, "https://etcd-"+itoa(m)+".example.com:2379", "https://localhost:"+itoa(ClientPort(m)))
	}
	if out == body {
		return "", errors.New("sdtest: the config names no etcd endpoint to rewrite")
	}
	return out, nil
}

// Policy is the shipped starting policy for the smoke: the device set is named k (the shared
// RotateCell's name) and read from the one file v1 in the keys directory, and the group admits
// subnet.
func Policy(body, subnet string) (string, error) {
	out := body
	for _, r := range [][2]string{
		{"192.0.2.0/24", subnet},
		{"key_ref: example}", "key_ref: k}"},
		{"\n  example:\n", "\n  k:\n"},
		{"file:/etc/port49/keys/example-v1", "file:/etc/port49/keys/tacacs_v1"},
	} {
		if !strings.Contains(out, r[0]) {
			return "", fmt.Errorf("sdtest: the policy has no %q to rewrite", r[0])
		}
		out = strings.ReplaceAll(out, r[0], r[1])
	}
	return out, nil
}

// NoKeys is policy without its keys: block (the key groups still name a key set), which port49d
// refuses at every load.
func NoKeys(policy string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(policy), &doc); err != nil {
		return "", err
	}
	if _, ok := doc["keys"]; !ok {
		return "", errors.New("sdtest: the policy has no keys: block")
	}
	delete(doc, "keys")
	b, err := yaml.Marshal(doc)
	return string(b), err
}

// Broker is the shipped broker config for a trial PKI (no OCSP responder) with its metrics on
// every address, so the host reaches them through the published port.
func Broker(body string) (string, error) {
	out := strings.Replace(body, "certificate_status: {ocsp: {use_aia: true}}", "certificate_status: {disabled: true}", 1)
	out = strings.Replace(out, `metrics_listen: "127.0.0.1:9050"`, `metrics_listen: ":9050"`, 1)
	if !strings.Contains(out, "disabled: true") || !strings.Contains(out, `metrics_listen: ":9050"`) {
		return "", errors.New("sdtest: the broker config lacks the lines the smoke rewrites")
	}
	return out, nil
}

// Daemon is the shipped port49d config with its metrics on every address.
func Daemon(body string) (string, error) {
	out := strings.Replace(body, `metrics_listen: "127.0.0.1:9049"`, `metrics_listen: ":9049"`, 1)
	if out == body {
		return "", errors.New("sdtest: the port49d config has no metrics_listen to rewrite")
	}
	return out, nil
}

// ParseShow reads `systemctl show` output: KEY=VALUE lines.
func ParseShow(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

// Refusal reports whether line is the fence's refusal naming dir: it names the directory and says
// it is writable by others.
func Refusal(line, dir string) bool {
	return strings.Contains(line, " "+dir+" is mode ") && strings.Contains(line, "writable by others")
}

// Ports are the host ports the container publishes, all on 127.0.0.1: TACACS+, the broker's API,
// and the two metrics listeners.
var Ports = []string{"49:49", "8443:8443", "9049:9049", "9050:9050"}

// RunArgs is the `docker run` line of the smoke's container. It is not --privileged: that gives
// the container every host device, which on a workstation includes the TPM and a security key. What
// it grants instead, each for a stated reason:
//   - --cgroupns=private: the container sees its own cgroup subtree as the root, so systemd as PID 1
//     manages only that subtree.
//   - --cap-add SYS_ADMIN: the units' sandboxing (PrivateDevices, PrivateTmp, ProtectSystem,
//     ProtectKernel*, ProtectHostname, ProtectControlGroups) builds mount and UTS namespaces, and the
//     image's init remounts the container's own cgroup mount read-write (Docker mounts it read-only
//     without --privileged). No other capability is added.
//   - --security-opt apparmor=unconfined: Docker's default AppArmor profile denies mount(2), which
//     those namespaces and the remount need. The default seccomp profile is kept: with SYS_ADMIN it
//     allows mount, unshare and setns.
//   - tmpfs /run, /run/lock, /tmp: systemd's runtime state, not the host's.
//
// No --device and no bind mount of /dev or of anything else. If the first real run shows a unit
// cannot start with these, the answer is to report the unit's error, never --privileged.
//
// This is not an isolation boundary. SYS_ADMIN, an unconfined AppArmor profile and no user namespace
// are a known container-escape set, so a hostile payload in the container could reach host root. The
// smoke therefore refuses to start on a host with a TPM or a Yubico key (shapetest.RefuseOnKeyHost).
func RunArgs(name, network, image string) []string {
	args := []string{"run", "-d", "--name", name, "--network", network,
		"--cgroupns=private", "--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined",
		"--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp"}
	for _, p := range Ports {
		args = append(args, "-p", "127.0.0.1:"+p)
	}
	return append(args, image)
}

// Forbidden lists what text must never contain to hand a smoke container the host: the full-privilege
// flag, a device, a bind mount of /dev, /sys or /, any capability but SYS_ADMIN, an unconfined seccomp
// profile, a device-cgroup rule, or the host's pid, user or network namespace. text is a harness file
// or a Makefile recipe.
func Forbidden(text string) []string {
	var found []string
	for _, f := range []struct{ name, pattern string }{
		{"--privileged", `--privileged`},
		{"--device", `--device(\s|=)`},
		{"--device-cgroup-rule", `--device-cgroup-rule`},
		{"seccomp=unconfined", `seccomp(=|:)unconfined`},
		{"the host's pid namespace", `--pid(\s+|=)host`},
		{"the host's user namespace", `--userns(\s+|=)host`},
		{"the host's ipc namespace", `--ipc(\s+|=)host`},
		{"the host's uts namespace", `--uts(\s+|=)host`},
		{"the host's network namespace", `--(net|network)(\s+|=)host`},
	} {
		if regexp.MustCompile(f.pattern).MatchString(text) {
			found = append(found, f.name)
		}
	}
	// Host bind mounts: no smoke binds any host path, so every absolute source is refused, in -v and
	// --volume (spaced, "=", attached as -v/x, or a separate quoted argument) and in --mount source=/src=.
	// The source is cleaned first, so ../ cannot hide a path. A relative source is a named volume, and a
	// tmpfs is not a bind; both stay allowed.
	for _, m := range regexp.MustCompile(`(?:^|[\s"'`+"`"+`])(?:-v|--volume)(?:\s*=\s*|\s+|"\s*,\s*"|\s*)(/[^\s:"'`+"`"+`]*)|(?:source|src)=(/[^\s,"'`+"`"+`]*)`).FindAllStringSubmatch(text, -1) {
		src := path.Clean(m[1] + m[2])
		switch {
		case src == "/":
			found = append(found, "a bind mount of /")
		case src == "/dev" || strings.HasPrefix(src, "/dev/"):
			found = append(found, "a bind mount of /dev")
		case src == "/sys" || strings.HasPrefix(src, "/sys/"):
			found = append(found, "a bind mount of /sys")
		default:
			found = append(found, "a host bind mount of "+src)
		}
	}
	for _, m := range regexp.MustCompile(`--cap-add(?:\s+|=)(\S+)`).FindAllStringSubmatch(text, -1) {
		if c := strings.Trim(m[1], `"',`); c != "SYS_ADMIN" {
			found = append(found, "--cap-add "+c)
			break
		}
	}
	return found
}

// Stat is one line of `stat -c '%U:%G %a %n'`.
type Stat struct {
	Owner, Mode, Path string
}

// ParseStat reads `stat -c '%U:%G %a %n'` output, one path per line.
func ParseStat(out string) ([]Stat, error) {
	var res []Stat
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || !strings.Contains(f[0], ":") || !regexp.MustCompile(`^[0-7]{3,4}$`).MatchString(f[1]) {
			return nil, fmt.Errorf("sdtest: stat line %q is not 'owner:group mode path'", l)
		}
		res = append(res, Stat{f[0], f[1], f[2]})
	}
	return res, nil
}

// Want checks one Stat against owner ("user:group") and mode.
func (s Stat) Want(owner, mode string) error {
	if s.Owner != owner || s.Mode != mode {
		return fmt.Errorf("%s is %s %s, want %s %s", s.Path, s.Owner, s.Mode, owner, mode)
	}
	return nil
}

// ParseSecurity reads `systemd-analyze security --no-pager <units>`: the exposure each unit row
// carries, by unit name.
func ParseSecurity(out string) (map[string]float64, error) {
	m := map[string]float64{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil {
			return nil, fmt.Errorf("sdtest: the exposure of %s is %q, not a number", f[0], f[1])
		}
		m[f[0]] = v
	}
	if len(m) == 0 {
		return nil, errors.New("sdtest: no unit rows in the systemd-analyze security output")
	}
	return m, nil
}

// breakGlassRE is the README's break-glass command line.
var breakGlassRE = regexp.MustCompile(`(?m)^sudo -u port49-broker port49-broker revoke --offline --principal \S+$`)

// BreakGlass is the README's break-glass command as written, for the smoke to run literally.
func BreakGlass(readme string) (string, error) {
	m := breakGlassRE.FindAllString(readme, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("sdtest: want exactly one `sudo -u port49-broker port49-broker revoke --offline --principal P` line in the README, found %d", len(m))
	}
	return m[0], nil
}

var reRead = regexp.MustCompile(`re-read: (\d+) roots \(was (\d+)\)`)

// ReRead is each "re-read: N roots (was M)" the journal holds (internal/port49d/permfa.go), as {N, M},
// in order.
func ReRead(journal string) [][2]int {
	var res [][2]int
	for _, m := range reRead.FindAllStringSubmatch(journal, -1) {
		n, _ := strconv.Atoi(m[1])
		was, _ := strconv.Atoi(m[2])
		res = append(res, [2]int{n, was})
	}
	return res
}

// PutScript is the shell the smoke's box.put runs: $1 is the path, $2 the owner, $3 the mode, and
// the body is on stdin. It makes the parent directory first (0755, before the umask is set), because
// the image does not have every directory a unit's file belongs in, then writes by a rename in that
// directory so a reader never sees a half-written file.
const PutScript = `set -eu; d=$(dirname "$1"); install -d -m 0755 "$d"; umask 077; t=$(mktemp "$d/.put.XXXXXX")
trap 'rm -f "$t"' EXIT; cat > "$t"; chown "$2" "$t"; chmod "$3" "$t"; mv "$t" "$1"`
