package shapes

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unit is a systemd unit file read as INI: a section's keys keep every value
// they were given, in order, since a unit may repeat a key.
type unit map[string]map[string][]string

func readUnit(t *testing.T, rel string) unit {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	u := unit{}
	section := ""
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";"):
		case strings.HasPrefix(ln, "["):
			section = strings.Trim(ln, "[]")
			if u[section] == nil {
				u[section] = map[string][]string{}
			}
		default:
			k, v, ok := strings.Cut(ln, "=")
			if !ok || section == "" {
				t.Fatalf("%s: a line that is not Key=Value: %q", rel, ln)
			}
			u[section][k] = append(u[section][k], v)
		}
	}
	return u
}

// one is the key's single value, and whether it is set at all.
func (u unit) get(section, key string) []string { return u[section][key] }

func (u unit) one(t *testing.T, section, key string) (string, bool) {
	t.Helper()
	v := u[section][key]
	if len(v) > 1 {
		t.Errorf("[%s] %s is set %d times", section, key, len(v))
	}
	if len(v) == 0 {
		return "", false
	}
	return v[0], true
}

func TestTheUnitsCarryTheirLimits(t *testing.T) {
	const absent = "\x00absent"
	type want struct{ section, key, daemon, broker string }
	for _, w := range []want{
		// 0 turns the start limit off: a port49d whose store is down at boot (30s start_timeout,
		// then exit 1, then RestartSec) would otherwise use up five starts in under five
		// minutes and stay failed after etcd came back.
		{"Unit", "StartLimitIntervalSec", "0", "0"},
		{"Unit", "StartLimitBurst", absent, absent},
		{"Service", "Restart", "on-failure", "on-failure"},
		{"Service", "RestartSec", "10s", "10s"},
		{"Service", "LimitNOFILE", "65536", "65536"},
		{"Service", "User", "port49d", "port49-broker"},
		{"Service", "Group", "port49d", "port49-broker"},
		{"Service", "ExecReload", `/bin/sh -c 'kill -HUP "$MAINPID"'`, `/bin/sh -c 'kill -HUP "$MAINPID"'`},
		{"Service", "UMask", "0077", "0077"},
		{"Service", "AmbientCapabilities", "CAP_NET_BIND_SERVICE", absent},
		{"Service", "RuntimeDirectory", absent, absent},
		{"Service", "StateDirectory", absent, "port49-broker"},
		{"Service", "StateDirectoryMode", absent, "0700"},
		{"Service", "ProtectSystem", "true", "true"},
		{"Service", "NoNewPrivileges", "yes", "yes"},
		{"Service", "PrivateTmp", "yes", "yes"},
		{"Service", "ProtectHome", "yes", "yes"},
		// None of these makes /etc read-only, so the fence's argument below still holds.
		{"Service", "PrivateDevices", "yes", "yes"},
		{"Service", "ProtectKernelTunables", "yes", "yes"},
		{"Service", "ProtectKernelModules", "yes", "yes"},
		{"Service", "ProtectKernelLogs", "yes", "yes"},
		{"Service", "ProtectControlGroups", "yes", "yes"},
		{"Service", "ProtectClock", "yes", "yes"},
		{"Service", "ProtectHostname", "yes", "yes"},
		{"Service", "RestrictNamespaces", "yes", "yes"},
		{"Service", "RestrictSUIDSGID", "yes", "yes"},
		{"Service", "LockPersonality", "yes", "yes"},
		{"Service", "RestrictRealtime", "yes", "yes"},
		{"Service", "SystemCallArchitectures", "native", "native"},
		{"Service", "RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX AF_NETLINK", "AF_INET AF_INET6 AF_UNIX AF_NETLINK"},
		{"Service", "SystemCallFilter", "@system-service", "@system-service"},
		{"Service", "CapabilityBoundingSet", "CAP_NET_BIND_SERVICE", ""},
	} {
		for i, name := range []string{"port49d", "port49-broker"} {
			u := readUnit(t, "deploy/systemd/"+name+".service")
			want := []string{w.daemon, w.broker}[i]
			got, set := u.one(t, w.section, w.key)
			switch {
			case want == absent && set:
				t.Errorf("%s: [%s] %s is set (to %q); it must be absent", name, w.section, w.key, got)
			case want != absent && !set:
				t.Errorf("%s: [%s] %s is not set; want %q", name, w.section, w.key, want)
			case want != absent && got != want:
				t.Errorf("%s: [%s] %s=%q, want %q", name, w.section, w.key, got, want)
			}
		}
	}
}

// exportCommand is the export unit's ExecStart: a dated file, written by --out (a new 0600 file, synced)
// to a temporary name in a directory only the broker's user can use, and renamed into place, so an
// export that is shorter than the last, or that fails, never leaves another's bytes in a file.
const exportCommand = `/bin/sh -c 'set -eu; umask 077; d=/var/backups/port49-broker; f=$$d/enrollments-$$(date +%%F).json; ` +
	`rm -f "$$f.tmp"; if /usr/bin/port49-broker export-enrollments --out "$$f.tmp"; then mv "$$f.tmp" "$$f"; else rm -f "$$f.tmp"; exit 1; fi; ` +
	`/usr/bin/find "$$d" -name "enrollments-*.json" -mtime +14 -delete; ` +
	`/usr/bin/find "$$d" -name "enrollments-*.json.tmp" -mtime +1 -delete'`

// Ruling 3: nothing makes /etc read-only inside the unit, since the fence
// excuses a directory's mode on a read-only mount, and a group-writable
// /etc/port49 on the host would pass. Ruling 5 of Task 3a and amendment A14,
// A16: no unit initializes state at start.
func TestTheUnitsHardenNothingTheFenceReads(t *testing.T) {
	for _, name := range []string{"port49d", "port49-broker"} {
		u := readUnit(t, "deploy/systemd/"+name+".service")
		svc := u["Service"]
		if v := svc["ProtectSystem"]; len(v) == 1 && (v[0] == "strict" || v[0] == "full") {
			t.Errorf("%s: ProtectSystem=%s mounts /etc read-only", name, v[0])
		}
		for _, k := range []string{"ReadOnlyPaths", "BindReadOnlyPaths", "InaccessiblePaths"} {
			if len(svc[k]) > 0 {
				t.Errorf("%s: %s= is set", name, k)
			}
		}
		if v := svc["ProtectHome"]; len(v) == 1 && v[0] == "read-only" {
			t.Errorf("%s: ProtectHome=read-only", name)
		}
		for _, v := range svc["TemporaryFileSystem"] {
			if strings.HasSuffix(strings.TrimSpace(v), ":ro") || strings.Contains(v, ":ro,") {
				t.Errorf("%s: TemporaryFileSystem=%s is read-only", name, v)
			}
		}
		for _, v := range append(svc["ExecStartPre"], svc["ExecStartPost"]...) {
			if strings.Contains(v, "init-revocations") || strings.Contains(v, "init-enrollments") {
				t.Errorf("%s: an Exec line initializes state at start: %s", name, v)
			}
		}
	}
}

func TestTheUsersAndDirectoriesAreDeclared(t *testing.T) {
	sysusers := read(t, "deploy/systemd/sysusers.d/port49.conf")
	for _, want := range []string{`u port49d - "port49 TACACS+ server"`, `u port49-broker - "port49 broker"`} {
		if !strings.Contains(sysusers, want) {
			t.Errorf("sysusers.d/port49.conf lacks %q", want)
		}
	}
	tmp := read(t, "deploy/systemd/tmpfiles.d/port49.conf")
	for _, want := range []string{
		"d /etc/port49 0755 root root -",
		"d /etc/port49/keys 0750 root port49d -",
		"d /etc/port49/secrets 0755 root root -",
		"d /etc/port49/etcd 0755 root root -",
		"d /etc/port49/broker 0755 root root -",
		"d /var/spool/port49d 0700 port49d port49d -",
		"d /var/backups/port49-broker 0700 port49-broker port49-broker -",
	} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(want) + `\s*$`).MatchString(tmp) {
			t.Errorf("tmpfiles.d/port49.conf lacks the line %q", want)
		}
	}
}

func read(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The etcd examples are for etcd hosts, not port49 hosts, and the backups run
// under UMask=0077 (systemd does no $(...) or redirection itself).
func TestTheEtcdAndBackupExamples(t *testing.T) {
	etcd := readUnit(t, "deploy/systemd/examples/etcd@.service")
	if v, _ := etcd.one(t, "Service", "ExecStart"); v != "/usr/local/bin/etcd --config-file /etc/etcd/%i.yaml" {
		t.Errorf("etcd@.service ExecStart=%q", v)
	}
	if v, _ := etcd.one(t, "Service", "User"); v != "etcd" {
		t.Errorf("etcd@.service User=%q", v)
	}
	if !strings.Contains(read(t, "deploy/systemd/examples/sysusers-etcd.conf"), "u etcd") {
		t.Error("sysusers-etcd.conf does not create the etcd user")
	}
	for _, n := range []string{"etcd-1", "etcd-2", "etcd-3"} {
		body := read(t, "deploy/systemd/examples/"+n+".yaml")
		for _, want := range []string{"auto-compaction-mode: periodic", `auto-compaction-retention: "1h"`,
			"quota-backend-bytes: 8589934592", "client-cert-auth: true"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s.yaml lacks %q", n, want)
			}
		}
	}
	snap := readUnit(t, "deploy/systemd/examples/port49-etcd-snapshot.service")
	if v, _ := snap.one(t, "Service", "UMask"); v != "0077" {
		t.Errorf("the snapshot unit's UMask=%q", v)
	}
	if v, _ := snap.one(t, "Service", "ExecStart"); v != `/bin/sh -c 'etcdctl snapshot save /var/backups/port49/etcd-$$(date +%%F).db'` {
		t.Errorf("the snapshot unit's ExecStart=%q", v)
	}
	// Each day's snapshot replaces the last, so a prune is for the days a host was off or the
	// date changed; two weeks stay.
	if v := snap.get("Service", "ExecStartPost"); len(v) != 1 || v[0] != `/usr/bin/find /var/backups/port49 -name 'etcd-*.db' -mtime +14 -delete` {
		t.Errorf("the snapshot unit's ExecStartPost=%q", v)
	}
	// The snapshot's directory is made on an etcd host by the etcd tmpfiles file, since
	// tmpfiles.d/port49.conf is not installed there.
	if !regexp.MustCompile(`(?m)^d /var/backups/port49 0700 root root -\s*$`).MatchString(read(t, "deploy/systemd/examples/tmpfiles-etcd.conf")) {
		t.Error("examples/tmpfiles-etcd.conf does not make /var/backups/port49 0700 root")
	}
	exp := readUnit(t, "deploy/systemd/examples/port49-enrollments-export.service")
	for k, want := range map[string]string{"User": "port49-broker", "UMask": "0077", "ExecStart": exportCommand} {
		if v, _ := exp.one(t, "Service", k); v != want {
			t.Errorf("the export unit's %s=%q, want %q", k, v, want)
		}
	}
	if v := exp.get("Service", "StandardOutput"); len(v) != 0 {
		t.Errorf("the export unit sets StandardOutput=%q: systemd's file: does not truncate", v)
	}
	for n, cal := range map[string]string{"port49-etcd-snapshot": "hourly", "port49-enrollments-export": "daily"} {
		tm := readUnit(t, "deploy/systemd/examples/"+n+".timer")
		if v, _ := tm.one(t, "Timer", "OnCalendar"); v != cal {
			t.Errorf("%s.timer OnCalendar=%q, want %q", n, v, cal)
		}
	}
}

// A key version is added file first, then the policy line, and removed policy line first: the other order
// crash-loops port49d on a missing file. Every shape's README says so and names the failure.
func TestEveryReadmeStatesTheKeyOrder(t *testing.T) {
	for _, rel := range []string{"deploy/compose/README.md", "deploy/systemd/README.md", "deploy/helm/port49/README.md"} {
		doc := strings.Join(strings.Fields(read(t, rel)), " ")
		for _, want := range []string{
			"Put the key file in place first, then add the policy line",
			"take the policy line out first, then the file",
			"`lstat ...: no such file`",
			"crash-loops",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s does not say %q", rel, want)
			}
		}
	}
}

// The shipped units run only what the package or an Essential package provides: /bin/kill is
// procps's, which debian:trixie-slim and a minimal host do not have, so a reload by it failed on a
// running broker. A reload is the shell's builtin kill.
func TestTheUnitsNameNoBinaryTheHostMayLack(t *testing.T) {
	allowed := map[string]bool{"/usr/bin/port49d": true, "/usr/bin/port49-broker": true, "/bin/sh": true}
	for _, name := range []string{"port49d", "port49-broker"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", name+".service"))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, ln := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(ln, "Exec") {
				continue
			}
			n++
			v := strings.TrimLeft(strings.SplitN(ln, "=", 2)[1], "-@:+!")
			if bin := strings.Fields(v)[0]; !allowed[bin] {
				t.Errorf("%s: %q runs %s, which a minimal host may not have", name, ln, bin)
			}
		}
		if n < 2 {
			t.Errorf("%s: %d Exec lines", name, n)
		}
	}
}
