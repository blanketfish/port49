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
		{"Unit", "StartLimitIntervalSec", "300", "300"},
		{"Unit", "StartLimitBurst", "5", "5"},
		{"Service", "Restart", "on-failure", "on-failure"},
		{"Service", "RestartSec", "10s", "10s"},
		{"Service", "LimitNOFILE", "65536", "65536"},
		{"Service", "User", "port49d", "port49-broker"},
		{"Service", "Group", "port49d", "port49-broker"},
		{"Service", "ExecReload", "/bin/kill -HUP $MAINPID", "/bin/kill -HUP $MAINPID"},
		{"Service", "UMask", "0077", "0077"},
		{"Service", "AmbientCapabilities", "CAP_NET_BIND_SERVICE", absent},
		{"Service", "RuntimeDirectory", absent, absent},
		{"Service", "StateDirectory", absent, "port49-broker"},
		{"Service", "StateDirectoryMode", absent, "0700"},
		{"Service", "ProtectSystem", "true", "true"},
		{"Service", "NoNewPrivileges", "yes", "yes"},
		{"Service", "PrivateTmp", "yes", "yes"},
		{"Service", "ProtectHome", "yes", "yes"},
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
		"d /var/spool/port49d 0700 port49d port49d -",
		"d /var/backups/port49 0700 root root -",
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
	exp := readUnit(t, "deploy/systemd/examples/port49-enrollments-export.service")
	for k, want := range map[string]string{"User": "port49-broker", "UMask": "0077",
		"ExecStart":      "/usr/bin/port49-broker export-enrollments",
		"StandardOutput": "file:/var/backups/port49/directory-export.json"} {
		if v, _ := exp.one(t, "Service", k); v != want {
			t.Errorf("the export unit's %s=%q, want %q", k, v, want)
		}
	}
	for n, cal := range map[string]string{"port49-etcd-snapshot": "hourly", "port49-enrollments-export": "daily"} {
		tm := readUnit(t, "deploy/systemd/examples/"+n+".timer")
		if v, _ := tm.one(t, "Timer", "OnCalendar"); v != cal {
			t.Errorf("%s.timer OnCalendar=%q, want %q", n, v, cal)
		}
	}
}
