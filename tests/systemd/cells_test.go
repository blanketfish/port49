//go:build systemd

package systemd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
	"github.com/blanketfish/port49/tests/systemd/sdtest"
)

// reloadCell: README says `systemctl reload port49-broker` re-reads the attestation roots (ExecReload=
// is a SIGHUP, internal/port49d/permfa.go). A second root is added and removed again; each reload says
// "re-read: N roots (was M)" and the broker is not restarted.
func reloadCell(t *testing.T, u stack) {
	t.Helper()
	b := u.b
	// ExecReload is `kill -HUP $MAINPID`: with the broker stopped or restarting there is no MAINPID and
	// the reload fails. An earlier cell may have left it restarting, so wait for it to be up and ready.
	shapetest.WaitFor(t, "the broker to be active with a main process", 2*time.Minute, func() bool {
		s := b.show("port49-broker", "ActiveState", "MainPID")
		return s["ActiveState"] == "active" && s["MainPID"] != "" && s["MainPID"] != "0"
	})
	shapetest.Ready(t, "127.0.0.1:9050")
	orig := readHost(t, filepath.Join(u.brokerDir, shapetest.RootsName))
	started := b.show("port49-broker", "ExecMainStartTimestamp")["ExecMainStartTimestamp"]
	lastReRead := func(since int64) (n, was int, ok bool) {
		all := sdtest.ReRead(b.journal("port49-broker", since))
		if len(all) == 0 {
			return 0, 0, false
		}
		l := all[len(all)-1]
		return l[0], l[1], true
	}
	reload := func(what string, want func(n, was int) bool) (int, int) {
		t.Helper()
		since := b.epoch()
		if out, err := b.exec("", "systemctl", "reload", "port49-broker"); err != nil {
			st := b.show("port49-broker", "ActiveState", "SubState", "MainPID", "ExecMainStatus", "NRestarts")
			t.Fatalf("systemctl reload port49-broker: %v\n%s\nActiveState=%s SubState=%s MainPID=%s ExecMainStatus=%s NRestarts=%s",
				err, filter(out), st["ActiveState"], st["SubState"], st["MainPID"], st["ExecMainStatus"], st["NRestarts"])
		}
		var n, was int
		shapetest.WaitFor(t, what, 30*time.Second, func() bool {
			var ok bool
			n, was, ok = lastReRead(since)
			return ok && want(n, was)
		})
		return n, was
	}
	base, _ := reload("the baseline reload to say how many roots it holds", func(n, was int) bool { return n == was })
	extra, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	added := strings.Count(string(extra.Anchors()), "BEGIN CERTIFICATE")
	b.put(rootsRef, "root:root", "0644", orig+"\n"+string(extra.Anchors()))
	reload(fmt.Sprintf("a reload to read %d roots (was %d)", base+added, base), func(n, was int) bool { return n == base+added && was == base })
	b.put(rootsRef, "root:root", "0644", orig)
	reload(fmt.Sprintf("a reload to read %d roots (was %d)", base, base+added), func(n, was int) bool { return n == base && was == base+added })
	if got := b.show("port49-broker", "ExecMainStartTimestamp", "ActiveState"); got["ExecMainStartTimestamp"] != started || got["ActiveState"] != "active" {
		t.Fatalf("a reload restarted or stopped the broker: started %q then %q, state %q", started, got["ExecMainStartTimestamp"], got["ActiveState"])
	}
}

// taskSevenExposure is what Task 7 measured, offline, with systemd 259 after the hardening: the score
// the units must not exceed. Debian trixie's systemd is older, so a higher online score is a finding to
// report, not a number to loosen.
var taskSevenExposure = map[string]float64{"port49d.service": 2.0, "port49-broker.service": 1.8}

// hardeningCell records `systemd-analyze security` for both units and fails above Task 7's numbers.
func hardeningCell(t *testing.T, b box) {
	t.Helper()
	scores, err := sdtest.ParseSecurity(b.sh("systemd-analyze security --no-pager port49d.service port49-broker.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"port49d.service", "port49-broker.service"} {
		got, ok := scores[unit]
		if !ok {
			t.Fatalf("systemd-analyze security printed no row for %s", unit)
		}
		fmt.Fprintf(os.Stderr, "systemd smoke: exposure of %s is %.1f (Task 7, offline: %.1f)\n", unit, got, taskSevenExposure[unit])
		if got > taskSevenExposure[unit] {
			t.Errorf("%s scores %.1f, above Task 7's %.1f: a directive the unit sets is not in force here", unit, got, taskSevenExposure[unit])
		}
	}
}

// listed is the names in dir, sorted.
func listed(b box, dir string) []string {
	names := strings.Fields(b.sh("ls -A " + dir))
	sort.Strings(names)
	return names
}

// backupsCell runs the shipped snapshot unit (with the ETCDCTL_ environment its comment says to set) and
// the shipped export unit. The snapshot is the success path: a 0600 file in the 0700 directory
// tmpfiles-etcd.conf makes, today's name, retention keeping a recent one and dropping an old one. This
// smoke's broker has no directory_password verifier, so the export refuses ("so it holds no second
// factors", internal/port49d/enrollcmd.go): the cell holds the unit's other promise, that a failed
// run changes nothing: no temporary file, no dated file, and no retention sweep.
func backupsCell(t *testing.T, u stack) {
	t.Helper()
	b := u.b
	ex := filepath.Join(u.root, "deploy", "systemd", "examples")
	for _, f := range []string{"port49-etcd-snapshot.service", "port49-enrollments-export.service"} {
		b.put("/etc/systemd/system/"+f, "root:root", "0644", readHost(t, filepath.Join(ex, f)))
	}
	b.sh("mkdir -p /etc/systemd/system/port49-etcd-snapshot.service.d")
	b.put("/etc/systemd/system/port49-etcd-snapshot.service.d/smoke.conf", "root:root", "0644",
		"[Service]\nEnvironment=ETCDCTL_ENDPOINTS="+members[0]+" ETCDCTL_CACERT=/etc/etcd/pki/ca.pem ETCDCTL_CERT=/etc/etcd/pki/root.pem ETCDCTL_KEY=/etc/etcd/pki/root-key.pem\n")
	b.sh("systemctl daemon-reload")

	// The snapshot.
	const snapDir = "/var/backups/port49"
	today := strings.TrimSpace(b.sh("date +%F"))
	b.sh("touch -d '20 days ago' " + snapDir + "/etcd-2000-01-01.db")
	b.sh("touch -d '3 days ago' " + snapDir + "/etcd-2000-01-02.db")
	if out, err := b.exec("", "systemctl", "start", "port49-etcd-snapshot.service"); err != nil {
		t.Fatalf("port49-etcd-snapshot.service: %v\n%s\n%s", err, filter(out), filter(b.journal("port49-etcd-snapshot", 0)))
	}
	st, err := sdtest.ParseStat(b.sh("stat -c '%U:%G %a %n' " + snapDir + " " + snapDir + "/etcd-" + today + ".db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st[0].Want("root:root", "700"); err != nil {
		t.Error(err)
	}
	if err := st[1].Want("root:root", "600"); err != nil {
		t.Error(err)
	}
	if got := listed(b, snapDir); strings.Join(got, " ") != "etcd-2000-01-02.db etcd-"+today+".db" {
		t.Errorf("%s holds %v, want today's snapshot and the 3-day-old one only (the 20-day-old one is retention's)", snapDir, got)
	}

	// The export.
	const expDir = "/var/backups/port49-broker"
	st, err = sdtest.ParseStat(b.sh("stat -c '%U:%G %a %n' " + expDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := st[0].Want("port49-broker:port49-broker", "700"); err != nil {
		t.Error(err)
	}
	b.sh("runuser -u port49-broker -- sh -c \"cd " + expDir + " && umask 077 && touch -d '20 days ago' enrollments-2000-01-01.json && touch -d '3 days ago' enrollments-2000-01-02.json\"")
	since := b.epoch()
	if out, err := b.exec("", "systemctl", "start", "port49-enrollments-export.service"); err == nil {
		t.Fatalf("the export succeeded on a broker with no directory_password verifier:\n%s", filter(out))
	}
	if got := b.show("port49-enrollments-export", "Result")["Result"]; got != "exit-code" {
		t.Errorf("the export unit's Result is %q, want exit-code", got)
	}
	if j := b.journal("port49-enrollments-export", since); !strings.Contains(j, "no directory_password verifier") {
		t.Errorf("the export did not fail for the reason this cell expects:\n%s", filter(j))
	}
	if got := listed(b, expDir); strings.Join(got, " ") != "enrollments-2000-01-01.json enrollments-2000-01-02.json" {
		t.Errorf("a failed export changed %s: it holds %v, want the two files this cell made (no .tmp, no dated file, no retention sweep)", expDir, got)
	}
}
