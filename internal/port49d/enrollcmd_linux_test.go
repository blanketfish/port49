package port49d

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/store/etcd"
)

// On etcd the commands open the directory store on the broker's identity: init
// creates the mark in the directory member once, a second run says it is
// already there, and the export is bytes the same store's import accepts
// (port49-broker; spec §12).
func TestBrokerInitAndExportEnrollmentsOnEtcd(t *testing.T) {
	srv, proxy := rolesMemberScoped(t, etcd.ScopeDirectory)
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	cfg.Broker.Directory.EnrollmentStore = directory.EnrollmentStore{Backend: config.BackendEtcd}
	bc, bk := srv.ClientFiles(t, "port49-broker")
	cfg.Role, cfg.Stores.Shared = config.RoleBroker, true
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: &config.EtcdConfig{
		Endpoints: []string{"https://" + proxy.Addr()}, CAFile: filepath.Join(srv.Dir, "ca.pem"),
		Broker:      &config.EtcdIdentity{CertFile: bc, KeyFile: bk},
		CallTimeout: 500 * time.Millisecond, BulkTimeout: 5 * time.Second, StartTimeout: 10 * time.Second,
		Breaker:     config.EtcdBreaker{Failures: 5, OpenFor: time.Second},
		MaxInFlight: config.EtcdInFlight{Token: 8, Context: 8, Bulk: 2}}}
	cfg.Stores.Session = cfg.Stores.Directory
	ctx := context.Background()
	run := func(op string, stdout io.Writer) (int, string) {
		var stderr bytes.Buffer
		return runEnrollments(ctx, "port49-broker", op, cfg, signInTestKeys, io.Discard, stdout, &stderr), stderr.String()
	}
	var out, sealed bytes.Buffer
	if code, say := run("init-enrollments", &out); code != 0 || !strings.Contains(out.String(), "created the enrollment store") {
		t.Fatalf("init: exit %d: %q %q", code, out.String(), say)
	}
	if n := keysUnder(t, srv, "/port49/v1/"); n == 0 {
		t.Fatal("init wrote nothing to the directory member")
	}
	out.Reset()
	if code, say := run("init-enrollments", &out); code != 1 || !strings.Contains(say, "already") {
		t.Fatalf("a second init: exit %d: %q", code, say)
	}
	if code, say := run("export-enrollments", &sealed); code != 0 || sealed.Len() == 0 {
		t.Fatalf("export: exit %d, %d bytes: %s", code, sealed.Len(), say)
	}
}
