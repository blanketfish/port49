package port49d

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// memRecorder is an issuerRecorder in memory with etcd's compare-and-swap:
// racer runs inside PutIssuerRecord before the compare, as another broker's
// write landing first.
type memRecorder struct {
	mu    sync.Mutex
	rec   etcdstore.IssuerRecord
	rev   uint64
	racer func()
	err   error
}

func (m *memRecorder) IssuerRecord(context.Context) (etcdstore.IssuerRecord, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rec, m.rev, m.err
}

func (m *memRecorder) PutIssuerRecord(_ context.Context, r etcdstore.IssuerRecord, over uint64) (bool, error) {
	if m.racer != nil {
		racer := m.racer
		m.racer = nil
		racer()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rev != over {
		return false, nil
	}
	r.WrittenAt = time.Now().UTC()
	m.rec, m.rev = r, m.rev+1
	return true, nil
}

// The record follows a rotation: a broker promoted here starts and updates it,
// one restarted before its files were copied is refused with the copy, and a
// broker with another CA is refused with both fingerprints (Review Focus 6;
// decision 53 ruling 10).
func TestTheIssuerRecordFollowsARotation(t *testing.T) {
	ctx := context.Background()
	rec := &memRecorder{}
	var out bytes.Buffer
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@a", &out); err != nil ||
		rec.rec.Current != "sha256:f1" || !strings.Contains(out.String(), "recorded the issuing CA sha256:f1") {
		t.Fatalf("first: %v %+v\n%s", err, rec.rec, out.String())
	}
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@b", &out); err != nil {
		t.Fatalf("same: %v", err)
	}
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f2", previous: "sha256:f1"}, "port49-broker@a", &out); err != nil ||
		rec.rec.Current != "sha256:f2" || rec.rec.Previous != "sha256:f1" {
		t.Fatalf("promoted: %v %+v", err, rec.rec)
	}
	err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@b", &out)
	if err == nil || !strings.Contains(err.Error(), "behind a promotion") || !strings.Contains(err.Error(), "issuing-ca-previous.pem") {
		t.Fatalf("behind: %v", err)
	}
	err = checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f9"}, "port49-broker@c", &out)
	if err == nil || !strings.Contains(err.Error(), "sha256:f9") || !strings.Contains(err.Error(), "sha256:f2") ||
		!strings.Contains(err.Error(), "forget-issuer") {
		t.Fatalf("other: %v", err)
	}
}

// Two brokers recording at once: the loser reads the winner's record and is
// judged against it.
func TestALostRaceToRecordIsJudgedAgain(t *testing.T) {
	rec := &memRecorder{}
	rec.racer = func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.rec, rec.rev = etcdstore.IssuerRecord{Current: "sha256:other", WrittenBy: "port49-broker@x"}, 1
	}
	var out bytes.Buffer
	err := checkIssuerRecord(context.Background(), rec, heldCA{current: "sha256:mine"}, "port49-broker@a", &out)
	if err == nil || !strings.Contains(err.Error(), "sha256:mine") || !strings.Contains(err.Error(), "sha256:other") {
		t.Fatalf("%v", err)
	}
	if rec.rec.Current != "sha256:other" {
		t.Fatalf("the loser wrote over the winner: %+v", rec.rec)
	}
	// And a loser holding the winner's CA is simply fine.
	rec = &memRecorder{}
	rec.racer = func() {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.rec, rec.rev = etcdstore.IssuerRecord{Current: "sha256:same"}, 1
	}
	if err := checkIssuerRecord(context.Background(), rec, heldCA{current: "sha256:same"}, "b", &out); err != nil {
		t.Fatalf("%v", err)
	}
}

// A store that does not answer is the caller's outage, not a refusal; a
// record that keeps changing ends in a fixed message.
func TestTheIssuerRecordSaysAnOutageAndAChurn(t *testing.T) {
	outage := errors.New("store: unavailable")
	if err := checkIssuerRecord(context.Background(), &memRecorder{err: outage}, heldCA{current: "sha256:a"}, "w",
		&bytes.Buffer{}); !errors.Is(err, outage) {
		t.Fatalf("%v", err)
	}
	churn := &churnRecorder{}
	err := checkIssuerRecord(context.Background(), churn, heldCA{current: "sha256:a"}, "w", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "kept changing") || churn.puts != 3 {
		t.Fatalf("%v after %d tries", err, churn.puts)
	}
}

// churnRecorder always loses the compare.
type churnRecorder struct{ puts int }

func (c *churnRecorder) IssuerRecord(context.Context) (etcdstore.IssuerRecord, uint64, error) {
	return etcdstore.IssuerRecord{}, 0, nil
}

func (c *churnRecorder) PutIssuerRecord(context.Context, etcdstore.IssuerRecord, uint64) (bool, error) {
	c.puts++
	return false, nil
}

// A rotation never goes backward: files {f1, previous f2} against a record
// {f2, previous f1} are a broker holding the CA the rotation retired (a copied
// or tampered file), refused as behind and never announced as a promotion.
func TestARollbackIsRefusedAndNotTakenForAPromotion(t *testing.T) {
	rec := &memRecorder{rec: etcdstore.IssuerRecord{Current: "sha256:f2", Previous: "sha256:f1"}, rev: 1}
	var out bytes.Buffer
	err := checkIssuerRecord(context.Background(), rec, heldCA{current: "sha256:f1", previous: "sha256:f2"},
		"port49-broker@a", &out)
	if err == nil || !strings.Contains(err.Error(), "behind a promotion") {
		t.Fatalf("a rollback: %v", err)
	}
	if rec.rec.Current != "sha256:f2" || rec.rev != 1 || strings.Contains(out.String(), "promoted") {
		t.Fatalf("the record moved or a promotion was said: %+v rev %d\n%s", rec.rec, rec.rev, out.String())
	}
}
