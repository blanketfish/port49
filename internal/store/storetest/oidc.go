package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// OncePutsOnceAndTakesOnce: a once-only record is written only where none
// lives, and taken once (plan 7h, Rulings 12 and 15).
func OncePutsOnceAndTakesOnce(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v1"), time.Hour); err != nil || !ok {
		t.Fatalf("the first put: %v %v", ok, err)
	}
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v2"), time.Hour); err != nil || ok {
		t.Fatalf("a second put wrote: %v %v", ok, err)
	}
	v, err := s.TakeOnce(ctx, "jti a")
	if err != nil || !bytes.Equal(v, []byte("v1")) {
		t.Fatalf("take: %q %v", v, err)
	}
	if _, err := s.TakeOnce(ctx, "jti a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second take: %v", err)
	}
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v3"), time.Hour); err != nil || !ok {
		t.Fatalf("a put after the take: %v %v", ok, err)
	}
	if _, err := s.TakeOnce(ctx, "never"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("taking a key never put: %v", err)
	}
}

// OnceExpires: past its TTL a record is gone for a take and for a put.
func OnceExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	if ok, _ := s.PutOnce(ctx, "challenge x", []byte("v"), time.Minute); !ok {
		t.Fatal("the put")
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if _, err := s.TakeOnce(ctx, "challenge x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired record was taken: %v", err)
	}
	if ok, err := s.PutOnce(ctx, "challenge x", []byte("w"), time.Minute); err != nil || !ok {
		t.Fatalf("a put over an expired record: %v %v", ok, err)
	}
}

// OnceRaces: of many concurrent puts one writes, and of many concurrent
// takes one gets the value.
func OnceRaces(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	for round := range 20 {
		key := "race " + string(rune('a'+round))
		var wrote, took atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := s.PutOnce(ctx, key, []byte("v"), time.Hour); err == nil && ok {
					wrote.Add(1)
				}
			}()
		}
		wg.Wait()
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.TakeOnce(ctx, key); err == nil {
					took.Add(1)
				}
			}()
		}
		wg.Wait()
		if wrote.Load() != 1 || took.Load() != 1 {
			t.Fatalf("round %d: %d puts wrote, %d takes took", round, wrote.Load(), took.Load())
		}
	}
}

// OIDCOwnerKeepsEveryPrincipal: an owner record holds every principal
// written under it, each with its own life and its last WrittenAt, and
// lapses with the last of them (plan 7h, Ruling 24; pre-flight I-1). A
// rename under one sub adds a principal; it never replaces one.
func OIDCOwnerKeepsEveryPrincipal(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", "8b2e")
	if _, err := s.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an owner never written: %v", err)
	}
	put := func(p string, ttl time.Duration) {
		t.Helper()
		if err := s.PutOIDCOwner(ctx, key, p, ttl); err != nil {
			t.Fatal(err)
		}
	}
	put("user:alice@example.com", time.Hour)
	advance(10 * time.Minute)
	put("user:alice@example.com", time.Hour)    // renewed: one entry, WrittenAt moves
	put("user:alice2@example.com", 2*time.Hour) // renamed: a second entry
	o, err := s.OIDCOwner(ctx, key)
	if err != nil || strings.Join(o.Names(), ",") != "user:alice2@example.com,user:alice@example.com" {
		t.Fatalf("owner %+v %v: both principals, sorted", o, err)
	}
	if a, ok := o.Entry("user:alice@example.com"); !ok || !a.WrittenAt.Equal(t0.Add(10*time.Minute)) ||
		!a.ExpiresAt.Equal(t0.Add(70*time.Minute)) {
		t.Fatalf("alice's entry %+v", a)
	}
	advance(61 * time.Minute) // alice's entry lapsed; alice2's stands
	if o, err := s.OIDCOwner(ctx, key); err != nil || strings.Join(o.Names(), ",") != "user:alice2@example.com" {
		t.Fatalf("after alice's entry lapsed: %+v %v", o, err)
	}
	advance(time.Hour)
	if _, err := s.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an owner past every entry's life: %v", err)
	}
	if err := s.PutOIDCOwner(ctx, "", "user:x@example.com", time.Hour); !errors.Is(err, store.ErrNoKey) {
		t.Fatalf("an owner with no key: %v", err)
	}
}

// OIDCOwnerMergesUnderARace: concurrent writes of different principals
// under one key all land; a compare-and-set merge loses none.
func OIDCOwnerMergesUnderARace(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	key := store.OIDCKey(store.OIDCSid, "https://sso.example.com", "s-race")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.PutOIDCOwner(ctx, key, fmt.Sprintf("user:p%d@example.com", i), time.Hour); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if o, err := s.OIDCOwner(ctx, key); err != nil || len(o.Principals) != 8 {
		t.Fatalf("%d of 8 principals kept: %v", len(o.Principals), err)
	}
}

// LogoutKeepsTheLaterAndExpires: of two logouts under one key the later
// At stands, with the longer life; past it the record is gone.
func LogoutKeepsTheLaterAndExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", "8b2e")
	if _, err := s.GetLogout(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a logout never written: %v", err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: key, At: t0, Origin: "backchannel_logout x"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: key, At: t0.Add(-time.Minute), Origin: "older"}, 3*time.Hour); err != nil {
		t.Fatal(err)
	}
	l, err := s.GetLogout(ctx, key)
	if err != nil || !l.At.Equal(t0) || l.Origin != "backchannel_logout x" || l.Key != key {
		t.Fatalf("logout %+v %v: the later At stands", l, err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetLogout(ctx, key); err != nil {
		t.Fatalf("the longer life was not kept: %v", err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetLogout(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a logout past its life: %v", err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: "", At: t0}, time.Hour); err == nil {
		t.Fatal("a logout with no key was written")
	}
}

// MFAProofKeepsTheLaterAndExpires: of two proofs under one key the later At
// stands, with the longer life; past it the proof is gone, and a key with no
// life or no name is refused (plan 9c, Task 11).
func MFAProofKeepsTheLaterAndExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	const key = "0a1b2c3d/hardware_key_touch"
	if _, err := s.GetMFAProof(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a proof never written: %v", err)
	}
	if err := s.PutMFAProof(ctx, store.MFAProof{Key: key, Method: "hardware_key_touch", At: t0}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMFAProof(ctx, store.MFAProof{Key: key, Method: "hardware_key_touch", At: t0.Add(-time.Minute)},
		3*time.Hour); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetMFAProof(ctx, key)
	if err != nil || !p.At.Equal(t0) || p.Method != "hardware_key_touch" || p.Key != key {
		t.Fatalf("proof %+v %v: the later At stands", p, err)
	}
	if err := s.PutMFAProof(ctx, store.MFAProof{Key: key, Method: "hardware_key_touch", At: t0.Add(time.Minute)},
		time.Minute); err != nil {
		t.Fatal(err)
	}
	if p, err = s.GetMFAProof(ctx, key); err != nil || !p.At.Equal(t0.Add(time.Minute)) {
		t.Fatalf("proof %+v %v: a later proof replaces the earlier", p, err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetMFAProof(ctx, key); err != nil {
		t.Fatalf("the longer life was not kept: %v", err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetMFAProof(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a proof past its life: %v", err)
	}
	if err := s.PutMFAProof(ctx, store.MFAProof{Key: "", At: t0}, time.Hour); !errors.Is(err, store.ErrNoKey) {
		t.Fatalf("a proof with no key: %v", err)
	}
	if err := s.PutMFAProof(ctx, store.MFAProof{Key: key, At: t0}, 0); !errors.Is(err, store.ErrBadTTL) {
		t.Fatalf("a proof with no life: %v", err)
	}
}

// LogoutMergesUnderARace: of concurrent logouts under one key, whatever
// order they land in, the latest At stands with its origin, and a write that
// reads, merges and writes without a compare would let an older one win.
func LogoutMergesUnderARace(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	for round := range 20 {
		key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", fmt.Sprintf("sub-race-%d", round))
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				l := store.Logout{Key: key, At: t0.Add(time.Duration(i) * time.Minute), Origin: fmt.Sprintf("origin %d", i)}
				if err := s.PutLogout(ctx, l, time.Duration(i+1)*time.Hour); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		l, err := s.GetLogout(ctx, key)
		if err != nil || !l.At.Equal(t0.Add(7*time.Minute)) || l.Origin != "origin 7" {
			t.Fatalf("round %d: logout %+v %v: the latest At must stand", round, l, err)
		}
	}
}

// OIDCRecordsRefuseWhatCannotBeKept: an owner with no principal, and a
// record with no life, are refused with an error naming neither key nor
// value, and write nothing.
func OIDCRecordsRefuseWhatCannotBeKept(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", "8b2e")
	const secret = "jti-never-in-an-error"
	if err := s.PutOIDCOwner(ctx, key, "", time.Hour); !errors.Is(err, store.ErrNoPrincipal) {
		t.Fatalf("an owner with no principal: %v", err)
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		_, onceErr := s.PutOnce(ctx, secret, []byte(secret), ttl)
		ownerErr := s.PutOIDCOwner(ctx, key, "user:a@example.com", ttl)
		logoutErr := s.PutLogout(ctx, store.Logout{Key: key, At: t0}, ttl)
		for name, err := range map[string]error{"PutOnce": onceErr, "PutOIDCOwner": ownerErr, "PutLogout": logoutErr} {
			if !errors.Is(err, store.ErrBadTTL) {
				t.Fatalf("%s with a ttl of %v: %v", name, ttl, err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "8b2e") {
				t.Fatalf("%s's error names a key or value: %v", name, err)
			}
		}
	}
	if _, err := s.TakeOnce(ctx, secret); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused put wrote: %v", err)
	}
	if _, err := s.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused put wrote an owner: %v", err)
	}
	if _, err := s.GetLogout(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused put wrote a logout: %v", err)
	}
}
