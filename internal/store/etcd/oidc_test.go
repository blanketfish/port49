package etcd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// A once-only, owner or logout record that does not decode is an error that
// says which operation and which kind of record, never the key: the key is
// a jti, a sid or a sub, and none appears in an error string (plan 7h).
func TestAnUndecodableOIDCRecordNamesNoKey(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	const jti, sid = "jti-9f3a77c1-secret", "sid-4be1d20e-secret"
	owner := store.OIDCKey(store.OIDCSid, "https://sso.example.com", sid)
	for _, k := range []string{s.k.once(jti), s.k.oidcOwner(owner), s.k.logout(owner)} {
		if _, err := s.tok.Put(ctx, k, "{"); err != nil {
			t.Fatal(err)
		}
	}
	_, putErr := s.PutOnce(ctx, jti, []byte("v"), time.Hour)
	_, takeErr := s.TakeOnce(ctx, jti)
	_, ownerErr := s.OIDCOwner(ctx, owner)
	_, logoutErr := s.GetLogout(ctx, owner)
	for name, err := range map[string]error{
		"PutOnce": putErr, "TakeOnce": takeErr, "PutOIDCOwner": s.PutOIDCOwner(ctx, owner, "user:a@example.com", time.Hour),
		"OIDCOwner": ownerErr, "PutLogout": s.PutLogout(ctx, store.Logout{Key: owner, At: time.Now()}, time.Hour),
		"GetLogout": logoutErr,
	} {
		if err == nil {
			t.Fatalf("%s read an undecodable record", name)
		}
		if strings.Contains(err.Error(), jti) || strings.Contains(err.Error(), sid) {
			t.Fatalf("%s's error names the key: %v", name, err)
		}
	}
}
