package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// descriptionsFile is the file the generated port49d reference is written from (internal/docgen). It
// is read as data: docgen imports this package, so this package cannot import it.
const descriptionsFile = "../docgen/descriptions/port49d.yaml"

// shown is a duration the way the reference writes one: 10m, 12h, 500ms.
func shown(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// TestTheDocsDescribeTheseDefaults loads a daemon config that sets none of the keys below and holds
// the reference's "Default `x`" for each to the value the loader gave it, so a changed default cannot
// leave the page saying the old one.
func TestTheDocsDescribeTheseDefaults(t *testing.T) {
	raw, err := os.ReadFile(descriptionsFile)
	if err != nil {
		t.Fatal(err)
	}
	desc := map[string]string{}
	if err := yaml.Unmarshal(raw, &desc); err != nil {
		t.Fatal(err)
	}

	setKeyEnv(t)
	body := strings.Replace(sample, `listen: ":4949"`+"\n", "", 1)
	body = strings.Replace(body, "limits: {per_nas_connections: 4}\n", "", 1)
	invPath := write(t, "inventory.yaml", inv)
	c, err := Load(write(t, "port49d.yaml", fmt.Sprintf(body, invPath)))
	if err != nil {
		t.Fatal(err)
	}

	// The broker's defaults come from a config with a broker block and an identity block, whose human
	// OIDC verifier gets the empty issuance block it needs (brokerWithIdentity).
	bc, err := loadWith(t, brokerWithIdentity(twoLists))
	if err != nil {
		t.Fatal(err)
	}
	b, id := bc.Broker, bc.Broker.Identity

	want := map[string]string{
		"inventory.max_removed_percent":                 strconv.Itoa(bc.MaxRemovedPercent),
		"broker.batch_max":                              strconv.Itoa(b.BatchMax),
		"broker.policy_watch_interval":                  shown(b.PolicyWatchInterval),
		"broker.max_conns_per_principal":                strconv.Itoa(b.MaxConnsPerPrincipal),
		"broker.max_pending_conns_per_source":           strconv.Itoa(b.MaxPendingConnsPerSource),
		"broker.refresh_interval":                       shown(b.RefreshInterval),
		"broker.identity.clock_skew":                    shown(id.Timing.ClockSkew),
		"broker.identity.max_token_age":                 shown(id.Timing.MaxTokenAge),
		"broker.identity.jwks_refresh_interval":         shown(id.Timing.JWKSRefresh),
		"broker.identity.jwks_max_age":                  shown(id.Timing.JWKSMaxAge),
		"broker.identity.issuance.certificate_lifetime": shown(id.Issuance.CertificateLifetime),
	}
	for key, v := range map[string]string{
		"listen":                          c.Listen,
		"metrics_listen":                  c.MetricsListen,
		"limits.per_nas_connections":      strconv.Itoa(c.Limits.PerNASConnections),
		"limits.idle_timeout":             shown(c.Limits.IdleTimeout),
		"limits.malformed_backoff_base":   shown(c.Limits.MalformedBackoffBase),
		"limits.malformed_backoff_max":    shown(c.Limits.MalformedBackoffMax),
		"limits.malformed_window":         shown(c.Limits.MalformedWindow),
		"limits.auth_failure_delay_base":  shown(c.Limits.AuthFailureDelayBase),
		"limits.auth_failure_delay_max":   shown(c.Limits.AuthFailureDelayMax),
		"limits.auth_failure_window":      shown(c.Limits.AuthFailureWindow),
		"receipt_idle_ttl":                shown(c.ReceiptIdleTTL),
		"receipt_max_age":                 shown(c.ReceiptMaxAge),
		"context_idle_ttl":                shown(c.ContextIdleTTL),
		"accounting.spool_capacity":       strconv.Itoa(c.Accounting.SpoolCapacity),
		"accounting.spool_path":           c.Accounting.SpoolPath,
		"session.grace_window":            shown(c.Session.GraceWindow),
		"session.index_ttl":               shown(c.Session.IndexTTL),
		"session.max_session_age_default": shown(c.Session.MaxSessionAgeDefault),
		"session.ceiling_warning":         shown(c.Session.CeilingWarning),
		"session.staleness_ceiling":       shown(c.Session.StalenessCeiling),
		"token.candidate_cap":             strconv.Itoa(c.Token.CandidateCap),
	} {
		want[key] = v
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		d, ok := desc[key]
		if !ok {
			t.Errorf("%s has no description", key)
			continue
		}
		if !strings.Contains(d, "Default `"+want[key]+"`") {
			t.Errorf("%s: the loader's default is %q, and the description does not say Default `%s`", key, want[key], want[key])
		}
	}
}
