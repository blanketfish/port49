package port49d

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// brokerStateDir is where the broker keeps its own state (config's
// BrokerStateDir: broker.state_dir on port49-broker, else the directory
// holding broker.revocations_file, as the kept CRLs are; plan 7b).
func brokerStateDir(cfg config.Config) string { return config.BrokerStateDir(cfg.Broker) }

// keyFile is where an issuer's fetched keys are kept (Ruling 4): the name
// config's collision lists check (pre-flight M-11).
func keyFile(stateDir, issuer string) string {
	return filepath.Join(stateDir, oidc.KeyFileName(issuer))
}

// stateDirWords is err, a refusal of the state directory (ownStateDir,
// writeOwnerOnly), as the process that has no broker.state_dir says it: port49d
// keeps its broker's state beside broker.revocations_file, so that is the key
// to name and the one to move. port49-broker's own key stays as it is.
func stateDirWords(cfg config.Config, stateDir string, err error) string {
	text := printsafe.Line(err.Error(), 300)
	if cfg.Broker.StateDir != "" {
		return text
	}
	text = strings.ReplaceAll(text, "broker.state_dir "+stateDir, "the directory of broker.revocations_file ("+stateDir+")")
	return strings.ReplaceAll(text, "port49-broker's own state is kept there; chmod 0700 it",
		"the broker's own state is kept there; chmod it 0700, or move broker.revocations_file into a 0700 directory")
}

// openOIDC builds broker.identity's OIDC set: one key set per issuer,
// shared by the issuer's verifiers, restored from stateDir and kept there.
// It fetches nothing: runKeySets does, so a start never waits on a
// provider (Ruling 4). Nil without an oidc verifier. A state directory it
// cannot keep keys in is said now, in one line, not first at a save an
// hour into a provider outage (pre-flight M-21); the broker still starts.
func openOIDC(cfg config.Config, stateDir string, m *metrics.Metrics, say func(string, ...any)) (*oidc.Set, error) {
	id := cfg.Broker.Identity
	if id == nil || len(id.OIDC) == 0 {
		return nil, nil
	}
	if err := ownStateDir(stateDir); err != nil {
		say("identity: the state directory %s cannot keep the providers' keys (%s): a restart during a provider "+
			"outage will refuse every OIDC token until a fetch succeeds", stateDir, stateDirWords(cfg, stateDir, err))
	}
	set := &oidc.Set{Timing: id.Timing, Now: time.Now, M: m}
	byIssuer := map[string]*oidc.KeySet{}
	for i, v := range id.OIDC {
		ks := byIssuer[v.Issuer]
		if ks == nil {
			var roots *x509.CertPool
			if v.CAFile != "" {
				pem, err := os.ReadFile(v.CAFile)
				if err != nil {
					return nil, fmt.Errorf("config: broker.identity %s verifier %d: ca_file: %w", v.Domain, i, err)
				}
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("config: broker.identity %s verifier %d: ca_file %s holds no certificate",
						v.Domain, i, v.CAFile)
				}
			}
			path := keyFile(stateDir, v.Issuer)
			ks = oidc.NewKeySet(oidc.KeySetConfig{Issuer: v.Issuer, Client: oidc.NewClient(roots),
				Refresh: id.Timing.JWKSRefresh, MaxAge: id.Timing.JWKSMaxAge, Now: time.Now, Say: say, M: m, Proc: procOf(cfg),
				Save: func(b []byte) error {
					if err := writeOwnerOnly(path, b); err != nil {
						return errors.New(stateDirWords(cfg, stateDir, err))
					}
					return nil
				},
				Load: func() ([]byte, error) { return readOwnerOnly(path) }})
			switch n, at, err := ks.Restore(); {
			case err != nil:
				say("identity: %s: the kept keys in %s are not used: %s", v.Issuer, path, printsafe.Line(err.Error(), 200))
			case n > 0:
				say("identity: %s: restored %d keys fetched %s from %s", v.Issuer, n, at.UTC().Format(time.RFC3339), path)
			}
			byIssuer[v.Issuer] = ks
		}
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: v, Keys: ks})
	}
	return set, nil
}

// runKeySets runs each issuer's refresh loop until ctx ends.
func runKeySets(ctx context.Context, set *oidc.Set) {
	if set == nil {
		return
	}
	var wg sync.WaitGroup
	seen := map[*oidc.KeySet]bool{}
	for _, v := range set.Verifiers {
		if seen[v.Keys] {
			continue
		}
		seen[v.Keys] = true
		wg.Add(1)
		go func(ks *oidc.KeySet) { defer wg.Done(); ks.Run(ctx) }(v.Keys)
	}
	wg.Wait()
}

// announceIdentity is the start's identity lines (What the operator sees).
func announceIdentity(w io.Writer, proc string, cfg config.Config, _ *oidc.Set) {
	id := cfg.Broker.Identity
	if id == nil {
		return
	}
	if id.Shorthand {
		fmt.Fprintf(w, "%s: identity: humans: x509 from broker.client_ca_file (no broker.identity is configured); "+
			"no OIDC verifier\n", proc)
		return
	}
	var humans, machines []string
	if id.X509AnchorFile != "" {
		humans = append(humans, "x509 (trust anchor "+id.X509AnchorFile+")")
	}
	algs := func(as []oidc.Alg) string {
		var s []string
		for _, a := range as {
			s = append(s, string(a))
		}
		return strings.Join(s, ", ")
	}
	for _, v := range id.OIDC {
		switch v.Domain {
		case oidc.Humans:
			claim := "principal from " + v.PrincipalClaim + " in " + strings.Join(v.PrincipalDomains, ", ")
			if v.PrincipalClaim == oidc.ClaimEmail {
				claim += ", email_verified required"
			}
			humans = append(humans, fmt.Sprintf("oidc %s (client_id %s, %s; algorithms %s)", v.Issuer, v.ClientID,
				claim, algs(v.Algorithms)))
		case oidc.Machines:
			var clients []string
			for _, c := range v.Clients {
				clients = append(clients, fmt.Sprintf("%s (sub %s)", c.ClientID, c.Sub))
			}
			machines = append(machines, fmt.Sprintf("oidc %s (audience %s; clients %s; principal app:<azp>; "+
				"algorithms %s)", v.Issuer, v.Audience, strings.Join(clients, ", "), algs(v.Algorithms)))
		}
	}
	if len(humans) > 0 {
		fmt.Fprintf(w, "%s: identity: humans: %s\n", proc, strings.Join(humans, "; "))
	}
	if len(machines) > 0 {
		fmt.Fprintf(w, "%s: identity: machines: %s\n", proc, strings.Join(machines, "; "))
	}
	for _, v := range id.OIDC {
		if v.Domain == oidc.Humans {
			fmt.Fprintf(w, "%s: identity: the principal claim must be one only the identity provider's "+
				"administrators can set: a person who can edit their own would choose whose principal they are; on a "+
				"provider brokering another, turn off \"trust email\"\n", proc)
			break
		}
	}
	// Once per issuer: how it is reached (pre-flight I-5) and what anchors it.
	seen := map[string]bool{}
	for _, v := range id.OIDC {
		if seen[v.Issuer] {
			continue
		}
		seen[v.Issuer] = true
		how := "directly (no HTTPS_PROXY)"
		if u, err := oidc.ProxyFor(v.Issuer); err == nil {
			how = oidc.DescribeProxy(u)
		} else {
			// The transport takes the environment's proxy as it parses it: a
			// value that does not is dropped or misread, never refused (final
			// review F3). The value is not said: it carries a password.
			how = "with an HTTPS_PROXY that is set but does not parse as a proxy URL (percent-encode '#', '/', '?' and " +
				"'%' in its password): the key fetch drops it and dials directly, or misreads it and dials a host nobody " +
				"configured, which a proxy-only egress refuses"
		}
		fmt.Fprintf(w, "%s: identity: %s is fetched %s\n", proc, v.Issuer, how)
	}
	clear(seen)
	for _, v := range id.OIDC {
		if v.CAFile == "" && !seen[v.Issuer] {
			seen[v.Issuer] = true
			fmt.Fprintf(w, "%s: identity: %s is trusted through the system's root certificates (no ca_file)\n", proc,
				v.Issuer)
		}
	}
	fmt.Fprintf(w, "%s: identity: keys refreshed every %s; trusted without a refresh until %s after the last "+
		"(broker.identity.jwks_max_age); clock_skew %s; max_token_age %s\n", proc, id.Timing.JWKSRefresh,
		id.Timing.JWKSMaxAge, id.Timing.ClockSkew, id.Timing.MaxTokenAge)
}
