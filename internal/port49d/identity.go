package port49d

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/egress"
	"github.com/rhwendt/port49/internal/k8sid"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
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

// openOIDC builds broker.identity's OIDC and k8s set: one key set per issuer,
// shared by the issuer's verifiers, restored from stateDir and kept there.
// It fetches nothing: runKeySets does, so a start never waits on a
// provider (Ruling 4). Nil without an oidc or k8s verifier. A state directory it
// cannot keep keys in is said now, in one line, not first at a save an
// hour into a provider outage (pre-flight M-21); the broker still starts.
func openOIDC(cfg config.Config, stateDir string, m *metrics.Metrics, say func(string, ...any)) (*oidc.Set, error) {
	id := cfg.Broker.Identity
	if id == nil {
		return nil, nil
	}
	vs := append(slices.Clone(id.OIDC), id.K8s...)
	if len(vs) == 0 {
		return nil, nil
	}
	if err := ownStateDir(stateDir); err != nil {
		say("identity: the state directory %s cannot keep the providers' keys (%s): a restart during a provider "+
			"outage will refuse every OIDC token until a fetch succeeds", stateDir, stateDirWords(cfg, stateDir, err))
	}
	set := &oidc.Set{Timing: id.Timing, Now: time.Now, M: m}
	byIssuer := map[string]*oidc.KeySet{}
	for i, v := range vs {
		if v.Kind == oidc.KindK8s {
			i -= len(id.OIDC) // a k8s verifier's index among the k8s ones, as the config lists them
		}
		ks := byIssuer[v.Issuer]
		if ks == nil {
			var roots *x509.CertPool
			if v.CAFile != "" {
				pem, err := os.ReadFile(v.CAFile)
				if err != nil {
					return nil, fmt.Errorf("config: broker.identity %s: ca_file: %w", verifierName(v, i), err)
				}
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("config: broker.identity %s: ca_file %s holds no certificate",
						verifierName(v, i), v.CAFile)
				}
			}
			path := keyFile(stateDir, v.Issuer)
			ks = oidc.NewKeySet(oidc.KeySetConfig{Issuer: v.Issuer, JWKS: v.JWKS, Who: v.Who(),
				Migrating: migrating(id.K8s, v), Client: oidc.NewClient(roots),
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

// verifierName is how a ca_file error names verifier i of vs (OIDC verifiers
// first, then k8s): "machines verifier 1", "machines k8s verifier 2".
func verifierName(v oidc.VerifierConfig, i int) string {
	if v.Kind == oidc.KindK8s {
		return fmt.Sprintf("%s k8s verifier %d", v.Domain, i)
	}
	return fmt.Sprintf("%s verifier %d", v.Domain, i)
}

// migrating is the issuers of the other k8s verifiers on v's JWKS: one
// cluster changing its issuer is two verifiers on one JWKS (decision 49
// ruling 4), and the key set says nothing about the discovery document naming
// either. Nil for an OIDC verifier.
func migrating(ks []oidc.VerifierConfig, v oidc.VerifierConfig) []string {
	if v.Kind != oidc.KindK8s {
		return nil
	}
	var out []string
	for _, o := range ks {
		if o.JWKS == v.JWKS && o.Issuer != v.Issuer && !slices.Contains(out, o.Issuer) {
			out = append(out, o.Issuer)
		}
	}
	return out
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

// announceWorkloadIdentities says the policy's spiffe:// identities no
// verifier can give (decision 40 ruling 16): with no workload verifier, all
// of them; with one, those whose trust domain it does not list. The policy
// still loads, as a group subject without a directory does.
func announceWorkloadIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	ids := pol.SPIFFEIdentities()
	if len(ids) == 0 || cfg.Broker == nil {
		return
	}
	var m *oidc.X509Machine
	if cfg.Broker.Identity != nil {
		m = cfg.Broker.Identity.X509Machine
	}
	var lines []string
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		parsed, err := spiffe.ParseWorkload(id)
		switch {
		case err != nil:
			continue // the policy's load refused it already
		case m == nil:
			lines = append(lines, fmt.Sprintf("%s (subject %s): no broker.identity.machines x509 verifier is configured",
				id, ids[id]))
		case !slices.Contains(m.TrustDomains, parsed.TrustDomain):
			lines = append(lines, fmt.Sprintf("%s (subject %s): no machines x509 verifier lists trust domain %s",
				id, ids[id], parsed.TrustDomain))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintf(w, "%s: policy: %d workload identities mint for no one: %s\n", proc, len(lines),
			strings.Join(lines, "; "))
	}
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
	for _, v := range id.K8s {
		machines = append(machines, fmt.Sprintf("k8s cluster %s (issuer %s; keys from %s; audience %s; namespaces %s; "+
			"principal system:serviceaccount:<namespace>:<name>; algorithms %s)", v.Cluster, v.Issuer, v.JWKS,
			v.Audience, strings.Join(v.Namespaces, ", "), algs(v.Algorithms)))
	}
	if m := id.X509Machine; m != nil {
		machines = append([]string{fmt.Sprintf("x509 (trust anchor %s; SPIFFE trust domains %s; principal: the "+
			"certificate's one URI SAN)", m.AnchorFile, strings.Join(m.TrustDomains, ", "))}, machines...)
	}
	if len(humans) > 0 {
		fmt.Fprintf(w, "%s: identity: humans: %s\n", proc, strings.Join(humans, "; "))
	}
	if len(machines) > 0 {
		fmt.Fprintf(w, "%s: identity: machines: %s\n", proc, strings.Join(machines, "; "))
	}
	if len(id.K8s) > 0 {
		fmt.Fprintf(w, "%s: identity: a k8s verifier trusts its cluster's administrators: whoever can create a pod or a "+
			"token for a service account in a listed namespace mints as it; a token stays valid here until its exp or "+
			"max_token_age after its pod or service account is deleted; port49 revoke --principal ends it at once\n", proc)
		fmt.Fprintf(w, "%s: identity: k8s namespaces: %s\n", proc, vouching(id.K8s))
	}
	if id.X509Machine != nil {
		fmt.Fprintf(w, "%s: identity: workload certificates are issued and renewed by your CA, never by port49; "+
			"one presented with under a quarter of its validity left is said here and counted in "+
			"port49_workload_certificates_renewal_late_total\n", proc)
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
	fetched := append(slices.Clone(id.OIDC), id.K8s...)
	for _, v := range fetched {
		if seen[v.Issuer] {
			continue
		}
		seen[v.Issuer] = true
		// A k8s verifier's fetch dials its jwks, not its issuer (often a name
		// only the cluster resolves), so the proxy is the jwks host's and the
		// line names it (pre-flight I9).
		target, host := v.Issuer, ""
		if v.Kind == oidc.KindK8s {
			target = v.JWKS
			if u, err := url.Parse(v.JWKS); err == nil {
				host = " (its jwks host " + u.Host + ")"
			}
		}
		how := "directly (no HTTPS_PROXY)"
		if u, err := egress.ProxyFor(target); err == nil {
			how = egress.Describe(u)
		} else {
			// The transport takes the environment's proxy as it parses it: a
			// value that does not is dropped or misread, never refused (final
			// review F3). The value is not said: it carries a password.
			how = "with an HTTPS_PROXY that is set but does not parse as a proxy URL (percent-encode '#', '/', '?' and " +
				"'%' in its password): the key fetch drops it and dials directly, or misreads it and dials a host nobody " +
				"configured, which a proxy-only egress refuses"
		}
		fmt.Fprintf(w, "%s: identity: %s is fetched %s%s\n", proc, v.Who(), how, host)
	}
	clear(seen)
	for _, v := range fetched {
		if v.CAFile == "" && !seen[v.Issuer] {
			seen[v.Issuer] = true
			fmt.Fprintf(w, "%s: identity: %s is trusted through the system's root certificates (no ca_file)\n", proc,
				v.Who())
		}
	}
	fmt.Fprintf(w, "%s: identity: keys refreshed every %s; trusted without a refresh until %s after the last "+
		"(broker.identity.jwks_max_age); clock_skew %s; max_token_age %s\n", proc, id.Timing.JWKSRefresh,
		id.Timing.JWKSMaxAge, id.Timing.ClockSkew, id.Timing.MaxTokenAge)
}

// announceServiceAccountIdentities says the policy's system:serviceaccount:
// identities no verifier can give (decision 49 ruling 13): with no k8s
// verifier, all of them; with some, those whose namespace none lists.
func announceServiceAccountIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	ids := pol.ServiceAccountIdentities()
	if len(ids) == 0 || cfg.Broker == nil {
		return
	}
	var ks []oidc.VerifierConfig
	if cfg.Broker.Identity != nil {
		ks = cfg.Broker.Identity.K8s
	}
	var lines []string
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		parsed, err := k8sid.Parse(id)
		switch {
		case err != nil:
			continue // the policy's load refused it already
		case len(ks) == 0:
			lines = append(lines, fmt.Sprintf("%s (subject %s): no broker.identity.machines k8s verifier is configured",
				id, ids[id]))
		case !slices.ContainsFunc(ks, func(v oidc.VerifierConfig) bool { return v.ListsNamespace(parsed.Namespace) }):
			lines = append(lines, fmt.Sprintf("%s (subject %s): no k8s verifier lists namespace %s", id, ids[id],
				parsed.Namespace))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintf(w, "%s: policy: %d service account identities mint for no one: %s\n", proc, len(lines),
			strings.Join(lines, "; "))
	}
}

// vouching is, for each namespace a k8s verifier lists, every cluster that
// vouches for it: "backup: eu_west; netops: eu_west, us_east". Several
// clusters may list one namespace (decision 49 ruling 4); the start says
// which, so an overlap nobody meant is seen (ruling 13). A cluster under two
// issuers is named once.
func vouching(ks []oidc.VerifierConfig) string {
	by := map[string][]string{}
	for _, v := range ks {
		for _, ns := range v.Namespaces {
			if !slices.Contains(by[ns], v.Cluster) {
				by[ns] = append(by[ns], v.Cluster)
			}
		}
	}
	var parts []string
	for _, ns := range slices.Sorted(maps.Keys(by)) {
		slices.Sort(by[ns])
		parts = append(parts, ns+": "+strings.Join(by[ns], ", "))
	}
	return strings.Join(parts, "; ")
}
