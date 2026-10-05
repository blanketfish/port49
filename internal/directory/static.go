package directory

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
)

// ForTestsStaticResolver is a Resolver for the tests of the packages that
// call one, and never for production: it answers without a directory.
// Map, Verify and Current answer from answers by principal (Map reads the
// principal as "user:" and the leaf's one email SAN, or the leaf's common
// name as is when it has none), or err when it is set; Stored and grace
// read st as a real resolver does. It never dials. Calls counts the
// answers it gave, so a test asserts it was not asked.
func ForTestsStaticResolver(st store.Store, answers map[string]Answer, err error) *Resolver {
	return &Resolver{Store: st, Now: time.Now, M: metrics.New(prometheus.NewRegistry()),
		Say: func(string, ...any) {}, static: func(principal string) (Answer, error) {
			if err != nil {
				return Answer{}, err
			}
			a, ok := answers[principal]
			if !ok {
				return Answer{}, fmt.Errorf("%w: no entry for %s", ErrUnmapped, principal)
			}
			return a, nil
		}}
}

// staticKey is the principal a static Map reads leaf as.
func staticKey(leaf *x509.Certificate) string {
	if len(leaf.EmailAddresses) == 1 {
		return "user:" + strings.ToLower(leaf.EmailAddresses[0])
	}
	return leaf.Subject.CommonName
}

func (r *Resolver) answerStatic(principal string) (Answer, error) {
	r.Calls.Add(1)
	return r.static(principal)
}
