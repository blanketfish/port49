// Package k8sid is a Kubernetes service account principal (spec §2; §13
// decision 49 ruling 8): system:serviceaccount:<namespace>:<name>, as a
// cluster names it in a token's sub. One parser for the policy, the k8s
// verifier, port49 revoke and port49 explain, so each reads one string the
// same way. Nothing is folded: a cluster never names an account in upper case.
package k8sid

import (
	"errors"
	"fmt"
	"strings"
)

// Prefix begins every service account principal.
const Prefix = "system:serviceaccount:"

// MaxLen is the longest principal: a 63-byte namespace and a 253-byte name.
const MaxLen = len(Prefix) + 63 + 1 + 253

// ErrNotServiceAccount is a string that does not begin with Prefix.
var ErrNotServiceAccount = errors.New("k8sid: not a system:serviceaccount: principal")

// ID is a service account: its namespace and its name.
type ID struct{ Namespace, Name string }

func (id ID) String() string { return Prefix + id.Namespace + ":" + id.Name }

// Parse reads s as system:serviceaccount:<namespace>:<name>: the namespace an
// RFC 1123 label, the name an RFC 1123 subdomain, as Kubernetes validates them.
func Parse(s string) (ID, error) {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return ID{}, ErrNotServiceAccount
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok {
		return ID{}, errors.New("no name after the namespace")
	}
	if err := CheckNamespace(ns); err != nil {
		return ID{}, err
	}
	if len(name) == 0 || len(name) > 253 {
		return ID{}, fmt.Errorf("the name is %d bytes; a service account's is 1 to 253", len(name))
	}
	for _, l := range strings.Split(name, ".") {
		if !label(l) {
			return ID{}, fmt.Errorf("the name %q is not an RFC 1123 subdomain (a-z, 0-9, - and ., each part beginning "+
				"and ending with a letter or digit)", name)
		}
	}
	return ID{Namespace: ns, Name: name}, nil
}

// CheckNamespace is a namespace as Kubernetes validates one: an RFC 1123 label.
func CheckNamespace(ns string) error {
	if !label(ns) {
		return fmt.Errorf("the namespace %q is not an RFC 1123 label (1 to 63 of a-z, 0-9 and -, beginning and ending "+
			"with a letter or digit)", ns)
	}
	return nil
}

func label(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (c != '-' || i == 0 || i == len(l)-1) {
			return false
		}
	}
	return true
}
