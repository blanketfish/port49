package oidc

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/rhwendt/port49/internal/k8sid"
	"github.com/rhwendt/port49/internal/printsafe"
)

// K8sBinding is what a verified service account token binds it to (spec
// §13 decision 49 rulings 7 and 9): recorded for attribution, never
// re-verified.
type K8sBinding struct {
	Cluster, ServiceAccountUID, Pod, PodUID, Node, JTI string
}

// boundObject is {name, uid}, each read by exact name.
type boundObject struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// object reads raw as {name, uid} by exact name. ok is false for anything
// else: not an object, a repeated member (exactObject refuses it), or a
// member that is name or uid in another case, which encoding/json would
// have read for it. A member port49 does not read is left alone.
func object(raw json.RawMessage) (boundObject, bool) {
	all, err := exactObject(raw)
	if err != nil || !exactNamesOnly(all, "name", "uid") {
		return boundObject{}, false
	}
	var o boundObject
	if exact(all, &o, []string{"name", "uid"}) != nil {
		return boundObject{}, false
	}
	return o, true
}

// exactNamesOnly is false when all holds a member equal to one of names in
// another case.
func exactNamesOnly(all map[string]json.RawMessage, names ...string) bool {
	for k := range all {
		for _, n := range names {
			if k != n && strings.EqualFold(k, n) {
				return false
			}
		}
	}
	return true
}

// serviceAccount is decision 49 rulings 6 to 8 for a k8s verifier, on a
// token whose signature, iss, aud and dates have verified: the principal and
// its binding, or the refusal.
func (v *Verifier) serviceAccount(all map[string]json.RawMessage, sub string) (string, *K8sBinding, *refusal) {
	for _, name := range MachineSessionClaims {
		if _, ok := all[name]; ok {
			return "", nil, refuseK8s(ErrInvalid, "invalid", "it carries %s, a person's session or delegated grant: a "+
				"cluster's service account token carries none (decision 49 ruling 6)", name)
		}
	}
	id, err := k8sid.Parse(sub)
	if err != nil {
		return "", nil, refuseK8s(ErrUnmapped, "unmapped", "its sub is not system:serviceaccount:<namespace>:<name> "+
			"(%s)", printsafe.Line(err.Error(), 120))
	}
	if !v.ListsNamespace(id.Namespace) {
		return "", nil, refuseK8s(ErrUnmapped, "unmapped", "its namespace %s is not one %s lists in namespaces "+
			"(decision 49 ruling 8)", id.Namespace, v.Who())
	}
	raw, ok := all["kubernetes.io"]
	if !ok || !exactNamesOnly(all, "kubernetes.io") {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it carries no kubernetes.io claim: it is not a projected "+
			"service account token (decision 49 ruling 7)")
	}
	b, err := exactObject(raw)
	if err != nil || !exactNamesOnly(b, "namespace", "serviceaccount", "pod", "node", "secret") {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io claim is not an object of distinct, "+
			"exactly named members")
	}
	var ns string
	sa, saOK := object(b["serviceaccount"])
	switch {
	case json.Unmarshal(b["namespace"], &ns) != nil || ns != id.Namespace || !saOK || sa.Name != id.Name:
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io binding does not name its sub's service "+
			"account")
	case !printableID(sa.UID):
		return "", nil, refuseK8s(ErrInvalid, "invalid", "its kubernetes.io binding has no serviceaccount uid")
	}
	if _, ok := b["secret"]; ok {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it is bound to a Secret, not a pod: a projected token "+
			"is bound to its pod (decision 49 ruling 7)")
	}
	pod, ok := object(b["pod"])
	if !ok || !printableID(pod.Name) || !printableID(pod.UID) {
		return "", nil, refuseK8s(ErrInvalid, "invalid", "it is not bound to a pod: request it through a projected "+
			"serviceAccountToken volume, not `kubectl create token` (decision 49 ruling 7)")
	}
	out := &K8sBinding{Cluster: v.Cluster, ServiceAccountUID: sa.UID, Pod: pod.Name, PodUID: pod.UID}
	if node, ok := object(b["node"]); ok && printableID(node.Name) {
		out.Node = node.Name
	}
	var jti string
	if json.Unmarshal(all["jti"], &jti) == nil && printableID(jti) {
		out.JTI = jti
	}
	return id.String(), out, nil
}

// refuseK8s is a refusal a k8s verifier makes: its record's method is k8s.
func refuseK8s(kind error, outcome, format string, args ...any) *refusal {
	r := refuse(kind, outcome, format, args...)
	r.method = KindK8s
	return r
}

// MethodOf is a Verify error's record method: k8s when only k8s verifiers
// judged the token, else oidc (decision 49 ruling 9).
func MethodOf(err error) string {
	var r *refusal
	if errors.As(err, &r) && r.method == KindK8s {
		return KindK8s
	}
	return "oidc"
}
