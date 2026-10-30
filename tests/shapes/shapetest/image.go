package shapetest

import "strings"

// DebianTrixieSlim is the one Debian base image the systemd smoke's Dockerfile and the client package's
// import test run in, by digest: a bump is an edit here, and a test requires the Dockerfile's FROM line to
// match it.
const DebianTrixieSlim = "debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31"

// ImageTag is an image reference's tag for a results note, with the digest it is pinned to in the
// form results.Leak recognises: "v1" for repo:v1, "v1 (sha256:<hex>)" for repo:v1@sha256:<hex>,
// "sha256:<hex>" for repo@sha256:<hex>. A port in the host (host:5000/repo) is not a tag. It is "" when
// ref names neither (repo alone), so a caller prints "not recorded".
func ImageTag(ref string) string {
	digest := ""
	if i := strings.Index(ref, "@"); i >= 0 {
		digest, ref = ref[i+1:], ref[:i]
	}
	tag := ""
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		tag = ref[i+1:]
	}
	switch {
	case tag != "" && digest != "":
		return tag + " (" + digest + ")"
	case tag != "":
		return tag
	}
	return digest
}
