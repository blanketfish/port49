package decision

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Known is the whole vocabulary: every Reason constant declared in
// reasons.go, and nothing else.
func TestKnownIsEveryReasonConstant(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "reasons.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Reason" {
				continue
			}
			for _, v := range vs.Values {
				lit := v.(*ast.BasicLit)
				declared++
				if r := Reason(lit.Value[1 : len(lit.Value)-1]); !Known(r) {
					t.Errorf("%s is declared but not Known", r)
				}
			}
		}
	}
	if declared != len(reasons) {
		t.Errorf("reasons.go declares %d reasons; Known lists %d", declared, len(reasons))
	}
	if Known("no_grant_matched") {
		t.Error("a typo is not a reason")
	}
}

// api_right_missing is in §5.7's vocabulary (plan 7c), so a policy test may
// expect it and the metrics count it.
func TestAPIRightMissingIsKnown(t *testing.T) {
	if !Known(APIRightMissing) || APIRightMissing != "api_right_missing" {
		t.Fatal("api_right_missing")
	}
}

// An explain record carries who asked, by principal and certificate, and
// whether a command was asked, never the command (spec §5.7); a revoke
// record's saved is absent unless it is a standing mark's.
func TestTheAPIRecordsShapes(t *testing.T) {
	var b bytes.Buffer
	l := NewJSONLines(&b)
	l.Emit(Record{Event: EventExplain, Verdict: VerdictDeny, Reason: NoGrantsMatched,
		Principal: "user:alice@example.com", Explain: &Explain{AskedBy: "user:bob@example.com",
			AskedByFingerprint: "sha256:ab12", Command: true}})
	l.Emit(Record{Event: EventRevoke, Verdict: VerdictDeny, Reason: CredentialRevoked,
		Revocation: &Revocation{By: "key", Device: "leaf-01", Username: "alice", At: "2026-10-02T03:12:09Z"}})
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if !strings.Contains(lines[0], `"explain":{"asked_by":"user:bob@example.com","asked_by_fingerprint":"sha256:ab12",`+
		`"command":true}`) || strings.Contains(lines[0], `"auth"`) {
		t.Fatalf("explain: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"device":"leaf-01","username":"alice"`) || strings.Contains(lines[1], `"saved"`) {
		t.Fatalf("revoke: %s", lines[1])
	}
}

// The directory's four reasons are in §5.7's vocabulary (plan 7g), so a
// policy test may expect them and the metrics count them.
func TestTheDirectoryReasonsAreKnown(t *testing.T) {
	for r, want := range map[Reason]string{IdentityUnmapped: "identity_unmapped",
		IdentityAmbiguous: "identity_ambiguous", DirectoryUnavailable: "directory_unavailable",
		CompositionRefused: "composition_refused"} {
		if !Known(r) || string(r) != want {
			t.Errorf("%q", r)
		}
	}
}

// certificate_issued is in §5.7's vocabulary (plan 9b), so a policy test may
// name it, and the issue event is spelled as §5.7 spells it.
func TestCertificateIssuedIsKnown(t *testing.T) {
	if !Known(CertificateIssued) || CertificateIssued != "certificate_issued" || EventIssue != "issue" {
		t.Fatal("certificate_issued or issue is not §5.7's")
	}
}

func TestTheSignInReasonsAreKnown(t *testing.T) {
	for _, r := range []Reason{SignInRefused, SignInThrottled, EnrollmentClosed, EnrollmentStoreLost, SecondFactorEnrolled} {
		if !Known(r) {
			t.Errorf("%s is not in the vocabulary", r)
		}
	}
}
