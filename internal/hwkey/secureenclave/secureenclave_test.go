package secureenclave

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// A secure-enclave: reference is label=NAME and nothing else (decision 45
// ruling 2); the label is a plain name, so it needs no escaping and cannot
// smuggle a second attribute or a query.
func TestParseRef(t *testing.T) {
	for ref, want := range map[string]string{
		"secure-enclave:label=port49":                         "port49",
		"secure-enclave:label=port49.broker.example_443.ab12": "port49.broker.example_443.ab12",
		"secure-enclave:label=A-z_0.9":                        "A-z_0.9",
	} {
		got, err := ParseRef(ref)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %q, %v; want %q", ref, got, err, want)
		}
		if back := Ref(got); back != ref {
			t.Errorf("Ref(%q) = %q, want %q", got, back, ref)
		}
	}
	for _, ref := range []string{
		"secure-enclave:",
		"secure-enclave:label=",
		"secure-enclave:port49",
		"secure-enclave:name=port49",
		"secure-enclave:label=port49;label=other",
		"secure-enclave:label=port49?pin-source=file:///x",
		"secure-enclave:label=a b",
		"secure-enclave:label=a/b",
		"secure-enclave:label=a%20b",
		"secure-enclave:label=café",
		"secure-enclave:label=a\nb",
		"secure-enclave:label=" + strings.Repeat("a", maxLabel+1),
		"pkcs11:label=port49",
		"label=port49",
	} {
		if got, err := ParseRef(ref); err == nil {
			t.Errorf("ParseRef(%q) = %q, want a refusal", ref, got)
		}
	}
	if _, err := ParseRef("secure-enclave:label=" + strings.Repeat("a", maxLabel)); err != nil {
		t.Errorf("a label of %d characters: %v", maxLabel, err)
	}
}

// fakeBackend makes this build's backend a Mac's for the test: usable, and
// open and generate succeed (or fail with err) without a Secure Enclave.
func fakeBackend(t *testing.T, err error) (opened, generated *[]string) {
	t.Helper()
	pa, po, pg := available, openKey, generateKey
	t.Cleanup(func() { available, openKey, generateKey = pa, po, pg })
	opened, generated = new([]string), new([]string)
	available = func() error { return nil }
	openKey = func(label string) (*Signer, error) {
		*opened = append(*opened, label)
		if err != nil {
			return nil, err
		}
		return &Signer{}, nil
	}
	generateKey = func(label string) (*Signer, error) {
		*generated = append(*generated, label)
		if err != nil {
			return nil, err
		}
		return &Signer{}, nil
	}
	return opened, generated
}

// warnings captures the experimental line for the test, and starts it as a
// fresh process would, with the line not yet said.
func warnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev, prevOnce := Warnings, experimental
	var b bytes.Buffer
	Warnings, experimental = &b, new(sync.Once)
	t.Cleanup(func() { Warnings, experimental = prev, prevOnce })
	return &b
}

// A process that opens or makes a key says, once in total, that the backend
// is experimental and untested (decision 45 ruling 6), whether the call then
// succeeds or fails: a login opens the held key, may open it again and make
// one, and says it once.
func TestAnOpenAndAGenerateSayItIsExperimentalOnceInTotal(t *testing.T) {
	for _, fail := range []error{nil, errors.New("secureenclave: OSStatus -34018 a required entitlement isn't present")} {
		w := warnings(t)
		opened, generated := fakeBackend(t, fail)
		if _, err := Open("p49"); (err != nil) != (fail != nil) {
			t.Fatalf("Open: %v", err)
		}
		if got := w.String(); got != ExperimentalWords+"\n" {
			t.Fatalf("after one open: %q", got)
		}
		if _, err := Generate("p49"); (err != nil) != (fail != nil) {
			t.Fatalf("Generate: %v", err)
		}
		if _, err := Open("p49"); (err != nil) != (fail != nil) {
			t.Fatalf("Open again: %v", err)
		}
		if got := w.String(); got != ExperimentalWords+"\n" {
			t.Fatalf("after an open, a generate and an open: %q", got)
		}
		if len(*opened) != 2 || len(*generated) != 1 || (*opened)[0] != "p49" || (*generated)[0] != "p49" {
			t.Fatalf("opened %v generated %v", *opened, *generated)
		}
	}
	// Generate first says it too.
	w := warnings(t)
	fakeBackend(t, nil)
	if _, err := Generate("p49"); err != nil || w.String() != ExperimentalWords+"\n" {
		t.Fatalf("a generate alone: %v said %q", err, w.String())
	}
	for _, w := range []string{"experimental", "untested", "L63", "issue tracker"} {
		if !strings.Contains(ExperimentalWords, w) {
			t.Errorf("%q is not in %q", w, ExperimentalWords)
		}
	}
}

// A label that is not a plain name is refused before the backend is asked
// anything, and says nothing experimental.
func TestABadLabelIsRefusedFirst(t *testing.T) {
	w := warnings(t)
	opened, generated := fakeBackend(t, nil)
	for _, label := range []string{"", "a b", "a/b", strings.Repeat("a", maxLabel+1)} {
		if _, err := Open(label); err == nil {
			t.Errorf("Open(%q) succeeded", label)
		}
		if _, err := Generate(label); err == nil {
			t.Errorf("Generate(%q) succeeded", label)
		}
	}
	if len(*opened)+len(*generated) != 0 || w.Len() != 0 {
		t.Fatalf("opened %v generated %v said %q", *opened, *generated, w.String())
	}
}

// Off macOS the backend refuses, naming macOS, and is never reached: no
// experimental line, no fallback to any other store.
func TestOffMacOSItRefusesNamingMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this is macOS")
	}
	w := warnings(t)
	for name, f := range map[string]func(string) (*Signer, error){"Open": Open, "Generate": Generate} {
		s, err := f("p49")
		if s != nil || err == nil || !strings.Contains(err.Error(), "macOS") || !strings.Contains(err.Error(), runtime.GOOS) {
			t.Errorf("%s: %v %v", name, s, err)
		}
	}
	if err := Delete("p49"); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("Delete: %v", err)
	}
	if err := Available(); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("Available: %v", err)
	}
	if _, err := HostID(); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("HostID: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("said %q", w.String())
	}
}

// Two or more keys under one label are a refusal naming the label and the
// count, never a choice of one, and name no remedy port49 has not measured:
// the caller that knows the label's owner names port49's own.
func TestKeysUnderOneLabelAreRefusedNamingTheCount(t *testing.T) {
	err := error(&DuplicateError{Label: "port49.broker.example_8443.aaaaaaaa", Count: 2})
	for _, w := range []string{"2 Secure Enclave keys", "port49.broker.example_8443.aaaaaaaa", "will not choose"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q is not in %q", w, err.Error())
		}
	}
	if strings.Contains(err.Error(), "Keychain Access") {
		t.Errorf("an unmeasured remedy: %q", err.Error())
	}
	var dup *DuplicateError
	if !errors.As(fmt.Errorf("wrapped: %w", err), &dup) || dup.Count != 2 {
		t.Fatalf("errors.As: %v", dup)
	}
}

// Delete checks the label before the backend is asked anything.
func TestDeleteRefusesABadLabelFirst(t *testing.T) {
	pd, pa := deleteKey, available
	t.Cleanup(func() { deleteKey, available = pd, pa })
	var deleted []string
	available = func() error { return nil }
	deleteKey = func(label string) error { deleted = append(deleted, label); return nil }
	if err := Delete("a/b"); err == nil {
		t.Error("Delete(a/b) succeeded")
	}
	if err := Delete("p49"); err != nil {
		t.Errorf("Delete(p49): %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "p49" {
		t.Fatalf("deleted %v", deleted)
	}
}

// The build without purego, on macOS, refuses by naming the build and the
// client release (ruling 22), never by calling macOS some other system.
func TestTheStaticBuildOnMacOSNamesTheBuild(t *testing.T) {
	err := platformRefusal("darwin")
	if err == nil || !strings.Contains(err.Error(), "built without Secure Enclave support") ||
		!strings.Contains(err.Error(), "client release") || strings.Contains(err.Error(), "macOS's") {
		t.Fatalf("darwin without hwkey_dlopen: %v", err)
	}
	err = platformRefusal("linux")
	if err == nil || !strings.Contains(err.Error(), "the Secure Enclave is macOS's, and this is linux") {
		t.Fatalf("linux: %v", err)
	}
}
