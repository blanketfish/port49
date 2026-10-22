package qual

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every fixture secret here is made up: FAKE runs and a JWT built from {"FAKE":"FAKE"}. A failure
// message names the case and never formats the output, so a leak would not reach the log either.
const (
	fake24  = "FAKEFAKEFAKEFAKEFAKEFAKE"       // 24 characters: the shortest run the mask takes
	fake23  = "FAKEFAKEFAKEFAKEFAKEFAK"        // 23: one short of it
	fake30  = "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFA" // 30
	fakeJWT = "eyJGQUtFIjoiRkFLRSJ9.eyJGQUtFIjoxfQ.FAKE"
)

type filterCase struct {
	name, in string
	want     string // "" means the line is dropped
}

var filterCases = []filterCase{
	// The structural line keeps its name, "token" in it included (re-review N2).
	{"fail line kept", "--- FAIL: TestQualify/ceos/token_login (1.20s)", "--- FAIL: TestQualify/ceos/token_login (1.20s)"},
	{"nested fail line kept", "        --- FAIL: TestQualify/ceos/token_login/step.1#01 (0.03s)", "        --- FAIL: TestQualify/ceos/token_login/step.1#01 (0.03s)"},
	{"pass line kept", "--- PASS: TestL76/secret_rotation (0.50s)", "--- PASS: TestL76/secret_rotation (0.50s)"},
	{"skip line kept", "    --- SKIP: TestL76/password_change (0s)", "    --- SKIP: TestL76/password_change (0s)"},
	{"23-character segment kept", "--- FAIL: TestX/" + fake23 + " (1.2s)", "--- FAIL: TestX/" + fake23 + " (1.2s)"},

	// On a structural line only the long segment is masked, wherever it sits in the name.
	{"long middle segment", "--- FAIL: TestQualify/" + fake24 + "/token_login (1.20s)", "--- FAIL: TestQualify/<LONG>/token_login (1.20s)"},
	{"long first segment", "--- FAIL: Test" + fake24 + " (1s)", "--- FAIL: <LONG> (1s)"},
	{"long last segment", "    --- PASS: TestX/a/" + fake30 + " (0.10s)", "    --- PASS: TestX/a/<LONG> (0.10s)"},
	{"two adjacent long segments", "--- FAIL: TestX/" + fake24 + "/" + fake30 + "/end (1.0s)", "--- FAIL: TestX/<LONG>/<LONG>/end (1.0s)"},
	{"jwt segment", "--- FAIL: TestX/" + fakeJWT + " (1.2s)", "--- FAIL: TestX/<LONG> (1.2s)"},
	{"short eyJ segment", "--- FAIL: TestX/eyJGQUtF/login (1.2s)", "--- FAIL: TestX/<LONG>/login (1.2s)"},

	// Anything but a name and a duration is not structural: today's drop-then-mask applies.
	{"text after the duration", "--- FAIL: TestX/token_login (1.2s) password=x", ""},
	{"a run after the duration", "--- FAIL: TestX/login (1.2s) " + fake30, "--- FAIL: TestX/login (1.2s) <LONG>"},
	{"one character after the duration", "--- FAIL: TestX/token_login (1.2s)x", ""},
	{"trailing space", "--- FAIL: TestX/token_login (1.2s) ", ""},
	{"text before the marker", "log: --- FAIL: TestX/token_login (1.2s)", ""},
	{"not a test status", "--- ERROR: TestX/token_login (1.2s)", ""},
	{"no duration", "--- FAIL: TestX/token_login", ""},
	{"plus and equals in the name", "--- FAIL: TestQualify/token=FAKE+FAKE (1.2s)", ""},
	{"base64 run in a name", "--- FAIL: TestX/QUFBQUFBQUFBQUFBQUFB+QUFB= (1.2s)", "--- FAIL: <LONG> (1.2s)"},
	{"space in the name", "--- FAIL: TestX/token login (1.2s)", ""},
	{"verdict line naming a token", "    qual_test.go:41: token login refused: want permit", ""},
	{"message line holding a jwt", "    got " + fakeJWT, ""},
	{"secret in any case", "Password: FAKE", ""},
	{"ordinary long run", "blob " + fake30 + " end", "blob <LONG> end"},
	{"ordinary short words", "ok  \tport49/tests/lab\t12.3s", "ok  \tport49/tests/lab\t12.3s"},
	{"package path is a run", "ok  \tgithub.com/rhwendt/port49/tests/lab\t12.3s", "ok  \t<LONG>\t12.3s"},
}

func runFilter(t *testing.T, in string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("bash is not on PATH; the filter is a bash script")
	}
	cmd := exec.Command(bash, "secret-filter.sh")
	cmd.Stdin = strings.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("secret-filter.sh: %v (stderr %d bytes)", err, errb.Len())
	}
	if errb.Len() != 0 {
		t.Fatalf("secret-filter.sh wrote %d bytes to stderr", errb.Len())
	}
	return out.String()
}

func TestSecretFilter(t *testing.T) {
	for _, c := range filterCases {
		t.Run(c.name, func(t *testing.T) {
			want := ""
			if c.want != "" {
				want = c.want + "\n"
			}
			if got := runFilter(t, c.in+"\n"); got != want {
				t.Errorf("output differs from the expected (got %d bytes, want %d; kept=%v want kept=%v)",
					len(got), len(want), got != "", want != "")
			}
		})
	}
}

// The cases fed as one stream: each line is judged on its own, so a structural line does not
// carry its branch into the next, and dropping one does not drop its neighbors.
func TestSecretFilterStream(t *testing.T) {
	var in, want strings.Builder
	for _, c := range filterCases {
		in.WriteString(c.in + "\n")
		if c.want != "" {
			want.WriteString(c.want + "\n")
		}
	}
	if got := runFilter(t, in.String()); got != want.String() {
		t.Errorf("stream output differs from the expected (got %d bytes, want %d)", len(got), want.Len())
	}
	if got := runFilter(t, ""); got != "" {
		t.Errorf("empty input gave %d bytes", len(got))
	}
}

// One filter: CI and vet.sh pipe through tests/qual/secret-filter.sh, and no script, workflow or
// Makefile holds an inline copy of its rules that could drift from it.
func TestSecretFilterHasOneCopy(t *testing.T) {
	root := filepath.Join("..", "..")
	var files []string
	for _, g := range []string{".github/workflows/*.yml", "tests/*/*.sh", "tests/*/*/*.sh", "scripts/*.sh", "Makefile"} {
		m, err := filepath.Glob(filepath.Join(root, g))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	inline := regexp.MustCompile(`<LONG>|password\\\|token|grep -v -i`)
	for _, f := range files {
		if filepath.Base(f) == "secret-filter.sh" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if inline.Match(b) {
			t.Errorf("%s holds an inline secret filter; pipe through tests/qual/secret-filter.sh", f)
		}
	}
	for _, f := range []string{".github/workflows/lab-free.yml", "tests/qual/vet.sh"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte("bash tests/qual/secret-filter.sh")) {
			t.Errorf("%s does not read its output through tests/qual/secret-filter.sh", f)
		}
	}
}
