package qual

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
	{"skip line kept", "    --- SKIP: TestL76/password_change (0.00s)", "    --- SKIP: TestL76/password_change (0.00s)"},
	{"six-digit duration kept", "--- FAIL: TestQualify/token_login (123456.78s)", "--- FAIL: TestQualify/token_login (123456.78s)"},
	{"23-character segment kept", "--- FAIL: TestX/" + fake23 + " (1.20s)", "--- FAIL: TestX/" + fake23 + " (1.20s)"},
	// The accepted bound: a name of short segments prints as is, even when / splits a secret.
	{"secret split into short segments", "--- FAIL: TestX/FAKEfakeFAKEfakeFAKE/fakeFAKEfak (1.00s)", "--- FAIL: TestX/FAKEfakeFAKEfakeFAKE/fakeFAKEfak (1.00s)"},

	// On a structural line only the long segment is masked, wherever it sits in the name.
	{"long middle segment", "--- FAIL: TestQualify/" + fake24 + "/token_login (1.20s)", "--- FAIL: TestQualify/<LONG>/token_login (1.20s)"},
	{"long first segment", "--- FAIL: Test" + fake24 + " (1.00s)", "--- FAIL: <LONG> (1.00s)"},
	{"long last segment", "    --- PASS: TestX/a/" + fake30 + " (0.10s)", "    --- PASS: TestX/a/<LONG> (0.10s)"},
	{"two adjacent long segments", "--- FAIL: TestX/" + fake24 + "/" + fake30 + "/end (1.00s)", "--- FAIL: TestX/<LONG>/<LONG>/end (1.00s)"},
	{"four adjacent long segments", "--- FAIL: TestX/" + fake24 + "/" + fake30 + "/" + fake24 + "/" + fake30 + " (1.00s)", "--- FAIL: TestX/<LONG>/<LONG>/<LONG>/<LONG> (1.00s)"},
	{"jwt segment", "--- FAIL: TestX/" + fakeJWT + " (1.20s)", "--- FAIL: TestX/<LONG> (1.20s)"},
	{"short eyJ segment", "--- FAIL: TestX/eyJGQUtF/login (1.20s)", "--- FAIL: TestX/<LONG>/login (1.20s)"},
	{"adjacent short eyJ segments", "--- FAIL: TestX/eyJGQUtF/eyJGQUtG/eyJGQUtH (1.20s)", "--- FAIL: TestX/<LONG>/<LONG>/<LONG> (1.20s)"},

	// Anything but a name and a go test duration is not structural: today's drop-then-mask applies.
	{"text after the duration", "--- FAIL: TestX/token_login (1.20s) password=x", ""},
	{"a run after the duration", "--- FAIL: TestX/login (1.20s) " + fake30, "--- FAIL: TestX/login (1.20s) <LONG>"},
	{"one character after the duration", "--- FAIL: TestX/token_login (1.20s)x", ""},
	{"trailing space", "--- FAIL: TestX/token_login (1.20s) ", ""},
	{"text before the marker", "log: --- FAIL: TestX/token_login (1.20s)", ""},
	{"not a test status", "--- ERROR: TestX/token_login (1.20s)", ""},
	{"no duration", "--- FAIL: TestX/token_login", ""},
	{"one decimal", "--- FAIL: TestX/token_login (1.2s)", ""},
	{"no decimals", "--- FAIL: TestX/token_login (1s)", ""},
	{"seven-digit duration", "--- FAIL: TestX/token_login (1234567.00s)", ""},
	{"duration carrying a run", "--- FAIL: TestX/login (123456789012345678901234567890.00s)", "--- FAIL: TestX/login (<LONG>)"},
	{"plus and equals in the name", "--- FAIL: TestQualify/token=FAKE+FAKE (1.20s)", ""},
	{"base64 run in a name", "--- FAIL: TestX/QUFBQUFBQUFBQUFBQUFB+QUFB= (1.20s)", "--- FAIL: <LONG> (1.20s)"},
	{"space in the name", "--- FAIL: TestX/token login (1.20s)", ""},
	{"crlf status line", "--- FAIL: TestX/token_login (1.20s)\r", ""},
	{"verdict line naming a token", "    qual_test.go:41: token login refused: want permit", ""},
	{"message line holding a jwt", "    got " + fakeJWT, ""},
	{"secret in any case", "Password: FAKE", ""},
	{"ordinary long run", "blob " + fake30 + " end", "blob <LONG> end"},
	{"ordinary short words", "ok  \tport49/tests/lab\t12.3s", "ok  \tport49/tests/lab\t12.3s"},
	{"package path is a run", "ok  \tgithub.com/rhwendt/port49/tests/lab\t12.3s", "ok  \t<LONG>\t12.3s"},
	{"crlf ordinary line kept", "ok  \tport49/tests/lab\t12.3s\r", "ok  \tport49/tests/lab\t12.3s\r"},

	// A byte outside printable ASCII and whitespace drops its line, whatever the locale: a raw
	// TACACS+ body printed with %s carries length bytes that split a run below the mask (I1).
	{"nul byte", "u\x00x\vFAKEPASSWD1", ""},
	{"0xff splits a run", "blob FAKEFAKEFAKE\xffFAKEFAKEFAKE end", ""},
	{"overlong utf-8", "blob FAKEFAKEFAKE\xc0\xafFAKEFAKEFAKE end", ""},
	{"lone continuation byte", "blob FAKEFAKEFAKE\x80FAKEFAKEFAKE end", ""},
	{"control byte", "blob FAKEFAKEFAKE\x01FAKEFAKEFAKE end", ""},
	{"escape byte", "\x1b[31mFAKE\x1b[0m", ""},
	{"valid utf-8 is dropped too", "blob \u2014 end", ""},
	{"non-ascii letter in a name", "--- FAIL: TestX/token/\u00e9 (1.20s)", ""},
	{"fullwidth letter in a name", "--- FAIL: TestX/\uff21login (1.20s)", ""},
}

// The locales the filter meets: C.UTF-8 on the GitHub runner, en_US.UTF-8 on a developer machine,
// and C. Its output must not depend on which.
var filterLocales = []string{"C.UTF-8", "en_US.UTF-8", "C"}

// runFilter runs the script under one locale, with every inherited LC_* and LANG removed and env
// appended, and kills it after limit.
func runFilter(t *testing.T, locale, in string, limit time.Duration, env ...string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("bash is not on PATH; the filter is a bash script")
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "secret-filter.sh")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "LC_") && !strings.HasPrefix(kv, "LANG=") && !strings.HasPrefix(kv, "LANGUAGE=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "LANG="+locale)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("secret-filter.sh under %s: %v (stderr %d bytes, limit %v)", locale, err, errb.Len(), limit)
	}
	if errb.Len() != 0 {
		t.Fatalf("secret-filter.sh under %s wrote %d bytes to stderr", locale, errb.Len())
	}
	return out.String()
}

func TestSecretFilter(t *testing.T) {
	for _, loc := range filterLocales {
		for _, c := range filterCases {
			t.Run(loc+"/"+c.name, func(t *testing.T) {
				want := ""
				if c.want != "" {
					want = c.want + "\n"
				}
				if got := runFilter(t, loc, c.in+"\n", 10*time.Second); got != want {
					t.Errorf("output differs from the expected (got %d bytes, want %d; kept=%v want kept=%v)",
						len(got), len(want), got != "", want != "")
				}
			})
		}
	}
}

// The cases fed as one stream: each line is judged on its own, so a structural line does not
// carry its branch into the next, and dropping one (a NUL line among them) does not drop its
// neighbors.
func TestSecretFilterStream(t *testing.T) {
	var in, want strings.Builder
	for _, c := range filterCases {
		in.WriteString(c.in + "\n")
		if c.want != "" {
			want.WriteString(c.want + "\n")
		}
	}
	for _, loc := range filterLocales {
		if got := runFilter(t, loc, in.String(), 10*time.Second); got != want.String() {
			t.Errorf("%s: stream output differs from the expected (got %d bytes, want %d)", loc, len(got), want.Len())
		}
		if got := runFilter(t, loc, "", 10*time.Second); got != "" {
			t.Errorf("%s: empty input gave %d bytes", loc, len(got))
		}
	}
}

// The same cases with busybox's sed and tr first on PATH, where busybox is installed: a second
// engine, and one whose regex ends a string at NUL. BSD sed has not been run.
func TestSecretFilterBusybox(t *testing.T) {
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("busybox is not installed")
	}
	dir := t.TempDir()
	for _, tool := range []string{"sed", "tr"} {
		if err := os.Symlink(bb, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	path := "PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH")
	for _, c := range filterCases {
		t.Run(c.name, func(t *testing.T) {
			want := ""
			if c.want != "" {
				want = c.want + "\n"
			}
			if got := runFilter(t, "C", c.in+"\n", 10*time.Second, path); got != want {
				t.Errorf("output differs from the expected (got %d bytes, want %d; kept=%v want kept=%v)",
					len(got), len(want), got != "", want != "")
			}
		})
	}
}

// Crafted output cannot stall a CI step: the mask is a fixed number of passes, linear in the
// line. A restarting loop took 70 s on the 2 MB long-segment line (review m4); two passes, 0.1 s.
func TestSecretFilterLinear(t *testing.T) {
	const n = 80000
	var long, jwt, short, longWant, jwtWant strings.Builder
	for range n {
		long.WriteString("/" + fake24)
		longWant.WriteString("/<LONG>")
		jwt.WriteString("/eyJGQUtF")
		jwtWant.WriteString("/<LONG>")
		short.WriteString("/FAKE")
	}
	big := strings.Repeat(fake30+" ", n)
	for _, c := range []filterCase{
		{"long segments", "--- FAIL: TestX" + long.String() + " (1.00s)", "--- FAIL: TestX" + longWant.String() + " (1.00s)"},
		{"eyJ segments", "--- FAIL: TestX" + jwt.String() + " (1.00s)", "--- FAIL: TestX" + jwtWant.String() + " (1.00s)"},
		{"short segments", "--- FAIL: TestX" + strings.Repeat(short.String(), 5) + " (1.00s)", "--- FAIL: TestX" + strings.Repeat(short.String(), 5) + " (1.00s)"},
		{"ordinary runs", big, strings.Repeat("<LONG> ", n)},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			got := runFilter(t, "C.UTF-8", c.in+"\n", 20*time.Second)
			if got != c.want+"\n" {
				t.Errorf("output differs from the expected (got %d bytes, want %d)", len(got), len(c.want)+1)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("a %d-byte line took %v", len(c.in), d)
			}
		})
	}
}

// No shell or workflow copy of the filter: nothing but tests/qual/secret-filter.sh holds its rules.
// (tests/lab's Go note filters are separate and not checked here.) And every workflow line that
// runs a lab test, notediff or genprofile, whose output the public job log shows, ends in the pipe.
func TestSecretFilterHasOneCopy(t *testing.T) {
	root := filepath.Join("..", "..")
	inline := regexp.MustCompile(`<LONG>|password\\\|token|grep -v -i|\[Pp\]\[Aa\]\[Ss\]\[Ss\]`)
	labStep := regexp.MustCompile(`-tags[ =]lab|cmd/notediff|cmd/genprofile|make lab|lab-qualify|qual-vet|tests/qual/vet\.sh`)
	const pipe = "| bash tests/qual/secret-filter.sh"
	steps := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".worktrees", ".superpowers", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		inGitHub := strings.HasPrefix(rel, ".github"+string(filepath.Separator))
		switch ext := filepath.Ext(p); {
		case inGitHub, ext == ".sh", ext == ".bash", ext == ".yml", ext == ".yaml", ext == ".mk", d.Name() == "Makefile":
		default:
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel != filepath.Join("tests", "qual", "secret-filter.sh") && inline.Match(b) {
			t.Errorf("%s holds an inline secret filter; pipe through tests/qual/secret-filter.sh", rel)
		}
		if inGitHub {
			for i, ln := range strings.Split(string(b), "\n") {
				if labStep.MatchString(ln) && !strings.HasPrefix(strings.TrimSpace(ln), "#") {
					steps++
					if !strings.HasSuffix(strings.TrimRight(ln, " \t\r"), pipe) {
						t.Errorf("%s:%d runs a lab step without %q", rel, i+1, pipe)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if steps == 0 {
		t.Error("found no lab step in .github; the check would pass on nothing")
	}
	b, err := os.ReadFile(filepath.Join(root, "tests", "qual", "vet.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("bash tests/qual/secret-filter.sh")) {
		t.Error("tests/qual/vet.sh does not read its output through tests/qual/secret-filter.sh")
	}
}
