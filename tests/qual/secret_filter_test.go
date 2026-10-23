package qual

import (
	"bytes"
	"context"
	"fmt"
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
	// \v, \f and a CR before the line's end split a run as well (re-review N1); a CRLF line's
	// final CR does not, and stays.
	{"vertical tab splits a run", "blob FAKEFAKEFAKE\vFAKEFAKEFAKE end", ""},
	{"form feed splits a run", "blob FAKEFAKEFAKE\fFAKEFAKEFAKE end", ""},
	{"mid-line cr splits a run", "blob FAKEFAKEFAKE\rFAKEFAKEFAKE end", ""},
	{"cr before a crlf end", "blob FAKE\r\r", ""},
	{"leading vertical tab on a status line", "\v--- FAIL: TestX/login (1.20s)", ""},
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

// The same cases under two more engines, each first on PATH: GNU sed with --posix, which refuses
// GNU extensions, and busybox's sed and tr, whose regex ends a string at NUL. Each is skipped
// where it is not installed. BSD sed has not been run.
func TestSecretFilterEngines(t *testing.T) {
	for _, engine := range []string{"gnu_posix", "busybox"} {
		t.Run(engine, func(t *testing.T) {
			dir := t.TempDir()
			switch engine {
			case "gnu_posix":
				sed, err := exec.LookPath("sed")
				if err != nil {
					t.Skip("sed is not installed")
				}
				if v, _ := exec.Command(sed, "--version").Output(); !bytes.Contains(v, []byte("GNU sed")) {
					t.Skip("sed is not GNU sed")
				}
				wrap := "#!/bin/sh\nexec '" + sed + "' --posix \"$@\"\n"
				if err := os.WriteFile(filepath.Join(dir, "sed"), []byte(wrap), 0o755); err != nil {
					t.Fatal(err)
				}
			case "busybox":
				bb, err := exec.LookPath("busybox")
				if err != nil {
					t.Skip("busybox is not installed")
				}
				for _, tool := range []string{"sed", "tr"} {
					if err := os.Symlink(bb, filepath.Join(dir, tool)); err != nil {
						t.Fatal(err)
					}
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

// The signs of a copy of the filter's rules: its placeholder, its 24+ class bound, its drop words
// in a row or in its bracket spelling, and a grep that both inverts and ignores case.
var (
	inlineFilter = regexp.MustCompile(`<LONG>|\{24,|(?i)password.{0,2}token|\[Pp\]\[Aa\]\[Ss\]\[Ss\]`)
	grepCall     = regexp.MustCompile(`\bgrep\b([^|;&]*)`)
	shortOpts    = regexp.MustCompile(`(?:^|\s)-([A-Za-z]+)`)
	// A lab step: a lab-tagged go test however the tags are quoted, any tests/lab or tests/qual
	// command, or a make target or script that runs one.
	labStep = regexp.MustCompile(`-tags[ =]["']?[A-Za-z0-9_, ]*\blab\b|go run \./tests/(lab|qual)/cmd/|cmd/notediff|cmd/genprofile|make lab|lab-qualify|qual-vet|tests/qual/vet\.sh`)
)

const filterPipe = "2>&1 | bash tests/qual/secret-filter.sh"

// grepInvertsIgnoringCase reports whether a grep on ln has both -v and -i, in any clustering.
func grepInvertsIgnoringCase(ln string) bool {
	for _, m := range grepCall.FindAllStringSubmatch(ln, -1) {
		var v, i bool
		for _, o := range shortOpts.FindAllStringSubmatch(m[1], -1) {
			v = v || strings.Contains(o[1], "v")
			i = i || strings.Contains(o[1], "i")
		}
		if v && i {
			return true
		}
	}
	return false
}

// filterUse walks root for what would show a lab log to the public job log unfiltered: a shell,
// make or workflow copy of the filter's rules anywhere but tests/qual/secret-filter.sh; a workflow
// line that runs a lab step without ending in filterPipe (a \-continued line is judged whole);
// and an artifact upload from a workflow that runs a lab step or names tests/lab, since an
// uploaded file is never filtered. It returns the problems and the number of lab steps found.
// (tests/lab's Go note filters are separate and not checked here.)
func filterUse(root string) (problems []string, steps int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		lines := strings.Split(string(b), "\n")
		if rel != filepath.Join("tests", "qual", "secret-filter.sh") {
			for i, ln := range lines {
				if inlineFilter.MatchString(ln) || grepInvertsIgnoringCase(ln) {
					problems = append(problems, fmt.Sprintf("%s:%d holds an inline secret filter; pipe through tests/qual/secret-filter.sh", rel, i+1))
				}
			}
		}
		if !inGitHub {
			return nil
		}
		fileSteps := 0
		for i := 0; i < len(lines); i++ {
			start, ln := i, strings.TrimRight(lines[i], " \t\r")
			for strings.HasSuffix(ln, "\\") && i+1 < len(lines) {
				i++
				ln = strings.TrimSuffix(ln, "\\") + " " + strings.TrimSpace(strings.TrimRight(lines[i], " \t\r"))
			}
			if strings.HasPrefix(strings.TrimSpace(ln), "#") || !labStep.MatchString(ln) {
				continue
			}
			fileSteps++
			if !strings.HasSuffix(ln, filterPipe) {
				problems = append(problems, fmt.Sprintf("%s:%d runs a lab step without ending in %q", rel, start+1, filterPipe))
			}
		}
		steps += fileSteps
		if fileSteps > 0 || bytes.Contains(b, []byte("tests/lab")) {
			for i, ln := range lines {
				if strings.Contains(ln, "upload-artifact") {
					problems = append(problems, fmt.Sprintf("%s:%d uploads an artifact from a lab job; an uploaded file is not filtered", rel, i+1))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	b, err := os.ReadFile(filepath.Join(root, "tests", "qual", "vet.sh"))
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Contains(b, []byte("bash tests/qual/secret-filter.sh")) {
		problems = append(problems, "tests/qual/vet.sh does not read its output through tests/qual/secret-filter.sh")
	}
	return problems, steps, nil
}

func TestSecretFilterHasOneCopy(t *testing.T) {
	problems, steps, err := filterUse(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if steps == 0 {
		t.Error("found no lab step in .github; the check would pass on nothing")
	}
}

// Each fixture is a file added to a tree that otherwise complies. A fixture with a non-empty flag
// must yield a problem naming that file; one with an empty flag must yield none.
func TestSecretFilterUseFixtures(t *testing.T) {
	const (
		good    = "      - run: go test -tags lab ./tests/lab/ -run '^TestL76$' 2>&1 | bash tests/qual/secret-filter.sh\n"
		vetGood = "filter() { bash tests/qual/secret-filter.sh; }\n"
		wf      = ".github/workflows/x.yml"
	)
	for _, c := range []struct {
		name, path, body string
		flagged          bool
	}{
		// round 1 (W1-W7)
		{"unpiped -tags=lab", wf, "      - run: go test -tags=lab ./tests/lab/\n", true},
		{"notediff piped elsewhere", wf, "      - run: go run ./tests/lab/cmd/notediff -note x.md 2>&1 | tee out.txt\n", true},
		{"action yaml copy", ".github/actions/x/action.yaml", "    - run: cat log | grep -v -i secret\n", true},
		{"root script mask", "mask.sh", "sed -E 's/[A-Za-z0-9]{24,}/<LONG>/g'\n", true},
		{"deep script copy", "tests/lab/a/b/f.sh", "grep -v -i x\n", true},
		{"vet.sh unfiltered", "tests/qual/vet.sh", "filter() { cat; }\n", true},
		// re-review N2
		{"grep -Evi", wf, "      - run: cat log | grep -Evi 'password|token|secret'\n", true},
		{"grep -iv split flags", "scripts/x.sh", "grep -i -E -v 'pw|key' log\n", true},
		{"other placeholder mask", "x.mk", "mask = sed -E 's/[A-Za-z0-9]{24,}/<MASK>/g'\n", true},
		{"password then token", "scripts/y.sh", "grep -e 'password|token' log\n", true},
		{"quoted -tags lab", wf, "      - run: go test -tags \"lab\" ./tests/lab/\n", true},
		{"single-quoted tags list", wf, "      - run: go test -tags 'lab hwkey' ./tests/lab/\n", true},
		{"pipe without 2>&1", wf, "      - run: go test -tags lab ./tests/lab/ | bash tests/qual/secret-filter.sh\n", true},
		{"other lab cmd", wf, "      - run: go run ./tests/lab/cmd/l99report -x\n", true},
		{"other qual cmd", wf, "      - run: go run ./tests/qual/cmd/qualified\n", true},
		{"upload of a raw lab log", wf, good + "      - uses: actions/upload-artifact@v4\n        with: {path: tests/lab/out.log}\n", true},
		// compliant shapes
		{"continued line ending in the pipe", wf, "      - run: |\n          go test -tags lab ./tests/lab/ \\\n            -run '^TestX$' 2>&1 | bash tests/qual/secret-filter.sh\n", false},
		{"plain grep -v", "scripts/z.sh", "grep -v '^#' f\n", false},
		{"comment naming genprofile", wf, "      # genprofile -check compares the stimulus\n", false},
		{"piped qual cmd", wf, "      - run: go run ./tests/qual/cmd/genprofile -check 2>&1 | bash tests/qual/secret-filter.sh\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				".github/workflows/lab-free.yml": good,
				"tests/qual/vet.sh":              vetGood,
				"tests/qual/secret-filter.sh":    "sed -E 's/[A-Za-z0-9_+/=.-]{24,}/<LONG>/g' | grep -v -i token\n",
			}
			files[c.path] = c.body
			for rel, body := range files {
				p := filepath.Join(root, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			problems, _, err := filterUse(root)
			if err != nil {
				t.Fatal(err)
			}
			named := false
			for _, p := range problems {
				if strings.HasPrefix(p, filepath.FromSlash(c.path)) {
					named = true
				}
			}
			if c.flagged && !named {
				t.Errorf("no problem names %s (problems: %q)", c.path, problems)
			}
			if !c.flagged && len(problems) != 0 {
				t.Errorf("a compliant %s was flagged: %q", c.path, problems)
			}
		})
	}
}
