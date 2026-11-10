package ci

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The docs workflow's own rules (plan 13, Task 2; versioned by mike): it builds on every pull request
// and deploys only from a public repository, by pushing one version of the site to the gh-pages branch.
// Nothing here runs a workflow.
//
// The deploy is two jobs, because only a job boundary isolates the write token from the docs toolchain
// (steps of one job share a VM: $GITHUB_ENV, $GITHUB_PATH, leftover processes, sudo):
//   - deploy: contents: read. Runs the toolchain, commits gh-pages locally, uploads it as a git bundle.
//   - push-pages: contents: write. No checkout, no setup actions: downloads the bundle and runs git.

const docsPublishIf = "github.event_name == 'push' && github.event.repository.private == false"

func docs(t *testing.T) (flow, string) { return load(t, "../../.github/workflows/docs.yml") }

func TestTheDocsDeployIsGatedOnAPublicRepository(t *testing.T) {
	f, raw := docs(t)
	dep, ok := f.Jobs["deploy"]
	if !ok {
		t.Fatal("docs.yml has no deploy job")
	}
	if want := "needs.build.outputs.publish == 'true' && " + docsPublishIf; dep.If != want {
		t.Errorf("deploy.if is %q, want %q", dep.If, want)
	}
	if n, ok := dep.Needs.(string); !ok || n != "build" {
		t.Errorf("deploy.needs is %v, want build", dep.Needs)
	}
	pp, ok := f.Jobs["push-pages"]
	if !ok {
		t.Fatal("docs.yml has no push-pages job")
	}
	// deploy's own answer (made at deploy time, after fetching the tags) gates the push, so a deploy that
	// found nothing to publish pushes nothing
	if want := "needs.deploy.outputs.publish == 'true' && " + docsPublishIf; pp.If != want {
		t.Errorf("push-pages.if is %q, want %q", pp.If, want)
	}
	if n, ok := pp.Needs.(string); !ok || n != "deploy" {
		t.Errorf("push-pages.needs is %v, want deploy", pp.Needs)
	}
	if f.Concurrency != nil || topLevel(raw, "concurrency:") != "" {
		t.Error("docs.yml has top-level concurrency: one group would cancel queued pull-request builds")
	}
	// the build job only checks; nothing in it publishes
	for _, s := range f.Jobs["build"].Steps {
		if strings.HasPrefix(s.Uses, "actions/upload-pages-artifact@") || strings.HasPrefix(s.Uses, "actions/deploy-pages@") {
			t.Errorf("build uses %s: the site is deployed by mike, not by the Pages actions", s.Uses)
		}
	}
	for id, j := range f.Jobs {
		if j.Environment != nil {
			t.Errorf("job %s names an environment (%v): Pages builds the gh-pages branch itself", id, j.Environment)
		}
	}
}

// siteStep is deploy's one step that decides, builds and commits.
func siteStep(t *testing.T) (job, step) {
	t.Helper()
	f, _ := docs(t)
	dep := f.Jobs["deploy"]
	var site step
	n := 0
	for _, s := range dep.Steps {
		if s.ID == "site" {
			site = s
			n++
		}
	}
	if n != 1 {
		t.Fatalf("deploy has %d steps with id site, want one", n)
	}
	return dep, site
}

// The docs toolchain (pip-installed code, mkdocs, mike) runs in a job that cannot write the repository
// and holds no token. Nothing in it pushes: it hands a bundle of the gh-pages branch to push-pages.
func TestTheDocsToolchainRunsWithoutAWriteToken(t *testing.T) {
	f, _ := docs(t)
	dep, site := siteStep(t)
	if !readOnly(map[string]any(dep.Permissions)) {
		t.Errorf("deploy's permissions are %v, want exactly contents: read", dep.Permissions)
	}
	// only push-pages may write, in the whole workflow
	for id, j := range f.Jobs {
		if id == "push-pages" {
			if p := j.Permissions; len(p) != 1 || p["contents"] != "write" {
				t.Errorf("push-pages' permissions are %v, want exactly contents: write", p)
			}
			continue
		}
		if !readOnly(map[string]any(j.Permissions)) {
			t.Errorf("job %s has permissions %v, want exactly contents: read", id, j.Permissions)
		}
	}
	var checkout, install, uploaded bool
	for _, s := range dep.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = true
			if s.With["fetch-depth"] != 0 {
				t.Errorf("deploy's checkout fetch-depth is %v, want 0 (docspublish reads history and tags)", s.With["fetch-depth"])
			}
			if s.With["persist-credentials"] != false {
				t.Errorf("deploy's checkout persist-credentials is %v, want false", s.With["persist-credentials"])
			}
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
			uploaded = true
			if s.If != "steps.site.outputs.publish == 'true'" || s.With["name"] != "gh-pages-bundle" ||
				s.With["path"] != "${{ runner.temp }}/gh-pages.bundle" || s.With["retention-days"] != 1 ||
				s.With["if-no-files-found"] != "error" || s.With["overwrite"] != true {
				t.Errorf("deploy's upload is %+v (if %q), want the bundle named gh-pages-bundle, retention 1 day, an error if missing, overwriting a re-run's", s.With, s.If)
			}
		}
		// no token of any kind reaches this job
		if strings.Contains(s.Run, "GH_TOKEN") || strings.Contains(s.Run, "github.token") || strings.Contains(s.Run, "x-access-token") {
			t.Errorf("deploy step %q uses a token", s.ID+s.Uses)
		}
		for k, v := range s.Env {
			if strings.Contains(strings.ToLower(k), "token") || strings.Contains(v, "token") || strings.Contains(v, "secrets.") {
				t.Errorf("deploy step %q: env %s is %q, a token", s.ID+s.Uses, k, v)
			}
		}
		for _, ln := range strings.Split(s.Run, "\n") {
			if strings.Contains(ln, "pip install") {
				install = true
				for _, want := range []string{"--require-hashes", "--only-binary=:all:", "packaging/requirements-docs.txt"} {
					if !strings.Contains(ln, want) {
						t.Errorf("deploy's install %q lacks %s", ln, want)
					}
				}
			}
		}
	}
	if !checkout || !install || !uploaded {
		t.Errorf("deploy lacks a checkout (%v), a hashed install (%v) or the bundle upload (%v)", checkout, install, uploaded)
	}
	if dep.Outputs["publish"] != "${{ steps.site.outputs.publish }}" {
		t.Errorf("deploy's output publish is %q, want the site step's", dep.Outputs["publish"])
	}
	for _, ln := range strings.Split(site.Run, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.Contains(ln, "mike ") {
			if strings.Contains(ln, "--push") {
				t.Errorf("a mike command pushes: %q", ln)
			}
			if !strings.Contains(ln, "--branch gh-pages") || !strings.Contains(ln, "--remote origin") {
				t.Errorf("a mike command that does not name its branch and remote: %q", ln)
			}
		}
		if strings.Contains(ln, "git push") {
			t.Errorf("the site step pushes: %q", ln)
		}
	}
	if !strings.Contains(site.Run, `git bundle create "$RUNNER_TEMP/gh-pages.bundle" gh-pages`) {
		t.Error("the site step does not bundle the gh-pages branch")
	}
}

// push-pages is the only job that holds the write token, and it runs no repository code and no setup
// action: a pinned download of the bundle, then git, on a bundle it verifies, in a clean bare repository.
func TestThePushJobRunsOnlyGitOnAVerifiedBundle(t *testing.T) {
	f, _ := docs(t)
	pp := f.Jobs["push-pages"]
	if len(pp.Steps) != 2 {
		t.Fatalf("push-pages has %d steps, want a download and one run of git", len(pp.Steps))
	}
	dl, run := pp.Steps[0], pp.Steps[1]
	// name and path only: a run-id or github-token input would download another run's bundle
	if !regexp.MustCompile(`^actions/download-artifact@[0-9a-f]{40}$`).MatchString(dl.Uses) || len(dl.With) != 2 ||
		dl.With["name"] != "gh-pages-bundle" || dl.With["path"] != "${{ runner.temp }}/bundle" {
		t.Errorf("push-pages' first step is %q with %v, want the pinned download of gh-pages-bundle into $RUNNER_TEMP/bundle, with no other input", dl.Uses, dl.With)
	}
	for _, s := range pp.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") || strings.HasPrefix(s.Uses, "actions/setup-") {
			t.Errorf("push-pages uses %s: it may run no repository code and no setup action", s.Uses)
		}
	}
	if run.Uses != "" || run.Run == "" {
		t.Fatalf("push-pages' second step is not a run: %+v", run)
	}
	if len(run.Env) != 1 || run.Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Errorf("push-pages' run env is %v, want exactly GH_TOKEN: ${{ github.token }}", run.Env)
	}
	for _, bad := range []string{"mike", "mkdocs", "python", "pip ", "go run", "go test", "make "} {
		if strings.Contains(run.Run, bad) {
			t.Errorf("push-pages runs %q: it may run only git", bad)
		}
	}
	// no shell, interpreter or repository script as a command word ("push" is not "sh")
	if m := regexp.MustCompile(`(^|[\s;&|(])(bash|sh|zsh|env|\./\S+|source)\s`).FindString(run.Run); m != "" {
		t.Errorf("push-pages runs %q: it may run only git", strings.TrimSpace(m))
	}
	for _, want := range []string{
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"git init -q --bare", `bundle verify "$b"`, "-c transfer.fsckObjects=true", `fetch -q "$b" gh-pages:gh-pages`,
		"core.hooksPath=/dev/null", "credential.helper=",
		"another deploy moved gh-pages; re-run all jobs of this run",
	} {
		if !strings.Contains(run.Run, want) {
			t.Errorf("push-pages lacks %q", want)
		}
	}
	if !strings.Contains(run.Run, `b="$RUNNER_TEMP/bundle/gh-pages.bundle"`) {
		t.Error("push-pages does not take the bundle from the download's directory")
	}
	pushes := 0
	for _, ln := range strings.Split(run.Run, "\n") {
		if !strings.Contains(ln, " push ") {
			continue
		}
		pushes++
		if !strings.Contains(ln, "gh-pages:gh-pages") || !strings.Contains(ln, "${GH_TOKEN}") || !strings.Contains(ln, `-C "$t"`) ||
			!strings.Contains(ln, "core.hooksPath=/dev/null") || !strings.Contains(ln, "credential.helper=") ||
			strings.Contains(ln, "--force") || strings.Contains(ln, " -f ") || strings.Contains(ln, "+") {
			t.Errorf("a push that is not a plain gh-pages:gh-pages push from the bare repo, hooks and credential helper off: %q", ln)
		}
	}
	if pushes != 1 {
		t.Errorf("push-pages has %d push commands, want exactly one", pushes)
	}
	// a stale bundle can only be rejected (fast-forward only); no retry replays work beside the token
	for _, loop := range []string{"for ", "while ", "until ", "sleep"} {
		if strings.Contains(run.Run, loop) {
			t.Errorf("push-pages loops or waits (%q): a lost race fails red and the whole run is re-run", loop)
		}
	}
	// the token is in the push URL and nowhere else in the script
	if n := strings.Count(run.Run, "GH_TOKEN"); n != 1 {
		t.Errorf("push-pages names GH_TOKEN %d times, want once, in the push", n)
	}
}

// A rejected main push whose commit is no longer main's tip lost to a newer main push, which deploys
// newer docs: it ends green with "superseded", not red. The check reads main's tip with no token, the
// same clean git flags, and only for main; a rejected tag push, or a main push that is still the tip,
// fails red as before.
func TestARejectedMainPushThatASupersedingPushBeatIsGreen(t *testing.T) {
	f, _ := docs(t)
	run := f.Jobs["push-pages"].Steps[1].Run
	lines := strings.Split(run, "\n")
	find := func(s string) int {
		for i, ln := range lines {
			if strings.Contains(ln, s) {
				return i
			}
		}
		return -1
	}
	push, guard, lsRemote, superseded, red := find(" push "), find(`if [ "$GITHUB_REF" = refs/heads/main ]; then`),
		find("ls-remote"), find(`echo "superseded by a newer main push; nothing to do"`), find("another deploy moved gh-pages; re-run all jobs of this run")
	if push < 0 || guard < 0 || lsRemote < 0 || superseded < 0 || red < 0 ||
		!(push < guard && guard < lsRemote && lsRemote < superseded && superseded < red) {
		t.Fatalf("push-pages must push (%d), then for main only (%d) read main's tip (%d) and end superseded (%d), before the red message (%d)",
			push, guard, lsRemote, superseded, red)
	}
	if !strings.Contains(lines[push], "if ! git") {
		t.Errorf("the guard is not on the push's failure: %q", lines[push])
	}
	ls := lines[lsRemote]
	if !strings.Contains(ls, `ls-remote "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/main`) {
		t.Errorf("the ls-remote is %q, want main's tip read from the public URL", ls)
	}
	for _, bad := range []string{"GH_TOKEN", "x-access-token", "github.token", "@github.com"} {
		if strings.Contains(ls, bad) {
			t.Errorf("the ls-remote carries a token (%q): %q", bad, ls)
		}
	}
	if !strings.Contains(ls, "-c core.hooksPath=/dev/null") || !strings.Contains(ls, "-c credential.helper=") {
		t.Errorf("the ls-remote lacks the push's clean flags: %q", ls)
	}
	// green only when main's tip is another commit; an empty answer stays red
	if !strings.Contains(run, `[ -n "$tip" ] && [ "$tip" != "$GITHUB_SHA" ]`) {
		t.Error("push-pages does not compare main's tip with $GITHUB_SHA")
	}
	if strings.TrimSpace(lines[superseded+1]) != "exit 0" || strings.TrimSpace(lines[red+1]) != "exit 1" {
		t.Errorf("superseded must exit 0 and the rejection exit 1: %q, %q", lines[superseded+1], lines[red+1])
	}
	// the main-only block closes before the red message, so every tag rejection is red
	fis := 0
	for _, ln := range lines[superseded+1 : red] {
		if strings.TrimSpace(ln) == "fi" {
			fis++
		}
	}
	if fis != 2 || strings.Count(run, "refs/heads/main ]") != 1 {
		t.Error("the superseded check is not one main-only block that ends before the red message")
	}
}

// Concurrency: deploy is read-only and has no group. The group is on push-pages, the one job that writes
// the branch, and it is per ref, so a main run's push can neither queue behind nor cancel a tag run's
// pending push, while a newer pending push of the same ref (which builds on a newer main) supersedes an
// older one. A run that loses the race to another ref's push is rejected (fast-forward only) and fails red.
func TestTheDocsPushIsGroupedPerRef(t *testing.T) {
	f, _ := docs(t)
	if f.Jobs["deploy"].Concurrency != nil || f.Jobs["build"].Concurrency != nil {
		t.Error("deploy or build has a concurrency group: only the push job may, or a group could cancel a pending job of another ref")
	}
	conc, _ := f.Jobs["push-pages"].Concurrency.(map[string]any)
	if conc["group"] != "gh-pages-push-${{ github.ref }}" || conc["cancel-in-progress"] != false {
		t.Errorf("push-pages' concurrency is %v, want group gh-pages-push-${{ github.ref }} and cancel-in-progress: false", f.Jobs["push-pages"].Concurrency)
	}
}

// Two deploys can overlap: a tag's and the main push that follows it. The decision is made inside the
// deploy job, not taken from the build job, and after fetching gh-pages and then the tags: every tag whose
// deploy is already on the gh-pages it saw is then in the tag list it decides from.
func TestTheDocsDeployDecidesAtDeployTime(t *testing.T) {
	_, site := siteStep(t)
	for _, stale := range []string{"needs.build.outputs.version", "needs.build.outputs.aliases", "needs.build.outputs.banner"} {
		if strings.Contains(raw(t), stale) {
			t.Errorf("docs.yml reads %s: the build job's decision is stale by the time deploy runs", stale)
		}
	}
	script := site.Run
	at := func(s string) int { return strings.Index(script, s) }
	pages, tags, decide, deploy, setDefault, bundle := at("+refs/heads/gh-pages:refs/heads/gh-pages"), at("git fetch --tags --force origin"),
		at("cmd/docspublish"), at("mike deploy"), at("mike set-default"), at("git bundle create")
	if pages < 0 || tags < 0 || decide < 0 || deploy < 0 || setDefault < 0 || bundle < 0 ||
		!(pages < tags && tags < decide && decide < deploy && deploy < setDefault && setDefault < bundle) {
		t.Errorf("the site step must fetch gh-pages (%d), then tags (%d), run docspublish (%d), mike deploy (%d), mike set-default (%d), then bundle (%d), in that order",
			pages, tags, decide, deploy, setDefault, bundle)
	}
	if !strings.Contains(script, `"publish=$publish" >> "$GITHUB_OUTPUT"`) {
		t.Error("the site step does not report publish")
	}
	// docspublish compares the run's commit with main's tip, freshly fetched before it runs, so a run or
	// re-run of an older main commit publishes nothing
	main := at("git fetch --tags --force origin '+refs/heads/main:refs/remotes/origin/main'")
	if main < 0 || main > decide {
		t.Error("the site step does not fetch origin/main before docspublish")
	}
	if !strings.Contains(script, `go run ./tests/ci/cmd/docspublish -ref "$GITHUB_REF" -sha "$GITHUB_SHA")`) {
		t.Error(`the site step's docspublish lacks -sha "$GITHUB_SHA"`)
	}
}

// The root 404.html and llms.txt ride in a commit on gh-pages, in the same push as the site.
func TestTheDocsDeployWritesTheRoot404(t *testing.T) {
	_, site := siteStep(t)
	script := site.Run
	for _, want := range []string{`.github/docs-404.html "$wt/404.html"`, `"$wt/latest/llms.txt" "$wt/llms.txt"`, "git worktree"} {
		if !strings.Contains(script, want) {
			t.Errorf("the site step does not %q", want)
		}
	}
	at := strings.Index(script, "docs-404.html")
	if at < strings.Index(script, "mike set-default") || at > strings.Index(script, "git bundle create") {
		t.Error("the 404 commit is not between mike's commits and the bundle")
	}
}

func raw(t *testing.T) string { _, r := docs(t); return r }

// The build job decides publish for the gate; the banner and version are the deploy job's to decide.
func TestTheDocsBuildOutputsOnlyTheGate(t *testing.T) {
	f, _ := docs(t)
	out := f.Jobs["build"].Outputs
	if want := "${{ steps.publish.outputs.publish }}"; out["publish"] != want {
		t.Errorf("build's output publish is %q, want %q", out["publish"], want)
	}
	if len(out) != 1 {
		t.Errorf("build's outputs are %v, want only publish", out)
	}
}

func TestTheDocsBuildRunsStrictWithHashes(t *testing.T) {
	f, _ := docs(t)
	b := f.Jobs["build"]
	strict, installs := false, 0
	for _, s := range b.Steps {
		for _, ln := range strings.Split(s.Run, "\n") {
			if strings.Contains(ln, "mkdocs build") && strings.Contains(ln, "--strict") {
				strict = true
			}
			if strings.Contains(ln, "pip install") {
				installs++
				if !strings.Contains(ln, "--require-hashes") {
					t.Errorf("a pip install without --require-hashes: %q", ln)
				}
				// the same flags as deploy's install, so the pull request's check proves the deploy's
				// install works on CI's Python (deploy never runs on a pull request)
				if !strings.Contains(ln, "--only-binary=:all:") {
					t.Errorf("the build's pip install lacks --only-binary=:all:, which deploy uses: %q", ln)
				}
			}
		}
	}
	if !strict {
		t.Error("the build job does not run mkdocs build --strict")
	}
	if installs == 0 {
		t.Error("the build job installs nothing")
	}
	if !readOnly(map[string]any(b.Permissions)) {
		t.Errorf("build's permissions are %v, want exactly contents: read", b.Permissions)
	}
}

func TestTheDocsWorkflowRunsOnPullRequests(t *testing.T) {
	f, _ := docs(t)
	got := strings.Join(triggers(f.On), ",")
	if got != "pull_request,push" {
		t.Errorf("docs.yml triggers are %s, want pull_request and push", got)
	}
	var on map[string]yaml.Node
	if err := f.On.Decode(&on); err != nil {
		t.Fatal(err)
	}
	var push struct {
		Branches []string `yaml:"branches"`
		Tags     []string `yaml:"tags"`
	}
	n := on["push"]
	if err := n.Decode(&push); err != nil {
		t.Fatal(err)
	}
	if len(push.Branches) != 1 || push.Branches[0] != "main" || len(push.Tags) != 1 || push.Tags[0] != "v*" {
		t.Errorf("push is branches %v tags %v, want [main] and ['v*']", push.Branches, push.Tags)
	}
}

// The required check is the job's name, and RELEASING.md tells the operator to select `docs`;
// python.yml also has a job called build.
func TestTheDocsBuildJobIsTheDocsCheck(t *testing.T) {
	f, _ := docs(t)
	if n := f.Jobs["build"].Name; n != "docs" {
		t.Errorf("docs.yml's build job is named %q, want docs", n)
	}
}

// The publish decision reads git tag -l and origin/main, so the checkout needs the full history;
// the banner reaches mkdocs through the step's env.
func TestTheDocsBuildFetchesHistoryAndPassesTheBanner(t *testing.T) {
	f, _ := docs(t)
	var checkouts, mkdocs int
	for _, s := range f.Jobs["build"].Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkouts++
			if s.With["fetch-depth"] != 0 {
				t.Errorf("the build checkout's fetch-depth is %v, want 0", s.With["fetch-depth"])
			}
		}
		if strings.Contains(s.Run, "mkdocs build") {
			mkdocs++
			if s.Env["PORT49_DOCS_BANNER"] != "${{ steps.publish.outputs.banner }}" {
				t.Errorf("the mkdocs step's PORT49_DOCS_BANNER is %q", s.Env["PORT49_DOCS_BANNER"])
			}
		}
	}
	if checkouts != 1 || mkdocs != 1 {
		t.Errorf("build has %d checkouts and %d mkdocs steps, want one each", checkouts, mkdocs)
	}
}

// topLevel is the lines of raw that start in column 0 and begin with prefix.
func topLevel(raw, prefix string) string {
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		if strings.HasPrefix(ln, prefix) {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}
