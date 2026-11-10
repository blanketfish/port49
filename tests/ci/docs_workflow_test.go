package ci

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The docs workflow's own rules (plan 13, Task 2; versioned by mike): it builds on every pull request
// and deploys only from a public repository, by pushing one version of the site to the gh-pages branch.
// Nothing here runs a workflow.

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
	if f.Concurrency != nil || topLevel(raw, "concurrency:") != "" {
		t.Error("docs.yml has top-level concurrency: one group would cancel queued pull-request builds")
	}
	// the build job only checks; nothing in it publishes
	for _, s := range f.Jobs["build"].Steps {
		if strings.HasPrefix(s.Uses, "actions/upload-pages-artifact@") || strings.HasPrefix(s.Uses, "actions/deploy-pages@") {
			t.Errorf("build uses %s: the site is deployed by mike, not by the Pages actions", s.Uses)
		}
	}
	if dep.Environment != nil {
		t.Errorf("deploy names an environment (%v): Pages builds the gh-pages branch itself", dep.Environment)
	}
}

// deployScript is the deploy job's run steps joined, with the env of the step that deploys.
func deployScript(t *testing.T) (script string, dep job) {
	t.Helper()
	f, _ := docs(t)
	dep = f.Jobs["deploy"]
	var parts []string
	for _, s := range dep.Steps {
		if s.Run != "" {
			parts = append(parts, s.Run)
		}
	}
	return strings.Join(parts, "\n"), dep
}

// The deploy job is the one job that writes the repository, and it writes one branch: gh-pages.
func TestTheDocsDeployPushesOnlyGhPages(t *testing.T) {
	script, dep := deployScript(t)
	if p := dep.Permissions; len(p) != 1 || p["contents"] != "write" {
		t.Errorf("deploy's permissions are %v, want exactly contents: write", p)
	}
	var checkout, install, deploying bool
	for _, s := range dep.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = true
			if s.With["fetch-depth"] != 0 {
				t.Errorf("deploy's checkout fetch-depth is %v, want 0 (docspublish reads history and tags)", s.With["fetch-depth"])
			}
			// the build runs without the repository token; only the one push command is given it
			if s.With["persist-credentials"] != false {
				t.Errorf("deploy's checkout persist-credentials is %v, want false", s.With["persist-credentials"])
			}
		}
		if strings.Contains(s.Run, "mike deploy") {
			deploying = true
			if s.Env["GH_TOKEN"] != "${{ github.token }}" {
				t.Errorf("the deploy step's GH_TOKEN is %q, want ${{ github.token }}", s.Env["GH_TOKEN"])
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
	for what, ok := range map[string]bool{"a checkout": checkout, "a hashed install": install, "a mike deploy step": deploying} {
		if !ok {
			t.Errorf("deploy has no %s", what)
		}
	}
	for _, ln := range strings.Split(script, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.Contains(ln, "mike "):
			// mike builds and commits locally; it never gets the token and never pushes
			if !strings.Contains(ln, "env -u GH_TOKEN") || strings.Contains(ln, "--push") {
				t.Errorf("a mike command that holds the token or pushes: %q", ln)
			}
			if !strings.Contains(ln, "--branch gh-pages") || !strings.Contains(ln, "--remote origin") {
				t.Errorf("a mike command that does not name its branch and remote: %q", ln)
			}
		case strings.Contains(ln, "git push"):
			// the one command that uses the token, and it pushes gh-pages, fast-forward only
			if !strings.Contains(ln, "gh-pages:gh-pages") || !strings.Contains(ln, "${GH_TOKEN}") ||
				strings.Contains(ln, "--force") || strings.Contains(ln, " -f ") || strings.Contains(ln, "+") {
				t.Errorf("a git push that is not a plain gh-pages:gh-pages push with the token: %q", ln)
			}
		case strings.Contains(ln, "GH_TOKEN") && !strings.Contains(ln, "env -u GH_TOKEN"):
			t.Errorf("the token is used outside the push: %q", ln)
		}
	}
	if strings.Count(script, "git push") != 1 {
		t.Errorf("deploy has %d git push commands, want exactly one", strings.Count(script, "git push"))
	}
}

// Two deploys can overlap: a tag's and the main push that follows it. The decision is made inside the
// job, after the tags are fetched, so a deploy never acts on what the build job saw earlier, and a
// deploy that loses the race for gh-pages starts over from the branch as it now is.
func TestTheDocsDeployDecidesAtDeployTimeAndRetries(t *testing.T) {
	script, dep := deployScript(t)
	conc, _ := dep.Concurrency.(map[string]any)
	if conc["group"] != "gh-pages-${{ github.ref }}" || conc["cancel-in-progress"] != false {
		t.Errorf("deploy's concurrency is %v, want group gh-pages-${{ github.ref }} and cancel-in-progress: false "+
			"(a group per ref: a pending main deploy must not cancel a pending tag deploy)", dep.Concurrency)
	}
	for _, stale := range []string{"needs.build.outputs.version", "needs.build.outputs.aliases", "needs.build.outputs.banner"} {
		if strings.Contains(raw(t), stale) {
			t.Errorf("docs.yml reads %s: the build job's decision is stale by the time deploy runs", stale)
		}
	}
	at := func(s string) int { return strings.Index(script, s) }
	fetch, decide, deploy, push := at("git fetch --tags --force origin"), at("cmd/docspublish"), at("mike deploy"), at("git push")
	if fetch < 0 || decide < 0 || deploy < 0 || push < 0 || !(fetch < decide && decide < deploy && deploy < push) {
		t.Errorf("deploy must fetch tags (%d), run docspublish (%d), mike deploy (%d), then push (%d), in that order", fetch, decide, deploy, push)
	}
	if !strings.Contains(script, "for attempt in 1 2 3") {
		t.Error("deploy has no bounded retry: for attempt in 1 2 3")
	}
	// each attempt starts from gh-pages as it is on origin now
	if !strings.Contains(script, "+refs/heads/gh-pages:refs/heads/gh-pages") {
		t.Error("deploy's retry does not refetch gh-pages")
	}
	if !strings.Contains(script, "exit 1") {
		t.Error("deploy does not fail when every attempt fails")
	}
	if !strings.Contains(script, "mike set-default") || !strings.Contains(script, "latest") {
		t.Error("deploy does not set the site root's default to latest")
	}
}

// The root 404.html and llms.txt ride in a commit on gh-pages, in the same push as the site.
func TestTheDocsDeployWritesTheRoot404(t *testing.T) {
	script, _ := deployScript(t)
	for _, want := range []string{`.github/docs-404.html "$wt/404.html"`, `"$wt/latest/llms.txt" "$wt/llms.txt"`, "git worktree"} {
		if !strings.Contains(script, want) {
			t.Errorf("deploy does not %q", want)
		}
	}
	if at := strings.Index(script, "docs-404.html"); at < strings.Index(script, "mike set-default") || at > strings.Index(script, "git push") {
		t.Error("the 404 commit is not between mike's commits and the push")
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
