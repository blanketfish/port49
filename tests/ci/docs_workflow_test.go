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

// deploySteps is the deploy job, its site step (the build: no token) and its push step (the token: only git).
func deploySteps(t *testing.T) (dep job, site, push step) {
	t.Helper()
	f, _ := docs(t)
	dep = f.Jobs["deploy"]
	var nSite, nPush int
	for _, s := range dep.Steps {
		switch s.ID {
		case "site":
			site = s
			nSite++
		case "push":
			push = s
			nPush++
		}
	}
	if nSite != 1 || nPush != 1 {
		t.Fatalf("deploy has %d steps with id site and %d with id push, want one each", nSite, nPush)
	}
	return dep, site, push
}

// The deploy job is the one job that writes the repository, and it writes one branch: gh-pages. The
// docs toolchain (pip-installed code, mkdocs, mike) runs in the site step with no token anywhere in
// reach; the push step holds the token and runs nothing but git, from a clean bare repository.
func TestTheDocsDeployPushesOnlyGhPagesAndKeepsTheTokenFromTheToolchain(t *testing.T) {
	dep, site, push := deploySteps(t)
	if p := dep.Permissions; len(p) != 1 || p["contents"] != "write" {
		t.Errorf("deploy's permissions are %v, want exactly contents: write", p)
	}
	var checkout, install bool
	order := map[string]int{}
	for i, s := range dep.Steps {
		if s.ID != "" {
			order[s.ID] = i
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = true
			if s.With["fetch-depth"] != 0 {
				t.Errorf("deploy's checkout fetch-depth is %v, want 0 (docspublish reads history and tags)", s.With["fetch-depth"])
			}
			if s.With["persist-credentials"] != false {
				t.Errorf("deploy's checkout persist-credentials is %v, want false", s.With["persist-credentials"])
			}
		}
		// the token is named in the push step's env and nowhere else in the job
		if s.ID != "push" {
			if len(s.Env) != 0 && s.Env["GH_TOKEN"] != "" || strings.Contains(s.Run, "GH_TOKEN") || strings.Contains(s.Run, "github.token") {
				t.Errorf("step %q reaches the token: env %v", s.ID+s.Uses, s.Env)
			}
			for k, v := range s.Env {
				if strings.Contains(v, "token") || strings.Contains(v, "secrets.") {
					t.Errorf("step %q: env %s is %q, a token", s.ID+s.Uses, k, v)
				}
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
	if !checkout || !install {
		t.Errorf("deploy lacks a checkout (%v) or a hashed install (%v)", checkout, install)
	}
	if order["push"] <= order["site"] {
		t.Error("the push step does not come after the site step")
	}

	// the site step builds and commits locally; no mike command pushes
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

	// the push step: only the token in its env, only git in its commands, a bare repo with nothing
	// of the workspace's or the runner's configuration
	if len(push.Env) != 1 || push.Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Errorf("the push step's env is %v, want exactly GH_TOKEN: ${{ github.token }}", push.Env)
	}
	if push.If != "steps.site.outputs.publish == 'true'" {
		t.Errorf("the push step's if is %q, want it skipped when the site step found nothing to publish", push.If)
	}
	for _, bad := range []string{"mike", "mkdocs", "python", "pip ", "go run", "go test", "make "} {
		if strings.Contains(push.Run, bad) {
			t.Errorf("the push step runs %q: it may run only git", bad)
		}
	}
	for _, want := range []string{
		"git init -q --bare", `fetch -q "$GITHUB_WORKSPACE" gh-pages:gh-pages`,
		"core.hooksPath=/dev/null", "credential.helper=", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"another deploy moved gh-pages; re-run this job",
	} {
		if !strings.Contains(push.Run, want) {
			t.Errorf("the push step lacks %q", want)
		}
	}
	pushes := 0
	for _, ln := range strings.Split(push.Run, "\n") {
		if !strings.Contains(ln, " push ") {
			continue
		}
		pushes++
		if !strings.Contains(ln, "gh-pages:gh-pages") || !strings.Contains(ln, "${GH_TOKEN}") || !strings.Contains(ln, `-C "$t"`) ||
			strings.Contains(ln, "--force") || strings.Contains(ln, " -f ") || strings.Contains(ln, "+") {
			t.Errorf("a push that is not a plain gh-pages:gh-pages push from the bare repo with the token: %q", ln)
		}
	}
	if pushes != 1 {
		t.Errorf("the push step has %d push commands, want exactly one", pushes)
	}
	for _, loop := range []string{"for attempt", "while ", "until ", "sleep"} {
		if strings.Contains(push.Run, loop) || strings.Contains(site.Run, loop) {
			t.Errorf("deploy retries (%q): a lost race fails red, and the job is re-run", loop)
		}
	}
}

// Two deploys can overlap: a tag's and the main push that follows it. The decision is made inside the
// job, not taken from the build job, and after fetching gh-pages and then the tags: every tag whose
// deploy is already on the gh-pages branch it saw is then in the tag list it decides from.
func TestTheDocsDeployDecidesAtDeployTime(t *testing.T) {
	dep, site, _ := deploySteps(t)
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
	script := site.Run
	at := func(s string) int { return strings.Index(script, s) }
	pages, tags, decide, deploy, setDefault := at("+refs/heads/gh-pages:refs/heads/gh-pages"), at("git fetch --tags --force origin"),
		at("cmd/docspublish"), at("mike deploy"), at("mike set-default")
	if pages < 0 || tags < 0 || decide < 0 || deploy < 0 || setDefault < 0 ||
		!(pages < tags && tags < decide && decide < deploy && deploy < setDefault) {
		t.Errorf("the site step must fetch gh-pages (%d), then tags (%d), run docspublish (%d), mike deploy (%d), mike set-default (%d), in that order",
			pages, tags, decide, deploy, setDefault)
	}
	if !strings.Contains(script, `"publish=$publish" >> "$GITHUB_OUTPUT"`) {
		t.Error("the site step does not report publish for the push step's if")
	}
	if !strings.Contains(script, "latest") {
		t.Error("the site step does not set the site root's default to latest")
	}
}

// The root 404.html and llms.txt ride in a commit on gh-pages, in the same push as the site.
func TestTheDocsDeployWritesTheRoot404(t *testing.T) {
	_, site, _ := deploySteps(t)
	script := site.Run
	for _, want := range []string{`.github/docs-404.html "$wt/404.html"`, `"$wt/latest/llms.txt" "$wt/llms.txt"`, "git worktree"} {
		if !strings.Contains(script, want) {
			t.Errorf("the site step does not %q", want)
		}
	}
	if at := strings.Index(script, "docs-404.html"); at < strings.Index(script, "mike set-default") {
		t.Error("the 404 commit comes before mike's commits")
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
