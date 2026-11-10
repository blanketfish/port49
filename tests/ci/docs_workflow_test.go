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

// The deploy job is the one job that writes the repository, and it writes one branch: gh-pages.
func TestTheDocsDeployPushesOnlyGhPages(t *testing.T) {
	f, _ := docs(t)
	dep := f.Jobs["deploy"]
	if p := dep.Permissions; len(p) != 1 || p["contents"] != "write" {
		t.Errorf("deploy's permissions are %v, want exactly contents: write", p)
	}
	conc, _ := dep.Concurrency.(map[string]any)
	if conc["group"] != "gh-pages" || conc["cancel-in-progress"] != false {
		t.Errorf("deploy's concurrency is %v, want group gh-pages and cancel-in-progress: false", dep.Concurrency)
	}
	var checkout, install, name, email, deploy, setDefault bool
	for _, s := range dep.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = true
			if s.With["fetch-depth"] != 0 {
				t.Errorf("deploy's checkout fetch-depth is %v, want 0 (mike reads history and tags)", s.With["fetch-depth"])
			}
			// mike pushes with the checkout's credentials; this is the one job allowed to keep them
			if s.With["persist-credentials"] != true {
				t.Errorf("deploy's checkout persist-credentials is %v, want true (mike pushes gh-pages with it)", s.With["persist-credentials"])
			}
		}
		for _, ln := range strings.Split(s.Run, "\n") {
			switch {
			case strings.Contains(ln, "pip install"):
				install = true
				if !strings.Contains(ln, "--require-hashes") || !strings.Contains(ln, "packaging/requirements-docs.txt") {
					t.Errorf("deploy installs without the hashed docs requirements: %q", ln)
				}
			case strings.Contains(ln, "git config") && strings.Contains(ln, "user.name"):
				name = true
			case strings.Contains(ln, "git config") && strings.Contains(ln, "user.email"):
				email = true
			case strings.Contains(ln, "mike deploy"):
				deploy = true
				for _, want := range []string{"--push", "--update-aliases", "--branch gh-pages", "--remote origin", `"$VERSION"`, "$ALIASES"} {
					if !strings.Contains(ln, want) {
						t.Errorf("deploy's mike deploy line %q lacks %s", ln, want)
					}
				}
				if s.Env["VERSION"] != "${{ needs.build.outputs.version }}" || s.Env["ALIASES"] != "${{ needs.build.outputs.aliases }}" ||
					s.Env["PORT49_DOCS_BANNER"] != "${{ needs.build.outputs.banner }}" {
					t.Errorf("the mike deploy step's env is %v, want VERSION, ALIASES and PORT49_DOCS_BANNER from build's outputs", s.Env)
				}
			case strings.Contains(ln, "mike set-default"):
				setDefault = true
				for _, want := range []string{"--push", "--branch gh-pages", "--remote origin", "latest"} {
					if !strings.Contains(ln, want) {
						t.Errorf("deploy's mike set-default line %q lacks %s", ln, want)
					}
				}
			}
		}
	}
	for what, ok := range map[string]bool{"a checkout": checkout, "a hashed install": install, "a git user.name": name,
		"a git user.email": email, "mike deploy": deploy, "mike set-default": setDefault} {
		if !ok {
			t.Errorf("deploy has no %s step", what)
		}
	}
	// no other command in the job may push: mike's own --push is the only one
	for _, s := range dep.Steps {
		if strings.Contains(s.Run, "git push") {
			t.Errorf("deploy runs git push: %q", s.Run)
		}
	}
}

func TestTheDocsBuildOutputsWhatDeployReads(t *testing.T) {
	f, _ := docs(t)
	out := f.Jobs["build"].Outputs
	for _, k := range []string{"publish", "banner", "version", "aliases"} {
		if want := "${{ steps.publish.outputs." + k + " }}"; out[k] != want {
			t.Errorf("build's output %s is %q, want %q", k, out[k], want)
		}
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
