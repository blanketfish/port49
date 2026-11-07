package ci

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The docs workflow's own rules (plan 13, Task 2): it builds on every pull request and deploys
// only from a public repository. Nothing here runs a workflow.

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
	var upload *step
	build := f.Jobs["build"]
	for i, s := range build.Steps {
		if strings.HasPrefix(s.Uses, "actions/upload-pages-artifact@") {
			upload = &build.Steps[i]
		}
	}
	if upload == nil {
		t.Fatal("build has no upload-pages-artifact step")
	}
	if want := "steps.publish.outputs.publish == 'true' && " + docsPublishIf; upload.If != want {
		t.Errorf("the upload step's if is %q, want %q", upload.If, want)
	}
	if upload.With["path"] != "site" {
		t.Errorf("the upload's path is %v, want site", upload.With["path"])
	}
	if last := build.Steps[len(build.Steps)-1]; last.Uses != upload.Uses {
		t.Error("the upload is not build's last step")
	}
	if n, ok := dep.Needs.(string); !ok || n != "build" {
		t.Errorf("deploy.needs is %v, want build", dep.Needs)
	}
	if dep.Concurrency == nil {
		t.Error("deploy has no concurrency")
	}
	if f.Concurrency != nil || topLevel(raw, "concurrency:") != "" {
		t.Error("docs.yml has top-level concurrency: one group would cancel queued pull-request builds")
	}
	if len(dep.Steps) != 1 || !strings.HasPrefix(dep.Steps[0].Uses, "actions/deploy-pages@") || dep.Steps[0].ID != "deployment" {
		t.Errorf("deploy's steps are %+v, want exactly deploy-pages with id deployment", dep.Steps)
	}
	if hasUses(dep, "actions/checkout@") {
		t.Error("deploy has a checkout")
	}
	env, _ := dep.Environment.(map[string]any)
	if env["name"] != "github-pages" || env["url"] != "${{ steps.deployment.outputs.page_url }}" {
		t.Errorf("deploy's environment is %v", dep.Environment)
	}
	p := dep.Permissions
	if len(p) != 2 || p["pages"] != "write" || p["id-token"] != "write" {
		t.Errorf("deploy's permissions are %v, want exactly pages: write and id-token: write", p)
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
