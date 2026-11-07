# Plan 13 — User and Admin Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish port49's user and admin documentation as a MkDocs Material site. The reference pages are generated from code and fail CI when stale. Every page is checked for secrets, removed names and unmeasured device claims. The site deploys to GitHub Pages only once the repository is public.

**Architecture:** `mkdocs.yml` sits at the repository root with `docs_dir: docs/site`. Existing READMEs (`deploy/*/README.md`, `examples/*/README.md`, `tests/qual/README.md`, `RELEASING.md`, `deploy/failure-matrix.md`, `docs/qualified-platforms.md`) are pulled in with `pymdownx.snippets`, never copied, so each fact keeps one home.

A new Go package, `internal/docgen`, writes these pages, each guarded by a drift test:
- the config, reason-code, metric, decision-log and alert references;
- the per-device lab-evidence tables;
- `llms.txt`.

Tests in `tests/ci` lint every page. The docs workflow builds with `mkdocs build --strict` on every pull request. Its deploy job is gated on `github.event.repository.private == false`. Until `v0.1.0` it deploys from `main` under a banner saying the site describes `main`. From the first `v*` tag on, it deploys only on `v*` tag pushes, under a banner naming the release.

Two small binary changes parked for this plan land first: `--version` on every binary, and a `healthcheck` subcommand.

**Tech Stack:**
- Go 1.26 (`internal/docgen`, `tests/ci`, `internal/version`, `internal/healthcheck`).
- MkDocs 1.6.1 and Material for MkDocs 9.8.0 (exact pins), with `pymdownx` (snippets, superfences, details, tabbed) and `admonition`, `attr_list` and `toc`. No mermaid: it loads `mermaid.js` from a CDN. Python 3.12 in CI.
- pip-tools, hash-pinned (`packaging/requirements-docs.txt`).
- GitHub Actions `actions/upload-pages-artifact` and `actions/deploy-pages`, pinned by SHA.

**Spec and history (read before any task):**
- `CLAUDE.md`.
- `docs/superpowers/plans/README.md`: the "Plan 13 — User and admin documentation" section, and every hand-off in the source map below.
- Spec §5.7 (`#### Events`, `#### Reason codes`) and §15 (the lab register): `docs/design/2026-08-23-policy-engine-spec.md`.
- Design §12 (failures), §13 (deployment) and §17 (API): `docs/design/2026-08-21-port49-design.md`.
- Every blanketfish pull request body's "Operator-facing notes": `gh pr view <n> --json body -q .body` for the merged PRs #1 to #49. The roadmap's as-built sections mirror the notes of the PRs before the move.

## Decisions for Ryan

Decided (2026-11-07). Only the README's wording is still open.

1. **The site URL** is `https://blanketfish.github.io/port49/`, set once as `site_url` in `mkdocs.yml`. Every generated absolute link derives from it: `llms.txt` and the alerts' `runbook_url`. A custom domain later is a `site_url` change, a re-run of Task 11's annotation generator (76 rules, the chart copy and the promtool test file), and a redirect.
2. **The Pages deploy job holds `id-token: write` and `pages: write`** (Ryan, 2026-11-07). `actions/deploy-pages` needs both. `docs.yml`'s `deploy` is the one job added to `tests/ci`'s id-token allowlist (four release jobs today). It runs only from a public repository, as Task 2's gate says, has no checkout, and runs one step, `deploy-pages`.
3. **The README's final wording** (Task 24) is Ryan's, before go-public. The plan fixes its structure and claims.
4. **The go-public settings this plan cannot make**, added to `RELEASING.md`'s one-time list (Task 2):
   - Pages source "GitHub Actions";
   - the `github-pages` environment restricted to `main` and `v*` tags;
   - `docs` added to the `main` ruleset's required checks;
   - an external link check, run once (item 9).
5. **Material for MkDocs reaches end of life on 2027-05-05** (its PyPI description; Zensical, its authors' successor, is in beta). Pin `mkdocs-material==9.8.0` for the beta. Pages use plain Markdown and the standard extensions only, with no Material-only plugin, so the move is a config change. Decide the Zensical move before 2027-05-05 (Left for later).

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case for every data name** in pages and examples: YAML keys, JSON log keys, metric names.
- **Reason codes come only from spec §5.7.** This plan adds none.
- **No device identity in a metric label.** This plan adds no metric.
- **No real secret on any page.** Pages never show a token, password, key, certificate body, challenge or response.
  - Use angle-bracket placeholders: `<token>`, `<KEY>`, `<BREAKGLASS_USER>`.
  - When the shape must show, use an all-`x` stand-in of the right length.
  - Never a value copied from a lab note, log or capture.
- **No personal or lab-host name:** no home path, `beehive`, `SER8` hostname, or `*.internal` hostname.
- **A device claim cites its evidence.**
  - A claim with a results note (`tests/lab/results/L<N>-<platform>.md`) links the note.
  - A claim on an open spec §15 row with no note for the page's platform goes in an `!!! warning "Unmeasured"` admonition, worded as unknown, never asserted (CLAUDE.md lab rules 1 and 2).
  - Task 4's test enforces both.
- **Deployment shapes are peers.** systemd, container/compose and Helm each get their own install page, in that order. No page says Kubernetes is required or preferred.
- **Troubleshooting is indexed by what the operator sees:** a person's report, an alert, a log line. Each entry gives what it means, what to do, and what not to do.
- **Verify each roadmap note before writing it** (trust but verify).
  - Grep the name in the tree first. Every recursive grep excludes `realm.json`, `*.env`, `*-key.pem` and `*.keytab`, and passes the pattern with `-e` (grep is ugrep).
  - Where the code and a note disagree, the page says what the code does, and the task report names the note.
  - Known cases:
    - plan 7h's "L45 sign-out-user caveat until it is decided" was decided: Ryan's ruling B, 2026-10-07 (spec decision 39 ruling 13);
    - plan 9a's `devices trust` and pins-file notes are withdrawn (plan 9d);
    - there is no `port49 policy lint`: `port49 policy` has `test`, `replay` and `diff` (`cmd/port49/policy.go`), and `deny_scope_unlogged` is reported by `port49 policy test` (the pre-beta note says `lint`);
    - no line says "served from the cached pin": the line is `directory store: not answering: serving <principal>'s cached directory membership (its pin as this region last read it); …` (`internal/store/placement/placement.go`);
    - "L73-nxos106" (#46) is a failed `lab-regress` rerun, not an open register row. L73 is closed, and `L73-cisco_nxos.md` measured Nexus 9300v 10.6(2)F on 2026-10-18. Under CLAUDE.md the register is the truth until a rerun says otherwise.
  - **"L2" and "L3" are register IDs.** For network layers write "layer 2" and "layer 3"; Task 4 reads every `L<N>`.
- **Removed things are not documented** (no deprecation pre-beta). No page names a removed key, command, metric or mechanism, even to say it is gone. Task 3 holds the list.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, `tests/lab/logs`, `tests/lab/captures`, `~/.ssh` or `~/.ansible`.
  - Read a results note only through `grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'`.
  - Never decode a capture.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
- **No lab run and no device** in this plan. CI runs the compose smoke (Task 10).
- **Tests:** `TMPDIR` is a private 0700 directory. Before the final review, run `make test && make vet && make docs-build` and report the real output.
- **Commits:** Conventional Commits, one per step that says "Commit", with an explicit pathspec. Each message ends with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` and nothing else: no `Claude-Session` line and no claude.ai link.
- **Branch:** this plan is written on `docs/plan-13` and lands on `main` first (docs-only). Execution then runs on `feature/user-and-admin-docs`, from `main` after that merge.
  - Tasks 1 to 11 are sequential.
  - Tasks 12 to 24 touch disjoint files, so they may run in parallel worktrees:
    - Task 1 writes the whole nav, every stub, and every snippet section marker in a shared README;
    - each content task writes its `mustSay` rows in its own file, `tests/ci/docs_content_<NN>_test.go`.
  - Task 25 is last.

## Review Focus

1. **A device page states as fact what the register says is open.** An operator who trusts it at 3am finds out on a live device. Task 4's test fails such a line, and Task 21 runs its mutation check on a real device page.
2. **A YAML example on a page does not load.** The operator copies it and port49d refuses it at start. Task 5's `TestEveryConfigExampleDecodes` strict-decodes every fenced block titled with a schema's file name through the loader's own strict decode, so a removed key is refused as `Load` refuses it. Decoding does not prove port49d starts on the example (paths, fences, a store), so the page names what the example leaves out.
3. **A command on a page that the CLI refuses** (renamed, moved to `port49-broker`, removed, or a wrong second word). Task 3's `TestEveryCommandTheDocsNameExists`.
4. **A troubleshooting entry names a metric or alert that does not exist,** so the operator searches Prometheus for nothing. Task 3's `TestEveryMetricTheDocsNameIsRegistered`.
5. **The deploy runs while the repository is private, or a pull request can deploy.** Task 2's `TestTheDocsDeployIsGatedOnAPublicRepository`.

## Source map: every roadmap hand-off and the task that writes it

Each "plan 13" item in `docs/superpowers/plans/README.md`, by the heading it sits under, and its owner. The final task checks every row off.

| Roadmap heading (item) | Task |
|---|---|
| Top: every PR's "Operator-facing notes" | 12–23 (each reads its PRs), 25 (checks off) |
| Top status line; 12c status ("next … plan 13"); "Pre-beta review" header (order: fixes, then 13) | no work: status; this plan's status line is Task 25's |
| Plan 6c — As built: operator notes (`HTTPS_PROXY`, webhook retries, shutdown, `inventory export`) | 20 |
| Plan 7a — As built: revocation operator notes, exit codes | 19 |
| Plan 7b — As built: `certificate_status`, CRL/OCSP, `max_session_age` | 19 |
| Plan 7c — As built: `init-revocations` first install, HTTP revocation | 13 (first install), 19 |
| Plan 7d — As built: `store:`, crypt, the context write witness | 15, 16 |
| Plan 7h — As built: OIDC operator docs, the three recovery forms, the L45 caveat (now ruling B) | 20 |
| Plan 8 — As built: Oxidized page, step-ca enrollment page | 20 |
| Plan 8b — As built: workload directory notes, M-5 | 20 |
| Plan 9a — As built: 0755 with no setgid or file capabilities; the exit-code table; `devices trust` withdrawn | 13, 14, 3 (removed names) |
| Plan 9b — As built: issuance, `init-issuer`, copies to every broker | 16, 20 |
| Plan 9b1 — As built: set 1.2.0, `rpc_entry_denies` | 19, 21 |
| Plan 9c — As built: the two builds, hardware keys, `per_login_mfa` | 13, 14 |
| Plan 9d — As built: OpenSSH host keys, Python and Ansible clients | 13, 14 |
| Plan 9e — As built: directory-password sign-in; issue #6 as intended behaviour | 14 (#6), 20 |
| Plan 9g — As built: set 1.3.0, `view-configuration` | 19, 21 |
| Plan 10 — As built: `examples/kubernetes/README.md` as the Kubernetes workload page | 20 |
| Plan 11 — As built, and "Plan 13" (RFC 9887 page, `tls_outcome`) | 15, 6 |
| Plan 11a — As built, and "Plan 13" (the Stores page, pending-logout dedupe note) | 15 |
| Plan 11b (leaves for later) and As built (qualified-platforms page, contributor guide, `packet_fields`, device traps, `lab-regress` env, NX-OS `-only=`) | 21, 23, 6 |
| Plan 12 (each artifact's README; an install page per shape) | 13 |
| Plan 12a — Hand-offs (`secret_ref` page with `key_secret_refs`, key rotation as policy edits, 30 s retry, the issuer record's three refusals, the shedding lines) | 16, 18 |
| Plan 12b — Carried forward (the pip-tools bootstrap; `--version`; `healthcheck`) | 1, 9, 10 |
| Plan 12b — Hand-offs (install pages, "When it will not start" tables, the `encryption:` rotation runbook, `--version`/`healthcheck`, the SemVer statement) | 13, 16, 18, 9, 10 |
| Plan 12c — Operator notes ("set up your key" is `port49 hwkey setup`, with its risk notes) | 14 |
| Plan 12c — Hand-offs (device pages from `deploy/device-aaa/README.md`, the alerts page, the 3am table, the hwkey page, the macOS admin exception, Mac/Homebrew `libykcs11`, the disk requirement, dedupe on `task_id`, the README) | 21, 11, 18, 14, 13, 18, 24 |
| Plan 12c — Go-public (the README selling points stay open) | 24 |
| Pre-beta fixes — As built (the restore floor, Velero `restore-unspent`, `session.username_redacted`, an ID token refused as a bearer, the include-scope grant refusal, `security_log` default and `deny_scope_unlogged` (from `policy test`, not a `lint`), the new alerts and PodMonitor, `deadline_on_entry`, the logout counter) | 17, 6, 20, 19, 11, 18 |
| Pre-beta fixes — Task 26 cadence ("before plan 13's release run") | no work here: the release run's |
| Pre-beta fixes — left for later: #46 and #47 ("before plan 13's release run") | #47 merged (PR #49). #46 is a failed rerun, not a register row: the NX-OS page states `L73-cisco_nxos.md` (10.6(2)F, closed) and notes, with no L-ID, that the 2026-11 rerun did not reproduce and is pending (issue #46): 21 |
| Pre-beta fixes — left for later: the 24h directory outage on the 3am page | 18 |
| Pre-beta fixes — left for later: CertNameToStr characters, multi-valued RDN, `identity_unmapped` printing the searched value | 20 |
| Pre-beta fixes — left for later: the `bundle.Open` key-id collision (a rotation note); a new grant is a reviewer's call | 16, 19 |
| Pre-beta fixes — "Plan 13 carries": SR Linux sends no command authorization (its page leads with it) | 21 |
| Plan 13 section: the six sections, the agent quick start and runbook, `llms.txt` | 12–24, 22, 8 |

---

### Task 1: The site skeleton, its dependencies and its build

**Files:**
- Create:
  - `mkdocs.yml`.
    - `site_name: port49`, `site_url` (Decision 1), `repo_url: https://github.com/blanketfish/port49`, `docs_dir: docs/site`, `strict: true`.
    - `theme: {name: material, font: false, custom_dir: docs/overrides}`: no third-party font requests. `features: [navigation.sections, navigation.indexes, content.code.copy, search.highlight]`.
    - `extra: {banner: !ENV [PORT49_DOCS_BANNER, "This site describes port49 as it is on main, not a release."]}`, rendered by `docs/overrides/main.html` in Material's `announce` block. Task 2 sets the variable on a tag build.
    - `markdown_extensions`:
      - `admonition`, `attr_list`, `md_in_html`, `tables`, `toc: {permalink: true}`;
      - `pymdownx.details`, `pymdownx.tabbed: {alternate_style: true}`;
      - `pymdownx.superfences` (no mermaid fence: Material loads `mermaid.js` from a CDN, which `font: false` exists to avoid);
      - `pymdownx.snippets: {base_path: ["."], check_paths: true}`.
    - `validation`: `omitted_files`, `absolute_links`, `unrecognized_links` and `anchors` all `warn`, and `nav: {omitted_files: warn, not_found: warn}`. `strict` turns every one into a failure: this is the link check.
    - `exclude_docs`: nothing yet.
    - The full `nav` below.
  - Every page in the nav, as a stub. Each has front matter `title:`, `description:` (one sentence, used by `llms.txt`) and `status: stub`, and one line of body.
  - `docs/overrides/main.html`: `{% extends "base.html" %}` and `{% block announce %}{{ config.extra.banner }}{% endblock %}`.
  - `packaging/requirements-docs.in`: `mkdocs==1.6.1` and `mkdocs-material==9.8.0`, exact. MkDocs has `2.0.dev*` releases: never compile with `--pre`.
  - `packaging/requirements-docs.txt`, compiled with hashes.
  - `packaging/requirements-piptools.in` (`pip-tools==7.5.0`) and `packaging/requirements-piptools.txt`, compiled with hashes. This closes plan 12b's unhashed pip-tools bootstrap.
  - `tests/ci/docs_test.go`.
  - `tests/ci/docs_content_test.go`: `var mustSay = map[string][]string{}` and `TestEveryPageSaysWhatItMust` (each page contains each literal string listed for it). The content tasks add rows from their own files.
- Modify:
  - `Makefile`:
    - `requirements-release` installs pip-tools with `pip install --require-hashes -r packaging/requirements-piptools.txt` and also compiles `requirements-docs.txt` and `requirements-piptools.txt`. Compile the docs file under Python 3.12, the docs job's (`PYTHON ?= python3.12` for that line; the Makefile's header warns that markers differ between 3.14 and 3.12), and say so in the recipe's comment.
    - New `docs-build`: `python3 -m venv bin/docs-venv`, `bin/docs-venv/bin/pip install --require-hashes -r packaging/requirements-docs.txt`, then `bin/docs-venv/bin/mkdocs build --strict --site-dir site`.
    - New `docs-serve`: the same venv, `mkdocs serve`.
  - `.gitignore`: `/site/`.
  - Snippet section markers (`<!-- --8<-- [start:<name>] -->` and `[end:<name>]`) in each shared README a later task includes in part: `deploy/systemd/README.md` and `deploy/compose/README.md` (`will_not_start`), `deploy/alerts/README.md` (`intro`, above `## The rules`), and `tests/lab/README.md` (`regressions`, around `## Regressions (plan 11b)`). Content tasks only include them.
  - `tests/ci/requirements_test.go`: add `TestTheDocsRequirementsAreExactAndHashed` (`exactAndHashed(t, "requirements-docs", []string{"mkdocs", "mkdocs-material"})`) and `TestThePipToolsBootstrapIsHashed` (the same for `requirements-piptools` with `pip-tools`, plus: the `requirements-release` recipe in `Makefile` holds no `pip install` without `--require-hashes`).

**The nav** (paths under `docs/site/`). Tasks 12 to 24 fill these files and change no other page's file.

```
Home: index.md
Concepts: concepts/index.md, concepts/tokens-receipts-contexts.md, concepts/identities.md,
  concepts/revocation.md, concepts/trust-domains.md
Operate:
  Install: operate/install/index.md, operate/install/systemd.md, operate/install/container.md,
    operate/install/helm.md, operate/install/clients.md
  operate/broker-and-agent.md, operate/login.md, operate/hardware-keys.md, operate/stores.md,
  operate/tls.md, operate/secrets.md, operate/backup-and-restore.md, operate/monitoring.md, operate/versions.md
  Troubleshooting: operate/troubleshooting/index.md, operate/troubleshooting/failure-matrix.md,
    operate/troubleshooting/will-not-start.md
Administer: admin/policy.md, admin/roles-and-grants.md, admin/key-rotation.md, admin/revocation.md,
  admin/identity-providers.md, admin/workloads.md, admin/inventory.md
  Devices: admin/devices/index.md, admin/devices/arista-eos.md, admin/devices/cisco-ios-xe.md,
    admin/devices/cisco-nx-os.md, admin/devices/cisco-ios-xr.md, admin/devices/juniper-junos.md,
    admin/devices/nokia-sr-linux.md, admin/devices/other-platforms.md
AI agents: agents/quick-start.md, agents/setup-runbook.md
Reference: reference/config/port49d.md, reference/config/policy.md, reference/config/inventory.md,
  reference/config/port49-inventory.md, reference/config/client.md, reference/reason-codes.md,
  reference/decision-log.md, reference/metrics.md, reference/alerts.md
Contributing: contributing/index.md, contributing/qualification.md, contributing/releasing.md
```

- [ ] **Step 1: Write the failing tests** in `tests/ci/docs_test.go`:
  - `TestEveryPageHasATitleAndADescription`: every `docs/site/**/*.md` outside `docs/site/_snippets/` (snippets cannot carry front matter: `pymdownx.snippets` would paste it into the page) starts with front matter holding a non-empty `title` and `description`, the description at most 160 characters and one sentence.
  - `TestTheNavAndThePagesAgree`: the `nav` paths in `mkdocs.yml` (walk the YAML) are exactly the `.md` files under `docs/site`, less `docs/site/_snippets/` (Task 8). A page in neither, or a nav entry with no file, fails, naming it.
  - The two requirements tests above.
- [ ] **Step 2: Run them and see them fail:** `go test ./tests/ci/ -run 'Docs|Nav|PageHas|PipTools' -count=1`. Expected: FAIL (no `mkdocs.yml`, no requirements files). Paste the red output.
- [ ] **Step 3: Write the files above.** The hashed bootstrap cannot install itself the first time, so build it in this order:
  1. with the recipe still as it is (`pip install pip-tools==$(PIP_TOOLS_VERSION)`, unhashed), run `bin/piptools-venv/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras -o packaging/requirements-piptools.txt packaging/requirements-piptools.in`;
  2. switch the recipe to `--require-hashes -r packaging/requirements-piptools.txt`;
  3. `rm -rf bin/piptools-venv` and run `make requirements-release`: it installs from the hashed file and writes every `.txt`.

  Never hand-edit a `.txt`.
- [ ] **Step 4: Run the tests, then the build:** `go test ./tests/ci/ -count=1` (PASS), then `make docs-build`. Expected: `INFO - Documentation built in …` and exit 0.

  **Mutation checks:**
  - a nav entry pointing at a missing page fails both the test and `make docs-build`;
  - a stub link to `concepts/nope.md` fails `make docs-build` under `strict`.

  Restore both.
- [ ] **Step 5: Commit:** `git add mkdocs.yml docs/site packaging/requirements-docs.in packaging/requirements-docs.txt packaging/requirements-piptools.in packaging/requirements-piptools.txt Makefile .gitignore docs/overrides deploy/systemd/README.md deploy/compose/README.md deploy/alerts/README.md tests/lab/README.md tests/ci/docs_test.go tests/ci/docs_content_test.go tests/ci/requirements_test.go && git commit -m "docs: the documentation site's skeleton, its hashed dependencies and its strict build"`

---

### Task 2: The docs workflow: build on every pull request, deploy only when public

**Files:**
- Create: `.github/workflows/docs.yml`; `tests/ci/cmd/docspublish/main.go` and its test.
  - `on: {push: {branches: [main], tags: ['v*']}, pull_request: {}}`; top-level `permissions: {contents: read}`. No top-level `concurrency`: one group would cancel queued pull-request builds, and `docs` is a required check.
  - **Job `build`** (`ubuntu-24.04`, `permissions: {contents: read}`, `timeout-minutes: 15`, `outputs: {publish: "${{ steps.publish.outputs.publish }}"}`):
    - checkout (`persist-credentials: false`, `fetch-depth: 0`, so the tags are present);
    - setup-go (`go-version-file: go.mod`);
    - step `id: publish`: `go run ./tests/ci/cmd/docspublish -ref "$GITHUB_REF" >> "$GITHUB_OUTPUT"`. It writes `publish=true|false` and `banner=<text>`:
      - `refs/heads/main` with no `v*` tag in `git tag -l 'v*'`: `publish=true`, banner "This site describes port49 as it is on main, not a release.";
      - `refs/heads/main` once a `v*` tag exists: `publish=false`;
      - `refs/tags/v<X>` whose commit is on `main` (`git merge-base --is-ancestor`): `publish=true`, banner "This site describes port49 v<X>.";
      - anything else, a pull request included: `publish=false`.
    - setup-python 3.12;
    - `python -m pip install --require-hashes -r packaging/requirements-docs.txt`;
    - `go test ./internal/docgen/ ./tests/ci/ -count=1`;
    - `mkdocs build --strict --site-dir site`, with `env: {PORT49_DOCS_BANNER: "${{ steps.publish.outputs.banner }}"}`;
    - `PORT49_DOCS_SITE=site go test ./tests/ci/ -run '^TestTheBuiltSite' -count=1` (Tasks 3 and 4);
    - last, `actions/upload-pages-artifact` with `path: site` and `if: steps.publish.outputs.publish == 'true' && github.event_name == 'push' && github.event.repository.private == false`.
  - **Job `deploy`**:
    - `needs: build`, and `if: needs.build.outputs.publish == 'true' && github.event_name == 'push' && github.event.repository.private == false`;
    - `concurrency: {group: pages, cancel-in-progress: false}`, on this job only;
    - `permissions: {pages: write, id-token: write}`;
    - `environment: {name: github-pages, url: "${{ steps.deployment.outputs.page_url }}"}`;
    - no checkout, and one step: `actions/deploy-pages` with `id: deployment`.
  - Pin every action by its 40-character SHA with the version as a comment, resolved with `gh api repos/<owner>/<action>/git/ref/tags/<tag>` (an annotated tag needs its `object.url` followed to the commit).
- Modify:
  - `tests/ci/workflows_test.go` (`allWorkflows`' count message and floor stay): rename `TestOnlyFourJobsHoldIDToken` to `TestOnlyThePublishersHoldIDToken`.
    - `may` becomes true also for `name == "docs.yml" && id == "deploy"`, and that job must hold exactly `{pages: write, id-token: write}`.
    - No other job in any workflow holds `pages`.
    - The environment loop runs over every workflow, not only `release.yml`: `docs.yml`'s `deploy` is the only job anywhere that names `github-pages`, and it names nothing else.
  - `RELEASING.md`, "One-time setup":
    - item 7: Pages source "GitHub Actions", and the `github-pages` environment's deployment branches and tags restricted to `main` and the `v*` tag pattern;
    - item 8: `docs` in the `main` ruleset's required checks;
    - item 9: at go-public, one external link check over the built site (for example `lychee` on `site/`), and fix what it finds.
- Test: `tests/ci/docs_workflow_test.go`.

- [ ] **Step 1: Write the failing tests** in `docs_workflow_test.go`, using `load` from `workflows_test.go`:
  - `TestTheDocsDeployIsGatedOnAPublicRepository`:
    - `deploy.If` equals exactly `needs.build.outputs.publish == 'true' && github.event_name == 'push' && github.event.repository.private == false`, and the upload step's `If` equals exactly `steps.publish.outputs.publish == 'true' && github.event_name == 'push' && github.event.repository.private == false` (exact strings: a `contains` would pass `… || true`);
    - `deploy.Needs` is `build`;
    - `deploy` has `concurrency` and the top level has none;
    - `deploy` has exactly one step, and it `uses: actions/deploy-pages@`;
    - `deploy` has no checkout.
  - `TestTheDocsBuildRunsStrictWithHashes`: the build job runs `mkdocs build --strict`; each `pip install` line carries `--require-hashes`; the build job's permissions are `contents: read` only.
  - `TestTheDocsWorkflowRunsOnPullRequests`: the triggers include `pull_request`, and `push` names `main` and the tag pattern `v*`.
  - `TestDocsPublish` (in `tests/ci/cmd/docspublish`), on a temporary git repository: each of the four cases above gives its `publish` and `banner`; a `v*` tag on a commit not on `main` gives `publish=false`.

  `TestEveryActionIsPinnedBySHA` already covers the new file.
- [ ] **Step 2: Run and see them fail:** `go test ./tests/ci/ -run 'Docs|Publishers' -count=1`. Expected: FAIL, no `docs.yml`.
- [ ] **Step 3: Write `docs.yml`** and make the edits above.
- [ ] **Step 4: Run** `go test ./tests/ci/ -count=1`. Expected: PASS.

  **Mutation checks:** each of these fails a named test; restore each.
  - drop `github.event.repository.private == false` from `deploy.If`;
  - append ` || true` to `deploy.If`;
  - add a checkout to `deploy`;
  - give `build` `id-token: write`, then `pages: write`;
  - move `concurrency` to the top level.
- [ ] **Step 5: Commit:** `git add .github/workflows/docs.yml tests/ci/docs_workflow_test.go tests/ci/workflows_test.go tests/ci/cmd/docspublish RELEASING.md && git commit -m "ci: build the docs site on every pull request and deploy it only from a public repository"`

---

### Task 3: The docs lint

The lint reads the page sources (`docs/site/**/*.md` and `README.md`). When `PORT49_DOCS_SITE` names a built site, it also reads that site's `*.html`, which holds every snippet expanded.

**Files:**
- Create: `tests/ci/docslint.go` (no build tag, so `tests/ci` tests and Task 4 share it), `tests/ci/docslint_test.go`, and `tests/ci/testdata/docslint/` (one bad fixture per rule).
- Modify: nothing outside `tests/ci`.

**Interfaces:**
- Produces:
  - `type Finding struct{ File string; Line int; Rule string }`. It never carries the matched text, so a failure prints no secret.
  - `func LintText(name string, text []byte) []Finding`.
  - `func DocSources(root string) (map[string][]byte, error)`.
  - `func BuiltSite(dir string) (map[string][]byte, error)`, which strips HTML tags and unescapes entities.

**The rules** (`Rule` names):

| Rule | Matches | Allowed |
|---|---|---|
| `token_shaped` | a run of 20 or more `[0-9A-Za-z]` that holds an upper, a lower and a digit (the device token is 30 base62 characters, `internal/token/format.go`) | a run that is all `x`/`X`/`0`. No angle-bracket exemption: a placeholder has no digit and never matches, and a real token in `<…>` must still fail. A git SHA is lowercase hex, so it never matches |
| `jwt` | `eyJ[A-Za-z0-9_-]{8,}` | none |
| `pem_block` | `-----BEGIN [A-Z0-9 ]+-----` (private keys, PGP private key blocks and certificate bodies alike) | none |
| `totp_seed` | `otpauth://`, or `secret=[A-Z2-7]{16,}` | none |
| `long_hex` | 32 or more hex characters, not all one character | a 40-character SHA |
| `home_path` | `/home/<word>`, `/Users/<word>`, `C:\Users\`, `~<word>/` | `/home/<user>` and `~/` (Task 13 changes the Ansible README's `/home/ops` to `/home/<user>`) |
| `lab_host` | `beehive`, `ser8` (as a hostname), `\.internal\b` | inside a `tests/lab/results/` path (a note's file name, such as `load-beehive-gates.md`) |
| `session_link` | the `.gitleaks.toml` `claude-session-link` regex | none |
| `device_secret` | every `[[rules]]` regex in `.gitleaks.toml`, read from the file at test time and compiled with Go's `regexp` (`TestTheLintMirrorsGitleaks` fails if a rule id is missing from the lint or a regex does not compile) | `<KEY>` |
| `removed_name` | `port49 devices trust` and `` `devices trust` `` (not the words "devices trust" in prose), `pins file`, `receipt_ttl`, `admin_socket`, `meta/purged`, `restore guard`, `port49_redemption_restore_guarded`, every key of `config.removedSecretKeys` (export it as `config.RemovedKeys() []string`), and the inventory's replaced `token_secret_env` and `webhook_secret_env` | none |

- [ ] **Step 1: Write the failing tests:**
  - `TestEachLintRuleCatchesItsFixture`: for each rule, `testdata/docslint/<rule>.md` yields exactly one finding with that rule. `testdata/docslint/clean.md` (placeholders, an all-`x` token, `/home/<user>`, a 40-hex SHA) yields none.
  - `TestThePagesPassTheLint`: `LintText` over `DocSources("../..")` finds nothing.
  - `TestTheBuiltSitePassesTheLint`: skips unless `PORT49_DOCS_SITE` is set, then `BuiltSite`, then `LintText`.
  - `TestTheLintMirrorsGitleaks`.
  - `TestEveryMetricTheDocsNameIsRegistered`:
    - every `\bport49_[a-z0-9_]+\b` not followed by `-` (compose volume names such as `port49_port49d-keys` are not metrics) in the sources is a registered metric (`alerts.RegisteredNames()`; Task 7 makes it a wrapper over `docgen.Metrics()`), with or without `_bucket`, `_sum`, `_count` or `_total`, or an alert name from `deploy/alerts/port49.rules.yaml`;
    - a name that is neither is a finding `unknown_metric`.
  - `TestEveryCommandTheDocsNameExists`, for every `` `<binary> <word> [<word>]`` and every such line at the start of a fenced shell block:
    - `port49 <word>` names a `case` of the top-level switch in `cmd/port49/main.go` (walk it with `go/ast`);
    - for `policy`, `platform`, `store`, `directory`, `hwkey`, `keys`, `devices`, `access`, `grants` and `inventory`, the second word (when it is not a flag) names that command's own `case` or `args[0] == "<word>"` comparison, found with `go/ast` in the function the top-level case calls;
    - `port49d <word>` is in `port49d.DaemonSubcommands()`, `port49-broker <word>` in `port49d.BrokerSubcommands()`, and `port49-inventory <word>` in the subcommands `cmd/port49-inventory/main.go` dispatches. Today `forget-issuer` is broker-only, and `init-revocations`, `keys-diagnose` and `store-roles` are port49d-only.
    - Both `port49d` lists are tables that `Main` and `BrokerMain` themselves dispatch from (`map[string]func(args []string) int`), replacing today's `if args[0] == …` chains, so a list cannot disagree with the dispatch. `TestEachSubcommandDispatches` in `internal/port49d` runs each name with `--help` and wants no "unknown command".
  - `TestRepoLinksNameTrackedFiles`: every `https://github.com/blanketfish/port49/(blob|tree)/main/<path>` in the sources names a path `git ls-files` lists.
- [ ] **Step 2: Run and see them fail:** `go test ./tests/ci/ -run 'Lint|Docs|Command|RepoLinks' -count=1`. Expected: FAIL, undefined `LintText`.
- [ ] **Step 3: Implement** `docslint.go`, `config.RemovedKeys`, the two `port49d` tables.
- [ ] **Step 4: Run** `go test ./tests/ci/ ./internal/config/ ./internal/port49d/ -run 'Lint|Docs|Command|RepoLinks|Removed|Subcommands' -count=1`. Expected: PASS.

  **Mutation checks:**
  - put an all-mixed 30-character run in `docs/site/index.md`: red, and the failure prints the file, line and rule but not the run;
  - name `port49 trust` on a stub: red;
  - name `port49 policy lint` on a stub: red;
  - name `port49d forget-issuer` on a stub: red;
  - wrap a real-looking 30-character mixed run in `<…>`: red.

  Restore both.
- [ ] **Step 5: Commit:** `git add tests/ci/docslint.go tests/ci/docslint_test.go tests/ci/testdata/docslint internal/config internal/port49d && git commit -m "test: the docs lint: secrets, home paths, removed names, unknown metrics and commands"`

---

### Task 4: Device claims follow the lab register

**Files:**
- Create: `internal/docgen/lab.go`, `internal/docgen/lab_test.go`, and `tests/ci/docs_lab_test.go`.

**Interfaces:**
- Produces:
  - `type LabRow struct{ ID string; Open bool }`.
  - `func LabRegister(spec []byte) (map[string]LabRow, error)`. It parses the spec's `## 15. Lab register` table:
    - the ID is the first cell with `**` stripped;
    - `Open` is false only when the Status cell (the last cell) begins `closed` or `**closed**`;
    - cells split on `|` not preceded by `\`.

The check (`TestOpenLabEntriesAreWrittenAsUnmeasured`) reads every `docs/site/**/*.md` except:
- `docs/site/_snippets/` (Task 8's tables), which the built-site pass covers through the page that includes them;
- a page carrying `docgen.Header`. Generated pages are drift-tested against the spec, the register's own document. The reason-codes page copies Meaning cells that cite open rows (L4, L17) verbatim.

On each page:
- Each match of `\bL[0-9]+[a-z]?\b` names a row in the register. An unknown ID fails (`unknown_lab_id`).
- A match on an **open** row passes only:
  - inside an `!!! warning "Unmeasured…"` admonition (the line itself, or an indented line under it); or
  - on a line that also links `https://github.com/blanketfish/port49/blob/main/tests/lab/results/L<N>…-<suffix>.md` (pages link repository files by that URL: a relative link out of `docs_dir` fails the strict build), where the file exists and `<suffix>` is one of the page's `platforms:` front-matter suffixes (device pages, Task 8). Otherwise it fails as `open_entry_asserted`.
- A match on a **closed** row inside an `Unmeasured` admonition fails as `closed_entry_unmeasured`: the page is stale.

**The built-site pass** (`TestTheBuiltSiteCitesOpenEntriesAsUnmeasured`, run when `PORT49_DOCS_SITE` is set, as `docs.yml` does). It holds every snippet expanded: `deploy/device-aaa/README.md`, `deploy/failure-matrix.md`, `docs/qualified-platforms.md` and the evidence tables.
- Each `site/<path>/index.html` maps back to `docs/site/<path>.md` for its `platforms:`.
- Generated pages are skipped as above.
- An open row passes:
  - inside `<div class="admonition warning">` whose title begins "Unmeasured";
  - in a sentence naming a `tests/lab/results/L<N>…` note for the page's platforms;
  - in a sentence that says "not measured", "unmeasured" or "open" (the READMEs' own wording).
- A README line that fails is fixed in the README, by the task that includes it: under CLAUDE.md the README is then wrong too.

**Device claims carry evidence** (`TestEveryDeviceClaimCitesItsEvidence`). On a page with `platforms:`, every list item under `## What the lab measured` and `## Traps`:
- links a results note for one of the page's suffixes; or
- sits in an `!!! warning "Unmeasured…"` admonition.

A claim with no L-ID at all fails too.

**Note-name matching** (shared with Task 8): a note `L<N>[-L<M>…]-<rest>.md` belongs to a suffix when `<rest>`, split on `-`, begins with that suffix's segments (`juniper_vjunos-router` is two segments). The longest suffix wins, so `juniper_vjunos` never takes a `juniper_vjunos-router` note.

- [ ] **Step 1: Write the failing tests:**
  - `TestLabRegisterReadsTheSpec`: on the real spec, `L4` and `L78` are open, `L45` and `L73` closed (as at `b36913f6`), and more than 90 rows load.
  - `TestLabRegisterSplitsEscapedPipes`: a fixture row with `\|` in a cell keeps its status.
  - `TestOpenLabEntriesAreWrittenAsUnmeasured`, with fixtures under `tests/ci/testdata/docslab/` for each failure. Each fixture is a page plus a fake register, so the test does not change when a row closes. Fixtures also cover a `_snippets/` file and a page with `Header`: both are skipped.
  - `TestTheBuiltSiteCitesOpenEntriesAsUnmeasured`, with an HTML fixture for each pass and fail case.
  - `TestEveryDeviceClaimCitesItsEvidence`, with fixtures: a cited bullet, an admonition bullet, a bare bullet (fails).
  - `TestNoteNamesMatchBySegments`: `L88-cisco_nxos-nxos106-tls.md` is `cisco_nxos`; `L88-juniper_vjunos-router-vjunos26-tls.md` is `juniper_vjunos-router`, not `juniper_vjunos`.
- [ ] **Step 2: Run and see them fail:** `go test ./internal/docgen/ ./tests/ci/ -run 'Lab' -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them:** PASS on the stubs. Then run the built-site pass on a local build (`make docs-build && PORT49_DOCS_SITE=site go test ./tests/ci/ -run '^TestTheBuiltSite' -count=1`); the stubs include no snippet yet, so it passes.
- [ ] **Step 5: Commit:** `git add internal/docgen/lab.go internal/docgen/lab_test.go tests/ci/docs_lab_test.go tests/ci/testdata/docslab && git commit -m "test: a page cites an open lab register entry only as unmeasured"`

---

### Task 5: `internal/docgen` and the config reference

Six schema files over five root types, each the type its loader strict-decodes:

| Schema | Root type | Page |
|---|---|---|
| `port49d.yaml` | `config.fileConfig` | `reference/config/port49d.md` |
| `port49-broker.yaml` | `config.fileConfig` (the broker's role) | the same page, with a section on the keys the broker role reads and refuses (`brokerRefusals`) |
| `policy.yaml` | `policy.file` | `reference/config/policy.md` |
| `inventory.yaml` | `admission.fileInventory` | `reference/config/inventory.md` |
| `port49-inventory.yaml` | `inventory.fileConfig` | `reference/config/port49-inventory.md` |
| `config.yaml` (the client, `~/.config/port49/`) | `userconfig.File` | `reference/config/client.md` |

**Files:**
- Create:
  - `internal/docgen/schema.go`, `internal/docgen/pages.go`, `internal/docgen/docgen_test.go`;
  - `internal/docgen/cmd/docgen/main.go`;
  - `internal/docgen/descriptions/{port49d,policy,inventory,port49-inventory,client}.yaml`;
  - the five generated pages.
- Modify:
  - each of `internal/config`, `internal/policy`, `internal/admission`, `internal/inventory`: one exported function, `func FileSchema() any`, returning the zero root value, with a comment that it exists for the docs generator;
  - each of those four, and `internal/userconfig`: `func DecodeStrict(raw []byte) error`, the loader's own decode path without the rest of the load (for `config`, `decodeFile`'s path, which refuses `admin_socket` and the removed keys by name);
  - `internal/config/docs_defaults_test.go` (below);
  - `Makefile`: `docs: ; go run ./internal/docgen/cmd/docgen`.

**Interfaces:**
- Produces:
  - `type Key struct{ Path, Type string }`. `Path` is dotted YAML: a map key is `<name>` and a list item is `[]`.
  - `func Keys(root reflect.Type) []Key`:
    - it walks exported fields by their `yaml` tag;
    - it skips `-` and the refused-by-name fields (`receipt_ttl`, the `config.RemovedKeys()` names);
    - a type implementing `yaml.Unmarshaler` is a leaf;
    - `time.Duration` and its wrappers read `duration`;
    - a field whose YAML name is `secret_ref` or ends `_secret_ref` reads `secret reference` (they are plain `string`s, so the name decides, not the type).
  - `type Schema struct{ File, Title, Page string; Root reflect.Type; Descriptions string; Decode func([]byte) error }`. `Decode` is the package's `DecodeStrict`.
  - `func Schemas() []Schema`.
  - `func ConfigPage(s Schema, desc map[string]string) (string, error)`. The error names every key without a description and every description without a key.
  - `func Pages(root string) (map[string]string, error)`: every generated file, from the repository-relative path to its contents. Tasks 6 to 8 and 11 add to it.
  - `const Header = "<!-- generated by make docs from code; do not edit -->"`. Every generated page carries it after its front matter.

**The descriptions files** are operator text, keyed by `Path`. Each entry says, in one to three sentences, what the key does, its default, its bound, and whether a change needs a restart or takes effect at SIGHUP or reload. Take those facts from the loader and the defaults code (`config.daemonDefaults`, `checkBroker`, `checkService`, each package's validation), never from a plan. Seed missing entries with `go run ./internal/docgen/cmd/docgen -seed`. It appends each missing key with its Go doc comment and the prefix `DRAFT:`, and `ConfigPage` refuses any entry that still begins `DRAFT:`.

- [ ] **Step 1: Write the failing tests:**
  - `TestKeysWalksTheYAMLTags`, on a fixture type with a `-` field, a pointer, a map, a slice of structs and an Unmarshaler. It wants exactly `a`, `b.c`, `m.<name>.d`, `l.[].e` and `u` (type `duration`).
  - `TestEveryKeyHasADescriptionAndEveryDescriptionAKey`: `ConfigPage` returns no error for each of `Schemas()`.
  - `TestTheCommittedPagesAreTheGenerated`: each `Pages("../..")` entry equals the file on disk, else "<path> is stale: run make docs".
  - `TestNoGeneratedPageIsUnlisted`: every file under `docs/site` holding `Header` is a key of `Pages`.
  - `TestEveryConfigExampleDecodes` in `tests/ci/docslint_test.go` (it needs `Schemas`, so it lands here, not in Task 3):
    - a fenced block opened as `` ```yaml title="<file>" `` with `<file>` one of `port49d.yaml`, `port49-broker.yaml`, `policy.yaml`, `inventory.yaml`, `port49-inventory.yaml` or `config.yaml` passes that schema's `Decode`;
    - mutation: a block holding `admin_socket:` fails.
  - `TestTheDocsDescribeTheseDefaults` in `internal/config/docs_defaults_test.go`, the defaults guard. It runs `daemonDefaults` (and the broker defaults) on a zero `fileConfig` and, for each of about ten keys, checks that the key's entry in `internal/docgen/descriptions/port49d.yaml` names the value the code set, formatted as the description writes it (`15m`, `4h`, `10`). Candidates, each checked in the code first: `receipt_idle_ttl`, `receipt_max_age`, `context_idle_ttl`, `session.grace_window`, `session.ceiling_warning`, `session.staleness_ceiling`, `session.max_session_age_default`, `token.candidate_cap`, `inventory.max_removed_percent`, `metrics_listen`. A changed default then fails until its description changes.
  - `TestSchemasDecodeTheShippedExamples`: these decode under `KnownFields(true)` into their schema's root:
    - `deploy/compose`'s `port49d.yaml` and policy;
    - `deploy/device-aaa/policy-platforms.yaml` (as `policy.yaml`);
    - the packaged client `/etc/port49/config.yaml` source (as `config.yaml`).

    This proves the roots are right. Locate the shipped example files with `git ls-files deploy packaging | grep -e '\.yaml$'`.
- [ ] **Step 2: Run and see them fail:** `go test ./internal/docgen/ -count=1`.
- [ ] **Step 3: Implement,** write the descriptions, and run `make docs`.
- [ ] **Step 4: Run** `go test ./internal/docgen/ ./tests/ci/ -count=1` (with `TestEveryConfigExampleDecodes`), then `make docs-build`. Expected: PASS and a clean strict build.

  **Mutation checks:** each is red; restore both.
  - add `foo string \`yaml:"foo"\`` to `fileConfig`: red, "no description for foo";
  - edit one generated line by hand: red, "stale".
- [ ] **Step 5: Commit:** `git add internal/docgen internal/config internal/policy internal/admission internal/inventory Makefile docs/site/reference/config tests/ci/docslint_test.go && git commit -m "docs: generate the config reference from the five schemas, with a drift test"`

---

### Task 6: Reason codes and the decision-log schema

**Files:**
- Create: `internal/docgen/decisionlog.go`, `internal/docgen/decisionlog_test.go`, `internal/docgen/descriptions/decision_log.yaml`, `docs/site/reference/reason-codes.md`, `docs/site/reference/decision-log.md`.
- Modify: `internal/decision/reasons.go`: `func Reasons() []Reason { return slices.Clone(reasons) }`.

**Interfaces:**
- Consumes: `Pages`, `Header` (Task 5).
- Produces:
  - `func SpecTable(spec []byte, heading string) ([][]string, error)`: the first pipe table after the heading line equal to `heading`, without its header and rule rows.
  - `func ReasonPage(spec []byte) (string, error)`: one row per `decision.Reasons()` in their declared order, with code and meaning (the spec row's Meaning cell). The error names a code with no spec row and a spec row with no code.
  - `func DecisionLogPage(spec []byte, desc map[string]string) (string, error)`. It holds:
    - the events table, from `#### Events`;
    - one row per JSON field of `decision.Record`, recursive, path dotted (`session.username_redacted`), with type and description;
    - the `tls_outcome` vocabulary (`devicecert.OK`, `devicecert.Resumed`, then `devicecert.Outcomes`), under a heading with the explicit anchor `{#tls_outcome}` (Task 15 links it);
    - `packet_fields`: its five fields; a validated request record carries them as enum names and an unvalidated one does not;
    - a fixed paragraph: credentials appear only as `credential_sha256`, an unvalidated body is never logged, and a token typed as a username leaves `session.username` empty with `session.username_redacted` true.

    The error names a field without a description and a description without a field.

- [ ] **Step 1: Write the failing tests:**
  - `TestEveryReasonHasASpecRow` and `TestEverySpecReasonIsACode`, on the real spec.
  - `TestSpecTableReadsTheReasonCodes`: the first row is `grants_matched`.
  - `TestEveryRecordFieldHasADescription`: `DecisionLogPage` returns no error.
  - `TestTheDecisionLogPageNamesEveryTLSOutcome`: each outcome string appears, and the page holds `{#tls_outcome}`.

  `TestTheCommittedPagesAreTheGenerated` covers both pages once `Pages` lists them.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement, describe the fields, and run `make docs`.**
- [ ] **Step 4: Run** `go test ./internal/docgen/ ./internal/decision/ -count=1`, then `make docs-build`.

  **Mutation check:** add `Foo Reason = "foo"` to `reasons.go` and `reasons`: `TestEveryReasonHasASpecRow` is red. Restore it.
- [ ] **Step 5: Commit:** `git add internal/docgen internal/decision/reasons.go docs/site/reference/reason-codes.md docs/site/reference/decision-log.md && git commit -m "docs: generate the reason codes and the decision-log schema from code and spec §5.7"`

---

### Task 7: The metrics reference

**Files:**
- Create: `internal/docgen/metrics.go`, `internal/docgen/metrics_test.go`, `docs/site/reference/metrics.md`.
- Modify: `tests/alerts/registered.go`. `RegisteredNames` becomes a wrapper over `docgen.Metrics()`, so one recorder serves both. Its existing tests stay green.

**Interfaces:**
- Produces:
  - `type Metric struct{ Name, Kind, Help string; Labels []string }`.
  - `func Metrics() ([]Metric, error)`:
    - a recording `prometheus.Registerer` runs `metrics.New` and `inventory.NewMetrics`;
    - it parses each `Desc.String()` for `fqName`, `help` and `variableLabels`;
    - `Kind` comes from a type switch on the collector: `counter`, `gauge`, `histogram`, `summary`, or `collector` for anything else.
  - `type Alert struct{ Name, Severity, For, Expr, Summary string }`.
  - `func Alerts(rules []byte) ([]Alert, error)`, which reads `deploy/alerts/port49.rules.yaml`.
  - `func MetricsPage(ms []Metric, as []Alert) string`. Group sections by the name's second word (`port49_store_*` under "store"). Each row gives the name, kind, labels, help, and the alerts whose `Expr` names the metric, linked to `alerts.md#<alert>`. The process collector's `process_*` series get one line, not rows.

- [ ] **Step 1: Write the failing tests:**
  - `TestMetricsFindsTheKnownSeries`: `port49_store_calls_total` is a counter with label `outcome`; `port49_connections_max` is a gauge.
  - `TestNoMetricHasADeviceLabel`: no label is `device`, `nas`, `device_name` or `address`, matching CLAUDE.md.
  - `TestRegisteredNamesIsMetrics`: `alerts.RegisteredNames()` equals the names of `Metrics()`.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement; run `make docs`.**
- [ ] **Step 4: Run** `go test ./internal/docgen/ ./tests/alerts/ ./tests/ci/ -count=1`, then `make docs-build`.
- [ ] **Step 5: Commit:** `git add internal/docgen tests/alerts/registered.go docs/site/reference/metrics.md && git commit -m "docs: generate the metrics reference from the registered collectors"`

---

### Task 8: Device evidence tables and `llms.txt`

**Files:**
- Create:
  - `internal/docgen/evidence.go`, `internal/docgen/llms.go` and their tests;
  - `docs/site/_snippets/evidence/<slug>.md`, one per device page (generated);
  - `docs/site/llms.txt` (generated).
- Modify: `mkdocs.yml`: `exclude_docs: _snippets/`.

**Interfaces:**
- Produces:
  - `type DevicePage struct{ Slug, Title string; Suffixes []string }`.
  - `var DevicePages = []DevicePage{…}`. Each page's suffixes:

    | Slug | Suffixes |
    |---|---|
    | `arista-eos` | `arista_eos`, `arista_ceos` |
    | `cisco-ios-xe` | `cisco_iosxe`, `cisco_iol` (IOL-XE 17.18.02 is IOS XE: `L71-cisco_iol-xe.md`) |
    | `cisco-nx-os` | `cisco_nxos` |
    | `cisco-ios-xr` | `cisco_xrd` |
    | `juniper-junos` | `juniper_vjunos-router`, `juniper_vjunos`, `juniper_vsrx`, `juniper_srx` |
    | `nokia-sr-linux` | `nokia_srlinux` |
    | `other-platforms` | none (the generic adapter has no notes) |

    Matching is by segments, longest suffix first (Task 4). Within a page, each note is listed once. `var MultiPage = map[string][]string{"L31-breakglass-cisco-singleconnection.md": {"cisco-ios-xe", "cisco-nx-os"}}` holds a note that measured two images.
  - `type Evidence struct{ ID, File, Platform, Image, Date string }`.
  - `func EvidenceFor(resultsDir string, p DevicePage) ([]Evidence, error)`:
    - it lists the notes that match the page by segments, plus `MultiPage`'s;
    - it reads only each note's header lines, in three shapes, which it parses and never prints otherwise:
      - list items `**Date measured:**`, `**Platform:**`, `**Image version:**`;
      - plain `Date:`, `Platform:`, `Image:` lines;
      - the L88 single line, `Platform: <p>. Image: <i>. Transport: <t>. Measured <date> by <test>.` (its date is the word after `Measured`);
    - a field it cannot parse is `—`.
  - `func EvidenceTable(ev []Evidence, reg map[string]LabRow) string`: one row per note, with the entry, image, date, link and the register status (open or closed).
  - `func LLMsTxt(mkdocsYAML []byte, docs string) (string, error)`, in the llmstxt.org shape:
    - `# port49`;
    - a `> ` summary from `index.md`'s description;
    - then `## Start here`: `agents/setup-runbook.md`, then `agents/quick-start.md`;
    - then one `##` per nav section in nav order. Each line is `- [title](<url>): description`, where `<url>` is `site_url` plus the page's directory URL (`index.md` is `site_url` itself; `a/b.md` is `a/b/`; `a/index.md` is `a/`).

  Each device page's front matter names `platforms:` (its suffixes) for Task 4's check.

- [ ] **Step 1: Write the failing tests:**
  - `TestEveryResultsNoteBelongsToOnePage`: every `tests/lab/results/L*.md` matches exactly one `DevicePages` entry by segments, or is in `MultiPage`, or its first segment is in `nonDevice`: `kind`, `regions`, `netbox`, `nautobot`, `openldap`, `samba`, `samba_ad`, `windows*`, `keycloak`, `ser8`, `systemd-docker`, `reference`, `step_ca`, `beehive*`. Files not named `L<N>-…` (`load-*`, `slice-*`, `session-*` and the like) are outside the test. A note that fits none fails, so a new platform's notes cannot go missing.
  - `TestEvidenceParsesEveryHeaderStyle`, on three fixtures shaped like `L4-arista_eos.md`, `L76-nokia_srlinux.md` and `L88-cisco_xrd.md` (header lines only).
  - `TestLLMsTxtFollowsTheNav`: the runbook is the first link, and every nav page appears once.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement; run `make docs`.** Each device stub includes its table under `## Lab evidence` with `--8<-- "docs/site/_snippets/evidence/<slug>.md"`.
- [ ] **Step 4: Run** `go test ./internal/docgen/ ./tests/ci/ -count=1`, then `make docs-build`.
- [ ] **Step 5: Commit:** `git add internal/docgen docs/site/_snippets docs/site/llms.txt docs/site/admin/devices mkdocs.yml && git commit -m "docs: generate each device page's lab evidence table and llms.txt"`

---

### Task 9: Every binary prints its version

Plan 12b parked it: "every binary prints its version".

**Files:**
- Create: `internal/version/version.go` and `internal/version/version_test.go`.
- Modify:
  - `cmd/port49/main.go` (`--version` and `version`);
  - `internal/port49d/main.go`: `Main` (`port49d --version`) and `BrokerMain` (`port49-broker --version`, `cmd/port49-broker/main.go`);
  - `cmd/port49-inventory/main.go`;
  - `Makefile` (`build`, `build-client`): `-ldflags "-X github.com/blanketfish/port49/internal/version.Version=$(VERSION)"`, with `VERSION ?= $(shell git describe --tags --always --dirty)`;
  - `.goreleaser.yaml`: each build's `ldflags` gains `-X github.com/blanketfish/port49/internal/version.Version={{.Version}}` beside `-s -w`.

**Interfaces:**
- Produces:
  - `var Version = "dev"`.
  - `func Line(binary string) string`, which returns `"<binary> <Version>"`.
  - `--version` prints `Line` to stdout and exits 0, before any config is read.

- [ ] **Step 1: Write the failing tests:**
  - `TestEveryBinaryPrintsItsVersion` in `internal/version`. It builds each of the four commands with `-ldflags -X …Version=v0.0.0-test` into `t.TempDir()`, and `cmd/port49` a second time as `make build-client` builds it (`-tags hwkey_dlopen`). It runs `<bin> --version` and wants exit 0 and stdout `<name> v0.0.0-test\n`. The same holds for `port49 version`.
  - `TestTheReleaseSetsTheVersion` in `tests/ci`: every `builds[].ldflags` in `.goreleaser.yaml` holds the `-X` flag.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/version/ ./tests/ci/ ./cmd/... -count=1`. Expected: PASS.
- [ ] **Step 5: Commit:** `git add internal/version cmd internal/port49d/main.go Makefile .goreleaser.yaml tests/ci && git commit -m "feat: every binary prints its version"`

---

### Task 10: A `healthcheck` subcommand, used by compose

Plan 12b parked it: "a `healthcheck` subcommand (the image has no shell)".

**Files:**
- Create: `internal/healthcheck/healthcheck.go` and its test.
- Modify:
  - `internal/port49d/main.go`: `Main` (`port49d healthcheck`) and `BrokerMain` (`port49-broker healthcheck`);
  - `cmd/port49-inventory/main.go`;
  - the address comes from what `port49d` already has: `offlineMetricsListenOf` (`internal/port49d/offline.go`) for the configured `metrics_listen`, falling to the role's default when it is empty (port49d `:9049`, broker `:9050`, `internal/config/config.go`), and `answeringOn`'s mapping (`offline_port49d.go`) from a wildcard to loopback. Move both into `internal/healthcheck` if they must be shared with `port49-inventory`; never write a third copy. No full `Load`: a fence or store fault must not make the check lie;
  - `deploy/compose/compose.yaml` (the file `make compose-smoke` runs): a `healthcheck:` on each service, with the service's own binary, `--ready`, `interval: 10s`, `timeout: 3s`, `retries: 3`, `start_period: 30s`:
    - port49d: `["CMD", "/usr/local/bin/port49d", "healthcheck", "--ready", "--config", "<its config path>"]`;
    - the broker: `["CMD", "/usr/local/bin/port49-broker", "healthcheck", "--ready", "--config", "<its config path>"]`.

    Compose only reports health and restarts nothing on it, so it can show readiness;
  - the compose smoke (`tests/compose/`), which asserts both services reach `healthy`;
  - `docs/site/operate/troubleshooting/will-not-start.md`'s stub gains the line Task 18 expands: which probe to use where.

**Interfaces:**
- Produces:
  - `func Run(ctx context.Context, listen, path string, out io.Writer) int`. It GETs `http://<host>:<port><path>` within 3 s, the host mapped as above. It exits 0 on 200, else 1 with one line: `healthcheck: <path> answered <code>: <first line of the body>` or `healthcheck: <dial error>`. Everything printed passes through `printsafe.Line` (`internal/printsafe`).
  - The subcommands are `port49d healthcheck`, `port49-broker healthcheck` and `port49-inventory healthcheck`, each `[--ready] [--config FILE]`, `--config` defaulting as the binary's start does.
  - **The default probes `/healthz` (liveness); `--ready` probes `/readyz`; there is no `--live`** (the lead's revised ruling 2, 2026-11-07). A port49d restarted during a store outage answers `/readyz` 503 for the whole outage, so anything that restarts or holds back on unhealthy (Swarm, autoheal, Nomad, ECS, a later `service_healthy` dependency) would kill it again, and it would lose its cached membership and pins. The chart already splits liveness (`/healthz`) from readiness (`/readyz`), and the default matches it. Use `--ready` only for routing or display. Task 18's page says so.
  - **Every path exits 0 or 1,** a bad flag and an unreadable config included: Docker reserves exit 2, and these mains' `flag.ContinueOnError` paths return 2 today, so the healthcheck parses its own flags.

- [ ] **Step 1: Write the failing tests:**
  - `TestRunProbesThePath` (`httptest`): `/healthz` 200 gives 0; `/readyz` 503 with body `waiting for the store` gives 1 and that line; a body holding a control character prints it escaped (`printsafe`).
  - `TestRunDialsLoopbackForAWildcard`: `:9049`, `0.0.0.0:9049` and `[::]:9049`.
  - `TestTheDefaultProbesHealthz`: the subcommand with no flag requests `/healthz`.
  - `TestReadyProbesReadyz`: with `--ready` it requests `/readyz`. There is no `--live`: it is refused as an unknown flag (exit 1).
  - `TestComposeHealthchecksPassReady` in `tests/ci`: every service in `deploy/compose/compose.yaml` with a `healthcheck:` runs its own binary's `healthcheck` with `--ready`.
  - `TestAHealthcheckNeverExitsTwo`: an unknown flag, a missing config file and an unreadable one each exit 1.
  - `TestAnEmptyMetricsListenTakesTheRoleDefault`: port49d `:9049`, the broker `:9050`.
  - `port49d.DaemonSubcommands()` and `BrokerSubcommands()` (Task 3) list `healthcheck`.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/healthcheck/ ./internal/port49d/ -run 'Healthcheck|Run|Default|Ready|Exits|MetricsListen|Subcommand' -count=1`, `go test ./tests/ci/ -run '^TestComposeHealthchecksPassReady$' -count=1` and `go vet -tags compose,failmatrix ./tests/compose/...`. The compose smoke runs in CI (`compose` workflow) on the pull request. Report its run.
- [ ] **Step 5: Commit:** `git add internal/healthcheck internal/port49d cmd/port49-inventory deploy/compose tests/compose tests/ci docs/site/operate/troubleshooting/will-not-start.md && git commit -m "feat: a healthcheck subcommand for images without a shell, used by compose"`

---

### Task 11: The alerts reference, with a `runbook_url` on every rule

**Files:**
- Create: `internal/docgen/alerts.go` and its test; `docs/site/reference/alerts.md` (generated).
- Modify:
  - `deploy/alerts/port49.rules.yaml` and its byte copy `deploy/helm/port49/files/port49.rules.yaml`: every rule's `annotations` gains `runbook_url: <site_url>reference/alerts/#<alert>`;
  - `deploy/alerts/port49.rules.test.yaml`: promtool compares annotations exactly, so each of its `exp_annotations` blocks gains the same `runbook_url` for its alert;
  - `tests/alerts/alerts_test.go`.

**Interfaces:**
- Consumes: `Alerts` (Task 7).
- Produces: `func AlertsPage(as []Alert, readme []byte) (string, error)`.
  - One `### <alert>` section per rule, in the file's order, with its anchor `{#<alert>}`.
  - Each section gives severity, `for`, the expression in a code block, the summary, and the `deploy/alerts/README.md` row for that alert (its "what to do" cells).
  - The page opens with the README's text above `## The rules`, through the `intro` snippet section marker Task 1 placed.
  - The error names a rule with no README row.

- [ ] **Step 1: Write the failing tests:**
  - `TestEveryRuleHasARunbookURL` in `tests/alerts`: the annotation equals `site_url` from `mkdocs.yml` joined with `reference/alerts/#` and the alert name.
  - `TestEveryRunbookAnchorExists`: the anchor is in `AlertsPage`'s output.
  - `TestEveryExpectedAnnotationCarriesTheRunbook`: every `exp_annotations` block in `port49.rules.test.yaml` holds its alert's `runbook_url`.

  `TestTheChartCarriesTheSameRules` already holds the copy.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement,** and add the annotations with a one-off `go run` over the YAML nodes of both the rules and the promtool test file. Never hand-edit 76 rules and 87 expected blocks. Run `make docs` and `make alerts-check`.
- [ ] **Step 4: Run** `go test ./tests/alerts/ ./internal/docgen/ -count=1`, `make alerts-check`, then `make docs-build`.
- [ ] **Step 5: Commit:** `git add deploy/alerts/port49.rules.yaml deploy/alerts/port49.rules.test.yaml deploy/helm/port49/files/port49.rules.yaml tests/alerts internal/docgen docs/site/reference/alerts.md && git commit -m "feat: every alert rule links its runbook on the docs site"`

---

## The pages (Tasks 12 to 24)

Every content task has the same five steps. Each task lists only its pages, its sources and its `mustSay` rows.

1. **Red.**
   - Write the task's rows in its own file, `tests/ci/docs_content_<NN>_test.go`, as `func init() { mustSay["<page>"] = append(mustSay["<page>"], …) }`. Task 1 created `mustSay` and `TestEveryPageSaysWhatItMust` in `tests/ci/docs_content_test.go`, so parallel tasks never edit one file.
   - Run `go test ./tests/ci/ -run '^TestEveryPageSaysWhatItMust$' -count=1` and paste the red.
2. **Write the pages.**
   - Remove `status: stub`.
   - Read each source in the task, and the PR bodies of the plans it covers.
   - Grep every name before writing it (Global Constraints).
   - Prefer a snippet to restating a README. A snippet README line that fails Task 3's lint or Task 4's built-site pass is fixed in that README, in this task.
   - Link the generated reference pages instead of listing keys, reasons or metrics again.
3. **Green.** `go test ./tests/ci/ ./internal/docgen/ -count=1`, `make docs-build` and `PORT49_DOCS_SITE=site go test ./tests/ci/ -run '^TestTheBuiltSite' -count=1`, all PASS.
4. **Read it as the operator.** For each troubleshooting or 3am line, trace the mechanism in the code or the failure matrix and confirm the page's "do this" works on a bad day: store down, broker unreachable, IdP down. The task report lists each line traced.
5. **Commit:** `git add <the task's pages> <any README it fixed> tests/ci/docs_content_<NN>_test.go && git commit -m "docs: <the pages>"`.

### Task 12: Concepts

**Pages:** `concepts/index.md` (one login end to end, as a numbered sequence or a committed SVG, not mermaid: person, `port49 login`, agent, broker, device, port49d), `concepts/tokens-receipts-contexts.md`, `concepts/identities.md` (people: x509, issued certificates over OIDC, directory password; machines: workload certificates, Kubernetes service accounts), `concepts/revocation.md`, `concepts/trust-domains.md`.

**Sources:** design §7 and §8, spec §5.1 and §5.6, decisions 15, 21, 39, 43, 47.

**mustSay:**
- `tokens-receipts-contexts.md`: `receipt_idle_ttl`, `receipt_max_age`, `token_spent`, `(nas, username)`;
- `revocation.md`: `port49 revoke`, `credential_revoked`;
- `trust-domains.md`: `trust_domain_unresolved`.

### Task 13: Install, clients and versions

**Pages:**
- `operate/install/index.md`:
  - choosing a shape, the three as peers;
  - the four requirements every shape states (plan 12: the source address unrewritten, two processes on etcd, `broker.state_dir` survives, the disk);
  - "install port49 0755 with no setgid and no file capabilities" (plan 9a P15, with the reason: the askpass);
  - `port49d init-revocations` as the first-install step (plan 7c).
- `operate/install/systemd.md`, `container.md`, `helm.md`: a short intro, then `--8<--` of `deploy/systemd/README.md`, `deploy/compose/README.md` and `deploy/helm/port49/README.md`.
- `operate/install/clients.md`:
  - the two `port49` builds and which has hardware keys (plan 9c);
  - the Python client and the Ansible collection, by snippet of their READMEs (change the Ansible README's `/home/ops` example to `/home/<user>`);
  - the Mac and Homebrew `libykcs11` notes (`--module`; no probe path ships for macOS).
- `operate/versions.md`: SemVer (Ryan, 2026-10-30). `v0.1.0` is the beta; 0.x may break config with loud notes; `1.0.0` is the compatibility promise; one version across every artifact; `--version` (Task 9).

**mustSay:**
- `install/index.md`: `0755`, `setgid`, `init-revocations`, `externalTrafficPolicy: Local`;
- `versions.md`: `v0.1.0`, `1.0.0`, `--version`;
- `clients.md`: `--module`, `libykcs11`.

### Task 14: The broker and the agent, logging in, hardware keys

**Pages:**
- `operate/broker-and-agent.md`.
- `operate/login.md`:
  - `port49 login`, `port49 token` (with `--json` and its reason codes), `port49 ssh`;
  - **the exit-code table** for `port49 ssh`, `port49 login`, `port49 revoke` and `port49 hwkey`, read from the code (`cmd/port49/*.go`) and plan 9a's carry: `port49 ssh`'s own refusals exit 1, as a remote command's exit 1 does, and the `port49 ssh:` line tells them apart; login exits 2 where ssh exits 1 for the same refused `~/.config`;
  - OpenSSH owns host keys (`accept-new`, `known_hosts`; plan 9d).
- `operate/hardware-keys.md` ("set up your key"):
  - `port49 hwkey setup` and `port49 hwkey status`, with the plan 12c operator notes' roots line and exit codes;
  - the two risk notes: a lent key plus its PIN is the user's login, and a wrong attestation root;
  - the macOS module check trusting group `admin`, written as unmeasured (L63 open);
  - L60's parallel-forks touch question, unmeasured;
  - **issue #6 as intended behaviour:** a wrong PIN typed in another process logs a running agent off its key, so log in again. The PR body says `Closes #6`.

**mustSay:**
- `login.md`: `port49 ssh:`, `--json`, `accept-new`;
- `hardware-keys.md`: `port49 hwkey setup`, `roots: from broker`, `--roots`.

### Task 15: Stores and RFC 9887

**Pages:**
- `operate/stores.md`: every bullet of the roadmap's "From plan 11a" Stores list, in order, plus `port49 store status` and the pending-logout dedupe note.
- `operate/tls.md`: every item of the roadmap's "From plan 11" list:
  - the two listeners, `listen: none`, `tls_listener`'s keys, identity by inventory name or address;
  - migrating `tcp` to `tls` with the dual-server window kept short;
  - the server certificate's names (the IOS XE 17.18.02 finding, cited to `L73-cisco_iosxe.md`; Junos and NX-OS unproven, so unmeasured);
  - `tls_name_clash`, unidentifiable devices, the Junos mutual-TLS line;
  - IOS XE and a down store;
  - the `component` label;
  - which edits need a restart.

  Link `reference/decision-log.md#tls_outcome` (Task 6 emits the anchor).

**mustSay:**
- `stores.md`: `port49 store status`, `port49 directory forget`, `--bump-revision`;
- `tls.md`: `tls_name_clash`, `identity_mismatch`, `tls mutual-authentication certificate-id`, `no_client_certificate`, `ignoring(component)`.

### Task 16: Secrets and key rotation

**Pages:**
- `operate/secrets.md`:
  - `secret_ref` forms and `key_secret_refs`, per shape;
  - the secret-file rule (owner root or the service user, no world bit, group-read for a group the service is in, Debian's `ssl-cert` refused);
  - Secret volumes mounted whole, never `subPath` (L82);
  - Vault Agent only with `agent-run-as-same-user: "true"` (L83);
  - the Secrets Store CSI driver not supported for device keys (L83).
- `admin/key-rotation.md`:
  - device keys as `keys:` policy edits, with the 30 s retry while a file is rendered;
  - add a version by a new file, never edit one in place (`port49_key_secret_files_changed`);
  - `single_device`;
  - the `bundle.Open` key-id collision note;
  - the `encryption:` three-step rotation (R27; one key set everywhere);
  - the issuing CA (`init-issuer` once, copies to every broker, compare the fingerprints; `rotate-issuer`; `forget-issuer`; the issuer record's three refusals at 3am from plan 12a).

**mustSay:**
- `secrets.md`: `subPath`, `agent-run-as-same-user`, `defaultMode`, `fsGroup`;
- `key-rotation.md`: `port49_key_secret_files_changed`, `single_device`, `init-issuer`, `rotate-issuer`.

### Task 17: Backup and restore

**Pages:** `operate/backup-and-restore.md`:
- what each shape must keep: `broker.state_dir` (`marks.json`, `witness.json`, the issuing CA), the revocations file, `<accounting.spool_path>.restore.json`, `enrollments.json`;
- the enrollments export (CronJob, `init-enrollments`);
- **the restore floor** as the pre-beta fixes built it:
  - `token_spent` for restored tokens;
  - the drop line;
  - `port49_store_restore_detected`;
  - `port49_redemption_restore_unjudged`;
  - `--bump-revision`;
- the Velero runbook by snippet of `deploy/helm/port49/examples/velero/README.md` (its "certificates your devices trust" passes the narrowed `removed_name` rule), with the `restore-unspent` Job, pods running (L89 c), and GitOps suspended (unmeasured, and it says so).

**mustSay:** `restore-unspent`, `token_spent`, `port49_redemption_restore_unjudged`, `--bump-revision`, `restore.json`.

### Task 18: Monitoring and troubleshooting

**Pages:**
- `operate/monitoring.md`:
  - scraping (`job` names `port49d` and `port49-broker`; the PodMonitor);
  - the alerts (link `reference/alerts.md`);
  - the disk requirement: WAL fsync p99 under 10 ms, `etcd_disk_slow`, `port49_accounting_spool_disk_slow`, `load-beehive-gates.md`, with no host name in the text;
  - dedupe accounting on `task_id`;
  - the shedding lines and `port49_connections_shed_total{reason="global_cap"}`.
- `operate/troubleshooting/failure-matrix.md`: an intro, then `--8<-- "deploy/failure-matrix.md"`.
- `operate/troubleshooting/will-not-start.md`:
  - the systemd and compose "When it will not start" sections, by their `will_not_start` snippet markers;
  - **which healthcheck to use where** (Task 10), said plainly: use the default (`/healthz`) for anything that restarts or holds back on unhealthy (Swarm, autoheal, Nomad, ECS, a `service_healthy` dependency); use `--ready` (`/readyz`) only for routing or display (compose's `healthy`, a load balancer's member check). A store outage must never restart-loop port49d, which would cost it its cached membership and pins;
  - a Kubernetes section written from the chart README's facts (a broker refused "behind a promotion" crash-loops: copy the CA files with a debug pod mounting its state PVC).
- `operate/troubleshooting/index.md`, **the 3am index**, in three parts:
  - **"A person tells you…"**: cannot log in to one device; to every device; break-glass does not work (IOS XE and XR do not fall to local on ERROR; the dead windows from `deploy/device-aaa/README.md`); a session ended early; "revoked at".
  - **"An alert fired"**: one line per page-severity alert, linking its `reference/alerts.md` anchor.
  - **"A log line says…"**, each with meaning and action:
    - `serving <principal>'s cached directory membership (its pin as this region last read it)`, said once per principal per 10 minutes; past 1024 principals the map behind it stops deduplicating, so it can repeat;
    - `the logout queue is full; a pass over the whole logout set follows`;
    - `the session store was restored from a snapshot`;
    - the 24 h directory outage that revokes directory sessions on restart (fails closed);
    - `port49_revocations_file_failed` at 1 (run the revoke again; do not restart).

  Each entry has four parts: **you see**, **it means**, **do this**, **don't**. In "A log line says…", the **you see** is the line in a code span, `<…>` for each variable part, copied from the code.

**An extra test:** `TestEveryQuotedLogLineIsInTheCode`. For each **You see:** code span in that section, the text, with each `<…>` a wildcard, matches a string literal in non-test Go under `internal/` or `cmd/`, a format verb (`%s`, `%v`, `%d`, `%q`) matching a wildcard. Mutation: change one word of a quoted line, and the test is red.

**mustSay:**
- `index.md`: `cached directory membership`, `the logout queue is full`, `port49_revocations_file_failed`, `store_unavailable`;
- `will-not-start.md`: `--ready`, `/healthz`;
- `monitoring.md`: `task_id`, `global_cap`, `10 ms`.

### Task 19: Policy, roles and grants, revocation

**Pages:**
- `admin/policy.md`:
  - the policy file (link `reference/config/policy.md`);
  - scopes, `on_missing`, the include-scope grant refusal and its fix;
  - `security_log` defaulting true for a deny-bearing scope, and `deny_scope_unlogged`;
  - `port49 policy test` (which also reports lint findings such as `deny_scope_unlogged`), `port49 policy diff` (the gate, `acknowledge:`, the ceiling line), `port49 policy replay`, `port49 explain`;
  - platform sets 1.1.0, 1.2.0 (`rpc_entry_denies`) and 1.3.0 (`view-configuration`), and `port49 platform upgrade`;
  - "a new grant is a reviewer's call: the gate does not see it".
- `admin/roles-and-grants.md`: roles, `max_session_age` per role, `machine_group:` subjects, `per_login_mfa`, `api:` rights.
- `admin/revocation.md`, every plan 7a, 7b and 7c operator note:
  - `port49 revoke --cert` over `--cert-serial`;
  - the exit codes;
  - close the device sessions after revoking a stolen certificate;
  - `certificate_status` (required; `disabled: true`);
  - CRL `issuer_file` rules;
  - `on_unavailable: refuse`;
  - lifting a CRL-origin mark.

**mustSay:**
- `policy.md`: `on_missing: exclude`, `deny_scope_unlogged`, `acknowledge:`, `rpc_entry_denies`, `view-configuration`;
- `revocation.md`: `--cert-serial`, `certificate_status_unavailable`, `issuer_file`, `disabled: true`.

### Task 20: Identity providers, workloads and inventory

**Pages:**
- `admin/identity-providers.md`:
  - OIDC issuance (`broker.identity.issuance`, `certificate_lifetime`);
  - a person's ID token is never a bearer except at `POST /v1/certificate` and as an `idp_mfa` proof;
  - back-channel logout under ruling B: a token with `sid` and `sub` ends every session of that `sub`;
  - the plan 7h recovery forms (read them from Plan 7h — As built);
  - the directory (LDAP, AD, Samba), and directory-password sign-in with TOTP enrolment;
  - CertNameToStr characters, the multi-valued RDN, and `identity_unmapped` printing the searched value.
- `admin/workloads.md`:
  - workload certificates and step-ca enrollment (`step-ca-workload.tpl`, the README's §2, §3 and §5);
  - the workload directory (plan 8b: opting in, choosing the attribute, M-5);
  - Kubernetes service accounts, by snippet of `examples/kubernetes/README.md`;
  - Oxidized, by snippet of `examples/oxidized/README.md`.
- `admin/inventory.md`:
  - the inventory file and the service, NetBox and Nautobot;
  - the plan 6c operator notes, verified first: `HTTPS_PROXY` "until plan 12" may have changed;
  - quarantine, `max_removed_percent` (10, and why it stays);
  - `inventory.service`.

**mustSay:**
- `identity-providers.md`: `POST /v1/certificate`, `idp_mfa`, `sid`, `identity_unmapped`;
- `workloads.md`: `machine_group:`, `step-ca`;
- `inventory.md`: `max_removed_percent`, `interval`.

### Task 21: Device pages

**Pages:** `admin/devices/index.md`:
- how to read a device page (measured, cited, or "Unmeasured");
- the qualified-platforms table by snippet of `docs/qualified-platforms.md`, with its "What an operator must do" list and its `partial` and "re-vet pending" meanings;
- the reference configurations by snippet of `deploy/device-aaa/README.md`.

Then one page per `DevicePages` entry, each with these sections in order:
1. a lead paragraph with the one thing that bites;
2. `## Reference configuration` (the `deploy/device-aaa/<platform>*.cfg` files, linked, and the placeholders table by reference);
3. `## What the lab measured`;
4. `## Traps`;
5. `## Unmeasured`: each item is its own `!!! warning "Unmeasured…"` admonition, the only form Task 4 accepts;
6. `## Lab evidence` (Task 8's snippet).

**Facts per page** (each cited per Task 4):
- **SR Linux** leads with "sends no command authorization" (L76, L88 e). Also `priv-lvl-authorization true`, where the default false sends port49 no authorization and the YANG says that is full admin; `services [ cli ]` per local role; `exit-on-reject true`; L92 (a `tls-profile` sent plain TACACS+) is open, so it goes in `Unmeasured`.
- **Junos:**
  - `authentication-order tacplus` alone (L4);
  - the IP sent as SNI (`server_names` lists every address or stays unset; `internal_error` at the device is `sni_mismatch` at port49d);
  - mutual TLS via `tls mutual-authentication certificate-id` (26.2R1+, not SRX);
  - `idle-timeout` per class (`port49 platform export --classes`);
  - set 1.2.0's `junoscript`/`op` denies and 1.3.0's `view-configuration`;
  - the live shell keeping its access until logout;
  - an ERROR is final;
  - **L78 (a reply over 255 bytes) is open on hardware:** `Unmeasured`, with Ryan's production prior stated as a prior, not a measurement. The page covers vJunos, vSRX and hardware: a hardware or SRX claim stays in an admonition even where a vJunos note link would pass Task 4.
- **IOS XE:** no fall to local on ERROR (L73 cell i, L4); the 30 to 39 s TCP and 57 to 67 s TLS dead windows; a server certificate naming another address accepted (L73).
- **IOS XR (XRd 26.1.1):** dials TLS on 49, not 300, unless `port` is set; `domain name` before enrolment; group member and host in separate commits; the `platforms:` privilege block (`policy-platforms.yaml`); no fall to local on ERROR; a local account logging in inside the dead window (L88 a).
- **NX-OS:** 10.6(2)F over TLS honors single-connect (`L80-cisco_nxos.md`). L73 is closed: state what `L73-cisco_nxos.md` measured on Nexus 9300v 10.6(2)F (2026-10-18), cited to it. Then say, in a paragraph (not a list item, so Task 4's claim check does not read it as a claim), with no L-ID and no admonition, that the 2026-11 regression rerun of that entry did not reproduce and is pending (issue #46). Never write L73 inside an `Unmeasured` admonition: it is closed, and Task 4 fails it.
- **EOS:** from its notes.
- **IOS XE** also carries IOL-XE (`L71-cisco_iol-xe.md`), named as such, and `L31-breakglass-cisco-singleconnection.md` with NX-OS.
- **Other platforms:** the generic adapter and `generic_platform`.

**mustSay:**
- `nokia-sr-linux.md`: `sends no command authorization`, `priv-lvl-authorization true`, `services [ cli ]`;
- `juniper-junos.md`: `authentication-order tacplus`, `server_names`, `sni_mismatch`, `Unmeasured`;
- `cisco-ios-xr.md`: `domain name`, `policy-platforms.yaml`;
- `cisco-ios-xe.md`: `break-glass`;
- `cisco-nx-os.md`: `single-connect`.

**Extra step, after Step 3:** two mutations, each restored:
- take one sentence citing an open row on `juniper-junos.md` out of its admonition: `TestOpenLabEntriesAreWrittenAsUnmeasured` goes red naming that line;
- remove the results-note link from one `## Traps` bullet: `TestEveryDeviceClaimCitesItsEvidence` goes red.

### Task 22: AI agents

**Pages:**
- `agents/quick-start.md`, as the roadmap's "Agent quick start" item describes it:
  - the agent's own machine identity, never a person's login;
  - a subject of its own with the narrowest roles;
  - the tooling mints and presents the token, so it never enters the agent's context or transcript;
  - a refusal reaches the agent as a reason code through its tooling, never by running `port49 token`: the `port49 ssh:` line, or the Python client's or the Ansible lookup's error. Verify that each carries the reason code (read the code) before writing it. On success, `port49 token --json` prints the broker's whole answer, the token included (`cmd/port49/main.go`), so the agent pages never run it;
  - every command is recorded under its principal;
  - `per_login_mfa_required` devices stay human;
  - the worked example: one read-only agent, from identity to a recorded `show` command, with every value a placeholder.
- `agents/setup-runbook.md`, written for an agent to follow:
  - the decisions it asks its human first (shape, identity provider, trust domain, devices);
  - per shape, the path as links into the operator guide (never restated), each step followed by its check (`port49 policy test`, a smoke login);
  - its stops for a human: secrets, hardware keys, any device's AAA configuration.

**mustSay:**
- `quick-start.md`: `per_login_mfa_required`, `port49 ssh:`;
- `setup-runbook.md`: `port49 policy test`, and the literal heading `## Stop and ask a human`.

**Two extra tests:**
- `TestTheRunbookLinksAndDoesNotRestate`: it fails if `setup-runbook.md` holds a fenced block longer than 5 lines, so steps stay links into the guide.
- `TestTheAgentPagesNeverRunPortTokenToStdout`: no fenced block under `docs/site/agents/` holds a line that runs `port49 token`.

### Task 23: Contributing

**Pages:**
- `contributing/index.md`: building, `make test && make vet`, `make hooks` once per clone (the gitleaks pre-commit), and the lab register rules (CLAUDE.md, restated for contributors).
- `contributing/qualification.md`:
  - `tests/qual/README.md` by snippet (vetting a firmware, adding a platform, `make qual`, `make qual-vet`, `make qual-fleet`, goldens, `engine_gaps`; vendor images are never hosted);
  - the `lab-regress` environment by its `regressions` snippet marker in `tests/lab/README.md` (Task 1). Rewrite that section's "(on beehive, …)" so it names no host;
  - the NX-OS boot hang's `-only=` workaround.
- `contributing/releasing.md`: `RELEASING.md` by snippet.

**mustSay:**
- `qualification.md`: `make qual-vet`, `engine_gaps`, `-only=`;
- `index.md`: `make hooks`.

### Task 24: The top-level README

**Files:** `README.md`; the site's `index.md` (the same points, shorter).

The README is an overview of why anyone would use port49, not a feature list (Ryan, 2026-11-03):
- one sentence on what it is;
- under the heading `## Why port49`, three to five selling points, each one claim and one reason, chosen from:
  - **identity on unmodified devices:** certificates or SSO for people and machines; the device sees ordinary TACACS+;
  - **nothing to steal:** a short-lived, single-use, device-bound token instead of a shared password;
  - **policy as reviewed code,** with a gate on widening changes;
  - **built for a bad day:** break-glass and failure behavior measured per platform;
  - **runs where you run things:** systemd, a container or Helm, as peers;
- a ten-line example of one login, with placeholders only;
- status (beta `v0.1.0`; what "beta" promises, per `operate/versions.md`);
- links to the site, the qualified platforms and `CONTRIBUTING`;
- the license.

Remove "Status: early design. Nothing is implemented yet." and "Kubernetes-native" from the tagline.

**mustSay:**
- `README.md`: `systemd`, `Helm`, `Apache-2.0`, the `site_url`;
- a negative check, `TestTheReadmeIsNotAFeatureList`: `## Why port49` holds three to five top-level bullets; the rest of the README holds at most 7 top-level bullets; and it does not say "Kubernetes-native" or "Nothing is implemented".

**The wording is Ryan's.** The task report and the PR body say "README wording awaits Ryan's review before go-public" (Decision 3). The roadmap keeps it on the go-public list until Ryan confirms.

### Task 25: Close

- [ ] **Step 1:** `TestNoPageIsAStub` in `tests/ci/docs_test.go`: no page's front matter holds `status: stub`. Run it: it must pass. A red here means a page task is unfinished; finish that page, never delete the test.
- [ ] **Step 2: The source map.** For each row above, name the page and heading that carries it in the task report. A row without one is a gap: fill it before Step 4.
- [ ] **Step 3: Verify:**
  - `make docs && git diff --exit-code docs/site`, which shows nothing stale;
  - `make test && make vet`;
  - `make docs-build`;
  - `PORT49_DOCS_SITE=site go test ./tests/ci/ -run '^TestTheBuiltSite' -count=1`;
  - `make leaks`.

  Report the real output of each.
- [ ] **Step 4: The roadmap.** In `docs/superpowers/plans/README.md`'s Plan 13 section, record the execution in the status line, and add "Plan 13 — As built". Its operator-facing notes are:
  - the site and its URL;
  - `--version`;
  - `healthcheck` and the compose healthchecks;
  - `runbook_url` on every alert;
  - the site's version banner, and deploys moving from `main` to `v*` tags at the first release;
  - `make docs`, `make docs-build`.

  Also list what is left: the README wording (Ryan) and Decision 4's settings (go-public).

  Commit: `git add docs/superpowers/plans/README.md tests/ci/docs_test.go && git commit -m "docs: plan 13 as built"`.
- [ ] **Step 5: The pull request.** The body carries:
  - "Operator-facing notes" (Step 4's list);
  - `Closes #6`;
  - "README wording awaits Ryan's review before go-public";
  - the compose CI run for Task 10.

  It carries no session link.

## Left for later

- **Older releases' docs:** the site shows one version, `main`'s before `v0.1.0` and the latest tag's after. Keeping each release's pages (for example `mike`) waits for 1.0.
- **An external link check:** every external link is unreachable while the repository is private. Run one at go-public: `RELEASING.md` item 9, Task 2.
- **Defaults in the config reference** are written into the descriptions by hand. Task 5's table test guards about ten of them; the rest are checked by review. A generator that reads `daemonDefaults` needs the defaults moved into data first.
- **The Zensical move:** Material for MkDocs reaches end of life on 2027-05-05. Decide the move before then.
