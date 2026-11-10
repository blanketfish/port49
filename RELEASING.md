# Releasing port49

<!-- --8<-- [start:release] -->
A release is a `v*` tag on a commit that is on `main`. The `release` workflow
(`.github/workflows/release.yml`) does the rest: it checks the tag against every version file, builds
the packages, image, chart, Python package and Galaxy collection, and publishes each from a job that
only downloads. The GitHub release stays a draft until every publisher has finished.

Nothing publishes until a tag is pushed. Do the one-time setup below first; it is what makes a tag
without approval harmless.

## Versioning

port49 uses SemVer. `v0.1.0` is the beta. In 0.x, configuration may break between releases, and every
such change gets a loud release note. `1.0.0` is the compatibility promise. There is one version across
every artifact (packages, image, chart, Python package, Galaxy collection), and bumps come from
Conventional Commits. Tags are pushed by hand and carry no pre-release suffix unless it maps to a valid
PEP 440 version. The docs site states the same on its Versions page.

## One-time setup, before the first tag

1. **PyPI trusted publisher.** Project `port49`, repository `blanketfish/port49`, workflow
   `release.yml`, environment `pypi`.
2. **Environments** (Settings, Environments):
   - `release` (the goreleaser, image and chart jobs): the maintainer as the **required reviewer**, so
     no tag publishes without approval.
   - `pypi` and `galaxy`: created beside it.
   - Each of `release`, `pypi` and `galaxy`: deployment branches and tags restricted to the **`v*`
     tag pattern**.
3. **`GALAXY_API_KEY`** is an **environment secret on `galaxy` only**: never a repository or
   organization secret, so no other job can read it.
4. **Tag ruleset.** A repository ruleset protecting `v*` tags (restrict creation, updates and
   deletion to the maintainers).
5. **Fork pull-request workflows.** Settings, Actions, General, "Fork pull request workflows from
   outside collaborators": **Require approval for all outside collaborators**.
6. **Public packages.** When the repository goes public, make the GHCR package `port49` and the
   chart package public.
7. **Docs site.** Settings, Pages, source **Deploy from a branch**: `gh-pages`, folder `/ (root)`.
   `docs.yml`'s `deploy` job runs [mike](https://github.com/jimporter/mike), which keeps one built
   copy of the site per version on that branch, and GitHub's own `pages-build-deployment` publishes
   it: there is no `github-pages` environment and no Pages token. Outside `release.yml`, the `deploy`
   job is the only workflow job with `contents: write`. It runs only from a public repository, in
   two steps that never share the token: `site` fetches `gh-pages` and then the tags, decides the
   version and aliases itself, builds with mike and commits locally, with no token in its
   environment; `push` holds the token, runs only git, and pushes `gh-pages` (never forced) from a
   clean bare repository with hooks and the runner's git configuration off. If another deploy moved
   `gh-pages` first, `push` fails with "another deploy moved gh-pages; re-run this job": re-run it,
   there is no automatic retry. Keep the `main` ruleset off `gh-pages`, or the bot's push is refused. The job also commits a root `404.html` that sends an old `/port49/<page>` link to
   `/port49/latest/<page>`, and a root `llms.txt` copied from `latest`.
8. **Required check.** Add `docs` (the build job in `docs.yml`, named `docs`) to the required
   status checks of the `main` ruleset. What deploys: every push to `main` replaces `/dev/`; a final
   `vX.Y.Z` tag on `main` replaces `/X.Y/` if it is the highest patch of that line, and moves
   `/latest/` (the alias the site root redirects to) if it is also the highest final tag. Only final
   tags that are on `main` count, so a stray tag elsewhere takes nothing. Before the
   first final tag, `/latest/` is an alias of `/dev/`. A lower patch pushed late deploys nothing.
9. **Link check.** At go-public, run one external link check over the built site (for example
   `lychee` on `site/`) and fix what it finds.

## Each release

1. Set the same version in `clients/python/pyproject.toml`, the collection's `galaxy.yml`, and the chart
   and app versions; `go run ./tests/ci/cmd/versioncheck -tag vX.Y.Z` must pass.
2. Merge to `main`. The tag must be on `main`; the workflow refuses it otherwise.
3. The maintainer pushes the tag; nobody else, and no automation, does. The maintainer approves the `release` environment when the run asks.
4. Check the draft release's assets and provenance attestations, then let the last job publish it.
<!-- --8<-- [end:release] -->
