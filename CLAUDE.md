# port49 — working conventions

port49 is a TACACS+ server in Go that delivers certificate- or OIDC-based identity to
unmodified network devices. Apache-2.0. Read this file first, then the plan you are executing.

## Where things are

| Path | What it is |
|---|---|
| `docs/design/2026-08-21-port49-design.md` | Architecture. §19 is the build sequence every plan follows. |
| `docs/design/2026-08-23-policy-engine-spec.md` | The spec. §13 records decisions; §15 is the lab register. |
| `docs/design/*-findings.md` | Review history. Every item is resolved; read for rationale, not for work. |
| `docs/superpowers/plans/` | Implementation plans, one per design §19 step group, numbered in build order. |
| `tests/lab/` | Containerlab harness and results notes (created by plan 1). |

## How the work is sequenced

- **One plan per design §19 step group**, named `YYYY-MM-DD-NN-<slug>.md` where `NN` is the
  step order. Plan 1 is the protocol core. **`docs/superpowers/plans/README.md` is the
  roadmap**: for every plan it lists what it builds, the spec sections it implements, what
  earlier plans hand it, what it leaves for later, and which lab entries close in it. Start
  there when writing a plan, and update its status line when a plan is written.
- **Write plan N+1 only after plan N is merged.** A plan names exact files and signatures,
  so it is written against real code, not a guess. The one exception: plan 2 may be written
  from plan 1's text, because plan 1 fixes the interfaces plan 2 builds on.
- **Do not write plan 3 before plan 1's lab results exist.**
- Execute a plan with `superpowers:subagent-driven-development` or
  `superpowers:executing-plans`, task by task, tests first.

## The lab register is the source of truth for device behavior

Spec §15 lists every claim about device behavior with an ID (L1–L12). Rules:

1. A claim cited to an open entry is unmeasured. Do not "fix" the docs to assert it.
2. A decision marked *provisional on L<N>* stays provisional until that row closes.
3. **Closing an entry** means: the lab test passed, `tests/lab/results/L<N>-<platform>.md`
   exists with platform, image version, observation, and a capture pointer, and the row's
   Status in spec §15 is edited to `closed — measured <date>; tests/lab/results/L<N>-<platform>.md`.
   Commit that as `docs: close lab register entries ...`. A row with one platform measured
   and others open stays open.
4. If a lab result contradicts a doc, the doc is wrong. Fix the doc, cite the results note,
   and say so in the commit message.

## Code conventions

- Go 1.26+ (etcd's floor, plan 7d), module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

## Git

- Conventional Commits. Branch per plan: `feature/<plan-slug>` (plan 1 is
  `feature/protocol-core`). Never commit code directly to `main`; docs-only changes to
  `main` are fine while the design is in flux.
- Small, atomic commits, one per plan task step that says "Commit".
- Commit messages end with:
  ```
  Co-Authored-By: Claude <model name> <noreply@anthropic.com>
  ```
  and nothing else: no `Claude-Session:` line and no claude.ai session link, in commits, PR
  descriptions, issues or comments (this repo is going public).

## About Ryan

Pronouns they/them. Judges every mechanism by what an operator sees at 3am when the store
is down or the broker is unreachable; trace that before proposing anything. Prefers short
answers with a concrete example over option surveys. Their TACACS+ instincts come from
running it in production and from the SRX lab tests; treat those as better than the docs
when they disagree, and settle disagreements in the lab.
