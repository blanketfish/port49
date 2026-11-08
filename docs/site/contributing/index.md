---
title: Contributing
description: How to build, test and change port49, and the lab register rules that decide what a doc may claim about a device.
---

# Contributing

port49 is a TACACS+ server in Go (Apache-2.0). This page is what a contributor needs before the first
change: how to build and test, the one-time hook setup, and the rule that decides what the docs may say
about a device.

## Build and test

You need Go 1.26 or later. The module is `github.com/blanketfish/port49`, and the build is static, with no cgo.

```sh
make build
make test && make vet
```

- `make test` runs the lab harness's unit tests (no device), the Python client and Ansible collection tests
  (Python 3.10 or later), and the whole Go suite (`go test ./... -count=1`). A full run takes about 20 minutes.
- `make vet` fails on any file `gofmt` would change, then runs `go vet`. A change is not ready until both
  commands pass, and you should report their real output in the pull request.
- Anything that needs a device image, a container runtime or the lab is a separate `make lab-*` target and
  is never part of `make test`. A pull request does not need the lab. Leave those targets to a maintainer
  with the lab; see [Qualification](qualification.md).

## Once per clone: the hooks

```sh
make hooks
```

`make hooks` points this clone's `core.hooksPath` at `.githooks`. That enables two checks on every commit:
a secret scan of the staged changes (`gitleaks`), and a check that the commit message carries no session
link or trailer. The setting lives in the clone's git configuration, which its worktrees share, so run it once per clone. Never bypass a finding with
`--no-verify`; fix it.

## Conventions

- **Branches and commits.** Branch from `main` as `feature/<slug>` or `fix/<slug>` and open a pull request.
  Commit with [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`,
  `chore:`, `refactor:`, `test:`). Keep commits small and atomic.
- **snake_case wherever it is data.** YAML keys, JSON log keys, configuration keys and metric names.
- **Reason codes are a closed list.** A decision's `reason` comes from the table in
  [spec §5.7](https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-23-policy-engine-spec.md)
  and `internal/decision/reasons.go`. To add one, add it to the spec table first.
- **The log never holds a secret.** No token, password, challenge or response, ever. A credential appears
  only as `credential_sha256`, and a body that has not been validated is never logged.
- **No device identity in a metric label.**

## The lab register

Every claim about how a device behaves has an entry, `L<N>`, in the lab register: the table in
[spec §15](https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-23-policy-engine-spec.md).
The register, not memory or a vendor manual, is the source of truth for device behavior. Four rules:

1. **A claim cited to an open entry is unmeasured.** Do not "fix" a doc to assert it.
2. **A decision marked provisional on `L<N>` stays provisional** until that row closes.
3. **Closing an entry** means all of these:
    - the lab test passed;
    - `tests/lab/results/L<N>-<platform>.md` exists, with the platform, the image version, the observation
      and a capture pointer;
    - the row's Status in spec §15 is edited to
      `closed — measured <date>; tests/lab/results/L<N>-<platform>.md`;
    - the change is committed as `docs: close lab register entries ...`.

    A row with one platform measured and others open stays open.
4. **If a lab result contradicts a doc, the doc is wrong.** Fix the doc, cite the results note, and say so
   in the commit message. A results note wins over a doc.

On this site, a device claim links its results note, or it sits in an "Unmeasured" box worded as unknown.

## Where the design lives

- [The architecture](https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-21-port49-design.md)
  and [the policy engine spec](https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-23-policy-engine-spec.md)
  (§13 records decisions, §15 is the register).
- `docs/superpowers/plans/`: one implementation plan per build step, and its `README.md` is the roadmap.
- `tests/lab/`: the lab harness, and `tests/lab/results/` for the notes the register cites.

## More

- [Qualification](qualification.md): vetting a firmware, adding a platform, and the lab regression run.
- [Releasing](releasing.md): how a release is cut and published.
