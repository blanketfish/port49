# Qualification suite: contributor procedures

The mock tier (`make qual`) replays each vetted firmware's measured behavior against a real
in-process port49d: no images, no lab, any runner. A mock exists only for a firmware the lab has
run. The lab run is `make lab-qualify`; `make qual-vet` wraps it. Details of the run itself are in
`tests/lab/README.md`, "Qualification".

Layout: `profiles/<platform>/<slug>.yaml` (the mock), `golden/<platform>/<slug>.json` (the expected
port49 decisions), `qual-policy.yaml` and `qual-daemon.yaml` (what every run is played under).
`docs/qualified-platforms.md` is generated from these (`make qualified-platforms`).

## Vet a new firmware and add its mock

1. Put the image on `/mnt/images`.
2. Add its `platforms` row in `tests/lab/harness_test.go`: selector, topology, image, version (as
   the device reports it) and a measured `boot`.
3. Run `make qual-vet P=<sel>`, for example `make qual-vet P=nxos106`. It refuses when
   `/tmp/port49-STOP-LAB` exists, the lab is occupied, or `tests/qual` or `tests/lab/results` has
   uncommitted changes. It then runs `make lab-qualify`, `genprofile`, `make qual` and
   `make qualified-platforms`, and commits nothing.
4. Review the profile against the note. `genprofile` prints a checklist; confirm every line of it
   against `tests/lab/results/QUAL-<slug>-<lp>.md` before you commit:
   - each reaction it pre-filled as `measured`;
   - each acceptance rule and its status;
   - the review-left defaults, `client_chain` and `server_identity`;
   - each engine gap id.

   A claim is measured only when a note for **this** firmware measured it (decision 52, ruling 4).
   On Junos the command cells are `not_applicable` (L18), so `genprofile` records the engine gap
   `command_authorization_not_sent`; that is expected, not a failure.
5. Commit the evidence, the note, the profile, the golden and the list.

No mock is added for an image the lab has not run (ruling 8).

## Add a platform

1. Add a `platforms` row and a topology.
2. Write a startup config with break-glass and the `port49` TACACS+ server group.
3. For TLS, add an `l73Dialects` row, written help first.
4. Give it a port49 inventory platform: built in, or generic (which logs `platform_unknown`).
5. Vet it as above.

Any engine gap it needs becomes an `engine_gaps` entry, plus Go in `internal/devicemock` with a test.

## When a mock fails on a PR

- **A gate (an acceptance rule).** The device would reject port49's reply. Fix port49, or, if the
  rule is wrong, re-measure it in the lab.
- **A golden difference.** If port49 changed on purpose, run `make qual-update` and review the diff.
  The list shows re-vet pending until the next lab run.
- **A missing reaction.** The vetter adds it from the notes.

## The release-tag gate

1. `make lab-regress`.
2. `make qual-vet` for every profile whose golden is pending.
3. Commit.
