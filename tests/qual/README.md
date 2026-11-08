# Qualification suite: contributor procedures

<!-- --8<-- [start:procedures] -->
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
   `/tmp/port49-STOP-LAB` exists, the lab is occupied, or `tests/qual`, `tests/lab/results`,
   `tests/lab/evidence` or `docs/qualified-platforms.md` has uncommitted changes. It then runs
   `make lab-qualify`, `genprofile`, `make qual` and `make qualified-platforms`, and commits
   nothing. If any step fails it lists the paths the run left changed: restore them before
   committing anything, or a failed run's note or evidence goes in with the next commit.
4. Review the profile against the note. `genprofile` prints a checklist; confirm every line of it
   against `tests/lab/results/QUAL-<slug>-<lp>.md` before you commit:
   - each reaction it pre-filled as `measured`;
   - each acceptance rule and its status;
   - the review-left defaults, `client_chain` and `server_identity`;
   - each engine gap id;
   - each device fact.

   A claim is measured only when a note for **this** firmware measured it (decision 52, ruling 4).
   On Junos the command cells are `not_applicable` (L18, open), so `genprofile` records the engine gap
   `command_authorization_not_sent`; that is expected, not a failure.

   The TLS login is played the way the device defaults, per-request (`tls_token_login`), and
   again with single-connection on (`tls_single_connection`); each verdict line names its mode.
   Where per-request TLS sends port49 no command authorization (NX-OS 10.6(2)F, L73 cell a),
   `genprofile` records the device fact `tls_per_request_no_command_authorization`, the mock plays
   that login with no command step, and the list's "command authorization over TLS" column reads
   "no" or "single-connection only". The `tls_denied_command` cell then types the denied command
   alone over per-request TLS and writes `tests/lab/results/L80-<lp>.md` (spec §15 L80); its
   verdict is `observed`, never `pass`, and `genprofile` records its outcome as the device fact
   `tls_per_request_denied_command_runs` or `..._refused`, citing that note. The list's TLS column
   then reads "no: over per-request TLS, a command port49 denies runs (L80)" or "no command
   authorization over per-request TLS; denied commands refused locally (L80)". The harness never
   turns single-connection on to make a per-request cell pass.

   For a platform port49 offers single-connect to over TLS (`platform.TLSServerSingleConnect`,
   decision 50 ruling 20: today `cisco_nxos`), run.json's `tls_server_single_connect_offered` is
   true, the run waits until no connection is open before and at `tls_token_login`'s capture
   (`tls_capture_started_clean`), and `genprofile` grades `tls_token_login` from its header-only
   `*.tls.json` and port49's records, writing nothing if the capture did not start clean, any two
   of the cell's connections overlap, or a record falls in no connection: `tls_server_single_connect_honored` when a connection carried a session after a
   completed one that was not accounting, `tls_server_single_connect_ignored` when every
   connection carried one session. Neither is written where port49 never offered: absent is no
   claim. The mock reuses an offered connection where the profile says honored. The drift test
   (`tests/qual/drift_test.go`) fails when the table and the profiles disagree either way, so a
   firmware that ignores the offer fails before a release ships the table entry for it.
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
<!-- --8<-- [end:procedures] -->
