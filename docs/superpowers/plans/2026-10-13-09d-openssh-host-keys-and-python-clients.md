# Plan 9d: OpenSSH's Own Host-Key Handling, and the Python and Ansible Clients — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Host keys become OpenSSH's job: `port49 ssh` runs the operator's OpenSSH against the
operator's own known_hosts under `StrictHostKeyChecking=accept-new`, plan 9a's pins file,
`internal/hostkeys` and `port49 devices trust` leave the product, and no host key is stored by
port49 anywhere. A Python library (identity, mint, sweep, retry) and an Ansible lookup plugin over
it give Python automation the same tokens, with Paramiko's accept-new in place of the Netmiko
example's strict pins.

**Branch:** `feature/openssh-host-keys-and-python-clients`. Base: `main` at `235beee` (plan 9c merged).

**What changes, in one screen:**
- **`port49 ssh`** passes `StrictHostKeyChecking=accept-new` (or `yes` where the operator's own
  ssh_config already says `yes`; never `no`) and `HostKeyAlias=<inventory name, lowercased>` (unless
  the operator's ssh_config sets its own), and nothing else about host keys: no
  `UserKnownHostsFile`, `GlobalKnownHostsFile`, `KnownHostsCommand`, `VerifyHostKeyDNS`,
  `UpdateHostKeys` or `CheckHostIP`. It reads the operator's settings with `ssh -G`, OpenSSH's own
  evaluation of ssh_config. A first connection is accepted and saved by OpenSSH ("Permanently
  added 'core-sw01'"); a changed key stops at OpenSSH's own warning, before the token is sent, and
  port49 says `ssh-keygen -R core-sw01`. No pin is checked first; nothing is refused for want of
  one.
- **Removed:** `port49 devices trust` (it now answers one line naming the change, exit 2),
  `internal/hostkeys`, `port49 ssh --known-hosts` (refused, naming `UserKnownHostsFile`). The 9a
  pins file is never read; while it exists, `port49 ssh` names it and says how to carry its keys
  over. `userconfig.LegacyDir` becomes unexported: nothing port49 keeps reads a file under
  `~/.config` through decision 42 ruling 6's walk, which ends 9b's group-writable `~/.config`
  refusal.
- **`port49 token --json`** prints one JSON object on every failure too: the broker's own item
  for a deny, or `{"device", "error", "detail"}` with a code from a closed client set
  (`per_login_mfa_required`, `touch_timeout`, `key_locked`, `key_absent`, `broker_refused`, …).
  Exit status is unchanged. **`port49 workload token --format json`** adds `refused` (each item
  not minted, with its §5.7 reason and no token) and prints its object on 75 and 77 too when the
  broker answered.
- **The Python library** (`clients/python`, import `port49`, Python 3.10+, no runtime
  dependency): `Agent` (a person, through `port49 token --json` and `port49 identity --json`) and
  `Workload` (a machine, through `port49 workload token --format json` and `workload identity
  --json`). It drives the CLI, so the per-login proof, the PIN, hardware keys, the broker CRL check,
  idempotency and paging stay in one implementation. Typed exceptions per code; retries only what
  the CLI says sent nothing. `port49.hostkeys` and `port49.netmiko.connect(device)`: accept-new
  under the inventory name in the operator's own known_hosts, read through `ssh -G` and
  `ssh-keygen -F`, shared with `port49 ssh`.
- **The Ansible lookup** (`clients/ansible`, collection `port49.client`, lookup
  `port49.client.token`) over the library. Host keys stay Ansible's own (`host_key_checking`,
  `host_key_auto_add`), as L66 measures them.
- **Lab:** L53 and L54 stay closed (their claims columns amended); new L64 (`port49 ssh` under
  accept-new per platform, the key surviving a reload included), L65 (the Python client and
  Netmiko per platform), L66 (the Ansible lookup: mints per task, host keys per `ssh_type`).

**Architecture:**
- `cmd/port49/ssh.go`: `sshTrust`, `sshPolicy` (`ssh -G`), `sshArgs` without the pins, `sshName`
  (decision 42 ruling 8's name set, moved from `hostkeys.ValidName`), `legacyPinsHint`.
- `cmd/port49/mint.go`: `tokenFailure`, `tokenFailureOf`; `cmd/port49/mfa.go`: `mfaUnprovedError`
  wraps a proof that failed, so its code survives.
- `cmd/port49/workload.go`: `workloadJSON`, `refusedItem`.
- `internal/userconfig`: `legacyDir` (unexported), `LegacyPinsPath`.
- `tests/lab/hostkeyscan_test.go`: the L53 scan, moved from `internal/hostkeys` into the lab.
- `clients/python/src/port49/`: `_run.py` (the CLI runner), `errors.py`, `client.py`,
  `hostkeys.py`, `netmiko.py`. Tests are stdlib `unittest` against a fake `port49` executable and
  fake `netmiko`; the host-key tests run the real `ssh` and `ssh-keygen`.
- `clients/ansible/ansible_collections/port49/client/`: `galaxy.yml`, `meta/runtime.yml`,
  `plugins/lookup/token.py`, `tests/unit/test_token.py` (stub `ansible` modules).
- `Makefile`: `test-python`, run by `make test`; `lab-ssh` and `lab-ansible`.

**Tech Stack:** Go 1.26, module `github.com/rhwendt/port49`, `CGO_ENABLED=0`, no new Go module.
OpenSSH 8.5+ on the operator's host (`ssh`, `ssh-keygen`). Python 3.10+ standard library;
`netmiko` (with Paramiko) only for `port49.netmiko`; `ansible-core` 2.16+ only for the lookup.
Lab: the host's `/home/rwendt/lab-venv` (Python 3.14.4, Netmiko 4.7.0, Paramiko 4.0.0,
ansible-core 2.21.4, `ansible.netcommon` 8.7.0, `arista.eos` 12.3.0, `cisco.nxos` 13.0.0 as of
2026-10-13; Task 12 adds `cisco.ios`, `junipernetworks.junos` and `ansible-pylibssh` and records
every version).

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`: §12 (`port49 ssh`, `devices trust` removed,
  `port49 token --json`, `port49 workload token --format json`), §13 (new decision 46; decision 42
  rulings 7, 9, 10 and 14 and decision 43 ruling 24 amended), §15 (L53 and L54 claims; new L64–L66).
- `docs/design/2026-08-21-port49-design.md` §17 (the address paragraph, "As built (plan 9a)", the
  client libraries table, the integration examples).
- The roadmap `docs/superpowers/plans/README.md`, "Plan 9", the 9d entry; "Plan 9a — As built"
  (I-1, P14, the operator notes), "Plan 9b — As built" (the `~/.config` carry), "Plan 9c — As
  built" (the socket codes). House style: plan 9c. Written against `main` at `235beee`.

**Prerequisite:** plan 9c merged (`main` at `235beee`).

## Owner's rulings this plan carries

1. **Host keys are OpenSSH's job** (Ryan, 2026-10-10; replaces decision 42's pin-first rule).
   port49 does not reimplement host-key trust. `port49 ssh` forces `StrictHostKeyChecking=accept-new`,
   never `no`, against the operator's own known_hosts. A first connection is accepted and saved; a
   changed key stops with OpenSSH's own warning and is re-trusted the usual way (`ssh-keygen -R`).
   A thousand-switch run that has never touched a device trusts nothing by hand. 9a's pins file,
   `internal/hostkeys` and `port49 devices trust` leave the user flow; `devices trust` stays only as
   an admin tool if a reason survives review.
2. **No inventory host keys** (Ryan, 2026-10-10). port49 stores no host keys anywhere. The
   first-contact window accept-new leaves is the one every SSH user accepts, and the docs say so
   plainly. A shop that wants verified first contact uses OpenSSH's own tools (a managed
   `GlobalKnownHostsFile`, or host certificates via `@cert-authority`), which `port49 ssh` leaves
   untouched.
3. **Why host keys matter, said plainly:** the device password is a one-time token, and an
   impostor that takes it can replay it to the real device within its lifetime.
4. **Netmiko and Python:** Paramiko's accept-new (save an unknown key; a changed one is always
   refused) replaces the example's strict `RejectPolicy`.
5. **Clients:** the Python library (~300 lines: identity, mint, sweep, retry) and the Ansible
   lookup plugin over it (design §17).
6. **The group-writable `~/.config`** (9b pre-flight 2, m5): fixed by the pins file's removal;
   nothing 9d keeps reads a file under `~/.config` through ruling 6's walk.
7. **Standing rules:** no user toil at fleet scale; snake_case for data; reason codes only from
   §5.7; no secrets in logs; never reimplement well-tested tooling; follow the spec, no
   feature-cutting provisional ruling; security first.

## Rulings this plan makes (recorded as decision 46 in Task 1)

Under the standing grant (security first, keep moving), each on reasoning unless it says data.

- **R1. port49 stores no host key.** Decision 42 rulings 7 (pinned host keys) and 9 (`devices
  trust`) are withdrawn, and ruling 14's inventory-carried fingerprint is not built. Design §17's
  "never accept a first-seen key silently for a device inventory already knows" and its "Inventory
  MAY carry a host-key fingerprint" are replaced by R2's rule.
- **R2. `port49 ssh`'s host-key options.** After the mint, `port49 ssh` runs `ssh -G` with the
  same `-F`, `HostName`, `-l` and `-p` it will run ssh with, and reads two settings from it:
  - `stricthostkeychecking`: `true` (the operator's `yes`) stands as `StrictHostKeyChecking=yes`;
    every other value (`ask`, OpenSSH's default; `false`; `accept-new`) is passed as
    `StrictHostKeyChecking=accept-new`. Never `no`.
  - `hostkeyalias`: when the operator's ssh_config sets one, it stands and port49 passes none;
    otherwise port49 passes `HostKeyAlias=<device>` lowercased (OpenSSH lowercases an alias).
  Nothing else about host keys is passed: the operator's `UserKnownHostsFile`,
  `GlobalKnownHostsFile` (with any `@cert-authority` or `@revoked` lines), `KnownHostsCommand`,
  `VerifyHostKeyDNS`, `UpdateHostKeys`, `CheckHostIP` and `HashKnownHosts` apply as they would to
  any ssh. `ssh -G` failing is a refusal before ssh runs ("nothing was sent"). Why the alias: a key
  filed under the inventory name meets an address added to the device in the source of truth, so
  design §17's attack (an address that leads to the attacker's host, which takes the token and
  replays it) fails at the key exchange for every device this operator has reached before, at no
  cost to anyone. Why `ssh -G`: it is OpenSSH's own reading of the operator's ssh_config, Match
  blocks included; port49 parses two lines of it and decides nothing OpenSSH does not.
- **R3. Names.** Decision 42 ruling 8 stands: a device name `port49 ssh` takes is letters, digits,
  `.`, `_` and `-`, starting with a letter or digit, 253 at most, since it is written into the
  operator's known_hosts as a host field. It moves from `hostkeys.ValidName` to `sshName` in
  `cmd/port49/ssh.go`.
- **R4. `port49 devices trust` is removed, not kept as an admin tool.** The reasons weighed for
  keeping it: (a) verified first contact, which OpenSSH already gives a shop that wants it (a
  managed `GlobalKnownHostsFile`, `@cert-authority`, or `ssh-keyscan` plus `ssh-keygen -lf` and
  L53's console commands); (b) pre-seeding keys for automation, which is per-device toil Ryan has
  ruled out and which would need port49 to store keys again; (c) jump hosts, where 9a's final
  review I-1 found it dialled directly. None survives, so I-1 is moot. `port49 devices trust`
  answers one line naming the change and exits 2, until the pre-beta review removes even that.
- **R5. Plan 9a's pins file.** Never read. While `$XDG_CONFIG_HOME/port49/known_hosts` (else
  `~/.config/port49/known_hosts`) exists as a regular file, `port49 ssh` says, once per run, that
  port49 no longer reads it, that its lines are already OpenSSH's format under the inventory name
  (the alias), and that keys the operator verified can be kept with `cat FILE >>
  ~/.ssh/known_hosts` after checking them. It is found by `Lstat` alone. `port49 ssh
  --known-hosts` is refused (exit 2), naming `UserKnownHostsFile` in an ssh_config.
  `userconfig.LegacyDir` becomes `legacyDir`, used only by `LoadAll`'s refusal of 9a's config
  file and by `LegacyPinsPath`; so nothing port49 keeps reads a file under `~/.config` through
  ruling 6's ownership walk, and a group-writable `~/.config` (Ubuntu's 0775) stops nothing.
- **R6. The OpenSSH floor** stays 8.5 unless Task 2's gate G1 finds an 8.5p1 that, under
  `accept-new`, accepts a key of another type for an alias that already holds one; then the floor
  rises to the earliest version Task 2 measured refusing it. Measured while this plan was written:
  OpenSSH 10.2p1 refuses it as a changed key ("Host key for leaf1 has changed and you have
  requested strict checking"), so an impostor that offers only another key type does not pass.
- **R7. The changed-key message.** A 255 before the token was sent, with ssh's "Host key
  verification failed", says the key filed under the name is not the one the address presents —
  either the device's key changed or the address inventory gives is not the device — and to verify
  the key on the console (L53's commands) and run `ssh-keygen -R <name>`. `<name>` is the alias
  port49 passed, or the operator's own as `ssh -G` printed it.
- **R8. The Python library drives the port49 CLI**, never the agent's socket or the broker's API
  directly. Why: the CLI already carries the per-login proof (a touch, an `idp_mfa` sign-in at the
  terminal), the PIN, hardware keys, the broker CRL check, the `Idempotency-Key`, paging and the
  deadline retry; a second client of the API would be a second implementation of each, kept in step
  by hand, and the agent's socket is not a public interface (`ErrAgentTooOld`). Design §17: "the
  CLI is the universal client". Its table's "Python library" row is amended to say so.
- **R9. `port49 token --json` on a failure** writes one JSON object to stdout and nothing else,
  and keeps its exit status (1; 2 on usage). A deny is the broker's item as sent (`device`,
  `verdict`, `reason`, `detail`; it holds no token); an item the broker could not decide is its
  item (`device`, `error`, `detail`). Anything else is `{"device", "error", "detail"}` with `error`
  one of the client codes: `no_agent`, `agent_too_old`, `session_over`, `credential_revoked`,
  `revocation_running`, `per_login_mfa_required` (with `per_login_mfa: {accept,
  reuse_for_seconds, reuse_from, levels}`, never the challenge), `touch_timeout`, `key_locked`,
  `key_absent`, `broker_refused`, `connection_changed`, `no_token` (a permit with no token), and
  `agent_error` (any other). These are the CLI's codes, like design §17's API error codes, not
  §5.7 reason codes; the deny's `reason` is §5.7's, as the broker sent it. `detail` is made
  printable (`printsafe.Line`, 512).
- **R10. `port49 workload token --format json`** gains `refused`: one entry per item not minted
  (`device`, `verdict`, `reason`, `error`, `detail`, and `per_login_mfa` without its challenge),
  never a token. With no `--out`, the object is printed whenever the broker answered, so on 77
  ("every device denied") and 75 (some pages minted) stdout says which and why. With `--out` the
  file is still written only when a permit is in it (decision 40 ruling 10, pre-flight I-1).
- **R11. The library's errors and retries.** One exception class per kind of code (`NoAgent`,
  `SessionOver`, `Denied` with the §5.7 `reason`, `MFARequired` with the requirement,
  `KeyUnavailable`, `BrokerRefused`, `Temporary`, `Final`, `NotInstalled`, `HostKeyError`), all
  under `Port49Error`. `Agent.token` retries only `revocation_running` and `connection_changed`,
  the two codes the CLI answers having sent nothing to mint with, up to `attempts` (default 3) with
  1s and 2s waits. It never retries a deny, a requirement, a key error or a touch timeout (decision
  45 ruling 14: a person touches; nothing is retried), and never reruns a workload run (the CLI's
  `--deadline` already retries under one `Idempotency-Key` per page; a rerun mints again). No
  exception, `repr` or message carries a token or the CLI's stdout.
- **R12. The CLI's terminal stays the person's.** The library passes stdin through (a pasted
  sign-in address) for `Agent` and gives `Workload` none; it forwards the CLI's stderr to the
  caller's as it comes, byte by byte, so "touch your key now" and a sign-in prompt reach the person,
  and keeps its last 2 KiB for an error's text.
- **R13. Python host keys: accept-new under the inventory name, in OpenSSH's files, read with
  OpenSSH's tools.** `port49.hostkeys.lookup` runs `ssh -G` (the same `-F` the caller names,
  `HostName`, `-p`) and reads `hostkeyalias`, `stricthostkeychecking`, `userknownhostsfile`,
  `globalknownhostsfile` and `hashknownhosts`; the name is the operator's alias, else the device
  lowercased, as R2. It runs `ssh-keygen -F <name> -f <file>` on each existing file and keeps the
  plain keys and the marker lines (`@cert-authority`, `@revoked`). Then:
  - plain keys found: Netmiko connects with them alone, written under the address (or
    `[address]:port`) to a private temporary file, and `ssh_strict=True`, so a changed key and a key
    of another type are refused before authentication (as OpenSSH 10.2p1 refuses the second);
  - none found, no marker line, and the operator's StrictHostKeyChecking not `yes`: Netmiko
    connects with Paramiko's `AutoAddPolicy` (`ssh_strict=False`), and the key the device presented
    is appended under the name to the first `userknownhostsfile`, hashed when `hashknownhosts` is
    `yes`, in one `O_APPEND` write, and said on stderr as OpenSSH says it;
  - none found and a marker line matches, or `yes`: refused before connecting, naming why. Paramiko
    cannot check a host certificate or a revocation list, so a shop's `@cert-authority` is never
    weakened to a first-contact accept by this client.
  `port49 ssh` and the Python client share the entry: whichever reaches a device first files its
  key, and the other verifies against it.
- **R14. Packaging, floor and tests.** `clients/python`: a `pyproject.toml` (setuptools, `name =
  "port49"`, `requires-python = ">=3.10"`, no runtime dependency, extra `netmiko = ["netmiko>=4.7"]`),
  sources in `src/port49/`. Python 3.10 is the floor: Ubuntu 22.04's, and ansible-core 2.16's
  controller floor. Tests are stdlib `unittest` (no pytest to install), run by `make test-python`,
  which `make test` runs; a missing `python3` fails `make test`. A test parses every source with
  `ast.parse(..., feature_version=(3, 10))`. Not published to PyPI until go-public (plan 12).
- **R15. The Ansible lookup.** Collection `port49.client` (`clients/ansible/ansible_collections/
  port49/client/`, `requires_ansible: ">=2.16"`), lookup `port49.client.token`. Terms are port49
  device names. `field`: `login` (default), `enable`, `username`, `address`, `platform`, or `all`
  (a dict). Person mode (the agent) by default; workload mode when `broker`, `broker_ca`, `cert`
  and `key` are given (one CLI run for every term). Errors are `AnsibleError` with the library's
  words, never a token. The README's pattern mints once per host per play: a `set_fact` with
  `no_log: true` in `pre_tasks`, since a lookup in `ansible_password` is templated at each task
  (L66 measures how many mints that costs). Host keys are Ansible's own; the README carries L66's
  settings per `ssh_type`. Ansible keys host keys by `ansible_host`, which comes from Ansible's
  inventory, not port49's.
- **R16. The Netmiko example** moves into the library as `port49.netmiko.connect(device)`;
  `examples/netmiko/` keeps a README and a twelve-line script that uses it.
- **R17. The lab.** L53 stays closed: its console commands are what the docs give for checking a
  first-contact key, and its reload result holds for the RSA key it scanned; the key type OpenSSH's
  defaults accept, and its survival across a reload, are L64's. L54 stays closed for what it
  measured (the method, the prompt, one ask, the exit status); its pinned-key clause measured 9a's
  command line, which L64 (c) and (d) re-measure under accept-new. L64, L65 and L66 are opened by
  Task 1 and closed by Tasks 11 and 12 when measured.

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, `CGO_ENABLED=0`; no new Go module. Static stays static
  (`make check-static`).
- Python 3.10+, standard library only in `port49` itself (`port49.netmiko` imports `netmiko` inside
  `connect`); every source parses under `feature_version=(3, 10)`. `PYTHONDONTWRITEBYTECODE=1` in
  every Makefile run, so no `__pycache__` lands in the tree.
- snake_case for all data: `per_login_mfa`, `reuse_for_seconds`, `refused`, `no_agent`,
  `agent_too_old`, `session_over`, `no_token`, `agent_error`, `field`, `broker_ca`, `touch_key`.
- Reason codes are §5.7's. This plan adds none: R9's client codes are the CLI's own, named in §12,
  and a deny's `reason` is passed through as the broker sent it.
- No token, PIN, challenge or ID token in any log, message, `repr`, exception or test failure
  output. Python never puts a token in argv or the environment; it reads it from the CLI's stdout
  and hands it to Netmiko or Ansible only.
- port49 stores no host key: no new file, flag or config key holds one.
- No per-user step at fleet scale: a first connection needs nothing typed; nothing new needs a
  config line per user.
- `port49 ssh` never passes `StrictHostKeyChecking=no` and never overrides the operator's
  known_hosts files.
- Lab: positive controls enforced, a failed control is `INVALID` before any note is written;
  results notes per CLAUDE.md; captures redacted into `tests/lab/evidence/`; the lab watchdog
  runs during every lab run.
- Commit trailer, every commit: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
  and nothing else (no `Claude-Session:` line, no claude.ai link).
- Verify before done: `make test && make vet`, real output reported.

## Review Focus

1. **An impostor that offers only another key type.** A device whose name holds an RSA key, and a
   host at its address that offers only Ed25519, must be refused before the token is sent, by
   `port49 ssh` and by the Python client alike, never filed as a new key. Tests: Task 3
   (`TestAKeyOfAnotherTypeUnderAKnownNameIsRefused`, real OpenSSH), Task 9
   (`test_a_key_of_another_type_under_a_known_name_is_refused`); Task 2's gate G1 for 8.5p1.
2. **An address moved in inventory to another host.** After a first login to a device, a mint
   that gives its name another host's address must end at the key exchange, the token unsent.
   Tests: Task 3 (`TestAnAddressMovedToAnotherHostNeverSeesTheToken`), Task 9
   (`test_an_address_moved_to_another_host_is_refused`).
3. **The operator's own ssh_config says `StrictHostKeyChecking no`.** port49 must pass
   `accept-new`, and an operator's `yes` must stand. Test: Task 3 (`TestSSHPolicyReadsTheOperatorsConfig`,
   real `ssh -G`, every value).
4. **Two workers reach a new device at once** (Nornir's ten, Ansible's forks). Both connect, and
   the known_hosts file holds whole lines only. Test: Task 9
   (`test_concurrent_first_contacts_write_whole_lines`).
5. **A token in a traceback.** An exception, a `repr`, a failed JSON decode or an Ansible error
   must never carry the token or the CLI's stdout. Tests: Task 7
   (`test_no_token_in_repr_errors_or_a_bad_answer`), Task 10
   (`test_errors_never_carry_the_token`).

---

## Task 1: Spec and design — decision 46, §12, §15 (L53, L54 amended; L64–L66 opened), design §17

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §12's `port49 devices trust` paragraph
  (~6289–6298) and `port49 ssh` paragraph (~6300–6306); after `**`port49 workload token … --scope
  NAME`**` (~6308) two new paragraphs; decision 42's heading note (~8258–8262) and rulings 7
  (~8348), 9 (~8363), 10's command-line bullet (~8392), 12 (~8437), 14 (~8456); decision 43 ruling
  24's "Where" bullet (~8732–8735); §13 a new decision 46 after decision 45's ruling 26, before the
  `---` above `## 14.` (~9273); §15's L53 and L54 rows' second column (~9993–9994), three rows
  after L63's (~10003), and a bullet after the `**L60**–**L63**` bullet (~11941–11948).
- Modify: `docs/design/2026-08-21-port49-design.md` §17: the paragraph from "**The address is a
  fact from the source of truth**" through "As built (plan 9a; … rulings 7–10)" and its three
  bullets (~2072–2093); the client libraries table (~2221–2226) and the paragraph after it; the
  integration examples (~2243–2262).

**Interfaces:** Produces the names every later task uses: decision 46 R1–R17, the client codes of
R9, `refused`, `sshName`, `LegacyPinsPath`, rows L64–L66, the collection `port49.client` and lookup
`port49.client.token`, the Python names `Agent`, `Workload`, `Token`, `MintResults`, `Refusal`.

- [ ] **Step 1: §12, `port49 devices trust`.** Replace the paragraph and its three bullets with:

```markdown
**`port49 devices trust`** was removed by plan 9d (§13 decision 46 ruling 4): port49 keeps no host
key. It answers one line naming the change and exits 2.
```

- [ ] **Step 2: §12, `port49 ssh`.** Replace its paragraph and bullets with:

```markdown
**`port49 ssh [--port N] [--ssh PATH] [--ssh-config FILE] [-v] DEVICE [-- COMMAND…]`** mints a
token through the agent and logs in with the operator's OpenSSH (8.5 or later).
- **Host keys are OpenSSH's** (§13 decision 46). The operator's own known_hosts files apply, with
  `StrictHostKeyChecking=accept-new` (or `yes`, where the operator's ssh_config says so; never
  `no`) and the device's inventory name as `HostKeyAlias` (unless the operator's ssh_config sets
  one). A first connection is accepted and saved by ssh; a changed key, or a key of another type
  under a name that holds one, stops ssh before the token is sent, and `port49 ssh` names
  `ssh-keygen -R`. Why it matters: the token is the device's password for its lifetime, and a host
  that takes it can replay it to the real device. The window this leaves is the first contact,
  per device and per operator; a shop that wants that verified too uses a managed
  `GlobalKnownHostsFile` or `@cert-authority`, which apply unchanged.
- **The token** goes only to the device's own password prompt, once, through ssh's askpass.
- **Exit and warnings.** It exits with ssh's status, and warns on the terminal within
  `session.ceiling_warning` of the device's ceiling (decision 42 rulings 10 and 11).
```

- [ ] **Step 3: §12, the two JSON outputs.** After the `port49 workload token … --scope NAME`
  paragraph add:

```markdown
**`port49 token --json DEVICE`** prints the broker's item as JSON on stdout. On a failure it
prints one JSON object too, keeping its exit status (§13 decision 46 ruling 9): a deny is the
broker's item (`verdict`, `reason`, `detail`; no token); an item the broker could not decide is its
item (`error`, `detail`); anything else is `{"device", "error", "detail"}`, `error` one of the
CLI's codes `no_agent`, `agent_too_old`, `session_over`, `credential_revoked`,
`revocation_running`, `per_login_mfa_required` (with `per_login_mfa`, never its challenge),
`touch_timeout`, `key_locked`, `key_absent`, `broker_refused`, `connection_changed`, `no_token`,
`agent_error`. These are the CLI's codes, not §5.7 reason codes.

**`port49 workload token --format json`** prints the broker's answer with only the minted items
in `results`, and every other item in `refused` (`device`, `verdict`, `reason`, `error`, `detail`,
`per_login_mfa` without its challenge). Without `--out` the object is printed whenever the broker
answered, on exit 75 and 77 too (§13 decision 46 ruling 10).
```

- [ ] **Step 4: Decision 42's amendments.** In its heading paragraph, after "9d host keys from
  inventory and the Python and Ansible clients." add: "Plan 9d (decision 46) made host keys
  OpenSSH's: rulings 7 and 9 are withdrawn, ruling 14's inventory fingerprint is not built, and
  ruling 10's host-key options are replaced." Prefix rulings 7 and 9 with "**Withdrawn by decision
  46 ruling 1.**"; in ruling 10, replace the first bullet under "**The command line.**" ("the pinned
  file, `HostKeyAlias`, …") with "host keys as decision 46 ruling 2 sets them (plan 9d), replacing
  9a's pinned file;"; in ruling 12, add "L64 re-measures `port49 ssh`'s host keys under decision 46
  (§15)."; prefix ruling 14 with "**Replaced by decision 46** (no inventory host keys; the clients
  drive the CLI and use OpenSSH's own known_hosts).". In decision 43 ruling 24's "Where" bullet,
  replace "and no host-key pins: those stay in plan 9a's `$XDG_CONFIG_HOME/port49/known_hosts` until
  plan 9d takes them out of the user's flow." with "and no host key: since plan 9d port49 keeps none
  (decision 46), and plan 9a's pins file is never read."

- [ ] **Step 5: Decision 46.** Add after decision 45's ruling 26:

```markdown
**46. The agent in full, fourth part: host keys are OpenSSH's, and the Python and Ansible
clients.** *Plan 9d, 2026-10-13, on Ryan's rulings of 2026-10-10 (host keys are OpenSSH's job; no
inventory host keys).* Rulings rest on reasoning unless they say data. Amends decision 42 rulings
7, 9, 10, 12 and 14, and decision 43 ruling 24.

- **1. port49 stores no host key.** Decision 42 rulings 7 and 9 are withdrawn, and ruling 14's
  inventory fingerprint is not built: keeping every device's key in the source of truth, and
  updating it at every re-key, is not feasible at production scale (Ryan). The first-contact
  window is the one every SSH user accepts. A shop that wants verified first contact uses
  OpenSSH's own tools, a managed `GlobalKnownHostsFile` or `@cert-authority`, which port49 leaves
  untouched. Why host keys matter at all: the device password is a one-time token, and an impostor
  that takes it can replay it to the real device within its lifetime.
- **2. `port49 ssh`'s host-key options.** After the mint it runs `ssh -G` with the `-F`,
  `HostName`, `-l` and `-p` it will run ssh with. `stricthostkeychecking true` (the operator's
  `yes`) stands; any other value is passed as `StrictHostKeyChecking=accept-new`; `no` is never
  passed. An operator's `HostKeyAlias` stands; otherwise `HostKeyAlias` is the device's inventory
  name, lowercased. Nothing else about host keys is passed. `ssh -G` failing refuses the run before
  ssh starts. The alias files a key under the name, so an address added to a device in the source
  of truth meets the key already known under its name, and design §17's replay attack fails at the
  key exchange for every device the operator has reached.
- **3. Names.** Decision 42 ruling 8 stands: the name is written into the operator's known_hosts.
- **4. `port49 devices trust` is removed.** Kept as an admin tool only if a reason survived; none
  did: verified first contact is OpenSSH's (above, or `ssh-keyscan` and `ssh-keygen -lf` against
  L53's console commands), pre-seeding keys per device is the toil ruling 1 rules out, and its
  direct dial past a jump host (plan 9a final review I-1) goes with it. It answers one line naming
  this and exits 2.
- **5. Plan 9a's pins file** is never read. While it exists, `port49 ssh` names it once per run and
  says how to keep the keys in it (its lines are already OpenSSH's format under the alias). It is
  found by `Lstat` alone. `port49 ssh --known-hosts` is refused, naming `UserKnownHostsFile`.
  Nothing port49 keeps reads a file under `~/.config` through decision 42 ruling 6's walk, so a
  group-writable `~/.config` stops nothing (plan 9b pre-flight 2, m5).
- **6. The OpenSSH floor** stays 8.5 unless an 8.5p1 under `accept-new` accepts a key of another
  type for an alias that holds one; then it rises to the earliest version measured refusing it
  (data: `tests/ssh-compat/2026-10-13-openssh-accept-new.md`; OpenSSH 10.2p1 refuses it as a
  changed key).
- **7. A changed key** ends ssh with exit 255 before the token is sent; `port49 ssh` says the key
  filed under the name is not the one the address presents, either because the device's key
  changed or because the address is not the device, and to verify the key on the console (§15 L53)
  and run `ssh-keygen -R <name>`.
- **8. The Python library drives the port49 CLI**, never the agent's socket or the broker's API:
  the CLI carries the per-login proof, the PIN, hardware keys, the broker CRL check, the
  `Idempotency-Key`, paging and the deadline retry, and a second client would be a second
  implementation of each. Design §17's "the CLI is the universal client".
- **9. `port49 token --json` on a failure** prints one JSON object (§12), keeping its exit status.
  Its `error` codes are the CLI's (§12), not reason codes; a deny's `reason` is §5.7's as the
  broker sent it; `detail` is made printable; a requirement's challenge is never printed.
- **10. `port49 workload token --format json`** adds `refused`, and without `--out` prints its
  object whenever the broker answered. With `--out`, decision 40 ruling 10 stands.
- **11. The library's errors and retries.** An exception class per kind of code. `Agent.token`
  retries `revocation_running` and `connection_changed` alone (the CLI sent nothing to mint with),
  three attempts by default, waiting 1s then 2s; never a deny, a requirement, a key error or a touch
  timeout (decision 45 ruling 14), and never a workload run, which the CLI's `--deadline` retries
  under one `Idempotency-Key` per page. No exception, `repr` or message carries a token or the
  CLI's stdout.
- **12. The person's terminal.** The library passes stdin through for a person and none for a
  workload, and forwards the CLI's stderr as it comes, so a touch or sign-in prompt is seen.
- **13. Python host keys** are accept-new under the name `port49 ssh` uses, in the operator's own
  files, read through `ssh -G` and `ssh-keygen -F`. A key known under the name is the only key
  accepted (a changed key, or another type, is refused before authentication); none known, a first
  contact is accepted and appended under the name, hashed when `HashKnownHosts` is `yes`; a
  `@cert-authority` or `@revoked` line matching the name with no plain key, or the operator's
  `StrictHostKeyChecking yes` with none, is refused before connecting, since Paramiko checks
  neither certificates nor revocations.
- **14. Packaging.** `clients/python` (import `port49`, Python 3.10+, no runtime dependency; the
  `netmiko` extra), stdlib `unittest`, run by `make test`. Not published before go-public.
- **15. The Ansible lookup** `port49.client.token`, in collection `port49.client` (ansible-core
  2.16+), over the library; person mode by default, workload mode with `broker`, `broker_ca`,
  `cert` and `key`. Host keys are Ansible's own (§15 L66).
- **16. The Netmiko example** is `port49.netmiko.connect`.
- **17. The lab.** L53 and L54 stay closed, their claims amended; L64, L65 and L66 are this plan's
  rows (§15).
```

- [ ] **Step 6: §15.** In L53's second column replace "§13 decision 42 rulings 9 and 12; the
  operator docs' "verify the key on the console" (plan 13)" with "§13 decision 42 rulings 9
  (withdrawn by decision 46) and 12; the operator docs' "check a first-contact key on the console"
  (decision 46 ruling 7; plan 13). The key it scanned is RSA; the type OpenSSH's defaults accept,
  and its survival across a reload, are L64's". In L54's second column replace "§13 decision 42
  rulings 10 and 11" with "§13 decision 42 rulings 10 and 11; its pinned-key clause measured plan
  9a's command line, which decision 46 replaced: L64 (c) and (d)". Add after L63's row:

```markdown
| **L64** | `port49 ssh` under decision 46 against each platform, with OpenSSH's default algorithms: (a) a first contact, the operator's known_hosts holding nothing for the device: whether the login succeeds with one askpass ask, and what ssh files under the inventory name (the key type); (b) after a reload with the configuration saved, the device seen down and back: whether `port49 ssh` logs in again with no host-key warning, the filed key still the device's; (c) the entry under the name replaced by another key of the same type: ssh refuses before any TACACS+ exchange, the token never presented, exit 255, `port49 ssh` naming `ssh-keygen -R`; (d) the entry replaced by a key of another type only: the same. Also recorded per platform: the method ssh used and the askpass asks (L54's cells, re-run under the new command line). | §13 decision 46 rulings 2, 6 and 7 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
| **L65** | The Python client (`port49.netmiko.connect`) against each platform: (a) a first contact: Netmiko logs in, and the key Paramiko accepted is filed under the inventory name (hashed under `HashKnownHosts yes`), its type recorded; (b) a second connection verifies against it; (c) the entry replaced by another key of the same type, and (d) by a key of another type only: refused before authentication, no TACACS+ exchange, the token never presented; (e) an entry `port49 ssh` filed (L64 (a)) verifies Python's connection with no line added, and one Python filed verifies `port49 ssh`'s. | §13 decision 46 ruling 13 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
| **L66** | The Ansible lookup `port49.client.token` over `ansible.netcommon.network_cli` against each platform: (a) a ten-task play with the lookup in `ansible_password`: how many mints per host; (b) the same play minting once in a `pre_tasks` `set_fact`: how many mints and how many TACACS+ authentications per host; (c) host keys with `host_key_checking: true` and `host_key_auto_add: true`, for `ssh_type` `libssh` and `paramiko`: a first contact accepted and saved (which file, under which name), and a changed key refused before authentication, no TACACS+ exchange, the token never presented; (d) a denied device: the task fails naming the reason, and `-vvv` output holds no token. | §13 decision 46 ruling 15 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
```

  After the `**L60**–**L63**` bullet add:

```markdown
- **L64**–**L66** — added by plan 9d. Why each is a row:
  - **L64**: L53 measured the RSA key an `x/crypto/ssh` scan negotiates; OpenSSH's defaults may
    accept an Ed25519 or ECDSA key on EOS and Junos, whose survival across a reload nobody
    measured, and a key that changes at every reload would stop every operator's `port49 ssh`.
  - **L65**: Paramiko negotiates host keys by its own preferences; that it is refused before
    authentication under the name is decision 46 ruling 13's claim.
  - **L66**: how often Ansible templates a lookup in a connection variable, and what
    `host_key_auto_add` does per `ssh_type`, are Ansible's behaviour, not documentation's.
```

- [ ] **Step 7: Design §17.** Replace the paragraph beginning "**The address is a fact from the
  source of truth**" with:

```markdown
**The address is a fact from the source of truth, and the client MUST NOT trust it further
than it trusts an SSH host key.** Whoever can add an address to `core-sw01`'s record can list
a host they control; `port49 ssh core-sw01` would connect to it, its SSH server would prompt,
the agent would supply the token, and the attacker would replay it against the real device
within the TTL from the real device's address — device binding and single-use both hold,
because the legitimate login never happened. Host keys are what stops this, and they are
OpenSSH's job (policy engine spec §13 decision 46): `port49 ssh` runs the operator's OpenSSH
against the operator's own known_hosts, accepting a key at first contact and refusing a changed
one (`StrictHostKeyChecking=accept-new`), with the key filed under the device's inventory name
(`HostKeyAlias`), so an address added to a device meets the key already known under its name.
The window left is the first contact, per device and per operator, the one every SSH user
accepts; a shop that wants it closed uses a managed `GlobalKnownHostsFile` or `@cert-authority`,
which apply unchanged. port49 stores no host key anywhere. An address added to an existing
device is a security event in the sync diff (policy engine spec, §10).
```

  Replace "As built (plan 9a; … rulings 7–10):" and its three bullets with:

```markdown
As built (plan 9a, then plan 9d; policy engine spec §13 decisions 42 and 46): `port49 ssh` runs the
operator's OpenSSH (8.5 or later) with the token answered once to the device's own prompt, and host
keys as above. Plan 9a's pins file and `port49 devices trust` were removed by plan 9d. L53's console
commands are how an operator checks a first-contact key; L64 measures `port49 ssh` under accept-new
per platform.
```

  In the client libraries table replace the two Python rows with:

```markdown
| Python library | identity, mint, sweep, retry over the CLI; Netmiko connect (`clients/python`, plan 9d) | v1 |
| Ansible lookup plugin | `port49.client.token`, a thin wrapper over the Python library (plan 9d) | v1 |
```

  and after the paragraph "A library's job is the ergonomics …" add: "As built (plan 9d; decision 46
  ruling 8): the Python library drives the CLI (`port49 token --json`, `port49 workload token
  --format json`), so the ergonomics it adds are Python's: typed exceptions, per-item results, a
  retry of what sent nothing, and Netmiko's host keys under the inventory name." Replace the Netmiko
  and Ansible examples with:

```python
# Netmiko / Python (clients/python, plan 9d). The mint returns the username to present
# beside the token (policy engine spec, §2); the device's key is OpenSSH's known_hosts
# entry under its inventory name, accepted at first contact and refused if changed.
from port49.netmiko import connect
conn = connect("core-sw01")
```

```yaml
# Ansible (clients/ansible, plan 9d): one mint per host per play.
pre_tasks:
  - ansible.builtin.set_fact:
      port49: "{{ lookup('port49.client.token', inventory_hostname, field='all') }}"
    no_log: true
  - ansible.builtin.set_fact:
      ansible_user: "{{ port49.username }}"
      ansible_password: "{{ port49.login }}"
    no_log: true
```

- [ ] **Step 8: Check** that nothing else in either document still asserts a pin, a pins file or
  `devices trust` as current:

```bash
grep -n "devices trust\|pinned host\|pins file\|known_hosts" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
```

  Expected: only decision 42's withdrawn rulings, decision 46, §12's removal line, §15's L53/L54
  history and the new rows.

- [ ] **Step 9: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 46 — host keys are OpenSSH's, the Python and Ansible clients; L64–L66

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: OpenSSH under accept-new — gate G1 and the `ssh -G` forms (containers)

**Files:**
- Create: `tests/ssh-compat/2026-10-13-openssh-accept-new.md`
- Create: `tests/ssh-compat/2026-10-13-openssh-accept-new/run.sh`,
  `tests/ssh-compat/2026-10-13-openssh-accept-new/keys.sh`
- Modify (only if G1 fails on 8.5p1): `cmd/port49/ssh.go` (`minSSH`), the spec's decision 42
  ruling 10 "Why 8.5" and decision 46 ruling 6

**Interfaces:** Produces the floor `minSSH` Task 3 relies on, and the `ssh -G` value forms
`sshPolicy` parses.

Plan 9a's note (`tests/ssh-compat/2026-10-09-openssh-askpass.md`) built 8.5p1 upstream in
`ubuntu:20.04` (`build-and-measure.sh 8.5p1`) and used `ubuntu:22.04` for 8.9p1; reuse its
`setup.sh` and build script. Each container runs its own `sshd` on 127.0.0.1 with an Ed25519 and
an RSA host key, and the client under test against it. No device; this is a note about the
operator's ssh client, not a lab register entry.

- [ ] **Step 1: Write `keys.sh`**, which, inside a container after `setup.sh`, makes the cells. For
  each cell it writes a known_hosts `kh` and runs, with no terminal and `BatchMode=yes`:

```sh
ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o HostKeyAlias=leaf1 -o UserKnownHostsFile=/work-out/kh -o GlobalKnownHostsFile=/dev/null \
    -o HostKeyAlgorithms=$ALGS -o PreferredAuthentications=password tuser@127.0.0.1 true
```

  Cells:
  - **g1-other-type:** `kh` holds `leaf1 <the server's RSA key>`; `ALGS=ssh-ed25519` (the server
    presents only Ed25519). Record ssh's exit status, its last three stderr lines, and `kh` after.
    **Gate G1:** passes when ssh refuses (exit 255, "has changed" or "verification failed") and
    `kh` is unchanged.
  - **g1-control:** `kh` empty, `ALGS=ssh-ed25519`: ssh accepts and files `leaf1` (the control;
    without it G1 is INVALID).
  - **changed-same-type:** `kh` holds `leaf1 <another Ed25519 key>`; refused.
  - **hashed:** `kh` empty and `-o HashKnownHosts=yes`: the line written starts `|1|` and
    `ssh-keygen -F leaf1 -f kh` finds it.
  - **g-forms:** `ssh -G -F cfg leaf1` for `cfg` holding, in turn, nothing, `StrictHostKeyChecking
    yes`, `no`, `ask`, `accept-new`, `off`, and `HostKeyAlias Corp-Leaf1`; record the
    `stricthostkeychecking` and `hostkeyalias` lines verbatim (expected from 10.2p1, measured while
    writing this plan: `true` for yes, `false` for no, `ask`, `accept-new`; `hostkeyalias` absent
    when unset and lowercased when set).
- [ ] **Step 2: Run** it on OpenSSH 8.5p1 (upstream build), 8.9p1 (`ubuntu:22.04`), 9.6p1
  (`ubuntu:24.04`) and the host's 10.2p1:

```bash
sg docker -c "docker run --rm -v $PWD/tests/ssh-compat/2026-10-13-openssh-accept-new:/work:ro -v $PWD/tests/ssh-compat/2026-10-09-openssh-askpass:/askpass:ro ubuntu:22.04 sh /work/run.sh"
```

  (`run.sh` runs `/askpass/setup.sh`, makes the server's keys, starts `sshd`, then `keys.sh`;
  the 8.5p1 run goes through `/askpass/build-and-measure.sh 8.5p1` with `keys.sh` as its
  measurement.) The host's 10.2p1 runs `keys.sh` against a container's sshd on a published
  127.0.0.1 port.
- [ ] **Step 3: Write the note** in the 2026-10-09 note's form: date, what it is for (decision 46
  rulings 2 and 6), where, the clients table, one table per cell (client × exit, stderr, `kh`),
  and the gate.
- [ ] **Step 4: Read G1.** If it passes on 8.5p1, the floor stays; say so in the note. If 8.5p1
  accepts the other type, set `minSSH` in `cmd/port49/ssh.go` to the earliest measured version that
  refuses, update its comment and the message in `sshCmd` ("port49 ssh needs 8.5 or later") and
  decision 42 ruling 10's "Why 8.5" and decision 46 ruling 6 to cite the note, and run `go test
  ./cmd/port49/ -run 'TestAnOldOpenSSHIsRefusedBeforeAMint' -count=1`. Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add tests/ssh-compat/2026-10-13-openssh-accept-new.md tests/ssh-compat/2026-10-13-openssh-accept-new
git commit -m "test: OpenSSH accept-new with a known alias, and ssh -G's forms, 8.5p1 to 10.2p1

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (Add `cmd/port49/ssh.go` and the spec if Step 4 changed them, and say so in the message.)

---

## Task 3: `port49 ssh` on the operator's OpenSSH known_hosts

**Files:**
- Modify: `cmd/port49/ssh.go` (`sshOptions`, `sshArgs`, `sshCmd`; new `sshTrust`, `sshPolicy`,
  `sshName`, `legacyPinsHint`; `shellWord` moved here from `cmd/port49/trust.go`)
- Modify: `cmd/port49/trust.go` (delete `shellWord`, now in `ssh.go`; the rest goes in Task 4)
- Modify: `internal/userconfig/userconfig.go` (add `LegacyPinsPath`)
- Modify: `cmd/port49/main.go` (usage: the `port49 ssh` lines)
- Test: `cmd/port49/ssh_test.go` (the rig; `TestSSHArgs`; the host-key tests),
  `cmd/port49/ssh_fix_test.go` (`TestPortSSHLogsInToADeviceNamedWithCapitals`,
  `TestTheHostKeyHintIsConditionalOnSSHsMessage`), new `cmd/port49/ssh_hostkeys_test.go`

**Interfaces:**
- Consumes: Task 2's `minSSH`.
- Produces:

```go
// sshTrust is what port49 ssh passes about host keys (decision 46 ruling 2).
type sshTrust struct {
	alias   string // HostKeyAlias to pass; "" when the operator's own stands
	keyName string // the name the device's keys are filed under: alias, or the operator's own
	strict  string // StrictHostKeyChecking: "yes" or "accept-new", never "no"
}

// sshPolicy runs `ssh -G` as ssh will run for o and reads the operator's
// StrictHostKeyChecking and HostKeyAlias from it.
func sshPolicy(ctx context.Context, bin string, o sshOptions) (sshTrust, error)

// sshName reports whether device can be an ssh destination and a known_hosts
// host field as written (decision 42 ruling 8; decision 46 ruling 3).
func sshName(device string) bool

// userconfig
// LegacyPinsPath is plan 9a's pins file, which nothing reads since plan 9d
// (decision 46 ruling 5).
func LegacyPinsPath() string
```

- [ ] **Step 1: Rewrite the test rig** in `cmd/port49/ssh_test.go`. The operator's known_hosts is
  named by the rig's ssh_config, not a flag. Replace `newSSHRig` and the `sshRig.known` comment:

```go
// sshRig is one port49 ssh run's world: an agent that answers each mint
// from items and its status from status, counting mints; an ssh_config
// naming the operator's known_hosts (holding the device's key under leaf1
// unless known is nil) and no global one; and the flags that reach them.
type sshRig struct {
	mints  *atomic.Int32
	flags  []string
	sock   string
	known  string // the operator's known_hosts, as the rig's ssh_config names it
	config string // the rig's ssh_config

	mu     sync.Mutex
	items  []api.MintItem
	status agent.Status
}

func newSSHRig(t *testing.T, dev *deviceSSH, item api.MintItem, warn int, known ssh.PublicKey, extra ...string) *sshRig {
	t.Helper()
	r := &sshRig{mints: new(atomic.Int32), items: []api.MintItem{item},
		status: agent.Status{CeilingWarningSeconds: warn}}
	r.sock = agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		r.mu.Lock()
		defer r.mu.Unlock()
		switch req.URL.Path {
		case "/token":
			n := int(r.mints.Add(1)) - 1
			_ = json.NewEncoder(w).Encode(r.items[min(n, len(r.items)-1)])
		case "/status":
			_ = json.NewEncoder(w).Encode(r.status)
		}
	}))
	dir := privateDir(t)
	r.known = filepath.Join(dir, "known_hosts")
	var lines []byte
	if known != nil {
		lines = []byte("leaf1 " + string(ssh.MarshalAuthorizedKey(known)))
	}
	if err := os.WriteFile(r.known, lines, 0o600); err != nil {
		t.Fatal(err)
	}
	r.config = filepath.Join(dir, "ssh_config")
	cfg := "UserKnownHostsFile " + r.known + "\nGlobalKnownHostsFile /dev/null\n" + strings.Join(extra, "\n") + "\n"
	if err := os.WriteFile(r.config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r.flags = []string{"--socket", r.sock, "--ssh", sshTestBin(t), "--ssh-config", r.config,
		"--port", strconv.Itoa(dev.port)}
	return r
}

// filed is every line ssh-keygen finds under name in the rig's known_hosts.
func (r *sshRig) filed(t *testing.T, name string) []string {
	t.Helper()
	out, _ := exec.Command("ssh-keygen", "-F", name, "-f", r.known).Output()
	var keys []string
	for _, l := range strings.Split(string(out), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	return keys
}
```

  Every existing caller passes its pin as `known` unchanged (the device's key, `dev.key`, or
  `nil`). Delete `TestNoPinnedKeyMintsNothing` (no pin is required any more; its replacement is
  Step 2's first test). In `cmd/port49/ssh_fix_test.go`'s `TestPortSSHLogsInToADeviceNamedWithCapitals`,
  write the rig's known_hosts line under `Leaf1` (the case a fold must match) instead of
  `hostkeys.Pin(r.known, "Leaf1", …)`.

- [ ] **Step 2: Write the failing tests** in `cmd/port49/ssh_hostkeys_test.go`:

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A first contact is OpenSSH's accept-new: the login goes on, once, and the
// key is filed under the device's inventory name (decision 46 ruling 2).
func TestFirstContactIsAcceptedAndFiledUnderTheName(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" || len(r.filed(t, "leaf1")) != 1 ||
		!strings.Contains(errb, "Permanently added 'leaf1'") {
		t.Fatalf("code %d stdout %q stderr %q attempts %q filed %q", code, out, errb, dev.attempts(), r.filed(t, "leaf1"))
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 1: an RSA key known under the name, and a host offering only
// Ed25519, is a changed key to OpenSSH, never a new one.
func TestAKeyOfAnotherTypeUnderAKnownNameIsRefused(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "LOGINTOKEN", 0) // Ed25519
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rpub, _ := ssh.NewPublicKey(&rk.PublicKey)
	r := newSSHRig(t, dev, sshPermit, 0, rpub)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 || !strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "ssh-keygen -R leaf1") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
	if got := r.filed(t, "leaf1"); len(got) != 1 || !strings.Contains(got[0], "ssh-rsa") {
		t.Fatalf("the known key was replaced or joined: %q", got)
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 2: once a device's key is filed under its name, a mint giving
// that name another host's address ends at the key exchange.
func TestAnAddressMovedToAnotherHostNeverSeesTheToken(t *testing.T) {
	real := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, real, sshPermit, 0, nil)
	if code, _, errb := r.run(t, "leaf1"); code != 0 {
		t.Fatalf("first login: %d %q", code, errb)
	}
	impostor := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0) // another key
	r.flags[len(r.flags)-1] = strconv.Itoa(impostor.port)
	code, out, errb := r.run(t, "leaf1")
	if code != 255 || len(impostor.attempts()) != 0 || !strings.Contains(errb, "is not the device") {
		t.Fatalf("code %d stderr %q impostor attempts %q", code, errb, impostor.attempts())
	}
	tokenNowhere(t, out, errb)
}

// Review Focus 3: the operator's yes stands; everything else is accept-new;
// no is never passed. Their HostKeyAlias stands, and is the name keys are
// filed under.
func TestSSHPolicyReadsTheOperatorsConfig(t *testing.T) {
	bin := sshTestBin(t)
	for _, tc := range []struct{ cfg, strict, alias, keyName string }{
		{"", "accept-new", "leaf1", "leaf1"},
		{"StrictHostKeyChecking yes", "yes", "leaf1", "leaf1"},
		{"StrictHostKeyChecking no", "accept-new", "leaf1", "leaf1"},
		{"StrictHostKeyChecking ask", "accept-new", "leaf1", "leaf1"},
		{"StrictHostKeyChecking accept-new", "accept-new", "leaf1", "leaf1"},
		{"Host leaf1\n  HostKeyAlias Corp-Leaf1", "accept-new", "", "corp-leaf1"},
	} {
		cfg := filepath.Join(privateDir(t), "ssh_config")
		if err := os.WriteFile(cfg, []byte(tc.cfg+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := sshPolicy(context.Background(), bin, sshOptions{config: cfg, device: "Leaf1",
			address: "192.0.2.7", username: "alice"})
		if err != nil || got.strict != tc.strict || got.alias != tc.alias || got.keyName != tc.keyName {
			t.Errorf("%q: got %+v, %v; want strict %s alias %q keyName %s", tc.cfg, got, err, tc.strict, tc.alias, tc.keyName)
		}
	}
}

// The operator's StrictHostKeyChecking yes refuses a first contact: nothing
// sent, nothing filed.
func TestTheOperatorsStrictYesStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "StrictHostKeyChecking yes")
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || len(dev.attempts()) != 0 || len(r.filed(t, "leaf1")) != 0 {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
}

// The operator's own HostKeyAlias is the name ssh looks the key up under.
func TestTheOperatorsHostKeyAliasStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "Host leaf1\n  HostKeyAlias corp-leaf1")
	if err := os.WriteFile(r.known, []byte("corp-leaf1 "+string(ssh.MarshalAuthorizedKey(dev.key))), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb := r.run(t, "leaf1")
	if code != 0 || len(r.filed(t, "leaf1")) != 0 || strings.Contains(errb, "Permanently added") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}

// --known-hosts named port49's own pins file, which is gone.
func TestTheKnownHostsFlagIsRefused(t *testing.T) {
	var out, errb lockedBuffer
	if code := run([]string{"ssh", "--known-hosts", "/k", "leaf1"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "UserKnownHostsFile") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// Plan 9a's pins file is named, never read: a pins file anyone can write
// stops nothing, and its keys are not used.
func TestThe9aPinsFileIsNamedNotRead(t *testing.T) {
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "port49"), 0o777); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(xdg, "port49", "known_hosts")
	if err := os.WriteFile(pins, []byte("leaf1 not-a-key\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	code, _, errb := r.run(t, "leaf1")
	if code != 0 || strings.Count(errb, pins) != 2 || !strings.Contains(errb, "no longer reads it") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}
```

  Rewrite `TestAHostWithAnotherKeyNeverSeesTheToken` (its rig's `known` is `testHostKey(t)`, as
  today) to expect `ssh-keygen -R leaf1` in place of the `port49 devices trust … --replace leaf1`
  hint. Rewrite `TestSSHArgs`:

```go
func TestSSHArgs(t *testing.T) {
	got := sshArgs(sshOptions{config: "/c", device: "leaf1", address: "10.0.0.1", username: "alice",
		trust: sshTrust{alias: "leaf1", keyName: "leaf1", strict: "accept-new"}, port: 2222, verbose: true,
		command: []string{"show", "version"}})
	want := `-F /c -o HostName="10.0.0.1" -o HostKeyAlias=leaf1 -o StrictHostKeyChecking=accept-new ` +
		"-o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password " +
		"-o KbdInteractiveAuthentication=yes -o PasswordAuthentication=yes -o NumberOfPasswordPrompts=1 " +
		"-o BatchMode=no -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no -v -l alice -p 2222 -- " +
		"leaf1 show version"
	if strings.Join(got, " ") != want {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	theirs := strings.Join(sshArgs(sshOptions{device: "leaf1", address: "fe80::1%eth0", username: "alice",
		trust: sshTrust{keyName: "corp-leaf1", strict: "yes"}}), " ")
	for _, gone := range []string{"HostKeyAlias", "UserKnownHostsFile", "GlobalKnownHostsFile", "UpdateHostKeys",
		"CheckHostIP", "VerifyHostKeyDNS", "KnownHostsCommand", "StrictHostKeyChecking=no"} {
		if strings.Contains(theirs, gone) {
			t.Errorf("%s passed: %s", gone, theirs)
		}
	}
	if !strings.Contains(theirs, `-o HostName="fe80::1%%eth0"`) || !strings.Contains(theirs, "StrictHostKeyChecking=yes") {
		t.Fatalf("got %s", theirs)
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'TestFirstContact|TestAKeyOfAnotherType|TestAnAddressMoved|TestSSHPolicy|TestTheOperators|TestTheKnownHostsFlag|TestThe9aPins|TestSSHArgs|TestAHostWithAnotherKey' -count=1`
Expected: FAIL to compile (`sshPolicy`, `sshTrust`, `sshOptions.trust` undefined).

- [ ] **Step 4: Implement.** In `cmd/port49/ssh.go`:
  - Replace `hostkeys.ValidName` with `sshName` (same regexp, moved here with its comment, ruling 8
    and decision 46 ruling 3 cited), and drop the `hostkeys` import.
  - Move `shellWord` from `trust.go` into `ssh.go` unchanged.
  - `sshOptions` loses `knownHosts` and gains `trust sshTrust`.
  - `sshArgs`:

```go
func sshArgs(o sshOptions) []string {
	var a []string
	if o.config != "" {
		a = append(a, "-F", o.config)
	}
	opts := []string{"HostName=" + sshValue(o.address)}
	if o.trust.alias != "" {
		opts = append(opts, "HostKeyAlias="+o.trust.alias)
	}
	opts = append(opts,
		"StrictHostKeyChecking="+o.trust.strict,
		// L51: every key offered and refused counts against the device's
		// authentication-attempt limit, and an IOS-XE login block-for
		// locks the source address out.
		"PubkeyAuthentication=no",
		"PreferredAuthentications=keyboard-interactive,password",
		"KbdInteractiveAuthentication=yes",
		"PasswordAuthentication=yes",
		"NumberOfPasswordPrompts=1",
		"BatchMode=no",
		"ControlMaster=no",
		"ControlPath=none",
		"ForwardAgent=no",
	)
	for _, opt := range opts {
		a = append(a, "-o", opt)
	}
	if o.verbose {
		a = append(a, "-v")
	}
	a = append(a, "-l", o.username)
	if o.port != 0 {
		a = append(a, "-p", strconv.Itoa(o.port))
	}
	a = append(a, "--", o.device)
	return append(a, o.command...)
}
```

  - `sshPolicy`:

```go
// sshPolicy asks the operator's OpenSSH what its ssh_config makes of this
// connection (`ssh -G`: OpenSSH's own reading of it, Match blocks
// included), and returns what port49 ssh passes about host keys (decision 46
// ruling 2). The operator's StrictHostKeyChecking yes stands, and every other
// value is accept-new, never no; the operator's HostKeyAlias stands, and
// otherwise the alias is the device's name, lowercased as ssh files it.
// Nothing about trust is decided here that OpenSSH does not decide itself.
func sshPolicy(ctx context.Context, bin string, o sshOptions) (sshTrust, error) {
	args := []string{"-G"}
	if o.config != "" {
		args = append(args, "-F", o.config)
	}
	args = append(args, "-o", "HostName="+sshValue(o.address), "-l", o.username)
	if o.port != 0 {
		args = append(args, "-p", strconv.Itoa(o.port))
	}
	args = append(args, "--", o.device)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil {
		return sshTrust{}, fmt.Errorf("%s -G (reading your ssh_config for %s): %v", bin, o.device, err)
	}
	t := sshTrust{alias: strings.ToLower(o.device), keyName: strings.ToLower(o.device), strict: "accept-new"}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "hostkeyalias":
			t.alias, t.keyName = "", printsafe.Line(v, 253)
		case "stricthostkeychecking":
			if v == "true" || v == "yes" {
				t.strict = "yes"
			}
		}
	}
	return t, nil
}
```

  - `legacyPinsHint`:

```go
// legacyPinsHint says, while plan 9a's pins file exists, that port49 no
// longer reads it, and how to keep the keys in it (decision 46 ruling 5). It
// is found by Lstat alone and never opened, so a pins file or a ~/.config
// others can write stops nothing.
func legacyPinsHint(stderr io.Writer) {
	p := userconfig.LegacyPinsPath()
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return
	}
	fmt.Fprintf(stderr, "port49 ssh: %s holds keys `port49 devices trust` pinned (plan 9a); port49 no longer reads it, "+
		"and uses your OpenSSH known_hosts. Its lines are filed under the device names port49 ssh uses, so to keep "+
		"keys you verified: check they are yours, then `cat %s >> ~/.ssh/known_hosts`, and remove it\n",
		p, shellWord(p))
}
```

  - In `sshCmd`: the `--known-hosts` flag stays registered with an empty default and the help
    "removed in plan 9d: port49 ssh uses your OpenSSH known_hosts"; given, it is refused:

```go
	if *knownHosts != "" {
		fmt.Fprintf(stderr, "%s: --known-hosts named port49's own pins file, which plan 9d removed: port49 ssh uses "+
			"your OpenSSH known_hosts. Name another with UserKnownHostsFile in an ssh_config (--ssh-config FILE)\n", cmd)
		return 2
	}
```

    Delete the `--known-hosts` quoting check, the `hostkeys.Lookup` and the "no host key is pinned"
    refusal. Call `legacyPinsHint(stderr)` after the name check. After the mint's address check
    and before `listenAskpass`:

```go
	opts := sshOptions{config: *sshConfig, device: device, address: item.Address, username: item.Username,
		port: *port, verbose: *verbose, command: command}
	if opts.trust, err = sshPolicy(context.Background(), path, opts); err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was sent to %s\n", cmd, err, device)
		return 1
	}
```

    and run ssh with `sshArgs(opts)`. The `code == 255` (not served) message becomes:

```go
	case code == 255:
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above). If it says Host key verification failed, the key your known_hosts files under "+
			"%s is not the one %s presents: either the device's key changed, or the address inventory gives for %s "+
			"is not the device. Verify the key on its console, then run 'ssh-keygen -R %s' and connect again\n",
			cmd, device, opts.trust.keyName, item.Address, device, shellWord(opts.trust.keyName))
```

  - Usage in `main.go`: the `port49 ssh` lines lose `[--known-hosts FILE]` and "DEVICE's key must be
    pinned first with port49 devices trust" becomes "host keys are your OpenSSH known_hosts',
    accepted at first contact and refused if changed".
  - `internal/userconfig/userconfig.go`: add, under `LegacyDir`:

```go
// LegacyPinsPath is plan 9a's pins file. Nothing reads it since plan 9d
// (decision 46 ruling 5); port49 ssh names it while it exists.
func LegacyPinsPath() string { return filepath.Join(LegacyDir(), "known_hosts") }
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./cmd/port49/ -run 'SSH|Askpass|Ceiling|Token' -count=1`
Expected: PASS (each host-key test runs the real OpenSSH; on a host with none they skip, as
`sshTestBin` says).

- [ ] **Step 6: Commit**

```bash
git add cmd/port49/ssh.go cmd/port49/trust.go cmd/port49/main.go cmd/port49/ssh_test.go cmd/port49/ssh_fix_test.go cmd/port49/ssh_hostkeys_test.go internal/userconfig/userconfig.go
git commit -m "feat: port49 ssh uses the operator's known_hosts under accept-new, filed under the inventory name

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Remove `port49 devices trust` and `internal/hostkeys`; nothing reads under `~/.config`

**Files:**
- Delete: `internal/hostkeys/hostkeys.go`, `internal/hostkeys/hostkeys_test.go`,
  `cmd/port49/trust.go`, `cmd/port49/trust_test.go`, `cmd/port49/trust_hint_test.go`
- Modify: `cmd/port49/main.go` (the `devices trust` case; usage), `internal/userconfig/userconfig.go`
  (`LegacyDir` → `legacyDir`)
- Create: `tests/lab/hostkeyscan_test.go` (`//go:build lab`: `labScan`, `labFingerprint`, moved from
  `hostkeys.Scan` and `hostkeys.Fingerprint`)
- Modify: `tests/lab/l53_l54_test.go` (the L54 half removed; `TestL53L54PortSSH` renamed
  `TestL53HostKeyScan`), `Makefile` (`lab-ssh`'s `-run`)
- Test: `cmd/port49/devices_test.go` (`TestDevicesTrustIsGone`), `cmd/port49/ssh_hostkeys_test.go`
  (`TestAGroupWritableConfigStopsNothing`)

**Interfaces:**
- Consumes: Task 3's `sshName`, `shellWord` in `ssh.go`, `LegacyPinsPath`.
- Produces: `userconfig.LegacyPinsPath` as the only exported route to plan 9a's directory.

- [ ] **Step 1: Write the failing tests.** In `cmd/port49/devices_test.go`:

```go
// port49 devices trust is gone (decision 46 ruling 4): one line, exit 2,
// and nothing dialled or minted.
func TestDevicesTrustIsGone(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--fingerprint", "SHA256:x", "leaf1"}, &out, &errb)
	if code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "removed in plan 9d") ||
		!strings.Contains(errb.String(), "known_hosts") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
```

  In `cmd/port49/ssh_hostkeys_test.go`:

```go
// Plan 9b pre-flight 2, m5: Ubuntu's 0775 ~/.config refused port49 ssh with no
// fix to run. Nothing port49 ssh reads is under it now.
func TestAGroupWritableConfigStopsNothing(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "port49"), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, ".config"), 0o775); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	if code, _, errb := r.run(t, "leaf1"); code != 0 {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}
```

- [ ] **Step 2: Run them to see the first fail**

Run: `go test ./cmd/port49/ -run 'TestDevicesTrustIsGone|TestAGroupWritableConfigStopsNothing' -count=1`
Expected: `TestDevicesTrustIsGone` FAIL (the old command runs and refuses its flags differently);
`TestAGroupWritableConfigStopsNothing` PASS already after Task 3 (it pins the fix).

- [ ] **Step 3: Remove.** Delete the five files. In `main.go`:

```go
	case "devices":
		if len(args) > 1 && args[1] == "trust" {
			// Decision 46 ruling 4: host keys are OpenSSH's. Until the
			// pre-beta review, the old command says where it went.
			fmt.Fprintln(stderr, "port49 devices trust was removed in plan 9d: port49 ssh uses your OpenSSH "+
				"known_hosts, which accepts a device's key at first contact and refuses a changed one. To check a "+
				"key at first contact, compare the fingerprint ssh prints with the device's console")
			return 2
		}
```

  and delete the `port49 devices trust` usage lines. In `internal/userconfig/userconfig.go` rename
  `LegacyDir` to `legacyDir` and its two uses (`noLegacy`, `LegacyPinsPath`); its comment becomes:
  "legacyDir is plan 9a's directory, `$XDG_CONFIG_HOME/port49`, else `~/.config/port49`. Nothing in
  it is read: a config.yaml there is refused by `Lstat`, naming the move (`LoadAll`), and the pins
  file is only named (`LegacyPinsPath`; decision 46 ruling 5)."
- [ ] **Step 4: The lab keeps its scan.** Create `tests/lab/hostkeyscan_test.go` with
  `//go:build lab`, `package lab`, holding `labScan` (the body of `hostkeys.Scan` with its
  `scanTimeout` and `errScanned`, renamed `labScanTimeout` and `errLabScanned`, its comment
  saying "moved from internal/hostkeys by plan 9d: the scan is L53's instrument now, not a
  product path") and `labFingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }`.
  In `tests/lab/l53_l54_test.go` replace `hostkeys.Scan` and `hostkeys.Fingerprint` with them;
  delete the block from `// L54: port49 devices trust, then port49 ssh with a command.` through
  the wrong-pin note (`say(&l54, "Against a wrong pin: …")`), the `l54` note variable and its
  writer, the `xdg` pins directory setup, and every claim assertion naming L54; rename
  `TestL53L54PortSSH` to `TestL53HostKeyScan` and its skip message. `Makefile`'s `lab-ssh` runs
  `-run 'TestL53HostKeyScan'` until Task 11 adds L64's test.
- [ ] **Step 5: Check** that nothing kept reads under `~/.config`:

```bash
grep -rn "LegacyDir\|legacyDir\|XDG_CONFIG_HOME\|\.config\"" --include='*.go' internal cmd
```

  Expected: only `internal/userconfig/userconfig.go` (`legacyDir`, `noLegacy`, `LegacyPinsPath`)
  and tests that set `XDG_CONFIG_HOME`.

- [ ] **Step 6: Run everything**

Run: `make test && make vet`
Expected: PASS; `make lab-unit` (inside `make test`) builds `tests/lab` with the moved scan.

- [ ] **Step 7: Commit**

```bash
git add -A internal/hostkeys cmd/port49 internal/userconfig tests/lab/hostkeyscan_test.go tests/lab/l53_l54_test.go Makefile
git commit -m "feat: remove port49 devices trust and internal/hostkeys; nothing reads under ~/.config

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `port49 token --json` says why it failed, as JSON

**Files:**
- Modify: `cmd/port49/mint.go` (new `tokenFailure`, `mfaRequirement`, `tokenFailureOf`),
  `cmd/port49/mfa.go` (`mintProved` wraps a failed proof as `*mfaUnprovedError`),
  `cmd/port49/main.go` (`tokenCmd` prints the failure under `--json`)
- Test: `cmd/port49/token_json_test.go` (new)

**Interfaces:**
- Consumes: `agent.ItemError`, `agent.MFARequiredError`, `agent.KeyCode`, `agent.ErrNoAgent`,
  `agent.ErrAgentTooOld`, `agent.ErrSessionOver`, `agent.RevokedError`,
  `agent.RevocationRunningError`, `agent.BrokerRefusedError`, `agent.ErrConnectionChanged`,
  `api.PerLoginMFA`, `api.MFALevel`, `printsafe.Line`.
- Produces (Task 7 parses exactly these):

```go
// tokenFailure is `port49 token --json`'s stdout on a failure (decision 46
// ruling 9): the broker's own item for a deny or an item it could not decide
// (no token in either), or a client code.
type tokenFailure struct {
	Device      string          `json:"device"`
	Verdict     string          `json:"verdict,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	Detail      string          `json:"detail,omitempty"`
	PerLoginMFA *mfaRequirement `json:"per_login_mfa,omitempty"`
}

// mfaRequirement is a requirement as printed: never its challenge.
type mfaRequirement struct {
	Accept          []string       `json:"accept"`
	ReuseForSeconds int            `json:"reuse_for_seconds"`
	ReuseFrom       string         `json:"reuse_from,omitempty"`
	Levels          []api.MFALevel `json:"levels,omitempty"`
}

func tokenFailureOf(device string, item api.MintItem, err error) tokenFailure

// mfaUnprovedError is a requirement prove could not meet: Error is the
// proof's own words, as mintFailed always said them.
type mfaUnprovedError struct {
	Requirement api.PerLoginMFA
	Err         error
}
```

- [ ] **Step 1: Write the failing tests** in `cmd/port49/token_json_test.go`:

```go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
)

func TestTokenFailureCodes(t *testing.T) {
	need := api.PerLoginMFA{Device: "core1", Challenge: "CHALLENGE", Accept: []string{"hardware_key_touch"},
		ReuseForSeconds: 900, ReuseFrom: "scope core"}
	for _, tc := range []struct {
		name string
		item api.MintItem
		err  error
		want tokenFailure
	}{
		{"deny", api.MintItem{Device: "core1", Verdict: "deny", Reason: "no_grants_matched", Detail: "d"}, nil,
			tokenFailure{Device: "core1", Verdict: "deny", Reason: "no_grants_matched", Detail: "d"}},
		{"item error", api.MintItem{Device: "core1", Error: "broker_error", Detail: "d"},
			&agent.ItemError{Device: "core1", Code: "broker_error", Detail: "d"},
			tokenFailure{Device: "core1", Error: "broker_error", Detail: "d"}},
		{"no agent", api.MintItem{}, fmt.Errorf("%w at /s: refused", agent.ErrNoAgent),
			tokenFailure{Device: "core1", Error: "no_agent"}},
		{"too old", api.MintItem{}, agent.ErrAgentTooOld, tokenFailure{Device: "core1", Error: "agent_too_old"}},
		{"over", api.MintItem{}, agent.ErrSessionOver, tokenFailure{Device: "core1", Error: "session_over"}},
		{"revoked", api.MintItem{}, &agent.RevokedError{Detail: "d"}, tokenFailure{Device: "core1", Error: "credential_revoked"}},
		{"running", api.MintItem{}, &agent.RevocationRunningError{Detail: "d"},
			tokenFailure{Device: "core1", Error: "revocation_running"}},
		{"mfa", api.MintItem{}, &agent.MFARequiredError{Requirement: need},
			tokenFailure{Device: "core1", Error: "per_login_mfa_required",
				PerLoginMFA: &mfaRequirement{Accept: need.Accept, ReuseForSeconds: 900, ReuseFrom: "scope core"}}},
		{"no terminal", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: errors.New("no terminal")},
			tokenFailure{Device: "core1", Error: "per_login_mfa_required",
				PerLoginMFA: &mfaRequirement{Accept: need.Accept, ReuseForSeconds: 900, ReuseFrom: "scope core"}}},
		{"touch timeout", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.KeyError{Err: hwkey.ErrTouchTimeout}}, tokenFailure{Device: "core1", Error: "touch_timeout"}},
		{"changed", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrConnectionChanged},
			tokenFailure{Device: "core1", Error: "connection_changed"}},
		{"refused", api.MintItem{}, &agent.BrokerRefusedError{Err: errors.New("revoked")},
			tokenFailure{Device: "core1", Error: "broker_refused"}},
		{"no token", api.MintItem{Device: "core1", Verdict: "permit"}, nil, tokenFailure{Device: "core1", Error: "no_token"}},
		{"other", api.MintItem{}, errors.New("agent: something"), tokenFailure{Device: "core1", Error: "agent_error"}},
	} {
		got := tokenFailureOf("core1", tc.item, tc.err)
		got.Detail, tc.want.Detail = "", "" // the words are checked below
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(tc.want)
		if string(gj) != string(wj) {
			t.Errorf("%s: got %s want %s", tc.name, gj, wj)
		}
		if strings.Contains(string(gj), "CHALLENGE") {
			t.Errorf("%s: the challenge was printed", tc.name)
		}
	}
}

// --json on a failure: one object on stdout, the exit status as before, the
// stderr line as before, and no token anywhere.
func TestTokenJSONOnADeny(t *testing.T) {
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	}))
	var out, errb lockedBuffer
	code := run([]string{"token", "--json", "--socket", sock, "leaf1"}, &out, &errb)
	var f tokenFailure
	if code != 1 || json.Unmarshal([]byte(out.String()), &f) != nil || f.Reason != "no_grants_matched" ||
		strings.Count(out.String(), "\n") != 1 || !strings.Contains(errb.String(), "deny no_grants_matched") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A detail with a control character is printed safe.
func TestTokenFailureDetailIsPrintable(t *testing.T) {
	f := tokenFailureOf("leaf1", api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched",
		Detail: "a\x1b[2Jb"}, nil)
	if strings.ContainsRune(f.Detail, 0x1b) {
		t.Fatalf("detail %q", f.Detail)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'TestTokenFailure|TestTokenJSON' -count=1`
Expected: FAIL to compile (`tokenFailureOf`, `mfaUnprovedError` undefined).

- [ ] **Step 3: Implement.** In `mfa.go`, `mintProved`'s failed proof:

```go
	if err := prove(ctx, sf.socket, sf, need.Requirement, stderr); err != nil {
		return api.MintItem{}, &mfaUnprovedError{Requirement: need.Requirement, Err: err}
	}
```

  with, beside it:

```go
func (e *mfaUnprovedError) Error() string { return e.Err.Error() }
func (e *mfaUnprovedError) Unwrap() error { return e.Err }
```

  (`mintFailed` and `ssh` print `unprefixed(err)`, so what they say is unchanged; `errors.Is` and
  `errors.As` reach the proof's own error through `Unwrap`.) In `mint.go`:

```go
// Client codes of `port49 token --json` (decision 46 ruling 9): the CLI's own,
// like the API's error codes, never §5.7 reason codes.
const (
	failNoAgent           = "no_agent"
	failAgentTooOld       = "agent_too_old"
	failSessionOver       = "session_over"
	failRevoked           = "credential_revoked"
	failRevocationRunning = "revocation_running"
	failMFARequired       = "per_login_mfa_required"
	failConnectionChanged = "connection_changed"
	failBrokerRefused     = "broker_refused"
	failNoToken           = "no_token"
	failAgent             = "agent_error"
)

func requirementOf(r api.PerLoginMFA) *mfaRequirement {
	return &mfaRequirement{Accept: r.Accept, ReuseForSeconds: r.ReuseForSeconds, ReuseFrom: r.ReuseFrom, Levels: r.Levels}
}

func tokenFailureOf(device string, item api.MintItem, err error) tokenFailure {
	f := tokenFailure{Device: device}
	if err != nil {
		f.Detail = printsafe.Line(unprefixed(err), safeLimit)
	}
	var ie *agent.ItemError
	var need *agent.MFARequiredError
	var unproved *mfaUnprovedError
	var revoked *agent.RevokedError
	var running *agent.RevocationRunningError
	var refused *agent.BrokerRefusedError
	switch {
	case err == nil && item.Verdict != "" && item.Verdict != "permit":
		f.Verdict, f.Reason = item.Verdict, item.Reason
		f.Detail = printsafe.Line(item.Detail, safeLimit)
	case err == nil:
		f.Error = failNoToken
	case errors.As(err, &ie):
		f.Error, f.Detail = ie.Code, printsafe.Line(ie.Detail, safeLimit)
	case agent.KeyCode(err) != "":
		f.Error = agent.KeyCode(err)
	case errors.Is(err, agent.ErrConnectionChanged):
		f.Error = failConnectionChanged
	case errors.As(err, &refused):
		f.Error = failBrokerRefused
	case errors.As(err, &unproved):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(unproved.Requirement)
	case errors.As(err, &need):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(need.Requirement)
	case errors.As(err, &revoked):
		f.Error = failRevoked
	case errors.As(err, &running):
		f.Error = failRevocationRunning
	case errors.Is(err, agent.ErrAgentTooOld):
		f.Error = failAgentTooOld
	case errors.Is(err, agent.ErrNoAgent):
		f.Error = failNoAgent
	case errors.Is(err, agent.ErrSessionOver):
		f.Error = failSessionOver
	default:
		f.Error = failAgent
	}
	return f
}
```

  (`KeyCode` is checked before the requirement, so a touch that timed out inside a proof says
  `touch_timeout`; `ErrConnectionChanged` before it too.) In `tokenCmd`:

```go
	if mintFailed("port49 token", *socket, device, item, err, stderr) {
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(tokenFailureOf(device, item, err))
		}
		return 1
	}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./cmd/port49/ -run 'TestTokenFailure|TestTokenJSON|MFA|Touch' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/mint.go cmd/port49/mfa.go cmd/port49/main.go cmd/port49/token_json_test.go
git commit -m "feat: port49 token --json prints why a mint failed, as one JSON object

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `port49 workload token --format json` lists what was refused

**Files:**
- Modify: `cmd/port49/workload.go` (`render`, `workloadToken`; new `workloadJSON`, `refusedItem`)
- Test: `cmd/port49/workload_test.go`

**Interfaces:**
- Consumes: `api.MintResponse`, `api.MintItem`, Task 5's `mfaRequirement` and `requirementOf`.
- Produces (Task 8 parses exactly these):

```go
// refusedItem is one item --format json did not mint: its words, never a token.
type refusedItem struct {
	Device      string          `json:"device"`
	Verdict     string          `json:"verdict,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	Detail      string          `json:"detail,omitempty"`
	PerLoginMFA *mfaRequirement `json:"per_login_mfa,omitempty"`
}

// workloadJSON is --format json's object: the broker's answer with only the
// minted items in results, and every other in refused (decision 46 ruling 10).
type workloadJSON struct {
	api.MintResponse
	Refused []refusedItem `json:"refused"`
}
```

- [ ] **Step 1: Write the failing tests** in `cmd/port49/workload_test.go`, over its existing
  `workloadBroker` and `mixed` (which permits every device but `fw1`, denied `no_grants_matched`):

```go
// mixedMFA is mixed, with core1 denied under a per-login requirement whose
// challenge must never be printed.
func mixedMFA(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		switch d {
		case "fw1":
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "no_grants_matched"})
		case "core1":
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "per_login_mfa_required",
				PerLoginMFA: &api.PerLoginMFA{Device: d, Challenge: "CHALLENGE", Accept: []string{"hardware_key_touch"},
					ReuseForSeconds: 900}})
		default:
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1",
				Platform: "arista_eos", Username: "svc-oxidized", Login: "TOKEN-" + d, ExpiresAt: "2026-10-08T03:00:00Z"})
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// --format json lists the refused beside the minted, with no token and no
// challenge, and exits 1 as before.
func TestWorkloadJSONListsTheRefused(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "leaf1", "fw1", "core1"),
		&out, &errb)
	var got workloadJSON
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 1 || len(got.Refused) != 2 ||
		got.Refused[0].Reason != "no_grants_matched" || got.Refused[1].PerLoginMFA == nil ||
		got.Refused[1].PerLoginMFA.ReuseForSeconds != 900 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "CHALLENGE") || strings.Count(out.String(), "TOKEN-") != 1 {
		t.Fatalf("stdout %q", out.String())
	}
}

// Every device denied: exit 77 as before, and stdout says which and why.
func TestWorkloadJSONOnEveryDeviceDenied(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "fw1"), &out, &errb)
	var got workloadJSON
	if code != 77 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 0 || len(got.Refused) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// With --out, nothing is written when nothing was minted (decision 40 ruling
// 10), and stdout stays empty.
func TestWorkloadJSONOutStillWritesOnlyAPermit(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("LAST"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json", "--out", path}, flags...), "fw1"),
		&out, &errb)
	if b, _ := os.ReadFile(path); code != 77 || string(b) != "LAST" || out.Len() != 0 {
		t.Fatalf("code %d file %q stdout %q", code, b, out.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'TestWorkloadJSON' -count=1`
Expected: FAIL (`workloadJSON` undefined).

- [ ] **Step 3: Implement.** `render` takes the refused too:

```go
// refusedOf is the items not minted, in refused's form.
func refusedOf(items []api.MintItem) []refusedItem {
	out := []refusedItem{}
	for _, it := range items {
		if it.Verdict == "permit" && it.Login != "" {
			continue
		}
		r := refusedItem{Device: it.Device, Verdict: it.Verdict, Reason: it.Reason, Error: it.Error,
			Detail: safe(it.Detail)}
		if it.PerLoginMFA != nil {
			r.PerLoginMFA = requirementOf(*it.PerLoginMFA)
		}
		out = append(out, r)
	}
	return out
}

func render(format string, resp api.MintResponse, permitted []api.MintItem, enable bool) ([]byte, error) {
	if format == "json" {
		refused := refusedOf(resp.Results)
		resp.Results = permitted
		return json.Marshal(workloadJSON{MintResponse: resp, Refused: refused})
	}
	…TSV unchanged…
}
```

  A TSV-unsafe permitted item left out under `--format json` cannot happen (JSON carries any
  character); under TSV it stays as today. In `workloadToken`, where nothing was permitted:

```go
	if len(permitted) == 0 {
		if *format == "json" && *out == "" && len(resp.Results) > 0 {
			// The broker answered: say which and why on stdout too (decision 46
			// ruling 10). A file named by --out keeps its last contents.
			if body, err := render("json", resp, nil, *enable); err == nil {
				_, _ = stdout.Write(body)
			}
		}
		if code == exitTemporary {
			return exitTemporary
		}
		return exitFinal
	}
```

  and for the empty sweep (`*scope != "" && len(resp.Results) == 0`), under `--format json` with no
  `--out`, print `{"principal": …, "results": [], "refused": []}` (render with no items) before
  returning 77, so the library can tell "nothing selected" from a failure.
- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./cmd/port49/ -run 'Workload' -count=1`
Expected: PASS, the Oxidized wrapper's tests (`examples/oxidized`) unchanged: `go test
./examples/oxidized/ -count=1` PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/workload.go cmd/port49/workload_test.go
git commit -m "feat: workload token --format json lists the refused, and answers on 75 and 77

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: The Python library — package, runner, errors, `Agent`

**Files:**
- Create: `clients/python/pyproject.toml`, `clients/python/README.md`,
  `clients/python/src/port49/__init__.py`, `clients/python/src/port49/_run.py`,
  `clients/python/src/port49/errors.py`, `clients/python/src/port49/client.py`
- Create: `clients/python/tests/fakeport49.py`, `clients/python/tests/test_agent.py`,
  `clients/python/tests/test_floor.py`
- Modify: `Makefile` (`test-python`; `test` depends on it; `.PHONY`)

**Interfaces:**
- Consumes: Task 5's JSON (`tokenFailure`), `port49 identity --json`.
- Produces (Tasks 8–10 rely on these names):

```python
# port49.errors
class Port49Error(Exception):          # .code: str, .detail: str, .device: str | None
class NotInstalled(Port49Error)        # code "not_installed"
class NoAgent(Port49Error)             # "no_agent", "agent_too_old"
class SessionOver(Port49Error)         # "session_over", "credential_revoked"
class Denied(Port49Error)              # a deny; .reason (a §5.7 code), .verdict
class MFARequired(Port49Error)         # "per_login_mfa_required"; .requirement: dict
class KeyUnavailable(Port49Error)      # "touch_timeout", "key_locked", "key_absent"
class BrokerRefused(Port49Error)       # "broker_refused"
class Temporary(Port49Error)           # "revocation_running", "connection_changed", workload exit 75; .results
class Final(Port49Error)               # workload exit 77 with no answer
class HostKeyError(Port49Error)        # Task 9

# port49.client
@dataclass(frozen=True)
class Token: device, address, platform, username, login (repr=False), enable (repr=False),
             expires_at, session_expires_at
@dataclass(frozen=True)
class Refusal: device, verdict, reason, error, detail, per_login_mfa
@dataclass
class MintResults: tokens: dict[str, Token]; refused: dict[str, Refusal]; def raise_for_refused(self) -> None
class Agent:
    def __init__(self, port49="port49", socket=None, attempts=3, timeout=None, stderr=None)
    def identity(self) -> dict
    def token(self, device: str, enable: bool = False, ttl: int | None = None) -> Token
    def tokens(self, devices, enable=False, ttl=None) -> MintResults

# port49._run
class Ran: code: int; stdout: bytes; stderr_tail: str
def run(argv, *, stdin=None, timeout=None, stderr=None) -> Ran
```

- [ ] **Step 1: Write the fake port49** `clients/python/tests/fakeport49.py`:

```python
"""A fake port49 for the library's tests: each run takes the next answer from
answers.json (stdout, stderr, code) and appends its argv to argv.jsonl."""

import json
import os
import stat
import sys

SCRIPT = """#!{python}
import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(d, "argv.jsonl"), "a", encoding="utf-8") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
with open(os.path.join(d, "answers.json"), encoding="utf-8") as f:
    answers = json.load(f)
n = sum(1 for _ in open(os.path.join(d, "argv.jsonl"), encoding="utf-8")) - 1
a = answers[min(n, len(answers) - 1)]
sys.stderr.write(a.get("stderr", ""))
sys.stdout.write(a.get("stdout", ""))
sys.exit(a.get("code", 0))
"""


def make(directory, answers):
    """A fake port49 in directory answering answers in turn, from the first; returns its path."""
    with open(os.path.join(directory, "answers.json"), "w", encoding="utf-8") as f:
        json.dump(answers, f)
    open(os.path.join(directory, "argv.jsonl"), "w").close()  # a new fake starts at its first answer
    path = os.path.join(directory, "port49")
    with open(path, "w", encoding="utf-8") as f:
        f.write(SCRIPT.format(python=sys.executable))
    os.chmod(path, stat.S_IRWXU)
    return path


def argvs(directory):
    """Every run's argv, in order."""
    with open(os.path.join(directory, "argv.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def item(**kw):
    """One JSON line, as port49 prints it."""
    return json.dumps(kw) + "\n"
```

- [ ] **Step 2: Write the failing tests** `clients/python/tests/test_agent.py`:

```python
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import fakeport49 as fake  # noqa: E402
from port49 import (Agent, BrokerRefused, Denied, KeyUnavailable, MFARequired, NoAgent,  # noqa: E402
                    NotInstalled, Port49Error, SessionOver, Temporary)

PERMIT = fake.item(device="leaf1", verdict="permit", address="10.0.0.11", platform="arista_eos",
                   username="alice", login="LOGINTOKEN", enable="ENABLETOKEN", expires_at="2026-10-13T10:00:00Z")


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.err = io.StringIO()
        self.slept = []

    def agent(self, *answers, **kw):
        a = Agent(port49=fake.make(self.dir, list(answers)), stderr=self.err, **kw)
        a._sleep = self.slept.append
        return a

    def test_a_token_through_the_cli(self):
        tok = self.agent({"stdout": PERMIT}).token("leaf1", enable=True, ttl=300)
        self.assertEqual((tok.address, tok.username, tok.login, tok.enable), ("10.0.0.11", "alice", "LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual(fake.argvs(self.dir), [["token", "--json", "--enable", "--ttl", "300s", "--", "leaf1"]])

    def test_a_deny_is_denied_with_its_reason(self):
        a = self.agent({"stdout": fake.item(device="leaf1", verdict="deny", reason="no_grants_matched", detail="d"), "code": 1})
        with self.assertRaises(Denied) as cm:
            a.token("leaf1")
        self.assertEqual((cm.exception.reason, cm.exception.device), ("no_grants_matched", "leaf1"))

    def test_each_code_is_its_class(self):
        for code, cls in [("no_agent", NoAgent), ("agent_too_old", NoAgent), ("session_over", SessionOver),
                          ("credential_revoked", SessionOver), ("per_login_mfa_required", MFARequired),
                          ("touch_timeout", KeyUnavailable), ("key_locked", KeyUnavailable),
                          ("key_absent", KeyUnavailable), ("broker_refused", BrokerRefused),
                          ("agent_error", Port49Error)]:
            a = self.agent({"stdout": fake.item(device="leaf1", error=code, detail="words"), "code": 1})
            with self.assertRaises(cls, msg=code) as cm:
                a.token("leaf1")
            self.assertEqual(cm.exception.code, code)

    def test_a_requirement_carries_what_it_accepts(self):
        a = self.agent({"stdout": fake.item(device="core1", error="per_login_mfa_required", detail="d",
                                            per_login_mfa={"accept": ["idp_mfa"], "reuse_for_seconds": 900}), "code": 1})
        with self.assertRaises(MFARequired) as cm:
            a.token("core1")
        self.assertEqual(cm.exception.requirement["accept"], ["idp_mfa"])
        self.assertIn("port49 token core1", str(cm.exception))

    def test_only_what_sent_nothing_is_retried(self):
        busy = {"stdout": fake.item(device="leaf1", error="revocation_running", detail="d"), "code": 1}
        tok = self.agent(busy, busy, {"stdout": PERMIT}).token("leaf1")
        self.assertEqual(tok.login, "LOGINTOKEN")
        self.assertEqual(self.slept, [1, 2])
        with self.assertRaises(Temporary):
            self.agent(busy, busy, busy, {"stdout": PERMIT}).token("leaf1")
        timeout = {"stdout": fake.item(device="leaf1", error="touch_timeout", detail="d"), "code": 1}
        with self.assertRaises(KeyUnavailable):
            self.agent(timeout, {"stdout": PERMIT}).token("leaf1")
        self.assertEqual(len(fake.argvs(self.dir)), 1)

    def test_tokens_collects_denies_and_stops_at_anything_else(self):
        deny = {"stdout": fake.item(device="leaf2", verdict="deny", reason="no_grants_matched"), "code": 1}
        res = self.agent({"stdout": PERMIT}, deny).tokens(["leaf1", "leaf2"])
        self.assertEqual((list(res.tokens), list(res.refused)), (["leaf1"], ["leaf2"]))
        self.assertEqual(res.refused["leaf2"].reason, "no_grants_matched")
        with self.assertRaises(Denied):
            res.raise_for_refused()
        with self.assertRaises(NoAgent):
            self.agent({"stdout": fake.item(device="leaf1", error="no_agent"), "code": 1}).tokens(["leaf1", "leaf2"])

    def test_stderr_reaches_the_person(self):
        self.agent({"stdout": PERMIT, "stderr": "port49: touch your key now\n"}).token("leaf1")
        self.assertIn("touch your key now", self.err.getvalue())

    def test_no_token_in_repr_errors_or_a_bad_answer(self):  # Review Focus 5
        tok = self.agent({"stdout": PERMIT}).token("leaf1")
        self.assertNotIn("LOGINTOKEN", repr(tok) + str(tok))
        self.assertNotIn("ENABLETOKEN", repr(tok) + str(tok))
        a = self.agent({"stdout": "LOGINTOKEN not json", "code": 0})
        with self.assertRaises(Port49Error) as cm:
            a.token("leaf1")
        self.assertNotIn("LOGINTOKEN", str(cm.exception) + repr(cm.exception.__dict__))
        a = self.agent({"stdout": fake.item(device="leaf1", verdict="permit", login=""), "code": 0})
        with self.assertRaises(Port49Error):
            a.token("leaf1")

    def test_a_flag_shaped_device_is_a_name(self):
        self.agent({"stdout": PERMIT}).token("--socket=/tmp/x")
        self.assertEqual(fake.argvs(self.dir)[0][-2:], ["--", "--socket=/tmp/x"])

    def test_no_port49(self):
        with self.assertRaises(NotInstalled):
            Agent(port49=os.path.join(self.dir, "none"), stderr=self.err).token("leaf1")

    def test_identity(self):
        a = self.agent({"stdout": '{"principal": "user:alice", "subjects": ["netops"]}\n'})
        self.assertEqual(a.identity()["principal"], "user:alice")
        self.assertEqual(fake.argvs(self.dir), [["identity", "--json"]])


if __name__ == "__main__":
    unittest.main()
```

  And `clients/python/tests/test_floor.py`:

```python
"""The floor is Python 3.10 (decision 46 ruling 14): every source parses as 3.10."""

import ast
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SOURCES = [os.path.join(ROOT, "python", "src", "port49"),
           os.path.join(ROOT, "ansible", "ansible_collections", "port49", "client", "plugins")]


class Floor(unittest.TestCase):
    def test_this_python_is_at_the_floor_or_later(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 10))

    def test_every_source_parses_as_3_10(self):
        n = 0
        for top in SOURCES:
            for d, _, files in os.walk(top):
                for name in files:
                    if name.endswith(".py"):
                        with open(os.path.join(d, name), encoding="utf-8") as f:
                            ast.parse(f.read(), filename=name, feature_version=(3, 10))
                        n += 1
        self.assertGreater(n, 0)
```

- [ ] **Step 3: Add the Makefile target** and run the tests to see them fail:

```make
# The Python library and the Ansible lookup (plan 9d), stdlib unittest. A
# missing python3 fails it: make test runs it (decision 46 ruling 14).
PYTHON ?= python3

test-python:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s clients/python/tests -v
	@if [ -d clients/ansible/ansible_collections/port49/client/tests/unit ]; then \
	  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=clients/python/src:clients/ansible $(PYTHON) -m unittest discover \
	    -s clients/ansible/ansible_collections/port49/client/tests/unit -v; fi
```

  `test:` becomes `test: lab-unit test-python`; add `test-python` to `.PHONY`.

Run: `make test-python`
Expected: FAIL (`ModuleNotFoundError: No module named 'port49'`).

- [ ] **Step 4: Implement.** `clients/python/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "port49"
version = "0.1.0"
description = "port49 device tokens for Python: identity, mint, sweep, retry, and Netmiko over the port49 CLI"
license = "Apache-2.0"
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
netmiko = ["netmiko>=4.7"]

[tool.setuptools.packages.find]
where = ["src"]
```

  `src/port49/_run.py`:

```python
"""Running the port49 CLI (decision 46 rulings 8 and 12).

stdout is read whole and never logged: on success it holds a token. stderr is
the person's: it is written to the caller's stderr as it comes, a byte at a
time if need be, so "touch your key now" or a sign-in prompt with no newline
is seen at once; its last 2 KiB are kept for an error's words."""

import os
import subprocess
import sys
import threading

from .errors import NotInstalled, Port49Error

TAIL = 2048


class Ran:
    __slots__ = ("code", "stdout", "stderr_tail")

    def __init__(self, code, stdout, stderr_tail):
        self.code, self.stdout, self.stderr_tail = code, stdout, stderr_tail

    def __repr__(self):
        return f"Ran(code={self.code})"  # never stdout


def printable(text, limit=512):
    """text with control characters but newline made '?', at most limit characters."""
    return "".join(c if c == "\n" or (c.isprintable()) else "?" for c in text)[:limit]


def run(argv, *, stdin=None, timeout=None, stderr=None):
    out = stderr if stderr is not None else sys.stderr
    try:
        p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise NotInstalled("not_installed", f"{argv[0]} is not on PATH: install port49, or pass port49=<path>") from None
    tail = bytearray()
    chunks = []

    def pump():
        while True:
            chunk = os.read(p.stderr.fileno(), 4096)
            if not chunk:
                return
            try:
                out.write(chunk.decode("utf-8", "replace"))
                out.flush()
            except (OSError, ValueError):
                pass
            tail.extend(chunk)
            del tail[:-TAIL]

    def drain():
        chunks.append(p.stdout.read())

    threads = [threading.Thread(target=pump, daemon=True), threading.Thread(target=drain, daemon=True)]
    for t in threads:
        t.start()
    try:
        code = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        raise Port49Error("timeout", f"{argv[0]} {argv[1]} did not finish within {timeout}s and was ended") from None
    for t in threads:
        t.join()
    return Ran(code, b"".join(chunks), printable(tail.decode("utf-8", "replace"), TAIL))
```

  `src/port49/errors.py`:

```python
"""The library's exceptions (decision 46 ruling 11). None carries a token or
the CLI's stdout: only the CLI's code, its printable detail, and the device."""


class Port49Error(Exception):
    def __init__(self, code, detail="", device=None):
        self.code, self.detail, self.device = code, detail, device
        super().__init__(str(self))

    def __str__(self):
        where = f"{self.device}: " if self.device else ""
        return f"port49: {where}{self.detail or self.code}"


class NotInstalled(Port49Error):
    """The port49 CLI is not there."""


class NoAgent(Port49Error):
    """No agent answers (no_agent), or it predates this port49 (agent_too_old): run port49 login."""


class SessionOver(Port49Error):
    """The agent's session ended (session_over) or was revoked (credential_revoked)."""


class Denied(Port49Error):
    """The broker denied the device; reason is its §5.7 code."""

    def __init__(self, code, detail="", device=None, reason=None, verdict=None):
        self.reason, self.verdict = reason, verdict
        super().__init__(code, detail, device)

    def __str__(self):
        said = f"port49: {self.device}: {self.verdict or 'deny'} {self.reason or self.code}"
        return said + (f": {self.detail}" if self.detail else "")


class MFARequired(Port49Error):
    """The device asks for a second factor that could not be given here."""

    def __init__(self, code, detail="", device=None, requirement=None):
        self.requirement = requirement or {}
        super().__init__(code, detail, device)

    def __str__(self):
        accept = ", ".join(self.requirement.get("accept", [])) or "a second factor"
        return (f"port49: {self.device}: asks for {accept} at each login, and it could not be given here "
                f"({self.detail or self.code}); run `port49 token {self.device}` at a terminal, and one proof "
                f"covers this agent's further logins for its reuse_for")


class KeyUnavailable(Port49Error):
    """The key timed out waiting for a touch, is locked, or is gone."""


class BrokerRefused(Port49Error):
    """The broker's certificate was refused (its CRL)."""


class Temporary(Port49Error):
    """Nothing was sent to mint with, or the broker could not answer by the deadline: run again."""

    def __init__(self, code, detail="", device=None, results=None):
        self.results = results
        super().__init__(code, detail, device)


class Final(Port49Error):
    """A workload run that cannot mint until someone acts (exit 77 with no answer)."""


class HostKeyError(Port49Error):
    """A host key that is not the one filed for the device, or that cannot be checked."""
```

  `src/port49/client.py` (the `Agent` half; Task 8 adds `Workload`):

```python
"""Identity, mint, sweep and retry over the port49 CLI (design §17; decision 46)."""

import json
import time
from dataclasses import dataclass, field

from . import _run
from .errors import (BrokerRefused, Denied, KeyUnavailable, MFARequired, NoAgent, Port49Error, SessionOver,
                     Temporary)

# The CLI's codes (spec §12) to their classes; any other is a Port49Error.
CLASSES = {
    "no_agent": NoAgent, "agent_too_old": NoAgent,
    "session_over": SessionOver, "credential_revoked": SessionOver,
    "per_login_mfa_required": MFARequired,
    "touch_timeout": KeyUnavailable, "key_locked": KeyUnavailable, "key_absent": KeyUnavailable,
    "broker_refused": BrokerRefused,
    "revocation_running": Temporary, "connection_changed": Temporary,
}

# The codes the CLI answers having sent nothing to mint with: the only ones retried.
RETRIED = {"revocation_running", "connection_changed"}


@dataclass(frozen=True)
class Token:
    device: str
    address: str
    platform: str
    username: str
    login: str = field(repr=False)
    enable: "str | None" = field(default=None, repr=False)
    expires_at: "str | None" = None
    session_expires_at: "str | None" = None

    @classmethod
    def of(cls, item):
        return cls(item["device"], item.get("address", ""), item.get("platform", ""), item.get("username", ""),
                   item["login"], item.get("enable") or None, item.get("expires_at"), item.get("session_expires_at"))


@dataclass(frozen=True)
class Refusal:
    device: str
    verdict: "str | None"
    reason: "str | None"
    error: "str | None"
    detail: str
    per_login_mfa: "dict | None" = None

    def exception(self):
        return error_for({"device": self.device, "verdict": self.verdict, "reason": self.reason,
                          "error": self.error, "detail": self.detail, "per_login_mfa": self.per_login_mfa})


@dataclass
class MintResults:
    tokens: dict
    refused: dict

    def raise_for_refused(self):
        for r in self.refused.values():
            raise r.exception()


def answer(ran):
    """The one JSON object the CLI printed, or None. Never quoted in an error: it may hold a token."""
    try:
        obj = json.loads(ran.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def error_for(obj, device=None):
    device = obj.get("device") or device
    detail = _run.printable(obj.get("detail") or "")
    verdict = obj.get("verdict")
    if verdict and verdict != "permit":
        return Denied(obj.get("reason") or verdict, detail, device, reason=obj.get("reason"), verdict=verdict)
    code = obj.get("error") or "agent_error"
    cls = CLASSES.get(code, Port49Error)
    if cls is MFARequired:
        return MFARequired(code, detail, device, requirement=obj.get("per_login_mfa"))
    return cls(code, detail, device)


def failed(ran, device, what):
    """The error for a run that printed no answer."""
    words = ran.stderr_tail.strip().splitlines()
    return Port49Error(f"exit_{ran.code}", words[-1] if words else f"{what} exited {ran.code}", device)


class Agent:
    """A person's tokens, through the agent `port49 login` started."""

    def __init__(self, port49="port49", socket=None, attempts=3, timeout=None, stderr=None):
        self.port49, self.socket, self.attempts, self.timeout, self.stderr = port49, socket, attempts, timeout, stderr
        self._sleep = time.sleep

    def _argv(self, *args):
        argv = [self.port49, *args]
        if self.socket:
            argv[2:2] = ["--socket", self.socket]
        return argv

    def identity(self):
        ran = _run.run(self._argv("identity", "--json"), timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if ran.code != 0 or obj is None:
            raise failed(ran, None, "port49 identity")
        return obj

    def token(self, device, enable=False, ttl=None):
        args = ["token", "--json"] + (["--enable"] if enable else []) + (["--ttl", f"{int(ttl)}s"] if ttl else [])
        argv = self._argv(*args) + ["--", device]
        for attempt in range(self.attempts):
            ran = _run.run(argv, timeout=self.timeout, stderr=self.stderr)
            obj = answer(ran)
            if ran.code == 0 and obj and obj.get("verdict") == "permit" and obj.get("login"):
                return Token.of(obj)
            if obj is None or ran.code == 0:
                raise failed(ran, device, "port49 token")
            err = error_for(obj, device)
            if err.code not in RETRIED or attempt + 1 == self.attempts:
                raise err
            self._sleep(2 ** attempt)
        raise AssertionError("unreachable")

    def tokens(self, devices, enable=False, ttl=None):
        """One mint per device, in turn. A deny is collected; anything else stops the run."""
        res = MintResults({}, {})
        for d in devices:
            try:
                res.tokens[d] = self.token(d, enable, ttl)
            except Denied as e:
                res.refused[d] = Refusal(d, e.verdict, e.reason, None, e.detail)
        return res
```

  (`_argv` puts `--socket` after the subcommand pair, `port49 token --socket S …`, as the CLI parses
  flags per subcommand; the fake-CLI test without a socket checks the exact argv.)
  `src/port49/__init__.py` exports `Agent`, `Workload` (Task 8), `Token`, `Refusal`, `MintResults`
  and every exception class. `clients/python/README.md`: install (`pip install ./clients/python`,
  `[netmiko]` for Netmiko), the `Agent` example, the exception table (code → class → what to do),
  what is retried and why, and "the token is never in argv, the environment, a log or a `repr`".
- [ ] **Step 5: Run the tests to see them pass**

Run: `make test-python`
Expected: PASS (`test_agent`, `test_floor`).

- [ ] **Step 6: Commit**

```bash
git add clients/python Makefile
git commit -m "feat: the Python library over the port49 CLI: Agent, typed errors, retry of what sent nothing

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: The Python library — `Workload` (identity, mint by name or scope)

**Files:**
- Modify: `clients/python/src/port49/client.py` (`Workload`), `clients/python/src/port49/__init__.py`,
  `clients/python/README.md`
- Create: `clients/python/tests/test_workload.py`

**Interfaces:**
- Consumes: Task 6's `workloadJSON` and `refusedItem`; Task 7's `Token`, `Refusal`, `MintResults`,
  `Temporary`, `Final`, `failed`, `answer`.
- Produces:

```python
class Workload:
    def __init__(self, broker, broker_ca, cert, key, touch_key=None, broker_crl=None, port49="port49",
                 deadline=None, timeout=None, stderr=None)
    def identity(self) -> dict
    def tokens(self, devices=None, scope=None, enable=False, ttl=None, purpose=None) -> MintResults
```

- [ ] **Step 1: Write the failing tests** `clients/python/tests/test_workload.py`:

```python
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import fakeport49 as fake  # noqa: E402
from port49 import Final, Port49Error, Temporary, Workload  # noqa: E402

MINTED = {"principal": "spiffe://corp/oxidized", "results": [
    {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
     "username": "svc", "login": "LOGINTOKEN", "expires_at": "2026-10-13T10:00:00Z"}],
    "refused": [{"device": "leaf2", "verdict": "deny", "reason": "no_grants_matched"},
                {"device": "core1", "verdict": "deny", "reason": "per_login_mfa_required",
                 "per_login_mfa": {"accept": ["hardware_key_touch"], "reuse_for_seconds": 900}}]}


class WorkloadTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.err = io.StringIO()

    def workload(self, *answers, **kw):
        return Workload("https://broker:8443", "/ca.pem", "/w.pem", "/w.key", port49=fake.make(self.dir, list(answers)),
                        stderr=self.err, **kw)

    def test_devices_go_in_a_file_and_results_come_back_per_item(self):
        res = self.workload({"stdout": json.dumps(MINTED), "code": 1}).tokens(["leaf1", "leaf2", "core1"], purpose="backup")
        self.assertEqual(res.tokens["leaf1"].login, "LOGINTOKEN")
        self.assertEqual(res.refused["leaf2"].reason, "no_grants_matched")
        self.assertEqual(res.refused["core1"].per_login_mfa["accept"], ["hardware_key_touch"])
        argv = fake.argvs(self.dir)[0]
        self.assertEqual(argv[:2], ["workload", "token"])
        self.assertIn("--devices-file", argv)
        self.assertEqual(argv[argv.index("--format") + 1], "json")
        self.assertNotIn("leaf1", argv)  # names travel in the file, never a flag

    def test_a_scope(self):
        self.workload({"stdout": json.dumps(MINTED)}).tokens(scope="core")
        argv = fake.argvs(self.dir)[0]
        self.assertEqual(argv[argv.index("--scope") + 1], "core")

    def test_every_device_denied_is_results_not_an_exception(self):
        res = self.workload({"stdout": json.dumps({"results": [], "refused": MINTED["refused"]}), "code": 77}).tokens(["leaf2"])
        self.assertEqual((res.tokens, len(res.refused)), ({}, 2))

    def test_a_scope_selecting_nothing_is_empty(self):
        res = self.workload({"stdout": json.dumps({"results": [], "refused": []}), "code": 77}).tokens(scope="none")
        self.assertEqual((res.tokens, res.refused), ({}, {}))

    def test_75_is_temporary_with_what_was_minted(self):
        with self.assertRaises(Temporary) as cm:
            self.workload({"stdout": json.dumps(MINTED), "code": 75}).tokens(["leaf1", "leaf9"])
        self.assertIn("leaf1", cm.exception.results.tokens)
        self.assertEqual(len(fake.argvs(self.dir)), 1)  # never rerun: a rerun mints again

    def test_77_with_no_answer_is_final(self):
        with self.assertRaises(Final) as cm:
            self.workload({"stderr": "port49 workload token: the certificate expired at …\n", "code": 77}).tokens(["leaf1"])
        self.assertIn("certificate expired", str(cm.exception))

    def test_flags_reach_the_cli(self):
        self.workload({"stdout": json.dumps(MINTED)}, touch_key="pkcs11:id=%02", deadline=120, broker_crl="require"
                      ).tokens(["leaf1"], enable=True, ttl=600)
        argv = fake.argvs(self.dir)[0]
        for flag, value in [("--touch-key", "pkcs11:id=%02"), ("--deadline", "120s"), ("--broker-crl", "require"),
                            ("--ttl", "600s")]:
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--enable", argv)

    def test_no_token_in_errors(self):
        with self.assertRaises(Port49Error) as cm:
            self.workload({"stdout": "LOGINTOKEN{", "code": 0}).tokens(["leaf1"])
        self.assertNotIn("LOGINTOKEN", str(cm.exception))
```

- [ ] **Step 2: Run them to see them fail**

Run: `make test-python`
Expected: FAIL (`ImportError: cannot import name 'Workload'`).

- [ ] **Step 3: Implement** in `client.py`:

```python
import os
import subprocess
import tempfile


class Workload:
    """A machine's tokens: `port49 workload token`, which reads the certificate and key at every run
    (design §17). The CLI pages, retries within deadline under one Idempotency-Key per page, checks the
    broker's CRL and proves a touch with touch_key; this never reruns it (decision 46 ruling 11)."""

    def __init__(self, broker, broker_ca, cert, key, touch_key=None, broker_crl=None, port49="port49",
                 deadline=None, timeout=None, stderr=None):
        self.port49, self.timeout, self.stderr = port49, timeout, stderr
        self.flags = ["--broker", broker, "--broker-ca", broker_ca, "--cert", cert, "--key", key]
        if touch_key:
            self.flags += ["--touch-key", touch_key]
        if broker_crl:
            self.flags += ["--broker-crl", broker_crl]
        if deadline:
            self.flags += ["--deadline", f"{int(deadline)}s"]

    def identity(self):
        ran = _run.run([self.port49, "workload", "identity", *self.flags, "--json"], stdin=subprocess.DEVNULL,
                       timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if ran.code != 0 or obj is None:
            raise (Temporary if ran.code == 75 else Final if ran.code == 77 else Port49Error)(
                *_words(failed(ran, None, "port49 workload identity")))
        return obj

    def tokens(self, devices=None, scope=None, enable=False, ttl=None, purpose=None):
        if (devices is None) == (scope is None):
            raise ValueError("name devices or a scope, not both")
        argv = [self.port49, "workload", "token", *self.flags, "--format", "json"]
        argv += (["--enable"] if enable else []) + (["--ttl", f"{int(ttl)}s"] if ttl else [])
        argv += ["--purpose", purpose] if purpose else []
        with tempfile.TemporaryDirectory(prefix="port49-") as tmp:
            if scope is not None:
                argv += ["--scope", scope]
            else:
                path = os.path.join(tmp, "devices")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("".join(d + "\n" for d in devices))
                argv += ["--devices-file", path]
            ran = _run.run(argv, stdin=subprocess.DEVNULL, timeout=self.timeout, stderr=self.stderr)
        obj = answer(ran)
        if obj is None:
            err = failed(ran, None, "port49 workload token")
            if ran.code == 75:
                raise Temporary(*_words(err))
            if ran.code == 77:
                raise Final(*_words(err))
            raise err
        res = MintResults(
            {it["device"]: Token.of(it) for it in obj.get("results", []) if it.get("login")},
            {r["device"]: Refusal(r["device"], r.get("verdict"), r.get("reason"), r.get("error"),
                                  _run.printable(r.get("detail") or ""), r.get("per_login_mfa"))
             for r in obj.get("refused", [])})
        if ran.code == 75:
            raise Temporary("exit_75", "the broker did not answer every device by the deadline; what was minted "
                            "is in .results; run again for the rest", None, results=res)
        return res


def _words(err):
    return err.code, err.detail, err.device
```

  `__init__.py` exports `Workload`. The README gains the `Workload` example (`Workload(broker=…,
  broker_ca=…, cert=…, key=…).tokens(scope="backup")`), and says a scope selecting nothing returns
  empty results, 75 is `Temporary` with what was minted, and the library never reruns a run.
- [ ] **Step 4: Run the tests to see them pass**

Run: `make test-python`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clients/python
git commit -m "feat: the Python library's Workload: identity and mint by name or scope over the CLI

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Python host keys and `port49.netmiko.connect` — accept-new under the inventory name

**Files:**
- Create: `clients/python/src/port49/hostkeys.py`, `clients/python/src/port49/netmiko.py`
- Create: `clients/python/tests/test_hostkeys.py`, `clients/python/tests/test_netmiko.py`
- Modify: `examples/netmiko/README.md`; replace `examples/netmiko/port49_netmiko.py` with
  `examples/netmiko/show_version.py`; delete `examples/netmiko/test_port49_netmiko.py` and
  `examples/netmiko/example_test.go`
- Modify: `clients/python/README.md` (host keys)

**Interfaces:**
- Consumes: Task 7's `Agent`, `Token`, `HostKeyError`; OpenSSH's `ssh -G` and `ssh-keygen -F`.
- Produces:

```python
# port49.hostkeys
@dataclass(frozen=True)
class KnownHosts:
    name: str                 # the name keys are filed under: the operator's alias, else the device lowercased
    keys: tuple               # ("ssh-ed25519 AAAA…", …): every plain key filed under name
    markers: tuple            # "@cert-authority …" / "@revoked …" lines matching name
    strict: bool              # the operator's StrictHostKeyChecking is yes
    hash_names: bool          # HashKnownHosts yes
    write_to: str             # the first UserKnownHostsFile
def lookup(device, address, *, port=22, ssh_config=None, ssh="ssh", ssh_keygen="ssh-keygen") -> KnownHosts
def remember(kh: KnownHosts, keytype: str, key_b64: str, stderr=None) -> None
def hashed(name: str, salt: bytes | None = None) -> str

# port49.netmiko
DEVICE_TYPES = {"arista_eos": "arista_eos", "cisco_nxos": "cisco_nxos", "cisco_iosxe": "cisco_xe",
                "juniper_junos": "juniper_junos"}
def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs)
```

- [ ] **Step 1: Write the failing tests.** `clients/python/tests/test_hostkeys.py` (the real `ssh`
  and `ssh-keygen`; skipped when either is missing):

```python
import base64
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from port49 import hostkeys  # noqa: E402

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs OpenSSH's ssh and ssh-keygen")
class HostKeysTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.kh = os.path.join(self.dir, "known_hosts")
        open(self.kh, "w").close()

    def config(self, *lines):
        path = os.path.join(self.dir, "ssh_config")
        with open(path, "w", encoding="ascii") as f:
            f.write("\n".join([f"UserKnownHostsFile {self.kh}", "GlobalKnownHostsFile /dev/null", *lines]) + "\n")
        return path

    def test_nothing_known(self):
        kh = hostkeys.lookup("Leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.name, kh.keys, kh.markers, kh.strict, kh.write_to), ("leaf1", (), (), False, self.kh))

    def test_a_key_filed_under_the_name_plain_or_hashed(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"{hostkeys.hashed('leaf1')} {ED}\nspine1 {ED}\n")
        kh = hostkeys.lookup("LEAF1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual(kh.keys, (ED,))

    def test_the_operators_alias_and_strict_yes(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"corp-leaf1 {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11",
                             ssh_config=self.config("StrictHostKeyChecking yes", "Host leaf1", "  HostKeyAlias corp-leaf1"))
        self.assertEqual((kh.name, kh.keys, kh.strict), ("corp-leaf1", (ED,), True))

    def test_a_marker_line_is_kept_apart(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"@cert-authority leaf* {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.keys, len(kh.markers)), ((), 1))

    def test_remember_files_under_the_name_hashed_when_asked(self):
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("HashKnownHosts yes"))
        hostkeys.remember(kh, "ssh-ed25519", ED.split()[1], stderr=open(os.devnull, "w"))
        with open(self.kh, encoding="ascii") as f:
            line = f.read()
        self.assertTrue(line.startswith("|1|"))
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config()).keys, (ED,))
        found = subprocess.run(["ssh-keygen", "-F", "leaf1", "-f", self.kh], capture_output=True, text=True).stdout
        self.assertIn(ED.split()[1], found)

    def test_concurrent_first_contacts_write_whole_lines(self):  # Review Focus 4
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        null = open(os.devnull, "w")
        threads = [threading.Thread(target=hostkeys.remember, args=(kh, "ssh-ed25519", ED.split()[1], null))
                   for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        with open(self.kh, encoding="ascii") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 20)
        self.assertTrue(all(line == f"leaf1 {ED}" for line in lines))

    def test_hashed_is_openssh_form(self):
        salt = b"\x01" * 20
        want = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(
            hmac.new(salt, b"leaf1", hashlib.sha1).digest()).decode()
        self.assertEqual(hostkeys.hashed("leaf1", salt), want)
```

  `clients/python/tests/test_netmiko.py` (a fake `netmiko`; host keys through `hostkeys.lookup`
  patched to return a chosen `KnownHosts`, so it runs with neither Netmiko nor OpenSSH):

```python
import io
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

captured = {}
NEXT_ERROR = []  # what the next connection raises, as Paramiko would
PRESENTED = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")


class BadHostKeyException(Exception):
    pass


class FakeConnection:
    def __init__(self, **kw):
        captured.clear()
        captured.update(kw)
        with open(kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(kw["alt_key_file"]).st_mode)
        if NEXT_ERROR:
            raise NEXT_ERROR.pop()
        key = types.SimpleNamespace(get_name=lambda: PRESENTED[0], get_base64=lambda: PRESENTED[1])
        transport = types.SimpleNamespace(get_remote_server_key=lambda: key)
        self.remote_conn_pre = types.SimpleNamespace(get_transport=lambda: transport)


sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=lambda **kw: FakeConnection(**kw))

from port49 import HostKeyError, Token, hostkeys  # noqa: E402
from port49 import netmiko as p49netmiko  # noqa: E402

TOKEN = Token("leaf1", "10.0.0.11", "arista_eos", "alice", "LOGINTOKEN", "ENABLETOKEN")


class FakeAgent:
    def __init__(self, token=TOKEN):
        self.token_ = token
        self.asked = []

    def token(self, device, enable=False, ttl=None):
        self.asked.append((device, enable))
        return self.token_


def known(*keys, markers=(), strict=False):
    return hostkeys.KnownHosts("leaf1", tuple(keys), tuple(markers), strict, False, "/dev/null")


class NetmikoTest(unittest.TestCase):
    def connect(self, kh, **kw):
        remembered = []
        with mock.patch.object(hostkeys, "lookup", return_value=kh), \
                mock.patch.object(hostkeys, "remember", side_effect=lambda k, t, b, stderr=None: remembered.append((k.name, t, b))):
            conn = p49netmiko.connect("leaf1", agent=FakeAgent(), **kw)
        return conn, remembered

    def test_a_known_key_is_the_only_key(self):
        _, remembered = self.connect(known("ssh-ed25519 AAAA1"))
        self.assertTrue(captured["ssh_strict"])
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-ed25519 AAAA1\n")
        self.assertEqual(captured["mode"], 0o600)
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        self.assertFalse(captured["system_host_keys"] or captured["use_keys"] or captured["allow_agent"])
        self.assertEqual((captured["username"], captured["password"], captured["secret"]), ("alice", "LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual(remembered, [])

    def test_a_first_contact_is_accepted_and_filed_under_the_name(self):
        _, remembered = self.connect(known())
        self.assertFalse(captured["ssh_strict"])
        self.assertEqual(captured["known_hosts"], "")
        self.assertEqual(remembered, [("leaf1", PRESENTED[0], PRESENTED[1])])

    def test_another_port_is_filed_in_brackets_for_paramiko(self):
        self.connect(known("ssh-ed25519 AAAA1"), port=2222)
        self.assertEqual(captured["known_hosts"], "[10.0.0.11]:2222 ssh-ed25519 AAAA1\n")

    def test_a_key_of_another_type_under_a_known_name_is_refused(self):  # Review Focus 1
        # Under ssh_strict, holding only the filed RSA key, Paramiko refuses an Ed25519 one as unknown.
        NEXT_ERROR.append(Exception("Server '10.0.0.11' not found in known_hosts"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-rsa AAAAB3"))
        self.assertTrue(captured["ssh_strict"])
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-rsa AAAAB3\n")
        self.assertIn("ssh-keygen -R leaf1", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_an_address_moved_to_another_host_is_refused(self):  # Review Focus 2
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAA9'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-ed25519 AAAA1"))
        self.assertIn("is not the one 10.0.0.11 presents", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_a_certificate_authority_alone_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(markers=("@cert-authority leaf* ssh-ed25519 AAAA",)))
        self.assertEqual(captured, {})
        self.assertIn("cannot check", str(cm.exception))

    def test_strict_yes_with_nothing_known_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError):
            self.connect(known(strict=True))
        self.assertEqual(captured, {})

    def test_the_security_options_cannot_be_overridden(self):
        with self.assertRaises(ValueError):
            self.connect(known("ssh-ed25519 AAAA1"), ssh_strict=False)
```

  Note on the impostor tests: Paramiko, holding only the filed key for the address under
  `ssh_strict=True`, raises `BadHostKeyException` for a different key of the same type and
  `SSHException("Server … not found in known_hosts")` for a key of another type; the fake raises
  each in turn, and `is_host_key_failure` (Step 3) recognises both by type name and message.
  L65 (c) and (d) measure both against devices.

- [ ] **Step 2: Run them to see them fail**

Run: `make test-python`
Expected: FAIL (`cannot import name 'hostkeys'`).

- [ ] **Step 3: Implement** `src/port49/hostkeys.py`:

```python
"""Host keys for the Python client (decision 46 ruling 13): OpenSSH's own
files and settings, read through OpenSSH's own tools, and accept-new under
the device's inventory name, the name `port49 ssh` files keys under.

`ssh -G` reads the operator's ssh_config as ssh would; `ssh-keygen -F` finds
the lines filed under a name, hashed or not, patterns included. Nothing here
parses ssh_config or matches known_hosts patterns itself."""

import base64
import hashlib
import hmac
import os
import subprocess
import sys
from dataclasses import dataclass

from .errors import HostKeyError


@dataclass(frozen=True)
class KnownHosts:
    name: str
    keys: tuple
    markers: tuple
    strict: bool
    hash_names: bool
    write_to: str


def _ssh_g(device, address, port, ssh_config, ssh):
    argv = [ssh, "-G"] + (["-F", ssh_config] if ssh_config else []) + ["-o", f"HostName={address}"]
    argv += (["-p", str(port)] if port and port != 22 else []) + ["--", device]
    try:
        out = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise HostKeyError("ssh_config_unread", f"{ssh} -G could not read your ssh_config: {e}", device) from None
    conf = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        conf[k] = v
    return conf


def lookup(device, address, *, port=22, ssh_config=None, ssh="ssh", ssh_keygen="ssh-keygen"):
    conf = _ssh_g(device, address, port, ssh_config, ssh)
    name = conf.get("hostkeyalias") or device.lower()
    files = conf.get("userknownhostsfile", "").split() + conf.get("globalknownhostsfile", "").split()
    keys, markers = [], []
    for path in files:
        if not os.path.isfile(path):
            continue
        r = subprocess.run([ssh_keygen, "-F", name, "-f", path], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=10)
        if r.returncode not in (0, 1):
            raise HostKeyError("known_hosts_unread", f"{ssh_keygen} -F {name} -f {path}: {r.stderr.strip()}", device)
        for line in r.stdout.splitlines():
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):
                markers.append(line)
                continue
            fields = line.split()
            if len(fields) >= 3:
                keys.append(f"{fields[1]} {fields[2]}")
    user = conf.get("userknownhostsfile", "").split()
    return KnownHosts(name, tuple(dict.fromkeys(keys)), tuple(markers),
                      conf.get("stricthostkeychecking") in ("true", "yes"), conf.get("hashknownhosts") == "yes",
                      user[0] if user else os.path.expanduser("~/.ssh/known_hosts"))


def hashed(name, salt=None):
    """name as OpenSSH's HashKnownHosts writes it: |1|base64(salt)|base64(HMAC-SHA1(salt, name))."""
    salt = salt if salt is not None else os.urandom(20)
    mac = hmac.new(salt, name.encode("utf-8"), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(mac).decode()}"


def remember(kh, keytype, key_b64, stderr=None):
    """File a first contact's key under kh.name: one O_APPEND write of one whole line, as ssh does, so
    concurrent first contacts never interleave. Said on stderr as OpenSSH says it."""
    host = hashed(kh.name) if kh.hash_names else kh.name
    line = f"{host} {keytype} {key_b64}\n".encode("ascii")
    os.makedirs(os.path.dirname(kh.write_to), mode=0o700, exist_ok=True)
    fd = os.open(kh.write_to, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    print(f"port49: permanently added '{kh.name}' ({keytype}) to {kh.write_to}", file=stderr or sys.stderr)
```

  `src/port49/netmiko.py`:

```python
"""Netmiko through port49 (design §17; decision 46 rulings 13 and 16).

The token comes from your agent through `port49 token --json`; the device's key
is OpenSSH's known_hosts entry under its inventory name: the only key accepted
once filed, and filed at first contact. The token is never printed."""

import os
import shutil
import sys
import tempfile

from . import hostkeys
from .client import Agent
from .errors import HostKeyError

DEVICE_TYPES = {"arista_eos": "arista_eos", "cisco_nxos": "cisco_nxos", "cisco_iosxe": "cisco_xe",
                "juniper_junos": "juniper_junos"}

# What connect sets and a caller may not: host keys, and no key offered (L51: every refused key counts
# against the device's login-attempt limit).
OWNED = {"ssh_strict", "system_host_keys", "alt_host_keys", "alt_key_file", "use_keys", "allow_agent", "host",
         "username", "password", "secret", "device_type"}


def is_host_key_failure(exc):
    """Whether exc, or what it wraps, is Paramiko refusing the host key: BadHostKeyException (a changed
    key), or an SSHException saying the server is not in known_hosts (a key of another type under
    ssh_strict). Netmiko may wrap either, so the chain is walked."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        text = str(exc)
        if type(exc).__name__ == "BadHostKeyException" or ("Host key for server" in text and "does not match" in text) \
                or "not found in known_hosts" in text:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs):
    from netmiko import ConnectHandler

    owned = OWNED & set(netmiko_kwargs)
    if owned:
        raise ValueError(f"port49.netmiko.connect sets {', '.join(sorted(owned))} itself")
    tok = (agent or Agent()).token(device, enable=enable)
    device_type = DEVICE_TYPES.get(tok.platform)
    if device_type is None:
        raise ValueError(f"{device}: platform {tok.platform!r} has no Netmiko device type here")
    port = int(netmiko_kwargs.get("port", 22))
    kh = hostkeys.lookup(device, tok.address, port=port, ssh_config=ssh_config)
    if not kh.keys and kh.markers:
        raise HostKeyError("host_key_uncheckable", f"a {kh.markers[0].split()[0]} line in your known_hosts covers "
                           f"{kh.name}, and Paramiko cannot check a host certificate or a revocation: file the "
                           f"device's own key under {kh.name}, or use port49 ssh", device)
    if not kh.keys and kh.strict:
        raise HostKeyError("host_key_unknown", f"no key is filed under {kh.name} and your ssh_config says "
                           f"StrictHostKeyChecking yes", device)
    field = tok.address if port == 22 else f"[{tok.address}]:{port}"
    tmp = tempfile.mkdtemp(prefix="port49-")  # 0700; the file inside is 0600
    try:
        known = os.path.join(tmp, "known_hosts")
        fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write("".join(f"{field} {k}\n" for k in kh.keys))
        try:
            conn = ConnectHandler(device_type=device_type, host=tok.address, username=tok.username,
                                  password=tok.login, secret=tok.enable or "",
                                  ssh_strict=bool(kh.keys), system_host_keys=False, alt_host_keys=True,
                                  alt_key_file=known, use_keys=False, allow_agent=False, **netmiko_kwargs)
        except Exception as e:
            if is_host_key_failure(e):
                raise HostKeyError("host_key_changed", f"the key filed under {kh.name} is not the one {tok.address} "
                                   f"presents: either the device's key changed, or the address is not the device. "
                                   f"Verify the key on its console, then run 'ssh-keygen -R {kh.name}'", device) from None
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not kh.keys:
        key = conn.remote_conn_pre.get_transport().get_remote_server_key()
        hostkeys.remember(kh, key.get_name(), key.get_base64(), stderr=sys.stderr)
    return conn
```

  (`from None` drops Paramiko's text, which names the address but never the token; the token is in
  no exception here, since Paramiko never puts a password in one.) `examples/netmiko/show_version.py`:

```python
"""port49 and Netmiko: `python3 show_version.py leaf1` (after `port49 login`)."""

import sys

from port49.netmiko import connect

conn = connect(sys.argv[1])
try:
    print(conn.send_command("show version"))
finally:
    conn.disconnect()
```

  `examples/netmiko/README.md` becomes: install (`pip install './clients/python[netmiko]'`), run,
  and what happens to host keys (accept-new under the inventory name in your known_hosts, shared
  with `port49 ssh`; a changed key refused before the token is sent; `@cert-authority` not
  checkable by Paramiko), with 9a's note on Paramiko presenting the token a second time by
  `keyboard-interactive` kept.

- [ ] **Step 4: Run the tests to see them pass**

Run: `make test-python && go test ./examples/... -count=1`
Expected: PASS (`examples/netmiko` has no Go test any more; `examples/oxidized` passes).

- [ ] **Step 5: Commit**

```bash
git add -A clients/python examples/netmiko
git commit -m "feat: Python host keys under the inventory name, and port49.netmiko.connect

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: The Ansible lookup `port49.client.token`

**Files:**
- Create: `clients/ansible/ansible_collections/port49/client/galaxy.yml`,
  `clients/ansible/ansible_collections/port49/client/meta/runtime.yml`,
  `clients/ansible/ansible_collections/port49/client/README.md`,
  `clients/ansible/ansible_collections/port49/client/plugins/lookup/token.py`,
  `clients/ansible/ansible_collections/port49/client/tests/unit/test_token.py`

**Interfaces:**
- Consumes: Tasks 7 and 8's `Agent`, `Workload`, `Token`, `Port49Error`.
- Produces: `lookup('port49.client.token', DEVICE..., field=…, enable=…, ttl=…, port49=…, socket=…,
  broker=…, broker_ca=…, cert=…, key=…, touch_key=…, deadline=…)`.

- [ ] **Step 1: Write the failing tests** `tests/unit/test_token.py`, with stub `ansible` modules
  and a stub `port49`:

```python
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class AnsibleError(Exception):
    pass


class LookupBase:
    def __init__(self, *a, **kw):
        self._opts = {}

    def set_options(self, var_options=None, direct=None):
        self._opts = dict(direct or {})

    def get_option(self, name):
        return self._opts.get(name)


for name, mod in {"ansible": types.ModuleType("ansible"), "ansible.errors": types.SimpleNamespace(AnsibleError=AnsibleError),
                  "ansible.plugins": types.ModuleType("ansible.plugins"),
                  "ansible.plugins.lookup": types.SimpleNamespace(LookupBase=LookupBase)}.items():
    sys.modules[name] = mod

import importlib.util  # noqa: E402

import port49  # noqa: E402  (clients/python/src on PYTHONPATH)

# Loaded by path: the standard library's `token` is imported already (unittest
# imports traceback, which imports tokenize), so `import token` would not
# reach the plugin.
_spec = importlib.util.spec_from_file_location(
    "port49_lookup_token", os.path.join(HERE, "..", "..", "plugins", "lookup", "token.py"))
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

TOK = port49.Token("leaf1", "10.0.0.11", "arista_eos", "alice", "LOGINTOKEN", "ENABLETOKEN")


class Calls:
    def __init__(self):
        self.agent, self.workload = [], []


class Plugin(unittest.TestCase):
    def setUp(self):
        self.calls = Calls()
        calls = self.calls

        class FakeAgent:
            def __init__(self, **kw):
                calls.agent.append(("init", kw))

            def token(self, device, enable=False, ttl=None):
                calls.agent.append(("token", device, enable, ttl))
                if device == "denied":
                    raise port49.Denied("no_grants_matched", "no grant", device, reason="no_grants_matched")
                return TOK

        class FakeWorkload:
            def __init__(self, *a, **kw):
                calls.workload.append(("init", a, kw))

            def tokens(self, devices=None, enable=False, ttl=None, **kw):
                calls.workload.append(("tokens", list(devices)))
                return port49.MintResults({"leaf1": TOK}, {"leaf2": port49.Refusal("leaf2", "deny", "no_grants_matched", None, "")})

        self.patches = [(plugin, "_agent", FakeAgent), (plugin, "_workload", FakeWorkload)]
        self.saved = [(o, n, getattr(o, n)) for o, n, _ in self.patches]
        for o, n, v in self.patches:
            setattr(o, n, v)

    def tearDown(self):
        for o, n, v in self.saved:
            setattr(o, n, v)

    def lookup(self, terms, **kw):
        return plugin.LookupModule().run(terms, variables={}, **kw)

    def test_the_login_token_by_default(self):
        self.assertEqual(self.lookup(["leaf1"]), ["LOGINTOKEN"])

    def test_fields(self):
        self.assertEqual(self.lookup(["leaf1"], field="username"), ["alice"])
        self.assertEqual(self.lookup(["leaf1"], field="enable", enable=True), ["ENABLETOKEN"])
        self.assertEqual(self.lookup(["leaf1"], field="all")[0]["login"], "LOGINTOKEN")
        with self.assertRaises(AnsibleError):
            self.lookup(["leaf1"], field="enable")  # no enable token asked for

    def test_workload_mode_is_one_run(self):
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf1", "leaf2"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertEqual(self.calls.workload[-1], ("tokens", ["leaf1", "leaf2"]))
        self.assertIn("leaf2", str(cm.exception))
        self.assertIn("no_grants_matched", str(cm.exception))

    def test_errors_never_carry_the_token(self):  # Review Focus 5
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf1", "denied"])
        self.assertIn("no_grants_matched", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_half_a_workload_is_refused(self):
        with self.assertRaises(AnsibleError):
            self.lookup(["leaf1"], broker="https://b")
```

- [ ] **Step 2: Run them to see them fail**

Run: `make test-python`
Expected: FAIL (`FileNotFoundError` for `plugins/lookup/token.py`).

- [ ] **Step 3: Implement** `plugins/lookup/token.py`:

```python
DOCUMENTATION = r"""
name: token
author: port49 contributors
short_description: Mint a port49 device token
description:
  - Mints a single-use device token for each device named, through the port49 CLI
    (C(port49 token --json) with your agent, or C(port49 workload token) with a workload certificate).
  - Each call is a mint. Mint once per host per play in a C(set_fact) with C(no_log), not in
    C(ansible_password), which Ansible templates at every task.
  - Needs the port49 Python library on the controller (C(pip install port49)).
options:
  _terms: {description: Device names as port49's inventory knows them., required: true, type: list, elements: str}
  field:
    description: What to return per device.
    type: str
    default: login
    choices: [login, enable, username, address, platform, all]
  enable: {description: Mint an enable token too., type: bool, default: false}
  ttl: {description: The lifetime asked for, in seconds; the broker clamps it., type: int}
  port49: {description: The port49 CLI., type: str, default: port49}
  socket: {description: The agent's socket., type: str}
  broker: {description: Workload mode, the broker URL., type: str}
  broker_ca: {description: Workload mode, the broker's CA., type: path}
  cert: {description: Workload mode, the certificate., type: path}
  key: {description: Workload mode, the key or a key reference., type: str}
  touch_key: {description: Workload mode, a touch key reference., type: str}
  deadline: {description: Workload mode, how long to retry the broker, in seconds., type: int}
"""

EXAMPLES = r"""
- name: one mint per host
  ansible.builtin.set_fact:
    port49: "{{ lookup('port49.client.token', inventory_hostname, field='all') }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: One value per device, the field asked for (a dict for C(all)).
  type: list
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

WORKLOAD = ("broker", "broker_ca", "cert", "key")


def _agent(**kw):
    import port49
    return port49.Agent(**kw)


def _workload(*a, **kw):
    import port49
    return port49.Workload(*a, **kw)


def _value(tok, field):
    if field == "all":
        return {"device": tok.device, "address": tok.address, "platform": tok.platform, "username": tok.username,
                "login": tok.login, "enable": tok.enable, "expires_at": tok.expires_at}
    value = getattr(tok, field)
    if value is None:
        raise AnsibleError(f"port49: {tok.device}: no {field} token was minted; pass enable=true")
    return value


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        try:
            import port49
        except ImportError:
            raise AnsibleError("the port49 lookup needs the port49 Python library on the controller: "
                               "pip install port49 (clients/python in the port49 repository)") from None
        opt = self.get_option
        field, enable, ttl = opt("field") or "login", bool(opt("enable")), opt("ttl")
        if field == "enable" and not enable:
            raise AnsibleError("port49: field=enable needs enable=true: no enable token is minted without it")
        given = [k for k in WORKLOAD if opt(k)]
        try:
            if given and len(given) != len(WORKLOAD):
                raise AnsibleError(f"port49: workload mode needs {', '.join(WORKLOAD)}; given only {', '.join(given)}")
            if given:
                wl = _workload(opt("broker"), opt("broker_ca"), opt("cert"), opt("key"), touch_key=opt("touch_key"),
                               port49=opt("port49") or "port49", deadline=opt("deadline"))
                res = wl.tokens(devices=list(terms), enable=enable, ttl=ttl)
                for d in terms:
                    if d in res.refused:
                        raise res.refused[d].exception()
                return [_value(res.tokens[d], field) for d in terms]
            agent = _agent(port49=opt("port49") or "port49", socket=opt("socket"))
            return [_value(agent.token(d, enable=enable, ttl=ttl), field) for d in terms]
        except port49.Port49Error as e:
            raise AnsibleError(str(e)) from None
```

  `galaxy.yml`: `namespace: port49`, `name: client`, `version: 0.1.0`, `readme: README.md`,
  `license: [Apache-2.0]`, `description`, `repository`. `meta/runtime.yml`: `requires_ansible:
  ">=2.16"`. The README: install (`ansible-galaxy collection install ./clients/ansible/…` and `pip
  install port49` on the controller), the `pre_tasks` pattern of design §17 with `no_log`, the
  workload options, why one mint per play (the lookup in `ansible_password` mints at each task,
  as L66 (a) measures), `receipt_max_age` (a play longer than it mints again), and a "Host keys"
  section left for Task 12 to fill from L66 (written now as: host keys are Ansible's own
  `host_key_checking` and `host_key_auto_add`, keyed by `ansible_host`; the per-`ssh_type` settings
  follow L66).
- [ ] **Step 4: Run the tests to see them pass**

Run: `make test-python`
Expected: PASS (both discover runs).

- [ ] **Step 5: Commit**

```bash
git add clients/ansible
git commit -m "feat: the Ansible lookup port49.client.token over the Python library

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Lab — L64 (`port49 ssh` under accept-new) and L65 (Python and Netmiko), five platforms

**Files:**
- Create: `tests/lab/l64_l65_test.go` (`//go:build lab`, behind `PORT49_LAB_SSH=1`),
  `tests/lab/l64_l65_unit_test.go`
- Create: `tests/lab/results/L64-<platform>.md`, `tests/lab/results/L65-<platform>.md` (five each)
- Modify: `Makefile` (`lab-ssh` runs `-run 'TestL53HostKeyScan|TestL64L65'`), the spec's §15 L64
  and L65 Status, and decision 46 if a reading contradicts it (CLAUDE.md rule 4)

**Interfaces:** Consumes `make build`, the lab venv (`/home/rwendt/lab-venv`, with
`pip install ./clients/python[netmiko]` into it, versions recorded), Task 4's lab helpers
(`labScan`), L53's reload steps (`l53Reload`, `l53WaitDown`, `l53Rebooted`), the capture and
TACACS+ packet counter (`l.capture`, `l29Packets`).

- [ ] **Step 1: The harness.** Per platform, a private `HOME` (0700) with `~/.ssh/config` holding
  only `UserKnownHostsFile ~/.ssh/known_hosts` and `GlobalKnownHostsFile /dev/null`, and an empty
  `known_hosts`; one capture for the run; each cell counts TACACS+ packets in its own window, the
  good login's window the positive control (a zero is a zero of a counter that counts). Cells:
  - **L64 (a):** `port49 ssh -v <node> -- show version`: exit, methods ssh tried, askpass asks,
    redeem records, the output present, and `ssh-keygen -F <node>` (the filed line's key type).
  - **L65 (e1):** `port49.netmiko.connect(<node>)` in the venv against that entry: connects, no
    line added (the file's line count before and after).
  - **L64 (b):** the reload with configuration saved (L53's steps; the device seen down, then
    back), then `port49 ssh` again: exit 0 and no "WARNING: REMOTE HOST IDENTIFICATION" in its
    stderr; record the uptime proof as L53 does.
  - **L64 (c):** the entry under the name replaced by a fresh key of the filed type; `port49 ssh`:
    exit 255, 0 TACACS+ packets, records other than `mint` and `blob` none, its line naming
    `ssh-keygen -R`. **(d):** replaced by a key of another type only (RSA if Ed25519 or ECDSA was
    filed, Ed25519 if RSA): the same.
  - **L65 (a):** `known_hosts` emptied (with `HashKnownHosts yes` in the config); `connect`:
    connects, one hashed line under the name, its key type. **(b):** `connect` again: connects, no
    line added. **(c)** and **(d):** as L64's, through `connect`: `HostKeyError`, 0 TACACS+
    packets, the token never presented. **(e2):** `port49 ssh` against the entry Python filed:
    exit 0, no line added.
  Never print a token; the venv script reads it from the library and prints only the outcome.
- [ ] **Step 2: Unit-test the readers.** `l64_l65_unit_test.go` tests the classifiers that read
  ssh's stderr into "accepted / changed / other type" and count lines, against fixtures from
  Task 2's note (OpenSSH 10.2p1's wording), under `make lab-unit`.
- [ ] **Step 3: Run** `PORT49_LAB_PLATFORMS=<each> make lab-ssh` with the lab watchdog armed (a
  background stall watchdog, re-armed on wake). Copy raw pcaps to the main checkout before removing
  any lab worktree.
- [ ] **Step 4: Write the notes** (platform, image version, the venv's Netmiko and Paramiko
  versions, OpenSSH's, each cell's observation, the capture pointer) and read them. Close L64 and
  L65 per platform only where every cell read as claimed; a row with one platform measured and
  others open stays open. If (b) finds a key that changes at a reload on some platform, the docs
  say so per platform (the operator note: "on <platform> the key changes at every reload; port49
  ssh stops at OpenSSH's warning; …") and decision 46 names it; nothing is weakened to hide it.
- [ ] **Step 5: Commit**

```bash
git add tests/lab Makefile docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L64 and L65

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (If a row stays open, the message says "measure lab register entries … (open: …)".)

---

## Task 12: Lab — L66 (the Ansible lookup), five platforms

**Files:**
- Create: `tests/lab/l66_test.go` (`//go:build lab`, behind `PORT49_LAB_ANSIBLE=1`),
  `tests/lab/l66_unit_test.go`, `tests/lab/l66/` (the playbooks and inventory the harness writes
  from), `tests/lab/results/L66-<platform>.md`
- Modify: `Makefile` (`lab-ansible`), `clients/ansible/ansible_collections/port49/client/README.md`
  (the "Host keys" section, from L66), the spec's §15 L66 Status

**Interfaces:** Consumes the lab venv with `ansible-galaxy collection install cisco.ios
junipernetworks.junos` and `pip install ansible-pylibssh ./clients/python`, the collection from
`clients/ansible` (`ANSIBLE_COLLECTIONS_PATH`), `make build`, the agent (`l29Agent`).

- [ ] **Step 1: The harness.** Per platform, a private `HOME`, `ANSIBLE_COLLECTIONS_PATH` naming
  `clients/ansible` first, and an inventory of the one node with `ansible_connection:
  ansible.netcommon.network_cli` and the platform's `ansible_network_os`. Cells:
  - **(a)** a ten-task play (each task a `*_command` `show version`) with `ansible_password: "{{
    lookup('port49.client.token', inventory_hostname) }}"` and `ansible_user` from a second lookup
    with `field='username'`: count `mint` records (and `redeem`s) for the run.
  - **(b)** the same play minting once in a `pre_tasks` `set_fact` (`field='all'`, `no_log`):
    count mints, redeems, and TACACS+ authentication starts in the capture.
  - **(c)** host keys, for `ansible_network_cli_ssh_type: libssh` and then `paramiko`, each from an
    empty known_hosts with `ANSIBLE_HOST_KEY_CHECKING=True` and `ANSIBLE_HOST_KEY_AUTO_ADD=True`:
    the play passes; which file gained which line under which name (address, port form). Then that
    line's key replaced by a fresh key of its type: the play fails before authentication, 0 TACACS+
    packets, the token never presented (records other than `mint` and `blob`: none).
  - **(d)** a denied device (inventory name with no grant): the task fails naming
    `no_grants_matched`; `ansible-playbook -vvv` output holds no token (grep for every minted
    token the harness learned from the decision log's `credential_sha256`, never the token itself:
    the harness hashes each `-vvv` word and compares).
  Record the versions: ansible-core, `ansible.netcommon`, each platform collection,
  `ansible-pylibssh`, Paramiko.
- [ ] **Step 2: Unit-test the readers** (the PLAY RECAP and the record counts) under `make lab-unit`.
- [ ] **Step 3: Run** `PORT49_LAB_ANSIBLE=1 PORT49_LAB_PLATFORMS=<each> make lab-ansible` with the
  watchdog armed (target: `go test -tags lab ./tests/lab/ -run 'TestL66' -count=1 -v -timeout 90m`).
- [ ] **Step 4: Write the notes, then the README's "Host keys".** For each `ssh_type`, the settings
  that give accept-new as measured (or, if one does not save a first contact or does not refuse a
  changed key before authentication, say so and recommend the one that does). The pattern's
  section states the measured counts: (a) N mints per host for ten tasks, (b) one. Close L66 per
  platform where every cell read as claimed.
- [ ] **Step 5: Commit**

```bash
git add tests/lab Makefile clients/ansible docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entry L66

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; the 9d entry; a new `### Plan 9d —
  As built` after `### Plan 9c — As built`'s operator notes; Plan 9a — As built's operator notes
  on `devices trust` marked superseded by 9d)

- [ ] **Step 1: Write "Plan 9d — As built"**: branch and base, each task's commits, gate G1's
  reading and the floor, the rows closed and left open, and carried at least:
  - **Plan 12:** the Python library and the Ansible collection published at go-public (PyPI
    `port49`, Galaxy `port49.client`), each shape's client package installing them beside the
    client build; the Oxidized example's `secure: true` asks for every device's key in
    `~/.ssh/known_hosts` before its first backup (per-device toil): measure Oxidized's own
    host-key options against accept-new and change the example, or say why not;
  - **pre-beta review:** the `port49 devices trust` removal line goes; plan 9a's pins file hint
    goes;
  - **L60's session:** whether parallel Ansible forks under a `hardware_key_touch` requirement ask
    one touch or several (the agent's token lock serializes them; unmeasured);
  - **plan 13:** these operator notes; plan 9a's `devices trust` notes withdrawn.
- [ ] **Step 2: Verify** — `make test && make vet`; paste the summary lines into the PR body.
- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap, plan 9d as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **Host keys are OpenSSH's now.** `port49 ssh` uses your own known_hosts: the first connection to
  a device is accepted and saved ("Permanently added 'core-sw01'"), and a changed key stops at
  OpenSSH's warning before the token is sent. Nothing to run first; `port49 devices trust` is gone
  (it says so and exits 2). Keys are filed under the device's inventory name (`HostKeyAlias`), so
  an address changed in inventory for a device you have reached before is refused at the key
  exchange.
- **Why it matters.** The token is the device's password for its lifetime. A host that takes it
  can replay it to the real device until it expires. The window port49 leaves is the first contact,
  per device and per operator, the same one every SSH user accepts.
- **Checking a first contact.** Compare the fingerprint ssh prints with the device's console:
  NX-OS `show ssh key` prints a SHA256 fingerprint; EOS `show management ssh hostkey <type>
  public`, Junos `file show /etc/ssh/ssh_host_<type>_key.pub`, IOS-XE `show ip ssh` print the key,
  so run `ssh-keygen -lf` on it (L53; the type is the one ssh filed, L64).
- **A changed key.** `port49 ssh` says the key filed under the name is not the one the address
  presents. Either the device was re-keyed (verify the new key on its console, then `ssh-keygen -R
  core-sw01`), or the address is not the device: tell security.
- **Verified first contact for a shop.** Ship a managed `GlobalKnownHostsFile` keyed by inventory
  name, or host certificates with `@cert-authority`; `port49 ssh` leaves both alone. Your own
  `StrictHostKeyChecking yes` and `HostKeyAlias` in ssh_config stand; `no` is never used.
- **Plan 9a's pins file** (`~/.config/port49/known_hosts`) is no longer read. `port49 ssh` names
  it while it exists; its lines are already OpenSSH's format under the same names, so keep keys you
  verified with `cat ~/.config/port49/known_hosts >> ~/.ssh/known_hosts`, then remove it. A
  group-writable `~/.config` (Ubuntu's default) no longer stops `port49 ssh`. `--known-hosts` is
  refused: use `UserKnownHostsFile` in an ssh_config (`--ssh-config`).
- **`port49 token --json`** prints one JSON object on a failure too (a deny's §5.7 `reason`, or a
  code: `no_agent`, `per_login_mfa_required`, `touch_timeout`, `key_locked`, `key_absent`,
  `broker_refused`, …); the exit status is unchanged. **`port49 workload token --format json`**
  lists what was not minted in `refused`, and prints on exit 75 and 77 too.
- **Python.** `pip install './clients/python[netmiko]'` (Python 3.10+). `port49.Agent().token(
  "core-sw01")` for a person, `port49.Workload(broker=…, broker_ca=…, cert=…, key=…).tokens(
  scope="backup")` for a machine, `port49.netmiko.connect("core-sw01")` for Netmiko. It runs the
  `port49` CLI, so touches, PINs, hardware keys and the broker CRL check work as they do for
  `port49 token`; prompts appear on your terminal. Errors are typed (`Denied` with the reason,
  `MFARequired`, `KeyUnavailable`, `NoAgent`, …). Netmiko's host keys follow `port49 ssh`'s rule
  in the same known_hosts. Paramiko cannot check `@cert-authority`, so a device covered only by
  one is refused there; use `port49 ssh`, or file its key.
- **Ansible.** `ansible-galaxy collection install` the collection and `pip install port49` on the
  controller. Mint once per host per play (`pre_tasks`, `set_fact`, `no_log: true`); a lookup in
  `ansible_password` mints at every task (L66). Host keys are Ansible's own:
  `host_key_checking: true` and `host_key_auto_add: true` (per `ssh_type`, as L66 measured).
