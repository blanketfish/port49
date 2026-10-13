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
  one. An ssh_config that keeps no host keys (`UserKnownHostsFile /dev/null` or `none`) is refused
  under accept-new, naming the setting, since every connection would be a first contact. The
  askpass answers the device's prompt under the inventory name or under the alias `ssh -G`
  reports, since ssh's prompt names the alias, and only to the ssh `port49 ssh` started: a
  ProxyJump hop's prompt under the same alias goes to the terminal.
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
  under the inventory name in the operator's own known_hosts, read through `ssh -G`,
  `ssh-keygen -F` and `ssh-keygen -Q`, shared with `port49 ssh`. A key an `@revoked` line or the
  operator's `RevokedHostKeys` names is refused, filed or presented at first contact (checked
  before authentication); a `KnownHostsCommand`, which Paramiko cannot run, is refused, naming
  it; a device name known_hosts would read as a pattern is refused before the mint.
- **The Ansible lookup** (`clients/ansible`, collection `port49.client`, lookup
  `port49.client.token`) over the library. Host keys stay Ansible's own (`host_key_checking`,
  `host_key_auto_add`), as L66 measures them. `network_cli` keys them by the address in
  Ansible's inventory, not the name, and the docs say what that leaves open; the README sets
  `HostKeyAlias={{ inventory_hostname }}` where the connection runs OpenSSH, and never
  recommends `host_key_auto_add` under `ssh_type: paramiko`, which rewrites `~/.ssh/known_hosts`
  without its `@revoked` and `@cert-authority` lines.
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
- `tests/lab/hostkeyscan_test.go`: the L53 scan, moved from `internal/hostkeys` into the lab;
  `tests/lab/hostkeyscan_unit_test.go`: its unit test, under `make lab-unit`.
- `clients/python/src/port49/`: `_run.py` (the CLI runner), `errors.py`, `client.py`,
  `hostkeys.py` (`lookup`, `valid_name`, `is_revoked`, `remember`, `hashed`), `netmiko.py`
  (`connect`, `FirstContact`). Tests are stdlib `unittest` against a fake `port49` executable and
  fake `netmiko`; the host-key tests run the real `ssh` and `ssh-keygen`.
  `clients/python/tests/testdata/`: `port49 workload token --format json`'s own bytes, which the
  Go tests compare against and the Python tests are fed.
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
  rulings 7, 8, 9, 10, 12 and 14 and decision 43 ruling 24 amended), §14 (two host-key
  assertions), §15 (L53 and L54 claims; new L64–L66).
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
  same `-F`, `HostName`, `-l` and `-p` it will run ssh with, and reads three settings from it:
  - `stricthostkeychecking`: `true` (the operator's `yes`) stands as `StrictHostKeyChecking=yes`;
    every other value (`ask`, OpenSSH's default; `false`; `accept-new`) is passed as
    `StrictHostKeyChecking=accept-new`. Never `no`.
  - `hostkeyalias`: when the operator's ssh_config sets one, it stands and port49 passes none;
    otherwise port49 passes `HostKeyAlias=<device>` lowercased (OpenSSH lowercases an alias).
    ssh's password prompt names the alias, so the askpass answers the device's prompt naming the
    inventory name or the alias `ssh -G` reported (pre-flight I1).
    That widening must not reach a ProxyJump hop: a `Match user` block can give the hop the same
    alias (measured on 10.2p1: `ssh -G -l alice jump1` prints the alias the device's block sets), and
    ssh runs the hop with the same `-F`, `-l` and `SSH_ASKPASS`, so the hop's prompt
    `(alice@<alias>) Password:` would match. So the askpass server answers a device prompt only to
    an asker whose parent is the ssh process `port49 ssh` started (pre-flight N3, ruled must-fix).
    ssh forks the askpass directly, so the asker's parent is the ssh that is asking, and a hop's is
    the hop's own ssh, which is never the one port49 started. The server reads the asker's pid from
    the socket, never from what the asker says: `SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS.
    It then reads that process's parent: `/proc/<pid>/stat` field 4 on Linux, `kern.proc.pid`'s
    `Eproc.Ppid` on macOS. A pid that is not ssh's is answered `N` (the terminal is asked, as ssh
    would have). A pid or parent that cannot be read, or any other OS, fails closed: nothing is
    sent, ssh is ended as `refuse` ends it, and `port49 ssh` says it could not tell which process
    asked. This holds for every hop and every alias, with or without a `Match` block.
  - `userknownhostsfile`: under accept-new, when every file it names is `/dev/null` or `none`,
    the run is refused before ssh starts, naming `UserKnownHostsFile`: such a config files
    nothing, so every connection is a first contact and accept-new would be accept-all, silently
    (pre-flight I7; fail closed). Under the operator's own `yes` it stands: nothing unknown is
    accepted there, and a managed `GlobalKnownHostsFile` with no user file is a verified setup.
  Nothing else about host keys is passed: the operator's `UserKnownHostsFile`,
  `GlobalKnownHostsFile` (with any `@cert-authority` or `@revoked` lines), `KnownHostsCommand`,
  `RevokedHostKeys`, `VerifyHostKeyDNS`, `UpdateHostKeys`, `CheckHostIP` and `HashKnownHosts`
  apply as they would to any ssh. `ssh -G` failing is a refusal before ssh runs ("nothing was
  sent"). These refusals come after the mint, since `ssh -G` reads the address it gives (`Match
  host`); the token minted is unused and expires, and the docs say so (pre-flight M14). The name
  check (R3) comes before it. Why the alias: a key filed under the inventory name meets an
  address added to the device in the source of truth, so design §17's attack (an address that
  leads to the attacker's host, which takes the token and replays it) fails at the key exchange
  for every device this operator has reached before through `port49 ssh` or the Python client,
  at no cost to anyone. Ansible's `network_cli` keys by address, so it does not hold there (R15).
  Why `ssh -G`: it is OpenSSH's own reading of the operator's ssh_config, Match blocks included;
  port49 parses three lines of it and decides nothing OpenSSH does not. An operator's `Host`
  pattern matches the destination as written, case and all, and `port49 ssh`'s destination is
  the inventory name unlowered: a `Host leaf1` block does not match a device named `Leaf1`
  (measured on 10.2p1, pre-flight M1; the docs say so).
- **R3. Names.** Decision 42 ruling 8 stands: a device name `port49 ssh` takes is letters, digits,
  `.`, `_` and `-`, starting with a letter or digit, 253 at most, since it is written into the
  operator's known_hosts as a host field. It moves from `hostkeys.ValidName` to `sshName` in
  `cmd/port49/ssh.go`, with its test (`TestSSHName`). The Python client keeps the same rule
  (`port49.hostkeys.valid_name`) before any mint and before any known_hosts write (pre-flight I6):
  it writes the name into the operator's known_hosts too.
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
  rises to the earliest version Task 2 measured refusing it. G1 is measured in the attack's
  shape: a server that offers only Ed25519, against an ECDSA key filed under the alias, and a
  client with OpenSSH's default algorithms (pre-flight I8; the client-side form, the client
  forced to `HostKeyAlgorithms=ssh-ed25519`, is kept as G1b). Measured while this plan was
  written and again at pre-flight, on OpenSSH 10.2p1, both forms refuse it as a changed key
  ("Host key for leaf1 has changed and you have requested strict checking"), so an impostor that
  offers only another key type does not pass.
- **R7. The changed-key message.** A 255 before the token was sent, with ssh's "Host key
  verification failed", says the key filed under the name is not the one the address presents —
  either the device's key changed or the address inventory gives is not the device — and to verify
  the key on the console (L53's commands) and run `ssh-keygen -R <name>`. `<name>` is the alias
  port49 passed, or the operator's own as `ssh -G` printed it. Under the operator's own
  `StrictHostKeyChecking yes` the same 255 may mean no key is filed at all, so the message says
  that too: add the device's key under `<name>` after checking it on the console (pre-flight M4).
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
  OpenSSH's tools.** `port49.netmiko.connect` checks the device name first, before any mint,
  against R3's set (`port49.hostkeys.valid_name`), naming the rule as `port49 ssh` does. After the
  mint, `port49.hostkeys.lookup` runs `ssh -G` as `port49 ssh` does (the caller's `-F`, `HostName`
  double-quoted with each `%` doubled, `-l` the minted username, `-p`; pre-flight M6) and reads
  `hostkeyalias`, `stricthostkeychecking`, `userknownhostsfile`, `globalknownhostsfile`,
  `hashknownhosts`, `revokedhostkeys` and `knownhostscommand`; the name is the operator's alias,
  else the device lowercased, as R2. Before anything connects it refuses (`HostKeyError`):
  - a name outside R3's set (`device_name`), as `connect` did; `lookup` checks it again, since it
    is public;
  - a `KnownHostsCommand` other than `none` (`host_key_uncheckable`, naming the setting and `port49
    ssh`): the client cannot run it as ssh does, and reading "nothing known" past it would accept
    a key OpenSSH refuses (pre-flight C1; fail closed);
  - under accept-new, a `UserKnownHostsFile` of only `/dev/null` or `none` (`host_keys_not_kept`,
    R2's rule; pre-flight I7).
  It runs `ssh-keygen -F <name> -f <file>` on each existing file and sorts the lines it prints:
  plain keys, `@cert-authority` lines, and the keys `@revoked` lines name. A plain key that an
  `@revoked` line names (same type and base64), or that `ssh-keygen -Q -f <RevokedHostKeys>`
  reports revoked (exit 1), is dropped, always, not only when no other key is filed: that is how
  a managed `GlobalKnownHostsFile` revokes a compromised device key that users' own files still
  hold from accept-new (pre-flight C1). If that leaves none where some were filed, it refuses
  (`host_key_revoked`). A `RevokedHostKeys` that `ssh-keygen -Q` cannot read (measured on 10.2p1:
  exit 255 for a file that is not a KRL) is refused (`host_key_uncheckable`), never passed. ssh
  itself honours a plain public-key list as `RevokedHostKeys` (ssh_config(5)), which `ssh-keygen
  -Q` cannot read, so the refusal says the file is not broken for ssh: this client needs a KRL
  (`ssh-keygen -k`); R13's README text says the same (pre-flight N5). Then:
  - keys left: Netmiko connects with them alone, written under the address (or
    `[address]:port`) to a private temporary file, and `ssh_strict=True`. Paramiko, holding a key
    for the address, raises `BadHostKeyException` for a changed key and for a key of another type
    alike (Paramiko 4.0.0 `client.py:461-466`), before authentication;
  - none, no `@cert-authority` line, and the operator's StrictHostKeyChecking not `yes`: a first
    contact. Netmiko is built with `auto_connect=False`, its `key_policy` is set to port49's
    `FirstContact`, and the connection is opened (`_open`, what `auto_connect=True` runs).
    Paramiko calls `FirstContact.missing_host_key` with the presented key after the key exchange
    and before authentication (`client.py:455-460`; Netmiko applies `key_policy` in
    `_build_ssh_client`). A key an `@revoked` line or `RevokedHostKeys` revokes is refused there
    (`host_key_revoked`); any other is appended under the name to the first kept
    `userknownhostsfile`, hashed when `hashknownhosts` is `yes`, in one `O_APPEND` write, and said
    on stderr as OpenSSH says it, before the token is presented (pre-flight C1);
  - none and an `@cert-authority` line matches, or `yes`: refused before connecting, naming why.
    Paramiko cannot check a host certificate, so a shop's `@cert-authority` is never weakened to a
    first-contact accept by this client (Q6). An `@revoked` line alone is no longer such a
    refusal: its keys are checked against the presented one, as above.
  A refusal after the mint leaves its token unused, to expire; the README says so (pre-flight
  M14). `connect` refuses `ssh_config_file`, `sock`, `ip` and `auto_connect` among the caller's
  Netmiko arguments (`ip` is Netmiko's other name for `host`: pre-flight N4), since the first
  three could steer Paramiko to another host than the address checked
  (pre-flight M16). `port49 ssh` and the Python client share the entry: whichever reaches a
  device first files its key, and the other verifies against it. The Paramiko claims are
  provisional on L65 until it closes (pre-flight M9).
- **R14. Packaging, floor and tests.** `clients/python`: a `pyproject.toml` (setuptools, `name =
  "port49"`, `requires-python = ">=3.10"`, no runtime dependency, extra `netmiko = ["netmiko>=4.7"]`),
  sources in `src/port49/`. Python 3.10 is the floor: Ubuntu 22.04's, and ansible-core 2.16's
  controller floor. Tests are stdlib `unittest` (no pytest to install), run by `make test-python`,
  which `make test` runs; a missing `python3`, or one below 3.10, fails `make test` with one line
  naming the floor, before any test is discovered (Q9; pre-flight M12). A test parses every source with
  `ast.parse(..., feature_version=(3, 10))`. Not published to PyPI until go-public (plan 12).
- **R15. The Ansible lookup.** Collection `port49.client` (`clients/ansible/ansible_collections/
  port49/client/`, `requires_ansible: ">=2.16"`), lookup `port49.client.token`. Terms are port49
  device names. `field`: `login` (default), `enable`, `username`, `address`, `platform`, or `all`
  (a dict). Person mode (the agent) by default; workload mode when `broker`, `broker_ca`, `cert`
  and `key` are given (one CLI run for every term). Errors are `AnsibleError` with the library's
  words, never a token. The README's pattern mints once per host per play: a `set_fact` with
  `no_log: true` in `pre_tasks`, since a lookup in `ansible_password` is templated at each task
  (L66 measures how many mints that costs). Host keys are Ansible's own; the README carries L66's
  settings per `ssh_type`, provisional on L66 until it closes (pre-flight M9). Ansible's
  `network_cli` keys host keys by `ansible_host`, the address from Ansible's inventory, not by
  the name (ansible.netcommon 8.7.0 `network_cli.py:688-697, 827-848`). When that inventory comes
  from the same source of truth (a NetBox dynamic inventory, the usual case), an address added
  to a device is a first contact for Ansible, and under `host_key_auto_add` design §17's attack is
  open there: the impostor's key is accepted and the token presented (pre-flight I4). The docs
  say so plainly, in decision 46 ruling 15, design §17 and the README. The README configures
  `HostKeyAlias={{ inventory_hostname }}` wherever the connection runs OpenSSH
  (`ansible.builtin.ssh`: `ansible_ssh_extra_args: "-o HostKeyAlias={{ inventory_hostname }}"`),
  which keys it by name as `port49 ssh` does; `network_cli`'s address keying (`paramiko`, and
  `libssh` unless L66 (e) finds it honours an alias) is documented as the gap it is. The README
  never recommends `host_key_auto_add` with `ssh_type: paramiko`: network_cli's paramiko
  `close()` writes a new `~/.ssh/known_hosts` from Paramiko's parsed entries and renames it over
  the old (`network_cli.py:827-848, 866-900`), and Paramiko's parser drops `@revoked` and
  `@cert-authority` lines and comments (`hostkeys.py:339-366`), which would silently weaken every
  later `port49 ssh` and Python login (pre-flight I5). It recommends the path that leaves the
  file intact (`libssh`, which appends, as L66 (c) measures). For devices that ask for
  `hardware_key_touch`, the README says to run `port49 token <one such device>` before the play,
  so `reuse_for` covers the forks rather than each fork asking for a touch (pre-flight M15).
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
6. **A revoked key.** A device key that an `@revoked` line or the operator's `RevokedHostKeys`
   names must never get the token from the Python client: filed beside the user's accept-new
   entry, or presented at first contact (refused before authentication). A `KnownHostsCommand`
   the client cannot run is refused, not read as "nothing known". Tests: Task 9
   (`test_a_revoked_filed_key_is_refused_before_connecting`, `test_a_krl_revokes_a_filed_key`,
   `test_known_hosts_command_is_refused`, `test_a_revoked_key_at_first_contact_is_refused_before_auth`).
7. **An ssh_config that keeps no host keys.** `UserKnownHostsFile /dev/null` under accept-new is
   accept-all; both clients refuse it, naming the setting. Tests: Task 3
   (`TestAKnownHostsFileOfDevNullIsRefused`), Task 9 (`test_a_known_hosts_file_of_dev_null_is_refused`).

---

## Task 1: Spec and design — decision 46, §12, §15 (L53, L54 amended; L64–L66 opened), design §17

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §12's `port49 devices trust` paragraph
  (~6289–6298) and `port49 ssh` paragraph (~6300–6306); after `**`port49 workload token … --scope
  NAME`**` (~6308) two new paragraphs; decision 42's heading note (~8258–8262) and rulings 7
  (~8348), 8 (~8357), 9 (~8363), 10's command-line bullet (~8392), 12 (~8437), 14 (~8456); decision
  43 ruling 24's "Where" bullet (~8732–8735); §13 a new decision 46 after decision 45's ruling 26,
  before the `---` above `## 14.` (~9273); §14 a "**Host keys**" block after the "**Hardware keys
  and per-login MFA**" block's last bullet (~9903–9904), before its `---`; §15's L53 and L54 rows'
  second column (~9993–9994), three rows after L63's (~10003), and a bullet after the
  `**L60**–**L63**` bullet (~11941–11948).
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
  `ssh-keygen -R`. An ssh_config that keeps no host keys (`UserKnownHostsFile /dev/null` or
  `none`) is refused under accept-new, naming the setting. Why it matters: the token is the
  device's password for its lifetime, and a host that takes it can replay it to the real device.
  The window this leaves is the first contact, per device and per operator; a shop that wants
  that verified too uses a managed `GlobalKnownHostsFile` or `@cert-authority`, which apply
  unchanged.
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
  46 ruling 1.**"; in ruling 8, after "`port49 ssh` and `port49 devices trust`" add "(the command
  is removed by decision 46; the rule stands for `port49 ssh` and the Python client, decision 46
  ruling 3)"; in ruling 10, replace the first bullet under "**The command line.**" ("the pinned
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
  name, lowercased. ssh's prompt names the alias, so the askpass answers the device's prompt
  naming the inventory name or the alias `ssh -G` reported. Under accept-new, a
  `UserKnownHostsFile` naming only `/dev/null` or `none` is refused, naming the setting: it files
  nothing, so every connection would be a first contact (fail closed, never a silent
  accept-all); under the operator's `yes` it stands. Nothing else about host keys is passed.
  `ssh -G` failing refuses the run before ssh starts. These refusals follow the mint, since `ssh
  -G` reads its address; that token is unused and expires. The alias files a key under the name,
  so an address added to a device in the source of truth meets the key already known under its
  name, and design §17's replay attack fails at the key exchange for every device the operator
  has reached through `port49 ssh` or the Python client (ruling 13). It does not hold for
  Ansible's `network_cli`, which keys host keys by address (ruling 15).
- **3. Names.** Decision 42 ruling 8 stands, for `port49 ssh` and for the Python client, which
  checks it before any mint and any known_hosts write: the name is written into the operator's
  known_hosts.
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
  (data: `tests/ssh-compat/2026-10-13-openssh-accept-new.md`, a server offering only Ed25519
  against an ECDSA key filed under the alias, the client on its default algorithms; OpenSSH
  10.2p1 refuses it as a changed key).
- **7. A changed key** ends ssh with exit 255 before the token is sent; `port49 ssh` says the key
  filed under the name is not the one the address presents, either because the device's key
  changed or because the address is not the device, and to verify the key on the console (§15 L53)
  and run `ssh-keygen -R <name>`. Under the operator's `StrictHostKeyChecking yes` it says too
  that no key may be filed under the name, and to add the device's key after checking it on the
  console.
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
  files, read through `ssh -G`, `ssh-keygen -F` and `ssh-keygen -Q`. The device name is checked
  against decision 42 ruling 8 before the mint. Refused before connecting: a `KnownHostsCommand`,
  which the client cannot run as ssh does (fail closed, naming it); under accept-new, a
  `UserKnownHostsFile` that keeps nothing (ruling 2); a device whose every filed key an
  `@revoked` line or the operator's `RevokedHostKeys` revokes, or whose `RevokedHostKeys`
  `ssh-keygen -Q` cannot read. A revoked key is dropped always, beside any other filed key. A key
  known under the name is the only key accepted (a changed key, or another type, is refused
  before authentication, *provisional on L65*); none known, a first contact's key is checked
  against the revocations and appended under the name, hashed when `HashKnownHosts` is `yes`,
  after the key exchange and before authentication (*provisional on L65*); an `@cert-authority`
  line matching the name with no plain key, or the operator's `StrictHostKeyChecking yes` with
  none, is refused before connecting, since Paramiko cannot check a host certificate. A refusal
  after the mint leaves its token unused.
- **14. Packaging.** `clients/python` (import `port49`, Python 3.10+, no runtime dependency; the
  `netmiko` extra), stdlib `unittest`, run by `make test`, which refuses a Python below 3.10 by
  name. Not published before go-public.
- **15. The Ansible lookup** `port49.client.token`, in collection `port49.client` (ansible-core
  2.16+), over the library; person mode by default, workload mode with `broker`, `broker_ca`,
  `cert` and `key`. Host keys are Ansible's own (§15 L66), and `network_cli` keys them by
  `ansible_host`, the address in Ansible's inventory: there an address added to a device is a
  first contact, and design §17's attack is open under `host_key_auto_add`. The README says so,
  sets `HostKeyAlias={{ inventory_hostname }}` where the connection runs OpenSSH, and never
  recommends `host_key_auto_add` with `ssh_type: paramiko`, which rewrites `~/.ssh/known_hosts`
  without its `@revoked` and `@cert-authority` lines (*provisional on L66*).
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
| **L64** | `port49 ssh` under decision 46 against each platform, with OpenSSH's default algorithms: (a) a first contact, the operator's known_hosts holding nothing for the device: whether the login succeeds with one askpass ask, and every line ssh files under the inventory name, before and after the login (its key types: `UpdateHostKeys`, on by default, may file more after authentication); (b) after a reload with the configuration saved, the device seen down and back: whether `port49 ssh` logs in again with no host-key warning, the filed key still the device's; (c) the entry under the name replaced by another key of the same type: ssh refuses before any TACACS+ exchange, the token never presented, exit 255, `port49 ssh` naming `ssh-keygen -R`; (d) the entry replaced by a key of another type only: the same. Also recorded per platform: the method ssh used and the askpass asks (L54's cells, re-run under the new command line). | §13 decision 46 rulings 2, 6 and 7 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
| **L65** | The Python client (`port49.netmiko.connect`) against each platform: (a) a first contact: Netmiko logs in, and the key Paramiko accepted is filed under the inventory name (hashed under `HashKnownHosts yes`), its type recorded; (b) a second connection verifies against it; (c) the entry replaced by another key of the same type, and (d) by a key of another type only: refused before authentication, no TACACS+ exchange, the token never presented; (e) an entry `port49 ssh` filed (L64 (a)) verifies Python's connection with no line added, and one Python filed verifies `port49 ssh`'s; (f) the device's own key named by an `@revoked` line beside the filed entry, and then, from an empty known_hosts, at first contact: refused before authentication, no TACACS+ exchange, the token never presented, nothing filed. | §13 decision 46 ruling 13 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
| **L66** | The Ansible lookup `port49.client.token` over `ansible.netcommon.network_cli` against each platform: (a) a ten-task play with the lookup in `ansible_password`: how many mints per host; (b) the same play minting once in a `pre_tasks` `set_fact`: how many mints and how many TACACS+ authentications per host; (c) host keys with `host_key_checking: true` and `host_key_auto_add: true`, for `ssh_type` `libssh` and `paramiko`: a first contact accepted and saved (which file, under which name), and a changed key refused before authentication, no TACACS+ exchange, the token never presented; and, per `ssh_type`, the known_hosts file's comments, `@revoked` and `@cert-authority` lines before and after the run (whether the file is appended to or rewritten without them); (d) a denied device: the task fails naming the reason, and `-vvv` output holds no token; (e) an address changed in Ansible's inventory for a device reached before, leading to another host: for `libssh` and `paramiko` (and `libssh` with a `HostKeyAlias` in `ansible_libssh_config_file`), and for `ansible.builtin.ssh` with `-o HostKeyAlias={{ inventory_hostname }}`, whether the other host's key is auto-added and whether the token is presented to it. | §13 decision 46 ruling 15 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open |
```

  After the `**L60**–**L63**` bullet add:

```markdown
- **L64**–**L66** — added by plan 9d. Why each is a row:
  - **L64**: L53 measured the RSA key an `x/crypto/ssh` scan negotiates; OpenSSH's defaults may
    accept an Ed25519 or ECDSA key on EOS and Junos, whose survival across a reload nobody
    measured, and a key that changes at every reload would stop every operator's `port49 ssh`.
  - **L65**: Paramiko negotiates host keys by its own preferences; that a changed, other-type or
    revoked key is refused before authentication is decision 46 ruling 13's claim.
  - **L66**: how often Ansible templates a lookup in a connection variable, what
    `host_key_auto_add` does to the known_hosts file per `ssh_type`, and what an address moved in
    Ansible's inventory meets, are Ansible's behaviour, not documentation's.
```

- [ ] **Step 7: §14.** After the "**Hardware keys and per-login MFA**" block's last bullet ("**The
  broker CRL**: …"), before the `---`, add (pre-flight M18):

```markdown
**Host keys (decision 46)**

- **Never `no`**: whatever the operator's ssh_config says, `port49 ssh` passes
  `StrictHostKeyChecking=accept-new`, or the operator's own `yes`, never `no`; under accept-new a
  `UserKnownHostsFile` of only `/dev/null` or `none` is refused before ssh starts, and so is it by
  the Python client.
- **The token unsent on a changed key**: a host presenting another key than the one filed under
  the device's name, of the same type or another, never sees the token, from `port49 ssh` or the
  Python client; nor does a key an `@revoked` line or `RevokedHostKeys` names, filed or presented
  at first contact, from the Python client.
```

- [ ] **Step 8: Design §17.** Replace the paragraph beginning "**The address is a fact from the
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
That holds for `port49 ssh` and the Python client, which file keys under the name. Ansible's
`network_cli` keys host keys by the address in Ansible's inventory, so there an address added
to a device is a first contact, and under `host_key_auto_add` this attack is open (policy engine
spec §13 decision 46 ruling 15, §15 L66). The window left is the first contact, per device and per operator, the one every SSH user
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
# entry under its inventory name, accepted at first contact and refused if changed or
# revoked, before authentication (provisional on L65).
from port49.netmiko import connect
conn = connect("core-sw01")
```

```yaml
# Ansible (clients/ansible, plan 9d): one mint per host per play. Host keys are
# Ansible's own, keyed by ansible_host under network_cli (§13 decision 46 ruling 15).
pre_tasks:
  - ansible.builtin.set_fact:
      port49: "{{ lookup('port49.client.token', inventory_hostname, field='all') }}"
    no_log: true
  - ansible.builtin.set_fact:
      ansible_user: "{{ port49.username }}"
      ansible_password: "{{ port49.login }}"
    no_log: true
```

- [ ] **Step 9: Check** that nothing else in either document still asserts a pin, a pins file or
  `devices trust` as current:

```bash
grep -n "devices trust\|pinned host\|pins file\|known_hosts" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
```

  Expected: only decision 42's withdrawn rulings and ruling 8's note, decision 46, §12's removal
  line, §14's host-key block, §15's L53/L54 history and the new rows.

- [ ] **Step 10: Commit**

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
`sshPolicy` (Task 3) and `port49.hostkeys.lookup` (Task 9) parse.

The harness is standalone (pre-flight I8): plan 9a's `build-and-measure.sh` hard-codes its own
tarball path and its own measurements, so nothing of `tests/ssh-compat/2026-10-09-openssh-askpass`
is mounted or run. Plan 9a's note built 8.5p1 upstream in `ubuntu:20.04`; this does too, with its
own build step. Each container runs two `sshd`s on 127.0.0.1: port 22 with every host key `ssh-keygen
-A` makes, and port 2222 with the Ed25519 key alone (the impostor of gate G1), and the client under
test against them. The cells are measured in the attack's shape: a server that offers only
Ed25519, a client on OpenSSH's default algorithms. No device; this is a note about the operator's
ssh client, not a lab register entry.

- [ ] **Step 1: Write `run.sh`**, which sets a container up and runs `keys.sh`:

```sh
#!/bin/sh
# Plan 9d, gate G1 and the ssh -G forms, inside one container. $1 is
# "distro" (the image's own OpenSSH client) or an upstream version to build
# (8.5p1), whose tarball's SHA-256 is pinned below. Nothing of plan 9a's
# harness is used.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server openssh-client curl ca-certificates >/dev/null 2>&1
if [ "$1" != distro ]; then
  v=$1
  case $v in
    # Written when the tarball is first fetched, after `gpg --verify` of its
    # .asc against the OpenSSH release key; the note records it.
    8.5p1) sum=SHA256_OF_openssh-8.5p1.tar.gz ;;
    *) echo "run.sh: no pinned checksum for $v" >&2; exit 1 ;;
  esac
  apt-get install -y -qq build-essential zlib1g-dev libssl-dev >/dev/null 2>&1
  cd /tmp
  curl -fsSLO "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$v.tar.gz"
  echo "$sum  openssh-$v.tar.gz" | sha256sum -c -
  tar xzf "openssh-$v.tar.gz" && cd "openssh-$v"
  ./configure -q >/dev/null 2>&1 && make -s -j8 ssh >/dev/null 2>&1
  mkdir -p /opt/b && cp ssh /opt/b/ssh
  export PATH=/opt/b:$PATH
fi
echo "client: $(ssh -V 2>&1)"
mkdir -p /run/sshd && ssh-keygen -A >/dev/null
useradd -m -s /bin/sh tuser
# The jump hop of cell g1c: it asks for a password, which its askpass never has.
useradd -m -s /bin/sh jumpuser && echo jumpuser:x | chpasswd
mkdir -p /root/.ssh /home/tuser/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/ctl
cp /root/.ssh/ctl.pub /home/tuser/.ssh/authorized_keys
chown -R tuser /home/tuser/.ssh && chmod 700 /home/tuser/.ssh
/usr/sbin/sshd
printf 'Port 2222\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\n' \
  > /etc/ssh/sshd_g1
/usr/sbin/sshd -f /etc/ssh/sshd_g1
# The impostor's positive control: port 2222 offers Ed25519 and nothing else.
ssh-keyscan -p 2222 127.0.0.1 2>/dev/null | awk '{print $2}' | sort -u > /tmp/g1types
[ "$(cat /tmp/g1types)" = ssh-ed25519 ] || { echo "INVALID: port 2222 offers $(cat /tmp/g1types)"; exit 1; }
[ "$2" = serve ] && exec sleep infinity
sh /work/keys.sh
```

  `run.sh <version> serve` starts the servers and waits, for the host's own client (Step 3).
- [ ] **Step 2: Write `keys.sh`**, the cells. Each writes a known_hosts `kh`, connects with no
  terminal, `BatchMode=yes`, as `tuser` by the control key, and prints ssh's exit status, its last
  three stderr lines, and `kh` after:

```sh
#!/bin/sh
# Plan 9d Task 2's cells. KEYS is where the server's public keys are (the
# container's /etc/ssh; a copy for the host's client), CTL the client key,
# P22 and P2222 the two servers' ports.
KEYS=${KEYS:-/etc/ssh} CTL=${CTL:-/root/.ssh/ctl} P22=${P22:-22} P2222=${P2222:-2222}
T=$(mktemp -d) # a rerun meets no earlier run's keys (pre-flight nit)
k() { cut -d' ' -f1,2 "$KEYS/ssh_host_$1_key.pub"; }
cell() { # name port kh-contents [ssh options...]
  name=$1 port=$2 lines=$3; shift 3
  printf '%s' "$lines" > "$T/kh"
  ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o HostKeyAlias=leaf1 \
      -o UserKnownHostsFile="$T/kh" -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$CTL" \
      -o PreferredAuthentications=publickey -p "$port" "$@" tuser@127.0.0.1 true 2>"$T/err"
  echo "== $name: exit $?"
  tail -n 3 "$T/err" | sed 's/^/  stderr: /'
  sed 's/^/  kh: /' "$T/kh"
}
ssh-keygen -q -t ed25519 -N '' -f "$T/other"
cell g1 "$P2222" "leaf1 $(k ecdsa)
"
cell g1-control "$P2222" ""
cell g1b "$P22" "leaf1 $(k ecdsa)
" -o HostKeyAlgorithms=ssh-ed25519
cell changed-same-type "$P22" "leaf1 $(cut -d' ' -f1,2 "$T/other.pub")
"
cell hashed "$P22" "" -o HashKnownHosts=yes
echo "  hashed found: $(ssh-keygen -F leaf1 -f "$T/kh" | grep -vc '^#')"
# g1c (pre-flight N3): who is the askpass's parent when a ProxyJump hop asks? SSH_ASKPASS logs its own
# parent pid, then fails. The top ssh is this shell's background job, so $top is its pid.
printf '#!/bin/sh\necho "$PPID" >> "%s/askers"\nexit 1\n' "$T" > "$T/ap" && chmod +x "$T/ap" && : > "$T/askers"
SSH_ASKPASS="$T/ap" SSH_ASKPASS_REQUIRE=force ssh -F /dev/null -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$T/kh-pj" -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$CTL" \
    -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
    -J "jumpuser@127.0.0.1:$P22" -p "$P2222" tuser@127.0.0.1 true 2>"$T/err-pj" &
top=$!; wait "$top"
echo "== g1c: top ssh $top; askpass parents: $(sort -u "$T/askers" | tr '\n' ' ')"
if [ -s "$T/askers" ] && ! grep -qx "$top" "$T/askers"; then echo "  g1c: PASS"; else echo "  g1c: FAIL"; fi
ssh-keygen -q -k -f "$T/krl" "$T/other.pub"
for cfg in "" "StrictHostKeyChecking yes" "StrictHostKeyChecking no" "StrictHostKeyChecking ask" \
    "StrictHostKeyChecking accept-new" "StrictHostKeyChecking off" "Host leaf1
  HostKeyAlias Corp-Leaf1" "UserKnownHostsFile /dev/null" "UserKnownHostsFile none" \
    "RevokedHostKeys $T/krl" "KnownHostsCommand /bin/true %H" "Match user alice
  HostKeyAlias alice-leaf1"; do
  printf '%s\n' "$cfg" > "$T/cfg"
  for dest in leaf1 Leaf1; do
    echo "== g-forms [$(echo "$cfg" | tr '\n' ';')] $dest:"
    ssh -G -F "$T/cfg" -o 'HostName="fe80::1%%eth0"' -l alice -- "$dest" |
      grep -E '^(stricthostkeychecking|hostkeyalias|userknownhostsfile|revokedhostkeys|knownhostscommand) ' |
      sed 's/^/  /'
  done
done
```

  The cells:
  - **g1:** `kh` holds `leaf1 <the server's ECDSA key>`; the server on 2222 presents only
    Ed25519, and the client has its default algorithms. **Gate G1:** passes when ssh refuses (exit
    255, "has changed" or "verification failed") and `kh` is unchanged.
  - **g1-control:** `kh` empty, against 2222: ssh accepts and files `leaf1` (exit 0). Without it
    G1 is INVALID.
  - **g1c (gate G1c, pre-flight N3):** a `-J` hop that asks for a password, with an askpass that
    logs its parent's pid and fails. **Gate G1c:** passes when the askpass ran and no logged
    parent is the top ssh's pid, which is what lets `port49 ssh` tell a hop's prompt from the
    device's by the asker's parent (decision 46 ruling 2). It is required on 8.5p1, the floor,
    and measured on every client.
  - **g1b:** the client-side form kept from the first draft: `kh` holds the ECDSA key, against
    every host key, the client forced to `HostKeyAlgorithms=ssh-ed25519`; refused.
  - **changed-same-type:** `kh` holds `leaf1 <another Ed25519 key>`; refused.
  - **hashed:** `kh` empty and `-o HashKnownHosts=yes`: the line written starts `|1|` and
    `ssh-keygen -F leaf1 -f kh` finds it.
  - **g-forms:** `ssh -G` with the zone-holding `HostName` `port49 ssh` would pass (the `%`
    doubled) and `-l alice`, against destinations `leaf1` and `Leaf1`, for `cfg` holding in turn
    each line above; the five settings' lines verbatim. Expected from 10.2p1 (measured while
    writing this plan and at pre-flight): `true` for yes, `false` for no, `ask`, `accept-new`;
    `hostkeyalias` absent when unset and lowercased when set; a `Host leaf1` block not matching
    destination `Leaf1` (pre-flight M1); `userknownhostsfile /dev/null` and `none` as written;
    `revokedhostkeys` and `knownhostscommand` absent when unset, and printed as written when set;
    the `Match user alice` block matching under `-l alice`.
- [ ] **Step 3: Run** it on OpenSSH 8.5p1 (upstream build), 8.9p1 (`ubuntu:22.04`), 9.6p1
  (`ubuntu:24.04`) and the host's 10.2p1:

```bash
d=$PWD/tests/ssh-compat/2026-10-13-openssh-accept-new
sg docker -c "docker run --rm -v $d:/work:ro ubuntu:20.04 sh /work/run.sh 8.5p1"
sg docker -c "docker run --rm -v $d:/work:ro ubuntu:22.04 sh /work/run.sh distro"
sg docker -c "docker run --rm -v $d:/work:ro ubuntu:24.04 sh /work/run.sh distro"
```

  The host's 10.2p1: `docker run -d --name p49-g1 -p 127.0.0.1::22 -p 127.0.0.1::2222 -v
  $d:/work:ro ubuntu:24.04 sh /work/run.sh distro serve`, then `docker cp` its `/etc/ssh/*.pub`
  and `/root/.ssh/ctl` into a 0700 scratch directory, and run `KEYS=<dir> CTL=<dir>/ctl P22=<port>
  P2222=<port> sh keys.sh` on the host with the published ports; `docker rm -f p49-g1` after.
- [ ] **Step 4: Write the note** in the 2026-10-09 note's form: date, what it is for (decision 46
  rulings 2 and 6), where, the clients table, the 8.5p1 tarball's SHA-256 and how it was checked,
  the impostor's control (port 2222's key types), one table per cell (client × exit, stderr,
  `kh`), the g-forms table, and the gates (G1, with G1b and G1c beside it).
- [ ] **Step 5: Read G1.** If it passes on 8.5p1, the floor stays; say so in the note. If 8.5p1
  accepts the other type, set `minSSH` in `cmd/port49/ssh.go` to the earliest measured version that
  refuses, update its comment and the message in `sshCmd` ("port49 ssh needs 8.5 or later") and
  decision 42 ruling 10's "Why 8.5" and decision 46 ruling 6 to cite the note, and run `go test
  ./cmd/port49/ -run 'TestAnOldOpenSSHIsRefusedBeforeAMint' -count=1`. Expected: PASS. If a g-forms
  line differs from what `sshPolicy` (Task 3) or `port49.hostkeys.lookup` (Task 9) parse, those
  tasks follow the note, not this plan's expectation. **Read G1c** the same way: if it fails on
  8.5p1 (a hop's askpass has the top ssh as its parent), the pid check of Task 3 cannot tell the
  hop from the device on that version. Stop and take it to Ryan before Task 3; do not weaken
  the check.
- [ ] **Step 6: Commit**

```bash
git add tests/ssh-compat/2026-10-13-openssh-accept-new.md tests/ssh-compat/2026-10-13-openssh-accept-new
git commit -m "test: OpenSSH accept-new with a known alias, and ssh -G's forms, 8.5p1 to 10.2p1

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (Add `cmd/port49/ssh.go` and the spec if Step 5 changed them, and say so in the message.)

---

## Task 3: `port49 ssh` on the operator's OpenSSH known_hosts

**Files:**
- Modify: `cmd/port49/ssh.go` (`sshOptions`, `sshArgs`, `sshCmd`, `askpassServer` (new field
  `keyName`) and its `answer`, `minSSH`'s comment; new `sshTrust`, `sshPolicy`, `sshName`,
  `legacyPinsHint`; `shellWord` moved here from `cmd/port49/trust.go`)
- Modify: `cmd/port49/trust.go` (delete `shellWord`, now in `ssh.go`; the rest goes in Task 4)
- Create: `cmd/port49/ssh_asker_linux.go`, `cmd/port49/ssh_asker_darwin.go`,
  `cmd/port49/ssh_asker_other.go` (`askerParent`, per OS; pre-flight N3)
- Modify: `internal/userconfig/userconfig.go` (add `LegacyPinsPath`)
- Modify: `cmd/port49/main.go` (usage: the `port49 ssh` lines)
- Test: `cmd/port49/ssh_test.go` (the rig; `fakeSSHHead`; `TestSSHArgs`; the host-key tests;
  `TestTheTokenIsNeverInArgvOrTheEnvironment`'s fake), `cmd/port49/ssh_fix_test.go`
  (`TestPortSSHLogsInToADeviceNamedWithCapitals`, `TestTheHostKeyHintIsConditionalOnSSHsMessage`,
  `TestSSHsStderrIsTheCallersOwn`), `cmd/port49/trust_hint_test.go` (one test deleted),
  `cmd/port49/ssh_pty_linux_test.go`
  (`TestSSHRestoresTheTerminalWhenItEnds`'s fake), new `cmd/port49/ssh_hostkeys_test.go`

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
// StrictHostKeyChecking, HostKeyAlias and UserKnownHostsFile from it; an
// error for a config that keeps no host keys under accept-new.
func sshPolicy(ctx context.Context, bin string, o sshOptions) (sshTrust, error)

// sshName reports whether device can be an ssh destination and a known_hosts
// host field as written (decision 42 ruling 8; decision 46 ruling 3).
func sshName(device string) bool

// askpassServer gains, beside device:
//	keyName     string // the alias ssh names in its prompt: sshTrust.keyName
//	askerParent func(net.Conn) (int, error) // the parent pid of the process on c; nil only in a test
//	                                        // that builds a server by hand
//	sshPid      int    // the ssh port49 started (setSSHPid, once it has started)
//	unverified  string // why an asker's parent could not be read, for sshCmd to report

// askerParent is the parent pid of the process that dialled c (pre-flight N3), in
// ssh_asker_{linux,darwin,other}.go. Linux: SO_PEERCRED's pid, then field 4 of
// /proc/<pid>/stat. macOS: LOCAL_PEERPID, then kern.proc.pid's Eproc.Ppid.
// Any other OS, and any read that fails, is an error.
func askerParent(c net.Conn) (int, error)

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

  The fake ssh scripts (pre-flight I2). `sshPolicy` runs the `--ssh` binary with `-G` before the
  real run, and four fakes answer only `-V`, so each would take `-G` as the real run: record argv
  and `exec "$SSH_ASKPASS"` with it unset, exit 255, background a `sleep 3 >&2` that holds the
  `-G` pipe, or run `stty -echo` and print nothing (which `sshPolicy` reads as no known_hosts kept,
  and refuses). Add to `cmd/port49/ssh_test.go`, beside `sshTestBin`:

```go
// fakeSSHHead is a fake ssh's first lines: OpenSSH 10.2p1 to -V, and to -G
// what a real `ssh -G` prints for the one setting sshPolicy needs to go on,
// a known_hosts kept. The lines after it are the fake's real run.
const fakeSSHHead = "#!/bin/sh\n" +
	"if [ \"$1\" = -V ]; then echo 'OpenSSH_10.2p1, OpenSSL 3.5.5' >&2; exit 0; fi\n" +
	"if [ \"$1\" = -G ]; then echo 'userknownhostsfile ~/.ssh/known_hosts'; exit 0; fi\n"
```

  and start each of the four fakes with it in place of its own first two lines:
  `TestTheTokenIsNeverInArgvOrTheEnvironment` (`cmd/port49/ssh_test.go`),
  `TestTheHostKeyHintIsConditionalOnSSHsMessage` and `TestSSHsStderrIsTheCallersOwn`
  (`cmd/port49/ssh_fix_test.go`), and `TestSSHRestoresTheTerminalWhenItEnds`
  (`cmd/port49/ssh_pty_linux_test.go`). For example:

```go
	script := fakeSSHHead + "echo 'remote username contains invalid characters' >&2\nexit 255\n"
```

  `ssh_fix2_test.go`'s wrapper forwards every run but `-V` to the real ssh, `-G` included, and
  stays. Rewrite `TestTheHostKeyHintIsConditionalOnSSHsMessage`'s expectation to Step 4's 255
  message:

```go
	if code != 255 || !strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "If it says Host key verification failed") ||
		!strings.Contains(errb, "run 'ssh-keygen -R leaf1'") || strings.Contains(errb, "devices trust") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
```

- [ ] **Step 2: Write the failing tests** in `cmd/port49/ssh_hostkeys_test.go`:

```go
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
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
// filed under; a Host block matches the destination as written, case and all
// (pre-flight M1). Review Focus 7: a known_hosts of /dev/null or none under
// accept-new is refused; under their yes it stands.
func TestSSHPolicyReadsTheOperatorsConfig(t *testing.T) {
	bin := sshTestBin(t)
	for _, tc := range []struct{ cfg, device, strict, alias, keyName, err string }{
		{"", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking yes", "leaf1", "yes", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking no", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking ask", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"StrictHostKeyChecking accept-new", "leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"Host leaf1\n  HostKeyAlias Corp-Leaf1", "leaf1", "accept-new", "", "corp-leaf1", ""},
		{"Host leaf1\n  HostKeyAlias Corp-Leaf1", "Leaf1", "accept-new", "leaf1", "leaf1", ""},
		{"Match user alice\n  HostKeyAlias alice-leaf1", "leaf1", "accept-new", "", "alice-leaf1", ""},
		{"UserKnownHostsFile /dev/null", "leaf1", "", "", "", "UserKnownHostsFile"},
		{"UserKnownHostsFile none", "leaf1", "", "", "", "UserKnownHostsFile"},
		{"UserKnownHostsFile /dev/null\nStrictHostKeyChecking yes", "leaf1", "yes", "leaf1", "leaf1", ""},
	} {
		cfg := filepath.Join(privateDir(t), "ssh_config")
		if err := os.WriteFile(cfg, []byte(tc.cfg+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := sshPolicy(context.Background(), bin, sshOptions{config: cfg, device: tc.device,
			address: "192.0.2.7", username: "alice"})
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: got %+v, %v; want a refusal naming %s", tc.cfg, got, err, tc.err)
			}
			continue
		}
		if err != nil || got.strict != tc.strict || got.alias != tc.alias || got.keyName != tc.keyName {
			t.Errorf("%q %s: got %+v, %v; want strict %s alias %q keyName %s", tc.cfg, tc.device, got, err,
				tc.strict, tc.alias, tc.keyName)
		}
	}
}

// Review Focus 7: an ssh_config that keeps no host keys would make every
// connection a first contact. It is refused before ssh starts, naming the
// setting; the device sees no connection.
func TestAKnownHostsFileOfDevNullIsRefused(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	if err := os.WriteFile(r.config, []byte("UserKnownHostsFile /dev/null\nGlobalKnownHostsFile /dev/null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := r.run(t, "leaf1")
	if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "UserKnownHostsFile /dev/null") ||
		!strings.Contains(errb, "nothing was sent to leaf1") {
		t.Fatalf("code %d conns %d stderr %q", code, dev.connections(), errb)
	}
	tokenNowhere(t, out, errb)
}

// The operator's StrictHostKeyChecking yes refuses a first contact: nothing
// sent, nothing filed, and the message says a key may be missing, not only
// changed (pre-flight M4).
func TestTheOperatorsStrictYesStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "StrictHostKeyChecking yes")
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || len(dev.attempts()) != 0 || len(r.filed(t, "leaf1")) != 0 ||
		!strings.Contains(errb, "ssh_config says StrictHostKeyChecking yes") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
}

// The operator's own HostKeyAlias is the name ssh looks the key up under, and
// the name ssh's prompt carries: the askpass answers it, once (pre-flight I1).
func TestTheOperatorsHostKeyAliasStands(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil, "Host leaf1\n  HostKeyAlias corp-leaf1")
	if err := os.WriteFile(r.known, []byte("corp-leaf1 "+string(ssh.MarshalAuthorizedKey(dev.key))), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := r.run(t, "leaf1")
	if code != 0 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" || len(r.filed(t, "leaf1")) != 0 ||
		strings.Contains(errb, "Permanently added") {
		t.Fatalf("code %d stderr %q attempts %q", code, errb, dev.attempts())
	}
	tokenNowhere(t, out, errb)
}

// The askpass takes the device's prompt under the inventory name or the
// alias, and no other (pre-flight I1).
func TestTheAskpassAnswersThePromptNamingTheAlias(t *testing.T) {
	for prompt, ours := range map[string]bool{
		"(alice@leaf1) Password: ": true, "(alice@corp-leaf1) Password: ": true,
		"alice@corp-leaf1's password: ": true, "(alice@jump1) Password: ": false,
	} {
		s := &askpassServer{token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "corp-leaf1"}
		a, b := net.Pipe()
		go s.answer(a)
		_, _ = io.WriteString(b, strconv.Quote(prompt)+"\n")
		reply, _ := bufio.NewReader(b).ReadString('\n')
		b.Close()
		if got := strings.HasPrefix(reply, "T "); got != ours {
			t.Errorf("%q: answered %q", prompt, reply)
		}
	}
}

// The device's prompt is answered only to the ssh port49 started: a ProxyJump
// hop's askpass has the hop's ssh for a parent, and its prompt can carry the same
// alias (pre-flight N3). The test process is the asker, over a real Unix
// socket; its parent is the "ssh" and its own pid is a "hop".
func TestTheAskpassAnswersOnlyTheSSHItStarted(t *testing.T) {
	ask := func(t *testing.T, sshPid int) (reply string, killed bool) {
		t.Helper()
		ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "a.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		s := &askpassServer{token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "corp-leaf1",
			askerParent: askerParent}
		s.setSSHPid(sshPid)
		s.setKill(func() { killed = true })
		go s.serve()
		c, err := net.Dial("unix", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = io.WriteString(c, strconv.Quote("(alice@corp-leaf1) Password: ")+"\n")
		reply, _ = bufio.NewReader(c).ReadString('\n')
		return reply, killed
	}
	if reply, _ := ask(t, os.Getppid()); reply != "T LOGINTOKEN\n" {
		t.Errorf("the asker's parent is the ssh: answered %q", reply)
	}
	if reply, killed := ask(t, os.Getpid()); reply != "N\n" || killed {
		t.Errorf("a hop (the asker's parent is another process): answered %q, killed %v", reply, killed)
	}
}

// A hop's prompt through a fake ssh: the askpass is run by a shell the "ssh"
// script started (the trailing echo keeps sh from exec'ing it), not by the
// script, so its parent is not the ssh pid port49 holds, and the token does
// not leave (pre-flight N3). TestTheTokenIsNeverInArgvOrTheEnvironment, whose
// fake execs the askpass itself, is the control: there the token is answered.
func TestAProxyJumpHopsPromptNeverGetsTheToken(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	dir := t.TempDir()
	answer := filepath.Join(dir, "answer")
	script := fakeSSHHead +
		"sh -c '\"$SSH_ASKPASS\" \"$1\" < /dev/null > \"$2\" 2>&1; echo' _ \"(alice@leaf1) Password: \" '" + answer + "'\n" +
		"exit 255\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = filepath.Join(dir, "ssh")
	_, out, errb := r.run(t, "leaf1")
	if b, _ := os.ReadFile(answer); strings.Contains(string(b), "LOGINTOKEN") {
		t.Fatalf("a hop's askpass was answered with the token: %q", b)
	}
	tokenNowhere(t, out, errb)
}

// When the asker's pid or its parent cannot be read (a net.Pipe has no peer
// credentials; neither does an OS this reads none on), nothing is sent and
// ssh is ended, as refuse ends it: never the token, never "not ours".
func TestAnAskerWhoseParentCannotBeReadGetsNothing(t *testing.T) {
	var killed bool
	s := &askpassServer{token: "LOGINTOKEN", username: "alice", device: "leaf1", keyName: "leaf1",
		askerParent: askerParent}
	s.setSSHPid(os.Getppid())
	s.setKill(func() { killed = true })
	a, b := net.Pipe()
	go s.answer(a)
	_, _ = io.WriteString(b, strconv.Quote("(alice@leaf1) Password: ")+"\n")
	reply, _ := bufio.NewReader(b).ReadString('\n')
	b.Close()
	if reply != "X\n" || !killed || s.unverified == "" {
		t.Errorf("answered %q, killed %v, unverified %q", reply, killed, s.unverified)
	}
}

// Decision 42 ruling 8, moved with sshName from hostkeys.ValidName
// (pre-flight M2).
func TestSSHName(t *testing.T) {
	for name, ok := range map[string]bool{
		"leaf1": true, "core-sw01.dc1": true, "srx_fw_04": true, strings.Repeat("a", 253): true,
		"": false, "*": false, "leaf*": false, "a,b": false, "!x": false, "@cert-authority": false,
		"|1|abc": false, "[leaf1]:22": false, "-leaf": false, ".leaf": false, "leaf 1": false,
		"leaf?": false, "leaf1\n": false, strings.Repeat("a", 254): false,
	} {
		if sshName(name) != ok {
			t.Errorf("sshName(%q) = %v", name, !ok)
		}
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

  Move `testHostKey` unchanged (with the `crypto/ed25519`, `crypto/rand` and `ssh` imports it
  needs) from `cmd/port49/trust_test.go` into `cmd/port49/ssh_test.go`: Task 4 deletes
  `trust_test.go`, and the test below still calls it (pre-flight N1). Delete
  `TestTheNoPinHintCarriesTheOperatorsFlags` from `cmd/port49/trust_hint_test.go`: it runs
  `port49 ssh` with no pin and expects the refusal this task removes, so Step 5's `Operators`
  pattern would run it red; the rest of that file goes with `trust.go` in Task 4 (pre-flight N2).
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

Run: `go test ./cmd/port49/ -run 'TestFirstContact|TestAKeyOfAnotherType|TestAnAddressMoved|TestSSHPolicy|TestAKnownHostsFile|TestTheOperators|TestTheAskpass|TestAProxyJump|TestAnAsker|TestSSHName|TestTheKnownHostsFlag|TestThe9aPins|TestSSHArgs|TestAHostWithAnotherKey|TestTheHostKeyHint' -count=1`
Expected: FAIL to compile (`sshPolicy`, `sshTrust`, `sshOptions.trust`, `sshName`,
`askpassServer.keyName`, `askpassServer.askerParent`, `setSSHPid`, `askerParent` undefined).
Without the asker check, `TestAProxyJumpHopsPromptNeverGetsTheToken` would fail on its assertion
(the hop's askpass is answered with the token).

- [ ] **Step 4: Implement.** In `cmd/port49/ssh.go`:
  - Replace `hostkeys.ValidName` with `sshName` (same regexp, moved here with its comment, ruling 8
    and decision 46 ruling 3 cited), and drop the `hostkeys` import.
  - Move `shellWord` from `trust.go` into `ssh.go` unchanged.
  - `minSSH`'s comment loses "8.5 is also the first with KnownHostsCommand, which port49 ssh turns
    off" (pre-flight M3) and gains: "Host keys are the operator's OpenSSH's own (decision 46 ruling
    2); plan 9d's gate G1 measured accept-new against a key of another type under a known alias
    (tests/ssh-compat/2026-10-13-openssh-accept-new.md)."
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
// Under accept-new, a UserKnownHostsFile that keeps nothing (/dev/null, none)
// is refused: every connection would be a first contact, accepted silently.
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
	c := exec.CommandContext(ctx, bin, args...)
	// A descendant holding ssh -G's stderr cannot keep port49 ssh waiting
	// past ssh itself (pre-flight I2).
	c.WaitDelay = time.Second
	out, err := c.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			err = fmt.Errorf("%v: %s", err, printsafe.Line(strings.TrimSpace(string(ee.Stderr)), 300))
		}
		return sshTrust{}, fmt.Errorf("%s -G (reading your ssh_config for %s): %v", bin, o.device, err)
	}
	t := sshTrust{alias: strings.ToLower(o.device), keyName: strings.ToLower(o.device), strict: "accept-new"}
	var userFiles string
	kept := false
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "hostkeyalias":
			t.alias, t.keyName = "", printsafe.Line(v, 253)
		case "stricthostkeychecking":
			if v == "true" || v == "yes" {
				t.strict = "yes"
			}
		case "userknownhostsfile":
			userFiles = v
			for _, f := range strings.Fields(v) {
				kept = kept || f != "/dev/null" && f != "none"
			}
		}
	}
	if !kept && t.strict != "yes" {
		return sshTrust{}, fmt.Errorf("your ssh_config keeps no host keys for %s (UserKnownHostsFile %s): every "+
			"connection would be a first contact, and a host at the device's address would get the token; remove "+
			"that line for port49 devices, or set StrictHostKeyChecking yes with a managed GlobalKnownHostsFile",
			o.device, printsafe.Line(cmp.Or(userFiles, "none"), 200))
	}
	return t, nil
}
```

  (`ssh.go` imports `cmp` for `cmp.Or`; `errors` it imports already.)

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

    and run ssh with `sshArgs(opts)`. The askpass server is built with the name ssh's prompt
    carries (pre-flight I1):

```go
	srv := &askpassServer{ln: ln, token: item.Login, username: item.Username, device: device,
		keyName: opts.trust.keyName, askerParent: askerParent, expiresAt: expiresAt, remint: …as today…}
```

    with, in `askpassServer`, beside `device`:

```go
	keyName          string // the HostKeyAlias ssh names in its prompt (decision 46 ruling 2)
	askerParent      func(net.Conn) (int, error) // see askerParent; nil only where a test builds the server by hand
	sshPid           int    // the ssh port49 started; set under mu by setSSHPid
	unverified       string // why an asker's parent could not be read
```

    `setSSHPid(pid int)` sets `sshPid` under `mu`; `sshCmd` calls it with `c.Process.Pid` beside
    `srv.setKill(...)`, before `go srv.serve()`. In `answer`, after the prompt is parsed and before
    the `switch`, the asker is checked for a device prompt (pre-flight N3):

```go
	own := ownPrompt(prompt, s.username, s.device) || ownPrompt(prompt, s.username, s.keyName)
	if own && s.askerParent != nil {
		ppid, err := s.askerParent(c)
		switch {
		case err != nil:
			// Fail closed: the prompt may be the device's, and nothing says which ssh asked.
			s.unverified = err.Error()
			s.refuse(c)
			return
		case ppid != s.sshPid:
			// A ProxyJump hop's askpass: its parent is the hop's ssh, never the one started here.
			_, _ = io.WriteString(c, "N\n")
			return
		}
	}
```

    (`answer` already holds `s.mu` there, as `refuse` needs.) The first case of the `switch`
    becomes `case !own:`, answering `N`. `sshCmd` reports `s.unverified` where it reports
    `expired`: "%s: could not tell which process asked for the token (%s), so it was not sent and
    ssh was ended".

    `askerParent` per OS. `cmd/port49/ssh_asker_linux.go`:

```go
// SO_PEERCRED names the process that dialled (the askpass, whatever it claims); its parent is
// ssh, which forks the askpass directly (pre-flight N3).
func askerParent(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the askpass connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/stat")
	if err != nil {
		return 0, err
	}
	// "pid (comm) S ppid ...": comm may hold spaces and ')', so count from the last ')'.
	i := bytes.LastIndexByte(stat, ')')
	f := strings.Fields(string(stat[i+1:]))
	if i < 0 || len(f) < 2 {
		return 0, errors.New("/proc/<pid>/stat is not in the form read")
	}
	return strconv.Atoi(f[1])
}
```

    `cmd/port49/ssh_asker_darwin.go` is the same shape, with
    `unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)` for the pid and
    `unix.SysctlKinfoProc("kern.proc.pid", pid)` for the parent (`kp.Eproc.Ppid`).
    `cmd/port49/ssh_asker_other.go` (`//go:build !linux && !darwin`) returns
    `errors.New("this OS has no way to read the asker's parent")`, so there `port49 ssh` ends
    before it sends a token rather than send one unchecked. `TestTheAskpassAnswersOnlyTheSSHItStarted`
    `t.Skip`s on an OS other than Linux and macOS; `TestAnAskerWhoseParentCannotBeReadGetsNothing`
    runs everywhere. L64 (a) and (c) also record, per platform, that the askpass was answered
    (the pid check passes on the platform's own `port49 ssh`).
```

    `ownPrompt`'s comment gains: "Under an operator's own HostKeyAlias the prompt names that alias
    (decision 46 ruling 2), so the askpass asks both names." The `code == 255` (not served)
    message becomes two cases, the operator's `yes` first (pre-flight M4):

```go
	case code == 255 && opts.trust.strict == "yes":
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above). Your ssh_config says StrictHostKeyChecking yes: if ssh says no host key is known, "+
			"no key is filed under %s, so add the device's key to your known_hosts after checking it on its console; "+
			"if it says the key changed, the key filed under %s is not the one %s presents, so verify it on the "+
			"console and run 'ssh-keygen -R %s'\n",
			cmd, device, opts.trust.keyName, opts.trust.keyName, item.Address, shellWord(opts.trust.keyName))
	case code == 255:
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above). If it says Host key verification failed, the key your known_hosts files under "+
			"%s is not the one %s presents: either the device's key changed, or the address inventory gives for %s "+
			"is not the device. Verify the key on its console, then run 'ssh-keygen -R %s' and connect again\n",
			cmd, device, opts.trust.keyName, item.Address, device, shellWord(opts.trust.keyName))
```

    `TestTheOperatorsStrictYesStands` reads the first; both open with "ssh stopped before … so it
    was never sent", which the other 255 tests read.

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

Run: `go test ./cmd/port49/ -run 'SSH|Askpass|ProxyJump|Asker|Ceiling|Token|FirstContact|KeyOfAnotherType|AddressMoved|KnownHosts|Operators|9aPins|HostKeyHint' -count=1`
Expected: PASS (each host-key test runs the real OpenSSH; on a host with none they skip, as
`sshTestBin` says).

- [ ] **Step 6: Commit**

```bash
git add cmd/port49/ssh.go cmd/port49/ssh_asker_linux.go cmd/port49/ssh_asker_darwin.go cmd/port49/ssh_asker_other.go cmd/port49/trust.go cmd/port49/trust_hint_test.go cmd/port49/main.go cmd/port49/ssh_test.go cmd/port49/ssh_fix_test.go cmd/port49/ssh_pty_linux_test.go cmd/port49/ssh_hostkeys_test.go internal/userconfig/userconfig.go
git commit -m "feat: port49 ssh uses the operator's known_hosts under accept-new, filed under the inventory name

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Remove `port49 devices trust` and `internal/hostkeys`; nothing reads under `~/.config`

**Files:**
- Delete: `internal/hostkeys/hostkeys.go`, `internal/hostkeys/hostkeys_test.go`,
  `cmd/port49/trust.go`, `cmd/port49/trust_test.go`, `cmd/port49/trust_hint_test.go`
- Modify: `cmd/port49/main.go` (the `devices trust` case; usage), `internal/userconfig/userconfig.go`
  (`LegacyDir` → `legacyDir`; the package comment), `internal/userconfig/userconfig_test.go` (its
  two `LegacyDir()` calls, ~719–725), `cmd/port49/mint.go` (`mintFailed`'s comment)
- Create: `tests/lab/hostkeyscan_test.go` (`//go:build lab`: `labScan`, `labFingerprint`, moved from
  `hostkeys.Scan` and `hostkeys.Fingerprint`), `tests/lab/hostkeyscan_unit_test.go`
  (`TestLabScanReadsTheKeyAndSendsNoCredential`, moved from `hostkeys_test.go`; pre-flight M2)
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
  file is only named (`LegacyPinsPath`; decision 46 ruling 5)." In `userconfig_test.go`, the two
  `LegacyDir()` calls (~719–725) become `legacyDir()` (the test is in package `userconfig`). The
  package comment's sentence "and the private-file reading and writing it shares with the pinned
  host keys (internal/hostkeys). Whoever can write these files chooses which broker the operator
  trusts and which device keys `port49 ssh` accepts, so …" becomes "and the private-file reading
  and writing it keeps for them. Whoever can write these files chooses which broker the operator
  trusts, so …" (pre-flight M3). In `cmd/port49/mint.go`, `mintFailed`'s comment "shared by `port49
  devices trust` and `port49 ssh`" becomes "shared by `port49 ssh`".
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
  `-run 'TestL53HostKeyScan'` until Task 11 adds L64's test. The scan keeps its unit test
  (pre-flight M2): create `tests/lab/hostkeyscan_unit_test.go` (`//go:build lab`, `package lab`),
  which `make lab-unit` runs by name:

```go
//go:build lab

package lab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// labScan reads the key the server presents and offers no credential: no
// authentication callback of the server's ever runs (moved from
// internal/hostkeys by plan 9d).
func TestLabScanReadsTheKeyAndSendsNoCredential(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var auths atomic.Int32
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { auths.Add(1) },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _, _, _ = ssh.NewServerConn(c, cfg)
		c.Close()
	}()
	got, err := labScan(context.Background(), ln.Addr().String())
	<-done
	if err != nil || string(got.Marshal()) != string(signer.PublicKey().Marshal()) || auths.Load() != 0 {
		t.Fatalf("key %v err %v, %d auth attempts", got, err, auths.Load())
	}
}
```
- [ ] **Step 5: Check** that nothing kept reads under `~/.config`:

```bash
grep -rn "LegacyDir\|legacyDir\|XDG_CONFIG_HOME\|\.config\"" --include='*.go' internal cmd
```

  Expected: only `internal/userconfig/userconfig.go` (`legacyDir`, `noLegacy`, `LegacyPinsPath`),
  `internal/userconfig/userconfig_test.go` (its `legacyDir()` checks) and tests that set
  `XDG_CONFIG_HOME`. Then check the words: `grep -rn "devices trust\|internal/hostkeys\|which port49
  ssh turns off" --include='*.go' internal cmd` prints only `main.go`'s removal line and its
  comment, `ssh.go`'s `legacyPinsHint`, and test lines asserting the words are absent (pre-flight
  M3).

- [ ] **Step 6: Run everything**

Run: `make test && make vet`
Expected: PASS; `make lab-unit` (inside `make test`) builds `tests/lab` with the moved scan.

- [ ] **Step 7: Commit**

```bash
git add -A internal/hostkeys cmd/port49 internal/userconfig tests/lab/hostkeyscan_test.go tests/lab/hostkeyscan_unit_test.go tests/lab/l53_l54_test.go Makefile
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
		// A proof that met the session's own failure says that failure (pre-flight M8).
		{"proof: revoked", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: &agent.RevokedError{Detail: "d"}},
			tokenFailure{Device: "core1", Error: "credential_revoked"}},
		{"proof: over", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrSessionOver},
			tokenFailure{Device: "core1", Error: "session_over"}},
		{"proof: no agent", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: fmt.Errorf("%w at /s: refused", agent.ErrNoAgent)}, tokenFailure{Device: "core1", Error: "no_agent"}},
		{"proof: too old", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrAgentTooOld},
			tokenFailure{Device: "core1", Error: "agent_too_old"}},
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
	case errors.As(err, &unproved):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(unproved.Requirement)
	case errors.As(err, &need):
		f.Error, f.PerLoginMFA = failMFARequired, requirementOf(need.Requirement)
	default:
		f.Error = failAgent
	}
	return f
}
```

  (`KeyCode` is checked before the requirement, so a touch that timed out inside a proof says
  `touch_timeout`; `ErrConnectionChanged` before it too. So are the session's own failures, which
  `prove` meets in `c.Status` and `mfaUnprovedError` wraps: a revoked or ended session, no agent,
  or an agent too old says so, not `per_login_mfa_required`, so the library never tells a person
  whose session was revoked to run `port49 token` at a terminal (pre-flight M8).) In `tokenCmd`:

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
- Create: `clients/python/tests/testdata/workload_every_device_denied.json`,
  `clients/python/tests/testdata/workload_empty_sweep.json` (the CLI's own bytes; Task 8 feeds
  them to the library)
- Test: `cmd/port49/workload_test.go`

**Interfaces:**
- Consumes: `api.MintResponse`, `api.MintItem`, Task 5's `mfaRequirement` and `requirementOf`.
- Produces (Task 8 parses exactly these; `results` and `refused` are `[]`, never `null`):

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

// goldenJSON fails t unless stdout is the golden file the Python library's
// tests are fed (pre-flight I3): the two sides read the same bytes.
func goldenJSON(t *testing.T, name string, stdout []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("..", "..", "clients", "python", "tests", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.TrimSpace(stdout); !bytes.Equal(got, bytes.TrimSpace(want)) {
		t.Fatalf("stdout\n%s\nis not %s\n%s", got, name, want)
	}
}

// Every device denied: exit 77 as before, and stdout says which and why,
// with "results": [] (never null).
func TestWorkloadJSONOnEveryDeviceDenied(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "fw1"), &out, &errb)
	var got workloadJSON
	if code != 77 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 0 || len(got.Refused) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	goldenJSON(t, "workload_every_device_denied.json", out.Bytes())
}

// A scope selecting nothing: exit 77 as before, and stdout says nothing was
// selected, told apart from a failure.
func TestWorkloadJSONOnAnEmptySweep(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Subject: "svc_oxidized"})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "--scope", "none"),
		&out, &errb)
	if code != 77 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	goldenJSON(t, "workload_empty_sweep.json", out.Bytes())
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
		if resp.Results == nil {
			// "results": [], never null: MintResponse.Results has no
			// omitempty, and a reader iterating it must not meet a null
			// (pre-flight I3).
			resp.Results = []api.MintItem{}
		}
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

  and for the empty sweep, after its stderr line:

```go
	case err == nil && *scope != "" && len(resp.Results) == 0:
		fmt.Fprintf(stderr, "%s: scope %s: no device it selects is one you hold a grant on, or no scope has that name\n",
			cmd, safe(*scope))
		if *format == "json" && *out == "" {
			// "Nothing selected", told apart from a failure (decision 46
			// ruling 10): {"principal": …, "results": [], "refused": []}.
			if body, err := render("json", resp, nil, *enable); err == nil {
				_, _ = stdout.Write(body)
			}
		}
		return exitFinal
```

  The golden files the Python tests read are written in this step (pre-flight I3; ruling: the
  Python tests are fed the CLI's own bytes), each the exact stdout of the Go test that reads it,
  without a trailing newline:
  - `clients/python/tests/testdata/workload_every_device_denied.json`:
    `{"principal":"spiffe://corp.example.com/host/oxidized-01","subject":"svc_oxidized","results":[],"refused":[{"device":"fw1","verdict":"deny","reason":"no_grants_matched"}]}`
  - `clients/python/tests/testdata/workload_empty_sweep.json`:
    `{"principal":"spiffe://corp.example.com/host/oxidized-01","subject":"svc_oxidized","results":[],"refused":[]}`

  If a Go test's output differs from its golden file, the golden file is wrong only if the plan's
  bytes are: fix whichever is wrong, and keep the two equal.
- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./cmd/port49/ -run 'Workload' -count=1`
Expected: PASS, the Oxidized wrapper's tests (`examples/oxidized`) unchanged: `go test
./examples/oxidized/ -count=1` PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/workload.go cmd/port49/workload_test.go clients/python/tests/testdata
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
class MFARequired(Port49Error)         # "per_login_mfa_required", the CLI's code or a deny for it;
                                       # .requirement: dict, .reason (the deny's, or None)
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

    def test_a_deny_for_a_second_factor_is_mfa_required(self):  # pre-flight M7: one condition, one class
        a = self.agent({"stdout": fake.item(device="core1", verdict="deny", reason="per_login_mfa_required",
                                            per_login_mfa={"accept": ["hardware_key_touch"], "reuse_for_seconds": 900}),
                        "code": 1})
        with self.assertRaises(MFARequired) as cm:
            a.token("core1")
        self.assertEqual((cm.exception.reason, cm.exception.requirement["accept"]),
                         ("per_login_mfa_required", ["hardware_key_touch"]))

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
	@$(PYTHON) -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { \
	  echo "make test needs python3 3.10 or later (decision 46 ruling 14)"; exit 1; }
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
    """The device asks for a second factor that could not be given here: the CLI's
    per_login_mfa_required, or the broker's deny for it (reason kept)."""

    def __init__(self, code, detail="", device=None, requirement=None, reason=None):
        self.requirement, self.reason = requirement or {}, reason
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
    verdict, reason = obj.get("verdict"), obj.get("reason")
    if verdict and verdict != "permit":
        if reason == "per_login_mfa_required" or obj.get("per_login_mfa"):
            # The condition the CLI's per_login_mfa_required code names: one class for both, a
            # Workload's refused item and an Agent's failure alike (pre-flight M7).
            return MFARequired("per_login_mfa_required", detail, device, requirement=obj.get("per_login_mfa"),
                               reason=reason)
        return Denied(reason or verdict, detail, device, reason=reason, verdict=verdict)
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
  what is retried and why (a `connection_changed` retry asks for a second touch, since the touch
  is bound to the connection that changed; pre-flight M8), and "the token is never in argv, the
  environment, a log or a `repr`".
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
- Consumes: Task 6's `workloadJSON` and `refusedItem`, and its golden files in
  `clients/python/tests/testdata/`; Task 7's `Token`, `Refusal`, `MintResults`, `Temporary`,
  `Final`, `MFARequired`, `failed`, `answer`.
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
from port49 import Final, MFARequired, Port49Error, Temporary, Workload  # noqa: E402

TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def golden(name):
    """The CLI's own stdout, as Task 6's Go tests check it byte for byte (pre-flight I3)."""
    with open(os.path.join(TESTDATA, name), encoding="utf-8") as f:
        return f.read()


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
        self.assertIsInstance(res.refused["core1"].exception(), MFARequired)  # as Agent raises it (M7)
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
        res = self.workload({"stdout": golden("workload_every_device_denied.json"), "code": 77}).tokens(["fw1"])
        self.assertEqual((res.tokens, list(res.refused)), ({}, ["fw1"]))
        self.assertEqual(res.refused["fw1"].reason, "no_grants_matched")

    def test_a_scope_selecting_nothing_is_empty(self):
        res = self.workload({"stdout": golden("workload_empty_sweep.json"), "code": 77}).tokens(scope="none")
        self.assertEqual((res.tokens, res.refused), ({}, {}))

    def test_a_null_list_is_an_empty_one(self):  # a CLI before Task 6's fix printed "results": null
        res = self.workload({"stdout": '{"principal": "p", "results": null, "refused": null}', "code": 77}).tokens(["x"])
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
        # `or []`: a null list is an empty one, never a TypeError (pre-flight I3).
        res = MintResults(
            {it["device"]: Token.of(it) for it in obj.get("results") or [] if it.get("login")},
            {r["device"]: Refusal(r["device"], r.get("verdict"), r.get("reason"), r.get("error"),
                                  _run.printable(r.get("detail") or ""), r.get("per_login_mfa"))
             for r in obj.get("refused") or []})
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
- Consumes: Task 7's `Agent`, `Token`, `HostKeyError`, `_run.printable`; OpenSSH's `ssh -G`,
  `ssh-keygen -F` and `ssh-keygen -Q`; Task 2's note for the `ssh -G` forms.
- Produces:

```python
# port49.hostkeys
@dataclass(frozen=True)
class KnownHosts:
    name: str                 # the name keys are filed under: the operator's alias, else the device lowercased
    keys: tuple               # ("ssh-ed25519 AAAA…", …): the plain keys filed under name, none of them revoked
    authorities: tuple        # "@cert-authority …" lines matching name
    revoked: tuple            # ("ssh-ed25519 AAAA…", …): the keys "@revoked" lines matching name revoke
    krl: str                  # the operator's RevokedHostKeys, or ""
    strict: bool              # the operator's StrictHostKeyChecking is yes
    hash_names: bool          # HashKnownHosts yes
    write_to: str             # the first UserKnownHostsFile that keeps keys ("" under strict with none)
NAME_RULE: str                # decision 42 ruling 8 in port49 ssh's words
def valid_name(device) -> bool
def lookup(device, address, *, port=22, username=None, ssh_config=None, ssh="ssh",
           ssh_keygen="ssh-keygen") -> KnownHosts
def is_revoked(kh: KnownHosts, keytype: str, key_b64: str, *, ssh_keygen="ssh-keygen") -> bool
def remember(kh: KnownHosts, keytype: str, key_b64: str, stderr=None) -> None
def hashed(name: str, salt: bytes | None = None) -> str

# port49.netmiko
DEVICE_TYPES = {"arista_eos": "arista_eos", "cisco_nxos": "cisco_nxos", "cisco_iosxe": "cisco_xe",
                "juniper_junos": "juniper_junos"}
class FirstContact:           # Paramiko's missing-host-key policy for a first contact
    def __init__(self, kh, device, stderr=None)
    def missing_host_key(self, client, hostname, key) -> None
def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs)
```

  `HostKeyError` codes: `device_name`, `address`, `ssh_config_unread`, `known_hosts_unread`,
  `host_key_uncheckable`, `host_keys_not_kept`, `host_key_revoked`, `host_key_unknown`,
  `host_key_changed`. They are the library's own, like the CLI's codes, not §5.7 reason codes.

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

from port49 import HostKeyError, hostkeys  # noqa: E402

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs OpenSSH's ssh and ssh-keygen")
class HostKeysTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.kh = os.path.join(self.dir, "known_hosts")
        open(self.kh, "w").close()

    def config(self, *lines, user=None):
        path = os.path.join(self.dir, "ssh_config")
        with open(path, "w", encoding="ascii") as f:
            f.write("\n".join([f"UserKnownHostsFile {user or self.kh}", "GlobalKnownHostsFile /dev/null", *lines]) + "\n")
        return path

    def newkey(self, name):
        """A fresh Ed25519 public key, "type base64", and its .pub file."""
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
        with open(path + ".pub", encoding="ascii") as f:
            return " ".join(f.read().split()[:2]), path + ".pub"

    def test_nothing_known(self):
        kh = hostkeys.lookup("Leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.name, kh.keys, kh.authorities, kh.revoked, kh.krl, kh.strict, kh.write_to),
                         ("leaf1", (), (), (), "", False, self.kh))

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

    def test_marker_lines_are_kept_apart(self):
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"@cert-authority leaf* {ED}\n@revoked * {ED}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual((kh.keys, len(kh.authorities), kh.revoked), ((), 1, (ED,)))

    def test_a_revoked_filed_key_is_refused_before_connecting(self):  # Review Focus 6; pre-flight C1
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n@revoked * {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config())
        self.assertEqual(cm.exception.code, "host_key_revoked")

    def test_a_revoked_key_beside_another_is_dropped(self):  # always, not only when nothing else is filed
        other, _ = self.newkey("other")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\nleaf1 {other}\n@revoked * {ED}\n")
        self.assertEqual(hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config()).keys, (other,))

    def test_a_krl_revokes_a_filed_key(self):  # Review Focus 6: RevokedHostKeys, read by ssh-keygen -Q
        bad, pub = self.newkey("bad")
        good, _ = self.newkey("good")
        krl = os.path.join(self.dir, "krl")
        subprocess.run(["ssh-keygen", "-q", "-k", "-f", krl, pub], check=True)
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {bad}\n")
        cfg = self.config(f"RevokedHostKeys {krl}")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=cfg)
        self.assertEqual(cm.exception.code, "host_key_revoked")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {good}\n")
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=cfg)
        self.assertEqual((kh.keys, kh.krl), ((good,), krl))
        self.assertTrue(hostkeys.is_revoked(kh, *bad.split()))
        self.assertFalse(hostkeys.is_revoked(kh, *good.split()))

    def test_a_krl_ssh_keygen_cannot_read_is_refused(self):  # fail closed (10.2p1: exit 255, not a KRL)
        plain = os.path.join(self.dir, "plain")
        with open(plain, "w", encoding="ascii") as f:
            f.write(ED + "\n")
        with open(self.kh, "w", encoding="ascii") as f:
            f.write(f"leaf1 {ED}\n")
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(f"RevokedHostKeys {plain}"))
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertIn("RevokedHostKeys", str(cm.exception))

    def test_known_hosts_command_is_refused(self):  # Review Focus 6; pre-flight C1
        with self.assertRaises(HostKeyError) as cm:
            hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("KnownHostsCommand /bin/true %H"))
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertIn("KnownHostsCommand", str(cm.exception))
        self.assertIn("port49 ssh", str(cm.exception))

    def test_a_known_hosts_file_of_dev_null_is_refused(self):  # Review Focus 7; pre-flight I7
        for user in ("/dev/null", "none"):
            with self.assertRaises(HostKeyError, msg=user) as cm:
                hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config(user=user))
            self.assertEqual(cm.exception.code, "host_keys_not_kept")
            self.assertIn("UserKnownHostsFile", str(cm.exception))
        kh = hostkeys.lookup("leaf1", "10.0.0.11", ssh_config=self.config("StrictHostKeyChecking yes", user="/dev/null"))
        self.assertEqual((kh.strict, kh.write_to), (True, ""))  # the operator's yes: nothing accepted, so it stands

    def test_names_known_hosts_would_misread_are_refused(self):  # pre-flight I6
        for name in ("leaf*", "a,b", "a b", "x\ny", "leaf1\n", "@x", "|1|x", "[leaf1]:22", "-leaf", "a" * 254, ""):
            self.assertFalse(hostkeys.valid_name(name), name)
            with self.assertRaises(HostKeyError, msg=repr(name)) as cm:
                hostkeys.lookup(name, "10.0.0.11", ssh_config=self.config())
            self.assertEqual(cm.exception.code, "device_name")
        self.assertTrue(hostkeys.valid_name("a" * 253))
        self.assertTrue(hostkeys.valid_name("core-sw01.dc1"))

    def test_ssh_g_runs_as_port49_ssh_runs_it(self):  # pre-flight M6: HostName's %, and -l for Match user
        kh = hostkeys.lookup("leaf1", "fe80::1%eth0", username="alice",
                             ssh_config=self.config("Match user alice", "  HostKeyAlias alice-leaf1"))
        self.assertEqual(kh.name, "alice-leaf1")

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
EVENTS = []      # "filed" and "authenticated", in the order they happened
NEXT_ERROR = []  # what the next connection raises, as Paramiko would
PRESENTED = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")


class BadHostKeyException(Exception):
    pass


class FakeConnection:
    """Netmiko 4.7.0's shape: with auto_connect=False nothing connects until _open, and key_policy is
    Paramiko's AutoAddPolicy or RejectPolicy as ssh_strict says, until the caller sets another."""

    def __init__(self, **kw):
        captured.clear()
        EVENTS.clear()
        captured.update(kw)
        self.kw = kw
        self.key_policy = "RejectPolicy" if kw["ssh_strict"] else "AutoAddPolicy"
        if not kw.get("auto_connect", True):
            return
        self._open()

    def _open(self):
        with open(self.kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(self.kw["alt_key_file"]).st_mode)
        captured["policy"] = self.key_policy
        if NEXT_ERROR:
            raise NEXT_ERROR.pop()
        key = types.SimpleNamespace(get_name=lambda: PRESENTED[0], get_base64=lambda: PRESENTED[1])
        if not captured["known_hosts"]:
            # Paramiko: no key held for the address, so the policy is asked, after the key exchange
            # and before authentication.
            self.key_policy.missing_host_key(None, self.kw["host"], key)
        EVENTS.append("authenticated")

    def disconnect(self):
        captured["disconnected"] = True


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


def known(*keys, authorities=(), revoked=(), strict=False):
    return hostkeys.KnownHosts("leaf1", tuple(keys), tuple(authorities), tuple(revoked), "", strict, False,
                               "/dev/null")


class NetmikoTest(unittest.TestCase):
    def connect(self, kh, device="leaf1", agent=None, **kw):
        remembered = []

        def remember(k, t, b, stderr=None):
            remembered.append((k.name, t, b))
            EVENTS.append("filed")

        with mock.patch.object(hostkeys, "lookup", return_value=kh), \
                mock.patch.object(hostkeys, "remember", side_effect=remember):
            conn = p49netmiko.connect(device, agent=agent or FakeAgent(), **kw)
        return conn, remembered

    def test_a_known_key_is_the_only_key(self):
        _, remembered = self.connect(known("ssh-ed25519 AAAA1"))
        self.assertTrue(captured["ssh_strict"])
        self.assertFalse(captured["auto_connect"])
        self.assertEqual(captured["policy"], "RejectPolicy")
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-ed25519 AAAA1\n")
        self.assertEqual(captured["mode"], 0o600)
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        self.assertFalse(captured["system_host_keys"] or captured["use_keys"] or captured["allow_agent"])
        self.assertEqual((captured["username"], captured["password"], captured["secret"]), ("alice", "LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual(remembered, [])

    def test_a_first_contact_is_filed_under_the_name_before_authentication(self):  # pre-flight C1
        _, remembered = self.connect(known())
        self.assertFalse(captured["ssh_strict"])
        self.assertIsInstance(captured["policy"], p49netmiko.FirstContact)
        self.assertEqual(captured["known_hosts"], "")
        self.assertEqual(remembered, [("leaf1", PRESENTED[0], PRESENTED[1])])
        self.assertEqual(EVENTS, ["filed", "authenticated"])

    def test_a_revoked_key_at_first_contact_is_refused_before_auth(self):  # Review Focus 6; pre-flight C1
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(revoked=(" ".join(PRESENTED),)))
        self.assertEqual(cm.exception.code, "host_key_revoked")
        self.assertEqual(EVENTS, [])  # neither filed nor authenticated
        self.assertTrue(captured.get("disconnected"))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_another_port_is_filed_in_brackets_for_paramiko(self):
        self.connect(known("ssh-ed25519 AAAA1"), port=2222)
        self.assertEqual(captured["known_hosts"], "[10.0.0.11]:2222 ssh-ed25519 AAAA1\n")

    def test_a_key_of_another_type_under_a_known_name_is_refused(self):  # Review Focus 1
        # Paramiko, holding the filed RSA key for the address, raises BadHostKeyException for an
        # Ed25519 one: our_key is None, so it compares against the first key held (client.py:461-466).
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAAC3', "
                                              "expected 'AAAAB3'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-rsa AAAAB3"))
        self.assertTrue(captured["ssh_strict"])
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-rsa AAAAB3\n")
        self.assertIn("ssh-keygen -R leaf1", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_an_address_moved_to_another_host_is_refused(self):  # Review Focus 2
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAA9', "
                                              "expected 'AAAA1'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-ed25519 AAAA1"))
        self.assertIn("is not the one 10.0.0.11 presents", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_a_certificate_authority_alone_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(authorities=("@cert-authority leaf* ssh-ed25519 AAAA",)))
        self.assertEqual(captured, {})
        self.assertIn("cannot check", str(cm.exception))

    def test_strict_yes_with_nothing_known_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError):
            self.connect(known(strict=True))
        self.assertEqual(captured, {})

    def test_a_bad_name_is_refused_before_minting(self):  # pre-flight I6, M14
        agent = FakeAgent()
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(), device="leaf*", agent=agent)
        self.assertEqual((cm.exception.code, agent.asked), ("device_name", []))

    def test_the_security_options_cannot_be_overridden(self):  # pre-flight M16 adds sock and ssh_config_file; N4 ip
        for kw in ("ssh_strict", "sock", "ssh_config_file", "auto_connect", "ip"):
            with self.assertRaises(ValueError, msg=kw):
                self.connect(known("ssh-ed25519 AAAA1"), **{kw: None})
```

  Note on the impostor tests (pre-flight M5): Paramiko 4.0.0, holding any key for the address,
  raises `BadHostKeyException` for a different key of the same type and for a key of another type
  alike (`client.py:461-466`: `our_key is None` takes the first key held, then raises); a
  missing-host-key policy is asked only when nothing is held. The fake raises it for both, and
  `is_host_key_failure` (Step 3) recognises it by type name and message. L65 (c) and (d) measure
  both against devices.

- [ ] **Step 2: Run them to see them fail**

Run: `make test-python`
Expected: FAIL (`cannot import name 'hostkeys'`).

- [ ] **Step 3: Implement** `src/port49/hostkeys.py`:

```python
"""Host keys for the Python client (decision 46 ruling 13): OpenSSH's own
files and settings, read through OpenSSH's own tools, and accept-new under
the device's inventory name, the name `port49 ssh` files keys under.

`ssh -G` reads the operator's ssh_config as ssh would; `ssh-keygen -F` finds
the lines filed under a name, hashed or not, patterns included; `ssh-keygen -Q`
reads a RevokedHostKeys file. Nothing here parses ssh_config, matches
known_hosts patterns or reads a KRL itself. What this client cannot honour as
ssh would (a KnownHostsCommand, a RevokedHostKeys ssh-keygen cannot read) is
refused, never passed."""

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace

from . import _run
from .errors import HostKeyError

# Decision 42 ruling 8, `port49 ssh`'s sshName: known_hosts reads '*', '?', '!', ',' and '[' as patterns, and a
# leading '@' or '|' as a marker or a hash, so a name holding one could file a key for other devices.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
NAME_RULE = ("port49 takes devices named with letters, digits, '.', '_' and '-' only (decision 42 ruling 8), since "
             "the name is written into your known_hosts; use `port49 token` and your own client for it")

# A UserKnownHostsFile that keeps nothing.
_KEEPS_NOTHING = ("/dev/null", "none")


@dataclass(frozen=True)
class KnownHosts:
    name: str
    keys: tuple
    authorities: tuple
    revoked: tuple
    krl: str
    strict: bool
    hash_names: bool
    write_to: str


def valid_name(device):
    """Whether device can be written into known_hosts as a host field, as `port49 ssh`'s sshName says."""
    return isinstance(device, str) and _NAME.fullmatch(device) is not None


def _ssh_g(device, address, port, username, ssh_config, ssh):
    # As `port49 ssh` runs it (sshPolicy): HostName double-quoted with each '%' doubled, since ssh expands
    # %-tokens in it (an IPv6 zone's "%eth0"), and -l, so a `Match user` block reads as it does for the login.
    argv = [ssh, "-G"] + (["-F", ssh_config] if ssh_config else [])
    argv += ["-o", 'HostName="' + address.replace("%", "%%") + '"'] + (["-l", username] if username else [])
    argv += (["-p", str(port)] if port and port != 22 else []) + ["--", device]
    try:
        out = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                             check=True).stdout
    except subprocess.CalledProcessError as e:
        said = _run.printable((e.stderr or "").strip(), 300) or f"exit {e.returncode}"
        raise HostKeyError("ssh_config_unread", f"{ssh} -G could not read your ssh_config: {said}", device) from None
    except (OSError, subprocess.SubprocessError) as e:
        raise HostKeyError("ssh_config_unread", f"{ssh} -G could not read your ssh_config: {e}", device) from None
    conf = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        conf[k] = v
    return conf


def lookup(device, address, *, port=22, username=None, ssh_config=None, ssh="ssh", ssh_keygen="ssh-keygen"):
    """What OpenSSH's files hold for device, as ssh reads them, with every revoked key dropped. Refuses,
    before anything connects, what this client cannot honour as ssh does (decision 46 ruling 13)."""
    if not valid_name(device):
        raise HostKeyError("device_name", f"{str(device)[:64]!r}: {NAME_RULE}")  # repr: no newline, no escape
    if '"' in address or "\n" in address:
        raise HostKeyError("address", "the broker gives an address ssh cannot be handed; tell the operator", device)
    conf = _ssh_g(device, address, port, username, ssh_config, ssh)
    command = conf.get("knownhostscommand", "")
    if command and command != "none":
        raise HostKeyError("host_key_uncheckable", "your ssh_config sets KnownHostsCommand, which this client cannot "
                           "run as ssh does, and reading past it could accept a key ssh refuses: use port49 ssh for "
                           "this device, or file its key in a known_hosts file", device)
    name = conf.get("hostkeyalias") or device.lower()
    strict = conf.get("stricthostkeychecking") in ("true", "yes")
    user = conf.get("userknownhostsfile", "").split()
    kept = [p for p in user if p not in _KEEPS_NOTHING]
    if not kept and not strict:
        raise HostKeyError("host_keys_not_kept", f"your ssh_config keeps no host keys (UserKnownHostsFile "
                           f"{' '.join(user) or 'none'}): every connection would be a first contact, and a host at "
                           f"the device's address would get the token; remove that line for port49 devices", device)
    krl = conf.get("revokedhostkeys", "")
    files = kept + [p for p in conf.get("globalknownhostsfile", "").split() if p not in _KEEPS_NOTHING]
    keys, authorities, revoked = [], [], []
    for path in files:
        if not os.path.isfile(path):
            continue
        r = subprocess.run([ssh_keygen, "-F", name, "-f", path], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=10)
        if r.returncode not in (0, 1):
            raise HostKeyError("known_hosts_unread", f"{ssh_keygen} -F {name} -f {path}: "
                               f"{_run.printable(r.stderr.strip(), 300)}", device)
        for line in r.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if fields[0] == "@revoked":
                if len(fields) >= 4:
                    revoked.append(f"{fields[2]} {fields[3]}")
            elif fields[0].startswith("@"):
                authorities.append(line)
            elif len(fields) >= 3:
                keys.append(f"{fields[1]} {fields[2]}")
    kh = KnownHosts(name, (), tuple(authorities), tuple(dict.fromkeys(revoked)), "" if krl == "none" else krl,
                    strict, conf.get("hashknownhosts") == "yes", kept[0] if kept else "")
    filed = tuple(k for k in dict.fromkeys(keys) if not is_revoked(kh, *k.split(" ", 1), ssh_keygen=ssh_keygen))
    if keys and not filed:
        raise HostKeyError("host_key_revoked", f"every key filed under {name} is revoked (an @revoked line, or your "
                           f"RevokedHostKeys): verify the device's key on its console before filing another", device)
    return replace(kh, keys=filed)


def is_revoked(kh, keytype, key_b64, *, ssh_keygen="ssh-keygen"):
    """Whether an @revoked line matching kh.name, or the operator's RevokedHostKeys, revokes the key, as ssh
    would refuse it. A RevokedHostKeys that ssh-keygen -Q cannot read is refused, never passed."""
    if f"{keytype} {key_b64}" in kh.revoked:
        return True
    if not kh.krl:
        return False
    with tempfile.TemporaryDirectory(prefix="port49-") as tmp:
        pub = os.path.join(tmp, "key.pub")
        with open(pub, "w", encoding="ascii") as f:
            f.write(f"{keytype} {key_b64}\n")
        try:
            r = subprocess.run([ssh_keygen, "-Q", "-f", kh.krl, pub], stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:
            r, why = None, str(e)
    if r is not None and r.returncode in (0, 1):  # measured on 10.2p1: 0 not revoked, 1 revoked
        return r.returncode == 1
    if r is not None:
        why = _run.printable(r.stderr.strip(), 300) or f"exit {r.returncode}"
    raise HostKeyError("host_key_uncheckable", f"{ssh_keygen} -Q could not read your RevokedHostKeys {kh.krl} "
                       f"({why}), so no key can be checked against it. ssh honours a plain key list there, but "
                       f"this client needs a KRL (ssh-keygen -k); or use port49 ssh for this device")


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
once filed, and filed at first contact, before authentication, unless revoked.
The token is never printed."""

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
# against the device's login-attempt limit); and ssh_config_file and sock, either of which could steer
# Paramiko to another host than the address the key was checked for (pre-flight M16); and ip, which Netmiko
# sets self.host from before host (base_connection.py:346-349), so a caller's ip= would do the same (N4).
OWNED = {"ssh_strict", "system_host_keys", "alt_host_keys", "alt_key_file", "use_keys", "allow_agent", "host",
         "username", "password", "secret", "device_type", "auto_connect", "ssh_config_file", "sock", "ip"}


class FirstContact:
    """Paramiko's missing-host-key policy for a device with no key filed (decision 46 ruling 13). Paramiko
    calls it with the key the device presented, after the key exchange and before any authentication
    (Paramiko 4.0.0 client.py:455-460), so the token never goes to a key refused here. A key an @revoked
    line or the operator's RevokedHostKeys revokes is refused; any other is filed under the inventory name,
    as OpenSSH's accept-new files it, before the login goes on."""

    def __init__(self, kh, device, stderr=None):
        self.kh, self.device, self.stderr = kh, device, stderr

    def missing_host_key(self, client, hostname, key):
        keytype, key_b64 = key.get_name(), key.get_base64()
        if hostkeys.is_revoked(self.kh, keytype, key_b64):
            raise HostKeyError("host_key_revoked", f"{hostname} presents a {keytype} key that is revoked (an "
                               f"@revoked line, or your RevokedHostKeys): it was not filed, and the token was not "
                               f"sent", self.device)
        hostkeys.remember(self.kh, keytype, key_b64, stderr=self.stderr)


def is_host_key_failure(exc):
    """Whether exc, or what it wraps, is Paramiko refusing the host key: BadHostKeyException, for a changed
    key and for a key of another type alike while any key is held for the address (Paramiko 4.0.0
    client.py:461-466), or an SSHException saying the server is not in known_hosts (RejectPolicy, should
    nothing be held). Netmiko may wrap either, so the chain is walked."""
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
    if not hostkeys.valid_name(device):
        # Before the mint: nothing is minted for a name known_hosts would misread (pre-flight I6, M14).
        raise HostKeyError("device_name", f"{str(device)[:64]!r}: {hostkeys.NAME_RULE}")
    tok = (agent or Agent()).token(device, enable=enable)
    device_type = DEVICE_TYPES.get(tok.platform)
    if device_type is None:
        raise ValueError(f"{device}: platform {tok.platform!r} has no Netmiko device type here")
    port = int(netmiko_kwargs.get("port", 22))
    # After the mint, since ssh -G reads the address it gives (Match host): a refusal from here on leaves
    # the token unused, to expire.
    kh = hostkeys.lookup(device, tok.address, port=port, username=tok.username, ssh_config=ssh_config)
    if not kh.keys and kh.authorities:
        raise HostKeyError("host_key_uncheckable", f"a {kh.authorities[0].split()[0]} line in your known_hosts "
                           f"covers {kh.name}, and Paramiko cannot check a host certificate: file the device's own "
                           f"key under {kh.name}, or use port49 ssh", device)
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
        conn = ConnectHandler(device_type=device_type, host=tok.address, username=tok.username,
                              password=tok.login, secret=tok.enable or "",
                              ssh_strict=bool(kh.keys), system_host_keys=False, alt_host_keys=True,
                              alt_key_file=known, use_keys=False, allow_agent=False, auto_connect=False,
                              **netmiko_kwargs)
        if not kh.keys:
            # A first contact: the presented key is checked and filed before authentication, not after
            # the login (pre-flight C1).
            conn.key_policy = FirstContact(kh, device, stderr=sys.stderr)
        try:
            conn._open()  # what auto_connect=True runs: the connection, then the session's preparation
        except BaseException as e:
            try:
                conn.disconnect()
            except Exception:
                pass
            if isinstance(e, HostKeyError):
                raise
            if is_host_key_failure(e):
                raise HostKeyError("host_key_changed", f"the key filed under {kh.name} is not the one {tok.address} "
                                   f"presents: either the device's key changed, or the address is not the device. "
                                   f"Verify the key on its console, then run 'ssh-keygen -R {kh.name}'", device) from None
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return conn
```

  (`from None` drops Paramiko's text, which names the address but never the token; the token is in
  no exception here, since Paramiko never puts a password in one. `_open` is Netmiko's own split of
  its constructor, "decouple connection creation from __init__", in 4.7.0; `netmiko>=4.7` pins it,
  and L65 runs it against devices.) `examples/netmiko/show_version.py`:

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
  `keyboard-interactive` kept. `clients/python/README.md`'s "Host keys" section says the same and
  what is refused, and why: a device name known_hosts would read as a pattern (before the mint);
  a `KnownHostsCommand` (use `port49 ssh`); a `UserKnownHostsFile /dev/null` under accept-new; a
  key an `@revoked` line or `RevokedHostKeys` names, filed or presented at first contact; a
  `RevokedHostKeys` `ssh-keygen -Q` cannot read (a plain key list, which ssh itself honours and
  this client does not: your file is not broken, make a KRL from it with `ssh-keygen -k`;
  pre-flight N5). A refusal after the mint leaves that token unused; it expires (pre-flight M14). The
  claims that Paramiko refuses before authentication are marked provisional on L65 until Task 11
  closes it (pre-flight M9).

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
  - Host keys are Ansible's own, and C(network_cli) keys them by C(ansible_host), not by the port49 name;
    see the collection README before setting C(host_key_auto_add), and never set it with C(ssh_type=paramiko).
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
  as L66 (a) measures), `receipt_max_age` (a play longer than it mints again), devices that ask
  for `hardware_key_touch` (run `port49 token <one such device>` before the play, so `reuse_for`
  covers the forks; pre-flight M15), and a "Host keys" section that Task 12 completes from L66.
  Written now, every setting in it marked provisional on L66 (pre-flight M9):
  - host keys are Ansible's own `host_key_checking` and `host_key_auto_add`, and `network_cli`
    keys them by `ansible_host`, the address in Ansible's inventory, not by the port49 name. So
    an address added to a device in the source of truth (a dynamic inventory from it, the usual
    case) is a first contact for Ansible, and under `host_key_auto_add` a host at that address
    is accepted and given the token: design §17's attack is open on this path, as it is not for
    `port49 ssh` (pre-flight I4). Said plainly, with what flags it: the sync diff's
    address-change security event (spec §10);
  - where the connection runs OpenSSH (`ansible.builtin.ssh`), set `ansible_ssh_extra_args: "-o
    HostKeyAlias={{ inventory_hostname }}"`, which files keys under the name as `port49 ssh` does
    and closes that gap there;
  - never `host_key_auto_add` with `ssh_type: paramiko`: its close rewrites `~/.ssh/known_hosts`
    from Paramiko's parse, which drops `@revoked` and `@cert-authority` lines and comments, and
    so silently weakens every later `port49 ssh` and Python login (pre-flight I5). Use the path
    that leaves the file intact (`libssh`, which appends);
  - a re-keyed device has two entries: the name (`port49 ssh`, Python, `ansible.builtin.ssh` with
    the alias) and the address (`network_cli`); `ssh-keygen -R` both (pre-flight M13).
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

The run is on the SER8 lab box: WSL2 cannot boot the vJunos-router and vSRX images (pre-flight
M10). The lab is single-occupant; the watchdog runs throughout.

- [ ] **Step 1: The harness.** Per platform, a private `HOME` (0700) with `~/.ssh/config` holding
  only `UserKnownHostsFile ~/.ssh/known_hosts` and `GlobalKnownHostsFile /dev/null`, and an empty
  `known_hosts`; one capture for the run; each cell counts TACACS+ packets in its own window, the
  good login's window the positive control (a zero is a zero of a counter that counts). Cells:
  - **L64 (a):** `port49 ssh -v <node> -- show version`: exit, methods ssh tried, askpass asks,
    redeem records, the output present, and every line `ssh-keygen -F <node>` finds, read after
    the login (ssh's `UpdateHostKeys`, on by default even under an alias, as `ssh -G` on 10.2p1
    shows, may file further key types after authentication; EOS runs OpenSSH): each line's key
    type, not only the first (pre-flight M17).
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
    exit 0, no line added. **(f):** an `@revoked` line naming the device's own key added beside
    the filed entry: `connect` raises `HostKeyError` (`host_key_revoked`) before connecting; then
    `known_hosts` emptied but for that `@revoked` line: `connect` raises `HostKeyError`
    (`host_key_revoked`) from `FirstContact`, 0 TACACS+ packets, the token never presented,
    nothing filed.
  Never print a token; the venv script reads it from the library and prints only the outcome.
- [ ] **Step 2: Unit-test the readers.** `l64_l65_unit_test.go` tests the classifiers that read
  ssh's stderr into "accepted / changed / other type" and count lines, against fixtures from
  Task 2's note (OpenSSH 10.2p1's wording), under `make lab-unit`.
- [ ] **Step 3: Commit the harness** before any run, so the results commit holds results only
  (pre-flight M10):

```bash
git add tests/lab/l64_l65_test.go tests/lab/l64_l65_unit_test.go Makefile
git commit -m "test: the L64 and L65 harness: port49 ssh under accept-new, and the Python client, per platform

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Run** `PORT49_LAB_PLATFORMS=<each> make lab-ssh` on the SER8 with the lab watchdog
  armed (a background stall watchdog, re-armed on wake). Copy raw pcaps to the main checkout
  before removing any lab worktree.
- [ ] **Step 5: Write the notes** (the host, platform, image version, the venv's Netmiko and
  Paramiko versions, OpenSSH's, each cell's observation, the capture pointer) and read them. Close
  L64 and L65 per platform only where every cell read as claimed; a row with one platform measured
  and others open stays open. **Gate (pre-flight M11):** if (b) finds a key that changes at a
  reload on any platform, stop and ask Ryan before writing any note's conclusion or doc. On such a
  platform every `port49 ssh` and every Python connection stops after each maintenance window
  and needs an `ssh-keygen -R` per device: fleet toil, which a doc note does not answer. Nothing
  is weakened to hide it while Ryan decides.
- [ ] **Step 6: Commit the results**

```bash
git add tests/lab/results tests/lab/evidence docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L64 and L65

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (If a row stays open, the message says "measure lab register entries … (open: …)".)

---

## Task 12: Lab — L66 (the Ansible lookup), five platforms

**Files:**
- Create: `tests/lab/l66_test.go` (`//go:build lab`, behind `PORT49_LAB_ANSIBLE=1`),
  `tests/lab/l66_unit_test.go`, `tests/lab/l66/` (the playbooks, inventory and the stand-in
  sshd's container setup the harness writes from), `tests/lab/results/L66-<platform>.md`
- Modify: `Makefile` (`lab-ansible`), `clients/ansible/ansible_collections/port49/client/README.md`
  (the "Host keys" section, from L66), the spec's §15 L66 Status

**Interfaces:** Consumes the lab venv with `ansible-galaxy collection install cisco.ios
junipernetworks.junos` and `pip install ansible-pylibssh ./clients/python`, the collection from
`clients/ansible` (`ANSIBLE_COLLECTIONS_PATH`), `make build`, the agent (`l29Agent`).

The run is on the SER8 lab box, as Task 11's (pre-flight M10).

- [ ] **Step 1: The harness.** Per platform, a private `HOME`, `ANSIBLE_COLLECTIONS_PATH` naming
  `clients/ansible` first, and an inventory of the one node with `ansible_connection:
  ansible.netcommon.network_cli` and the platform's `ansible_network_os`. One capture for the
  run; each cell counts TACACS+ packets in its own window, and a good login's window in the same
  capture is the positive control for every "0 TACACS+ packets" (a zero is a zero of a counter
  that counts; pre-flight M10). Cells:
  - **(a)** a ten-task play (each task a `*_command` `show version`) with `ansible_password: "{{
    lookup('port49.client.token', inventory_hostname) }}"` and `ansible_user` from a second lookup
    with `field='username'`: count `mint` records (and `redeem`s) for the run.
  - **(b)** the same play minting once in a `pre_tasks` `set_fact` (`field='all'`, `no_log`):
    count mints, redeems, and TACACS+ authentication starts in the capture.
  - **(c)** host keys, for `ansible_network_cli_ssh_type: libssh` and then `paramiko`, each from a
    known_hosts holding only a comment line, an `@revoked` line for an unrelated key and an
    `@cert-authority` line for an unrelated pattern, with `ANSIBLE_HOST_KEY_CHECKING=True` and
    `ANSIBLE_HOST_KEY_AUTO_ADD=True`: the play passes; which file gained which line under which
    name (address, port form); and the file's comment and marker lines after the run, verbatim
    beside the before (whether it was appended to, or rewritten without them; pre-flight I5).
    Then that line's key replaced by a fresh key of its type: the play fails before
    authentication, 0 TACACS+ packets, the token never presented (records other than `mint` and
    `blob`: none).
  - **(d)** a denied device (inventory name with no grant): the task fails naming
    `no_grants_matched`; `ansible-playbook -vvv` output holds no token (grep for every minted
    token the harness learned from the decision log's `credential_sha256`, never the token itself:
    the harness hashes each `-vvv` word and compares).
  - **(e)** an address moved (pre-flight I4): after a run that filed the device's key, the
    inventory's `ansible_host` changed to a stand-in host (a throwaway sshd container on the lab
    bridge, its own key, logging each password attempt but never its text). For `libssh`,
    `paramiko`, `libssh` with `ansible_libssh_config_file` naming an ssh_config with `Host *` /
    `HostKeyAlias <the node's name>`, and `ansible.builtin.ssh` (the `raw` module, `ansible_ssh_extra_args:
    "-o HostKeyAlias={{ inventory_hostname }}"`): whether the stand-in's key is auto-added, and
    whether the stand-in logged a password attempt (the token presented).
  Record the versions: ansible-core, `ansible.netcommon`, each platform collection,
  `ansible-pylibssh`, Paramiko, OpenSSH.
- [ ] **Step 2: Unit-test the readers** (the PLAY RECAP, the record counts, the known_hosts
  before/after diff, the stand-in's log) under `make lab-unit`.
- [ ] **Step 3: Commit the harness** before any run (pre-flight M10):

```bash
git add tests/lab/l66_test.go tests/lab/l66_unit_test.go tests/lab/l66 Makefile
git commit -m "test: the L66 harness: the Ansible lookup's mints and host keys, per platform and ssh_type

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Run** `PORT49_LAB_ANSIBLE=1 PORT49_LAB_PLATFORMS=<each> make lab-ansible` on the
  SER8 with the watchdog armed (target: `go test -tags lab ./tests/lab/ -run 'TestL66' -count=1 -v
  -timeout 90m`).
- [ ] **Step 5: Write the notes, then the README's "Host keys".** For each `ssh_type`, the settings
  that give accept-new as measured (or, if one does not save a first contact or does not refuse a
  changed key before authentication, say so and recommend the one that does). Never
  `host_key_auto_add` with an `ssh_type` that (c) found rewriting the file without its marker
  lines or comments; recommend the one that leaves it intact (ruling I5). (e) says, per path,
  whether an address moved in Ansible's inventory meets the key under the name; where it does
  not, the README says so as the gap it is (ruling I4). Drop the "provisional on L66" marks only
  for what was measured. The pattern's section states the measured counts: (a) N mints per host
  for ten tasks, (b) one. Close L66 per platform where every cell read as claimed.
- [ ] **Step 6: Commit the results**

```bash
git add tests/lab/results tests/lab/evidence clients/ansible docs/design/2026-08-23-policy-engine-spec.md
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
    one touch or several (the agent's token lock serializes them; unmeasured); the README's
    pre-play `port49 token <one such device>` stands until then;
  - **Ansible's address keying:** if L66 (e) finds no `network_cli` path that keys host keys by
    name, design §17's attack stays open for `network_cli` under `host_key_auto_add`, documented as
    a gap; whether port49 can close it (for one, a lookup check that refuses a new address for a
    device whose key is filed under its name) is a decision for Ryan, not this plan;
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
  exchange. An ssh_config with `UserKnownHostsFile /dev/null` (often beside `StrictHostKeyChecking
  no` in a `Host *` block) is refused, naming the line: it would make every connection a first
  contact. Your own `Host` blocks match the device name as written, case and all. A refusal that
  comes after the mint (`ssh -G` failing, that `/dev/null`) leaves the token unused; it expires.
- **Why it matters.** The token is the device's password for its lifetime. A host that takes it
  can replay it to the real device until it expires. The window port49 leaves is the first contact,
  per device and per operator, the same one every SSH user accepts.
- **Checking a first contact.** Compare the fingerprint ssh prints with the device's console:
  NX-OS `show ssh key` prints a SHA256 fingerprint; EOS `show management ssh hostkey <type>
  public`, Junos `file show /etc/ssh/ssh_host_<type>_key.pub`, IOS-XE `show ip ssh` print the key,
  so run `ssh-keygen -lf` on it (L53; the type is the one ssh filed, L64).
- **A changed key.** `port49 ssh` says the key filed under the name is not the one the address
  presents. Either the device was re-keyed (verify the new key on its console, then `ssh-keygen -R
  core-sw01`), or the address is not the device: tell security. Ansible's `network_cli` files its
  own entry under the address, so a re-keyed device you also reach from Ansible needs both:
  `ssh-keygen -R core-sw01` and `ssh-keygen -R 10.0.0.11` (`-R '[10.0.0.11]:2222'` on another
  port). For a planned fleet re-key (an image upgrade), over a file of inventory names and one of
  their addresses: `while read -r d; do ssh-keygen -R "$d"; done < devices.txt` and the same over
  `addresses.txt`. That reopens the first-contact window for every device in it, until each is
  reached again; check a sample on the console.
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
  one is refused there; use `port49 ssh`, or file its key. A key an `@revoked` line or your
  `RevokedHostKeys` (a KRL) names is refused, filed or at first contact, before authentication;
  a `KnownHostsCommand` is refused (use `port49 ssh`); a device name holding `*`, `,`, a space and
  the like is refused before anything is minted.
- **Ansible.** `ansible-galaxy collection install` the collection and `pip install port49` on the
  controller. Mint once per host per play (`pre_tasks`, `set_fact`, `no_log: true`); a lookup in
  `ansible_password` mints at every task (L66). For devices that ask for a touch, run `port49
  token <one such device>` before the play, so one proof covers the forks. Host keys are
  Ansible's own, and `network_cli` keys them by `ansible_host`, the address, not the name: an
  address changed in Ansible's inventory is a first contact there, and with `host_key_auto_add`
  the host at it gets the token. Where the connection runs OpenSSH, set `-o HostKeyAlias={{
  inventory_hostname }}`. Never use `host_key_auto_add` with `ssh_type: paramiko`: it rewrites
  `~/.ssh/known_hosts` without its `@revoked` and `@cert-authority` lines. The settings per
  `ssh_type` are as L66 measured.
