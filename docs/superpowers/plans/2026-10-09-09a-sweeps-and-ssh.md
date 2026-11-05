# Plan 9a: Sweeps by Scope, the Per-User Config File, and `port49 ssh` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first part of design §19 step 9, "Agent in full". It covers four things: mint by
`scope`, owed by plan 8; the per-user config file, owed by plan 3; `port49 ssh` with pinned host
keys and `port49 devices trust`; and the Netmiko integration example. The work is written into
the spec first and measured on five platforms.

**Plan 9 is split four ways** (roadmap, "Plan 9"). This is 9a.
- **9b:** the OIDC public client.
- **9c:** hardware-backed client keys and the broker certificate's CRL check.
- **9d:** host keys carried by inventory, and the Python and Ansible clients.

The boundary is the client's credential. 9a works with today's credential, a PEM key and a
certificate. 9b and 9c change what the agent holds. 9d changes what the broker returns.

- **Mint by scope (ruling 1).** `POST /v1/tokens` takes `scope` in place of `devices`, and `after`
  to continue.
  - A page holds the devices the scope selects on which the caller holds a grant, in name order,
    `batch_max` at most. The answer carries `next` while more devices remain.
  - Each device is answered per item, exactly as a device named would be.
- **No enumeration oracle (ruling 2).** Three requests get one answer, byte for byte, and one
  record:
  - a scope the policy does not declare;
  - a declared scope selecting no device the caller holds a grant on;
  - a page past the end.
- **`port49 workload token --scope NAME` (ruling 5).** It sweeps page by page, and the Oxidized
  wrapper takes `PORT49_SCOPE`. Oxidized can then ask for "every device I may back up" in place
  of a node list.
- **The config file (ruling 6).** `$XDG_CONFIG_HOME/port49/config.yaml` holds `broker`,
  `broker_ca`, `cert` and `key`, and each flag overrides its key.
  - It is read only when the operator alone can write it and its directory.
  - `broker_ca` stays required: it pins the CA, never the system roots.
- **Pinned host keys (rulings 7–9).** `$XDG_CONFIG_HOME/port49/known_hosts` is OpenSSH format,
  keyed by the device's inventory name.
  - `port49 devices trust DEVICE` reads the key the device presents, by a key exchange abandoned
    before authentication. It pins the key only against a `--fingerprint` the operator verified,
    or on a `yes` typed at a terminal.
  - A device with no pinned key is refused before anything is minted.
- **`port49 ssh DEVICE [-- COMMAND]` (ruling 10).** It mints through the agent and runs the
  operator's OpenSSH (8.5 or later, measured: `tests/ssh-compat/2026-10-09-openssh-askpass.md`)
  with their own `ssh_config`. These are forced on the command line:
  - the pinned file, the device's name as `HostKeyAlias`, and strict checking;
  - no public-key authentication (L51);
  - `keyboard-interactive,password`.

  The token reaches ssh only through its askpass, which is port49 itself. It is answered once,
  to the prompt naming `<username>@<device>`. A second ask for it ends the connection, so no
  repeated or empty password reaches the device. A token that expired before the device asked
  for it is replaced by one fresh mint, or nothing is sent. The token is never in argv or the
  environment.
- **The in-session warning (ruling 11).** Within `session.ceiling_warning` of the device's
  ceiling, `port49 ssh` warns before ssh starts. If the session runs past that moment, it warns
  once on the terminal then, unless a `port49 refresh` since has moved the ceiling, which the
  agent's `/status` now carries. On EOS, NX-OS and Junos this is the only warning (L34).
- **Lab (ruling 12).** Two new rows:
  - **L53:** the host key each platform presents, the console command that shows it, whether it
    survives a reload, and what the scan leaves on the device;
  - **L54:** `port49 ssh` on each platform.

**Architecture:**
- **`internal/policy`:** `(*Policy).SweepPage`, and a sweep index built once per policy: every
  inventory name sorted, and each declared scope's selection as positions in that order. A page
  walks only the caller's own granted devices, so its cost and timing say nothing about which
  scopes exist.
- **`internal/broker/api`:**
  - `MintRequest.Scope` and `After`; `MintResponse.Next`.
  - The `devices` key becomes `omitempty`. The agent always sends devices, so its bytes are
    unchanged.
- **`internal/decision`:** `Record.Sweep`. **`internal/token`:** `Request.Sweep`, copied onto the
  permit record.
- **`internal/broker`:** the sweep in `tokens`, with the page resolved before the reservation; the
  empty-page answer; `sweepOf` on every record a page writes.
- **`internal/workload`:** `MintOptions.Scope`; `Client.sweep` follows `next` and refuses one that
  does not advance.
- **`internal/userconfig` (new):** `Dir`, `Path`, `Load`, `ReadPrivate` and `WritePrivate`.
- **`internal/hostkeys` (new):** `Path`, `ValidName`, `Lookup`, `Pin`, `Scan` and `Fingerprint`.
- **`internal/agent`:** `Status.Sessions`, the last refresh's per-device answer, so `port49 ssh`'s
  in-session warning follows a `port49 refresh` run in another terminal.
- **`cmd/port49`:**
  - `sessionFlags.fill` (the config file);
  - `devicesTrust` (`trust.go`);
  - `sshCmd` and `askpassMain` (`ssh.go`);
  - `mintFailed`, `ceilingWarning` and `warnNearCeiling`, factored out of `tokenCmd` unchanged in
    their words;
  - `--scope` on `workload token`.
- **`examples/oxidized`:** `PORT49_SCOPE`. **`examples/netmiko` (new):** the integration example.
- **`tests/lab`:** `l53_l54_test.go` and `l53_unit_test.go`; `make lab-ssh`.

**Tech Stack:**
- Go 1.26, module `github.com/blanketfish/port49`, **no cgo**, and **no new module in the build
  graph**. `golang.org/x/crypto/ssh` is in `golang.org/x/crypto` v0.55.0, already required.
  `golang.org/x/term` v0.45.0 is already in `go.sum` through it, and becomes a direct requirement
  for the askpass's terminal read.
- `ssh` is the operator's own OpenSSH, 8.5 or later. The test box has 10.2p1.
- Python 3 runs the Netmiko example's own test, skipped where it is absent.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.1 (mint);
  - §5.7 (the `mint` event and the `no_grants_matched` row);
  - §12 (tooling);
  - §13: decision 33 (refresh and the ceiling warning), decision 40 ruling 10 (the agentless
    client), and the new decision 42;
  - §15: L34, L51, and the new L53 and L54.
- `docs/design/2026-08-21-port49-design.md`:
  - §7 (the paths differ in what the agent holds);
  - §17: Surface; Minting ("Targets are named, not addressed", the host-key paragraph); Client
    libraries; Integration examples.
- The roadmap `docs/superpowers/plans/README.md`, "Plan 9". It holds what plans 3 and 8 owe, and
  this plan's split.
- House style: plan 8b (`2026-10-09-08b-workload-directory.md`). This plan is written against
  `main` at `d6bc054`.

**Prerequisite:** plan 8b merged (`main` at `d6bc054`).

## Pre-flight questions

Each question had a recommended answer, and each was ruled as recommended on 2026-10-09. Task 1
records the answers in decision 42: Q1 in ruling 10, Q3 in ruling 2, Q4 in ruling 9, Q2 in ruling
13 and Q5 in ruling 14. Q1, Q3 and Q4 shape this plan's code. Q2 and Q5 shape 9c and 9d, and are
asked now so those plans can be written against an answer.

- **Q1. `port49 ssh`: wrap the operator's OpenSSH, or build a client on `x/crypto/ssh`?**
  **Recommended: wrap OpenSSH 8.5+.**
  - **What wrapping keeps:** the operator's `ssh_config`, and with it jump hosts (`ProxyJump`),
    per-host legacy algorithms for old devices, `~.` escapes and the terminal handling people
    already trust at 3am. A native client loses all of them.
  - **What L51 measured** was the OpenSSH client with exactly the options this plan forces
    (`PubkeyAuthentication no`,
    `PreferredAuthentications keyboard-interactive,password`), on five platforms.
  - **The token's route** is ssh's own askpass hook. Measured here on OpenSSH 10.2p1, against an
    `x/crypto/ssh` server:
    - `SSH_ASKPASS_REQUIRE=force` makes ssh ask the askpass even with a terminal.
    - ssh closes every inherited descriptor above 2 (fd 7 was not in the askpass's
      `/proc/self/fd`), so a pipe cannot carry the token. A socket in the agent's 0700
      directory can.
    - The prompts ssh passes name the `HostKeyAlias`: `alice@dev1's password: ` and
      `(alice@dev1) Password: `.
    - A pinned key the server does not hold stops ssh (`Host key verification failed`, exit 255)
      before the askpass is ever run.
    - With both methods offered and the token refused, ssh asks a second time, for `password`.
      This plan's askpass ends the connection there (ruling 10).
  - **The cost, measured** (`tests/ssh-compat/2026-10-09-openssh-askpass.md`, 2026-10-09, in
    containers):
    - **8.0p1 (Rocky 8) and 8.2p1 (Ubuntu 20.04)** ignore `SSH_ASKPASS_REQUIRE=force`: with a
      terminal, ssh takes the terminal prompt and never runs the askpass.
    - **The other route on them** is ssh with no controlling terminal (`setsid`) and `DISPLAY`
      set. It does run the askpass, and stdin, ^C, `~` escapes and the exit status survive. It
      loses `~^Z`, and a window resize unless port49 forwards `SIGWINCH`.
    - **The decisive fault, on 8.0p1, 8.2p1 and 8.4p1** (Debian 11's, and upstream's built from
      source): a keyboard-interactive prompt reaches the askpass as the server's bare text,
      `Password: `, with no `(user@host)`. The askpass then cannot tell the device's prompt from
      a jump host's, so "answered once, to the prompt naming `<username>@<device>`" cannot hold,
      and answering a bare prompt could hand the token to a host that is not the device.
    - **8.5p1** (upstream, built) writes `(tuser@dev1) Password: ` and honours `force`. 8.9p1
      (Ubuntu 22.04) does the same.
    - **So the floor is 8.5.** `port49 ssh` refuses an older ssh by name. `port49 token` still
      serves RHEL 8, Ubuntu 20.04 and Debian 11 hosts.
- **Q2. Hardware-backed keys without cgo (for 9c).** **Recommended:**
  - **PKCS#11 through `github.com/ebitengine/purego`.** It covers YubiKey PIV (Yubico's
    `libykcs11` or OpenSC), smartcards and HSMs. The module is `dlopen`ed at run time with
    `CGO_ENABLED=0`. CI tests it against SoftHSM2, so no hardware is needed there.
  - **TPM 2.0 through `github.com/google/go-tpm`.** It is pure Go. CI tests it against `swtpm`
    over the MS-simulator TCP protocol (`go-tpm`'s `tpmutil/mssim`), never `go-tpm-tools`'
    simulator, which is cgo.
  - **macOS Secure Enclave through purego** on `Security.framework`, behind a spike task on a
    macOS host. If the spike shows a persistent Secure Enclave key needs a code-signing
    entitlement an unsigned `port49` cannot have, that is the tested technical reason to serve
    macOS through PKCS#11 (a YubiKey works there). Only then is the Secure Enclave dropped, and it
    goes back to Ryan.

  What was checked, from the source in the module cache (2026-10-09):

  | Library | Version | cgo? |
  |---|---|---|
  | `go-piv/piv-go/v2` | v2.6.0 | **cgo** on Linux, macOS, FreeBSD and OpenBSD (`piv/pcsc_unix.go` links pcsclite or `PCSC.framework`); pure on Windows (`winscard.dll` through syscall) |
  | `miekg/pkcs11` | v1.1.2 | **cgo** |
  | `ThalesGroup/crypto11` (now `eclipse-keypont/crypto11`) | v1.6.8 | **cgo**: it wraps `miekg/pkcs11` |
  | `google/go-pkcs11` | v0.3.0 | **cgo** |
  | `google/go-tpm` | v0.9.8 | **pure Go**, no `import "C"` anywhere |
  | `google/go-tpm-tools` | v0.4.10 | cgo only in `simulator/` |
  | `gballet/go-libpcsclite` | `1ec6f2e601c6` | **pure Go**: it speaks pcscd's private IPC socket, protocol 4.3/4.4, Linux and BSD only |
  | `ebitengine/purego` | v0.11.1 | **no cgo** on Tier 1 (Linux, macOS and Windows on amd64 and arm64); "beta software" by its README; it reimplements `runtime/cgo`'s startup (`internal/fakecgo`) |

  **Could not verify here:**
  - whether a PKCS#11 module that starts threads (`libykcs11`) behaves under purego's `fakecgo`;
    9c's first task measures it against SoftHSM2 and a real YubiKey;
  - the Secure Enclave's entitlement rule: there is no macOS host here;
  - whether Ryan's lab has a YubiKey for the 9c lab row.

  **The alternatives:**
  - PIV straight over pcscd's socket (`go-libpcsclite`) with port49's own APDU layer. It is Linux
    only and tied to a private protocol.
  - cgo allowed in `cmd/port49` alone on macOS, behind a build tag. That breaks the "no cgo" rule,
    so it is Ryan's call.
- **Q3. What may a sweep reach?** **Recommended: any declared scope, intersected with the devices
  the caller holds a grant on.**
  - An undeclared scope is the same answer as a scope with no granted device.
  - It never lists a device the caller could not have named and been answered for, so it tells
    no more than minting by name does.
  - The alternative, scopes named in the caller's own grants only, refuses "my grant is
    `all_devices`; sweep `dc_fabric`" for no security gain.
- **Q4. Where does `port49 devices trust` learn the address?** **Recommended: one mint through
  the agent, or `--address`.**
  - The mint asks a 60s TTL. Its token is never used, and it expires at its TTL. A device the
    caller holds no grant on is refused there, so trust is no oracle.
  - The mint record says it happened.
  - The alternative adds an address to `/v1/explain`, an API change for one command.
- **Q5. Inventory-carried host-key fingerprints (design §17's "MAY") and the Python and Ansible
  clients go to 9d.** **Recommended: yes, both, after L53.**
  - Third-party clients (Ansible's `network_cli` over paramiko or libssh, Netmiko) look host keys
    up by address. The design requires every shipped client to verify host keys.
  - So those clients can verify only once the mint carries the device's fingerprint (design
    §17), and that format waits on what L53 shows devices present.
  - 9a's Netmiko example verifies against port49's own pins, mapped by address for the one
    connection (Task 7).

## Rulings where the brief is open

The roadmap leaves these choices to the plan. Each is ruled here on reasoning, and Task 1 writes
it into decision 42.

- **R1. The page is resolved before the reservation, from the policy in force then
  (`Policy.Load`).** The reservation needs the device list (`Minter.Reserve`). Each device is
  then minted under the hold against the held policy, exactly as a device named would be.
  - A reload between the two can only change an item's answer, never add a device the page did
    not list.
  - A retry under the key with the same body recomputes the page. Devices already minted under
    the key are replayed, never minted twice.
  - **One edge, said rather than built around.** A reload between a page and its retry can add a
    granted device below the page's end. The recomputed page then shifts by one: its last device,
    already minted under the key, falls off the retry's answer, and the next page mints it again
    under the next key. Its first token is never returned, is never used, and expires at its TTL.
- **R2. Byte order of inventory names.** It is stable, needs no collation, and lets `after` be a
  plain name. A device added below the cursor during a sweep is in the next run.
- **R3. The config file gives defaults to `login` alone.** `port49 workload` keeps its explicit
  flags: a cron job should say what it trusts in its own line. The roadmap's "may later serve
  `port49 workload`" stays open.
- **R4. Device names for `port49 ssh` and `trust`:** `^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`.
  - `known_hosts` reads `* ? ! , [` as patterns, and a leading `@` or `|` as a marker or a hash.
  - Every name in the lab inventory and the spec's examples fits.
  - A name outside it is refused with the reason. `port49 token` still serves it.
- **R5. The ownership rule for both new files is `keyfile`'s for a private key, applied to
  writing:**
  - this user or root owns the file and each directory above it, up to the home directory or `/`
    (OpenSSH's StrictModes walk). A root-owned file, such as one provisioned under
    `/etc/port49`, is as safe as the user's own;
  - none is writable by group or others, except a directory with the sticky bit, as `/tmp` has:
    there nobody else can rename or replace an entry they do not own, which is all the walk
    guards against;
  - the file is no symlink.

  It is portable to macOS, unlike `internal/fence` (Linux-only `O_PATH`). The broker CA file the
  config names is read as plan 3 reads `--broker-ca`, and is refused first when group or others
  can write it: whoever can write it chooses which broker the operator trusts, as with the
  config file itself.

## What this plan does not do

- **No new reason code.** The `no_grants_matched` row widens to name the empty sweep page (Task
  1), and `internal/decision/reasons.go` is unchanged.
- **No new API error code.** A malformed sweep is `400 bad_request`.
- **No new metric.** A sweep's items count in `port49_decisions_total` as a batch's do.
- **One addition to the agent socket, and no new endpoint.** `GET /status` gains `sessions`, the
  last refresh's per-device answer, which `port49 ssh` reads when its in-session warning is due
  (ruling 11). Otherwise `port49 ssh` and `trust` use `POST /token` and `GET /status` as `port49
  token` does.
- **No OIDC, no hardware key, no broker CRL check:** 9b and 9c. **No host key from inventory, no
  Python library and no Ansible plugin:** 9d.
- **No `--enable` on `port49 ssh`.** The enable prompt is the device's, inside the session, where
  ssh's askpass never sees it. `port49 token --enable --json` serves it.
- **No claim about devices before L53 and L54 close:**
  - which console command shows a key;
  - that a scan leaves no trace;
  - which method a device takes.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **`port49 login` with no flags** (Task 4, `TestLoginTakesWhatItLacksFromTheConfigFile`) reads
  `~/.config/port49/config.yaml`:

  ```yaml
  broker: https://port49-broker.example.com:8443
  broker_ca: ca.pem          # relative to this file's directory
  cert: ~/.port49/alice.pem
  key: ~/.port49/alice-key.pem
  ```

  A file others can write is refused (`TestAConfigFileOthersCanWriteIsRefused`), exit 2:

  ```
  port49 login: /home/alice/.config/port49/config.yaml is writable by others (mode -rw-rw-r--); whoever can write the port49 config file chooses what port49 trusts: chmod go-w /home/alice/.config/port49/config.yaml
  ```
- **Pinning a key** (Task 5, `TestTrustAsksOnATerminal` and
  `TestTrustPinsTheFingerprintYouVerified`):

  ```
  $ port49 devices trust leaf1
  leaf1 at 172.100.100.11:22 presents ssh-ed25519 SHA256:3s0t…
  Compare it with the key leaf1's console shows. Pin it? [yes/no]: yes
  pinned ssh-ed25519 SHA256:3s0t… for leaf1 in /home/alice/.config/port49/known_hosts
  ```

  In a script, `--fingerprint SHA256:3s0t…` is required (exit 2 without it). A mismatch pins
  nothing and exits 1:

  ```
  port49 devices trust: leaf1 presents SHA256:9QzA…, not the SHA256:3s0t… you verified: nothing pinned; the address inventory gives may not be leaf1's, so check inventory's address for leaf1 before anything else
  ```
- **`port49 ssh` with no pinned key** (Task 6, `TestNoPinnedKeyMintsNothing`) exits 1 with no
  mint:

  ```
  port49 ssh: no host key is pinned for leaf1: verify its key on its console and run 'port49 devices trust leaf1' first; a key never seen is never accepted (design §17)
  ```
- **A key that changed** (`TestAHostWithAnotherKeyNeverSeesTheToken`). ssh's own warning prints
  first, then this, exit 255:

  ```
  port49 ssh: ssh stopped before leaf1 asked for the token, so it was never sent (ssh exit 255, its message is above); if ssh says the host key changed, the address inventory gives for leaf1 may not be the device: verify the key on its console, then run 'port49 devices trust --replace leaf1'
  ```
- **The device refusing the token and asking again** (`TestTheTokenIsPresentedOnce`), exit 255:

  ```
  port49 ssh: leaf1 asked for the password again after it was sent the token; port49 ssh ended the connection, so no second or empty password reached it; `port49 explain --device leaf1` says whether your policy permits you, and port49d's decision log says why the device refused
  ```
- **The session's ceiling, mid-session** (`TestTheCeilingWarningComesInSession`), on the terminal:

  ```
  port49: your session on leaf1 ends at 2026-10-09T21:00:00Z (in 30m); run 'port49 refresh'
  ```
- **A token that expired before the device asked for it, and no fresh one**
  (`TestATokenExpiredBeforeThePromptIsNeverSent`), exit 255, nothing sent:

  ```
  port49 ssh: leaf1 asked for the token 1m12s after it was minted, past its expires_at (2026-10-09T03:01:00Z), and a fresh mint answered deny no_grants_matched; nothing was sent to leaf1, and ssh was ended. Run `port49 ssh leaf1` again; a slow jump host login is the usual cause
  ```
- **An OpenSSH too old** (`TestAnOldOpenSSHIsRefusedBeforeAMint`), exit 1, nothing minted:

  ```
  port49 ssh: /usr/bin/ssh is OpenSSH 8.4; port49 ssh needs 8.5 or later, the first whose prompts name the device they ask for. Run `port49 token leaf1` and your own ssh instead
  ```
- **A sweep** (Task 3, `TestWorkloadTokenSweepsAScope`): `port49 workload token … --scope
  backup_targets` writes one TSV line per permitted device across every page. An empty sweep
  (`TestAnEmptySweepIsFinal`) exits 77:

  ```
  port49 workload token: scope backup_targets: no device it selects is one you hold a grant on, or no scope has that name
  ```

## Operator notes

These are for the PR body and plan 13's operator guide. Plan 13 owns the guide, and every line
here is pinned by a test or a lab row.

- **`port49 login` needs no flags** once `~/.config/port49/config.yaml` exists.
  - It holds `broker`, `broker_ca`, `cert` and `key`; a flag overrides its key, and relative paths
    are from the file's directory.
  - Keep the file, the CA file it names, and every directory above them writable by you alone
    (root may own them too): anyone who can write them chooses which broker you trust.
    `--config FILE` reads another file, which must exist.
  - On Ubuntu, whose default umask (002) leaves directories such as `~/.config` group-writable,
    run `chmod go-w ~/.config` once. `port49 login` names the directory and that command when it
    refuses.
- **Before `port49 ssh DEVICE`, pin the device's key once:** `port49 devices trust DEVICE`.
  - Compare the fingerprint it prints with the device's own, read on its console. *Which console
    command shows it, per platform, is L53's and is not stated until L53 closes.* Then answer
    `yes`.
  - In automation, pass `--fingerprint`.
  - The pins are in `~/.config/port49/known_hosts`, keyed by the device's inventory name, never
    its address. A device whose inventory address changes keeps its pin.
  - A device that presents another key is refused before the token is sent. Treat that as a
    possible hijack of the inventory address until you have verified the new key on the console.
    Then pin it with `--replace`.
- **`port49 ssh DEVICE` mints a fresh token and logs you in.** `port49 ssh DEVICE -- show version`
  runs one command and exits with its status.
  - It runs your OpenSSH, 8.5 or later, with your `~/.ssh/config`, so jump hosts and per-host
    algorithms work.
  - It forces public-key authentication off for the device (L51: refused keys count against the
    device's attempt limits, and an IOS-XE `login block-for` locks the source out).
  - A jump host's password prompt is asked of your terminal as usual. The token goes only to the
    device's own prompt, once.
  - `-v` passes `ssh -v` for a connection that fails.
  - A slow jump host can outlast the token's lifetime. When the device asks after the token
    expired, `port49 ssh` mints one fresh token and sends that; if it cannot, it sends nothing
    and says so.
  - RHEL 8 (8.0), Ubuntu 20.04 (8.2) and Debian 11 (8.4) ship an older OpenSSH: there, use
    `port49 token DEVICE` and your own ssh. Before 8.5, ssh either ignores the askpass when a
    terminal is open or does not say which host a keyboard-interactive prompt is for
    (`tests/ssh-compat/2026-10-09-openssh-askpass.md`).
- **The session-ceiling warning.** On EOS, NX-OS and Junos the device shows no warning before
  your session's ceiling (L34). `port49 ssh` prints one on your terminal `session.ceiling_warning`
  before it. Run `port49 refresh` in another terminal to extend the session in place: the warning
  then waits for the new ceiling.
- **A device that refuses your token** is not asked again. `port49 ssh` ends the connection
  rather than let ssh send an empty password, one more refused attempt against the device's limits
  (L51). Check `port49 explain --device DEVICE`, then port49d's decision log.
- **`port49 workload token --scope NAME`** mints every device the scope selects that the
  workload's subjects hold a grant on. It pages by the broker's `batch_max` and needs no node
  list.
  - The Oxidized wrapper takes `PORT49_SCOPE` in place of `OXIDIZED_NODES`.
  - A scope that selects nothing you hold a grant on, and a scope name that does not exist, both
    exit 77 with one message. The broker never tells them apart.
- **Decision log.** Every record a sweep page writes carries `sweep: {scope, after}`, a refusal of
  the whole page included. An empty page writes one `mint deny no_grants_matched` naming the sweep
  and no device.

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module in the build graph**. `golang.org/x/term` v0.45.0 moves from indirect to direct with
  `go mod tidy`, and nothing else changes in `go.sum`.
- snake_case everywhere it is data: `scope`, `after`, `next`, `sweep`, `broker_ca`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan adds
  none.** The `no_grants_matched` row is widened in the spec first (Task 1).
- **The log never contains a token, password, challenge or response.**
  - The askpass socket carries the token once, over a socket in a 0700 directory.
  - The token is never in argv, the environment, stdout or stderr.
    `TestTheTokenIsNeverInArgvOrTheEnvironment` asserts it for ssh's argv and environment, with a
    fake ssh that records both and runs the askpass, and that the askpass socket is gone after.
    Every test in which ssh runs asserts it for stdout and stderr (`tokenNowhere`).
- No device identity and no principal in a metric label.
- **Fail closed, never widen.** Each of these is a refusal:
  - a config or pins file another user can write;
  - a device with no pin;
  - an OpenSSH under 8.5;
  - a token past its `expires_at` when the device asks, and no fresh mint;
  - a `--fingerprint` that differs;
  - a non-terminal `trust` without `--fingerprint`;
  - a second ask for the device's password;
  - a sweep `next` that does not advance.
- **The lab register rules** (CLAUDE.md 1–4). L53 and L54 are opened by Task 1 and measured by
  Task 8. Until they close, no doc names a console command, says a scan is invisible, or says
  which method a platform takes.
- Verify with `make test && make vet`, and `make test-race` on every touched package, and report
  the real output. Tests that run `ssh` or `python3` skip, saying why, where those are absent. The
  test box has both.
- Conventional Commits, on branch `feature/sweeps-and-ssh`. Commit messages end with:

  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```
- Implementers never run `git checkout`, `restore`, `reset`, `stash` or `clean`.

## Review Focus

The five inputs or conditions most likely to bite a person, and the test that pins each:

1. **Inventory gives a device an address that is not the device.** A source-of-truth edit or a
   typo sends `leaf1` to a host the attacker runs (design §17).
   - **Expected:** ssh refuses the host's key before authentication. The askpass is never asked,
     the token never leaves port49, and port49 ssh says so and how to re-pin.
   - **Pinned by** Task 6's `TestAHostWithAnotherKeyNeverSeesTheToken`: a device server with
     another key records no attempt, and the agent's minted token appears nowhere.
2. **The broker is unreachable, the agent is gone, or the session is over when the operator types
   `port49 ssh leaf1` at 3am.**
   - **Expected:** no ssh process starts, and the agent's own words say why, exit 1. With no
     pinned key, nothing is minted at all.
   - **Pinned by** Task 6's `TestNoTokenNoSSH` (no agent; a 410 session end; a 502 broker
     unreachable, each with the device server seeing no connection) and `TestNoPinnedKeyMintsNothing`.
3. **The device refuses the token, or asks twice.** Both methods are offered, so ssh retries with
   `password`.
   - **Expected:** the token is presented once. The second ask ends the connection before ssh
     sends anything: no empty password reaches the device, and no second failed login reaches its
     counters.
   - **Pinned by** Task 6's `TestTheTokenIsPresentedOnce` (the server sees exactly one attempt,
     the token) and `TestAskpassAnswersTheDevicesPromptOnce`.
4. **A sweep used to map the fleet.**
   - **The inputs:** an undeclared scope; a declared scope whose devices the caller holds no grant
     on; `all_devices` from a caller granted one site.
   - **Expected:** the first two are byte-identical answers and records, and cost the same: a page
     walks only the caller's own granted devices, never the inventory. The third lists only the
     granted devices. Paging lists each granted device once, never repeats one, and stops.
   - **Pinned by** Task 2's `TestASweepIsNoEnumerationOracle`, `TestASweepPagesTheGrantedDevicesByName`,
     `TestASweepVisitsOnlyGrantedDevices`, and Task 3's `TestASweepThatDoesNotAdvanceStops`.
5. **The device session's ceiling arriving mid-session on a platform that shows no warning.**
   EOS, NX-OS and Junos show none (L34).
   - **Expected:** `port49 ssh` writes the warning on the terminal at `ceiling_warning` before the
     ceiling, once. If it is already inside the window at start, it writes it before ssh runs. If
     a `port49 refresh` in another terminal moved the ceiling, it writes nothing then, and waits
     for the new moment.
   - **Pinned by** Task 6's `TestTheCeilingWarningComesInSession`,
     `TestTheCeilingWarningBeforeSSHStarts` and `TestARefreshInSessionMovesTheWarning`.

## Conflict scan: where tasks share a file or an interface

- **`internal/broker/api/api.go`:** Task 2 alone. Task 3 reads the new fields.
- **`internal/decision/log.go` and `internal/token/minter.go`:** Task 2 alone.
- **`internal/policy`:** Task 2 alone. It adds `sweep.go` and two fields on `Policy` in `load.go`.
- **`internal/broker/broker.go`:** Task 2 alone.
- **`internal/workload`, `cmd/port49/workload.go` and `examples/oxidized`:** Task 3 alone.
- **`internal/userconfig`:** Task 4 creates it. Task 5 reads `ReadPrivate`, `WritePrivate` and
  `Dir`.
- **`internal/hostkeys`:** Task 5 creates it. Task 6 reads `Lookup`, `Path` and `ValidName`.
- **`internal/agent/agent.go`:** Task 6 alone (`Status.Sessions`).
- **`cmd/port49/main.go`** is touched by Tasks 4, 5 and 6, in that order, each in its own region:
  - Task 4: `sessionFlags`, `login`, `agentMain` and usage;
  - Task 5: `tokenCmd`'s refusal and warning blocks, moved to `mint.go` with the same words; the
    `devices` case; usage;
  - Task 6: the `ssh` case, the askpass check in `main`, and usage.
- **`cmd/port49/main_test.go`'s `TestMain`:** Task 4 isolates `XDG_CONFIG_HOME`; Task 6 adds the
  askpass dispatch.
- **`tests/lab/`, `Makefile` (`lab-ssh`) and the `L53`/`L54` rows:** Task 8 alone.
- **The spec and the design:** Task 1 writes them. Task 7 fixes design §17's integration examples.
  Task 8 closes L53 and L54 and fixes any text its results contradict.

Tasks 2 and 4 touch disjoint packages and could run in parallel after Task 1. Task 3 needs 2.
Task 5 needs 4. Task 6 needs 5. Task 7 needs 6. Task 8 needs 1–7. Task 9 is last.

## File Structure

**Create:**
- `internal/policy/sweep.go` and `sweep_test.go`.
- `internal/broker/sweep_test.go`.
- `internal/userconfig/userconfig.go` and `userconfig_test.go`.
- `internal/hostkeys/hostkeys.go` and `hostkeys_test.go`.
- `cmd/port49/config_test.go`.
- `cmd/port49/mint.go`, holding `mintFailed`, `ceilingWarning` and `warnNearCeiling`.
- `cmd/port49/trust.go` and `trust_test.go`.
- `cmd/port49/ssh.go`, `ssh_test.go` and `sshserver_test.go`.
- `examples/netmiko/port49_netmiko.py`, `test_port49_netmiko.py`, `README.md` and
  `example_test.go`.
- `tests/lab/l53_l54_test.go` and `tests/lab/l53_unit_test.go`.
- `tests/lab/results/L53-<platform>.md` and `L54-<platform>.md`, written by the run, with their
  evidence.

**Already in the working tree, committed by Task 1:** `tests/ssh-compat/2026-10-09-openssh-askpass.md`
and its scripts in `tests/ssh-compat/2026-10-09-openssh-askpass/`, the measurement ruling 10's
OpenSSH floor rests on (pre-flight I-5).

**Modify:**
- `docs/design/2026-08-23-policy-engine-spec.md` and `docs/design/2026-08-21-port49-design.md`
  (Task 1; Task 7 for §17's examples; Task 8 closes L53 and L54).
- `internal/broker/api/api.go`, `internal/decision/log.go`, `internal/token/minter.go`,
  `internal/policy/load.go` and `internal/broker/broker.go` (Task 2).
- `internal/workload/client.go` and `client_test.go`, `cmd/port49/workload.go` and
  `workload_test.go`, `examples/oxidized/port49-oxidized-run`, `run_test.go` and `README.md`
  (Task 3).
- `cmd/port49/main.go` and `main_test.go` (Tasks 4, 5, 6).
- `internal/agent/agent.go` and `agent_test.go` (Task 6: `Status.Sessions`).
- `go.mod` (Task 6: `golang.org/x/term` direct).
- `examples/oxidized/README.md` (Task 3: `PORT49_SCOPE`).
- `Makefile` (`lab-ssh`) and `tests/lab/README.md` (Task 8).
- `docs/superpowers/plans/README.md` (Task 9).

---

### Task 1: The spec says what plan 9a builds: decision 42, the sweep in §5.7, §12's commands, L53 and L54

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §5.7 (the `mint` event row, the
  `no_grants_matched` row), §12 (after `port49 refresh`), §13 (decision 42, new), §15 (L53, L54)
- Modify: `docs/design/2026-08-21-port49-design.md`: §17 (Surface, Minting, Client libraries)

**Interfaces:**
- Consumes: the pre-flight answers Q1–Q5 and rulings R1–R5 above.
- Produces: decision 42, rulings 1–14, which every later task cites (13 and 14 are 9c's and
  9d's); the widened rows; L53 and L54 (Task 8 measures them).

This task is docs only. Each step is an edit with the exact text. Where a step says "replace", the
old text is quoted and appears once; check with `grep -n` before editing.

- [ ] **Step 1: Decision 42, after decision 41**

Find the end of decision 41 with `grep -n "^## 14. Required test assertions" docs/design/2026-08-23-policy-engine-spec.md`.
The line two above it is `---`, and the line above that ends decision 41 (`  - Task 8.`). Between
decision 41's last line and the `---`, insert a blank line and:

```markdown
**42. The agent in full, first part: sweeps by scope, the per-user config file, `port49 ssh` with
pinned host keys.** *Plan 9a, 2026-10-09.* Rulings rest on reasoning unless they say data. Plan
9a's pre-flight questions Q1–Q5 were answered as the plan recommended; Ryan may override any.
Plan 9 is split: 9b the OIDC public client, 9c hardware-backed keys and the broker certificate's
CRL check, 9d host keys from inventory and the Python and Ansible clients.

- **1. Mint by scope** (design §17: "a device name or a `scope`, resolved through inventory").
  - **The request.** `POST /v1/tokens` takes `scope` in place of `devices`, one or the other, and
    `after` to continue a sweep. Each is 1 to 253 printable ASCII characters. Anything else is
    `400 bad_request`: both keys, `after` without `scope`, neither.
  - **The page.** In the byte order of their inventory names, after `after`, at most `batch_max`:
    the devices the scope selects (§5.5) on which the caller's subjects hold a grant unexpired
    now. `next` names the page's last device when more remain, and is absent at the end.
  - **Per item.** Each device is answered exactly as the same device named would be: the same
    records, the same refusals, a quarantine or a refused admission included.
  - **When the page is resolved.** Against the policy in force when the request arrives, before
    the reservation, which needs the list. Each device is then minted under the hold. A reload
    between the two changes an item's answer, never the list.
  - Task 2.
- **2. No enumeration oracle.** These three are one answer, byte for byte, and one record:
  - a scope the policy does not declare;
  - a declared scope selecting no device the caller holds a grant on;
  - a page past the end.

  The answer is 200, `results: []`, no `next`; the record is one `mint` record, `deny
  no_grants_matched`, carrying the sweep and no device. A sweep never lists a device the caller
  holds no grant on, so it tells the caller nothing a mint by name would not. Any declared scope
  may be swept, intersected with the caller's grants (pre-flight Q3).

  **Nor a timing oracle.** A page walks only the devices the caller holds an unexpired grant on,
  from an index built once per policy, never the inventory. The swept scope filters that walk,
  and an undeclared scope is walked as one selecting nothing. So what a page costs, and how long
  it takes, depends on the caller's own grants, never on which scopes exist or how many devices
  lie in a range of the caller's choosing. Task 2.
- **3. Paging and idempotency.**
  - **Its own request.** Each page is its own request under its own `Idempotency-Key`.
  - **A retry.** A retry under the key, with the same body, is resolved again. Devices minted
    under the key are replayed, never minted again. A reload between the page and its retry that
    adds a granted device below the page's end shifts the page by one. Its last device, minted
    under the key, is then not in the retry's answer, and the next page mints it again. The first
    token is never returned and expires at its TTL.
  - **The policy each page sees.** Each page is resolved against the policy in force when it is
    asked. A device added below the cursor during a sweep is in the next run's sweep; a device
    removed is not answered.
  - **The client** stops when `next` is absent, and refuses a `next` that does not advance past
    `after`: a fault, never a loop.
  - Tasks 2 and 3.
- **4. The record.** Every record a sweep page writes carries `sweep: {scope, after}`: each item's
  `mint` record, permit or deny; the empty page's; and a refusal of the whole page (the directory's,
  the store's, a username collision, the mint gate). Task 2.
- **5. `port49 workload token --scope NAME`.**
  - It sweeps in place of `DEVICE…` and `--devices-file`; naming both is usage, exit 2.
  - Nothing selected for the workload exits 77, with one message for an undeclared scope and an
    ungranted one alike.
  - `examples/oxidized` takes `PORT49_SCOPE` in place of `OXIDIZED_NODES`.
  - Task 3.
- **6. The per-user config file** (plan 3's rulings, 2026-09-24).
  - **Where and what.** `$XDG_CONFIG_HOME/port49/config.yaml`, else
    `~/.config/port49/config.yaml`, holding `broker`, `broker_ca`, `cert` and `key`.
  - **Precedence.** `port49 login` takes from it each value its flags leave out; a flag always
    wins.
  - **Paths.** A relative path is taken from the file's directory, and `~/` is the home
    directory.
  - **Who can write it.** It is read only when this user or root owns it and every directory
    above it up to the home directory or `/`, none is writable by group or others (a sticky
    directory, as `/tmp` is, excepted), and it is no symlink. Whoever can write it chooses which
    broker the operator trusts.
  - **Strict.** An unknown key, or a second YAML document, is refused. `--config FILE` names
    another file, which must exist; a missing file at the default path is no file.
  - **The CA.** `broker_ca` stays required, from the flag or the file, and never falls back to the
    system roots. It pins the CA that issued the broker's certificate, not the leaf, so a renewal
    breaks nothing. A CA file the config file names is refused when group or others can write it.
  - **Not `port49 workload`.** A cron job states what it trusts on its own line.
  - Task 4.
- **7. Pinned host keys** (design §17).
  - **The file.** `$XDG_CONFIG_HOME/port49/known_hosts`, in OpenSSH's format, one line per key,
    whose host field is the device's inventory name. It is held to ruling 6's ownership rule.
  - **How `port49 ssh` uses it.** As ssh's only known-hosts source, with the device's name as
    `HostKeyAlias` and strict checking. A key is checked against the device it was pinned for,
    whatever address inventory gives today, so an address moved to another host fails before
    authentication.
  - **No pin.** A device with no pinned key is refused before anything is minted.
  - Tasks 5 and 6.
- **8. Names.** `port49 ssh` and `port49 devices trust` take device names of letters, digits, `.`,
  `_` and `-`, starting with a letter or a digit, 253 at most.
  - `known_hosts` reads `*`, `?`, `!`, `,` and `[` as patterns, and a leading `@` or `|` as a
    marker or a hash, so a name holding one could pin a key for other devices.
  - A name outside the set is refused with the reason; `port49 token` still serves it.
  - Task 5.
- **9. `port49 devices trust DEVICE`.**
  - **The address.** It comes from one mint through the agent, asking a 60s TTL; the token is
    never used and expires at its TTL. A device the caller holds no grant on is refused there, so
    trust is no oracle. `--address` skips the mint (pre-flight Q4).
  - **The key.** It is read by a key exchange abandoned before authentication: no username is
    offered and no credential is sent. What a device does with that is L53's (open).
  - **When it pins.** Only when `--fingerprint` equals the SHA-256 fingerprint presented, or the
    operator answers `yes` on a terminal. Never on a non-terminal without `--fingerprint`.
  - **An existing pin.** It is replaced only with `--replace`.
  - Task 5.
- **10. `port49 ssh DEVICE [-- COMMAND…]`** (pre-flight Q1: the operator's OpenSSH, 8.5 or later).
  - **Why 8.5, measured** (`tests/ssh-compat/2026-10-09-openssh-askpass.md`, in containers):
    - OpenSSH 8.0p1 and 8.2p1 ignore `SSH_ASKPASS_REQUIRE=force` and take the terminal prompt.
    - Run with no controlling terminal and `DISPLAY` set, they do ask the askpass, but on 8.0p1,
      8.2p1 and 8.4p1 a keyboard-interactive prompt reaches it as the server's bare text
      (`Password: `). The askpass cannot then tell the device's prompt from a jump host's, and
      could hand the token to a host that is not the device.
    - 8.5p1 names the host, as `(<user>@<HostKeyAlias>) Password: `, and honours `force`.

    `port49 token` serves an older ssh.
  - **The command line.** `ssh_config` is honoured. The command line forces:
    - the pinned file, `HostKeyAlias`, `StrictHostKeyChecking yes`, no host-key update, no DNS or
      `KnownHostsCommand` source. The file's path and the address are quoted and `%`-escaped, since
      ssh expands `%` tokens and splits on whitespace there;
    - `PubkeyAuthentication no` (L51: every refused key counts against the device's attempt
      limit, and an IOS-XE `login block-for` locks the source address out);
    - `PreferredAuthentications keyboard-interactive,password`, one prompt each;
    - no multiplexing, no agent forwarding.
  - **The token's route.** It reaches ssh through ssh's askpass alone. That askpass is port49
    itself, which ssh runs with `SSH_ASKPASS_REQUIRE=force` and one argument; it asks `port49
    ssh` over a socket in the agent's 0700 directory. The token is never in argv or the
    environment. A port49 that ssh's children run otherwise (a `ProxyCommand`, a `Match exec`)
    inherits the socket's variable, and refuses to run as a command there when given two or more
    arguments. Given one, it acts as an askpass for that argument as the prompt, which moves no
    token, since that prompt is not the device's.
  - **A token that expired first.** When the device's prompt comes within 5s of the token's
    `expires_at` or after it, as behind a slow jump host, `port49 ssh` mints once more through the
    agent and answers with that token, still once. When no fresh token is had, nothing is sent,
    ssh is ended, and `port49 ssh` says why.
  - **Answered once, to one prompt.** The token is answered once, to the prompt naming
    `<username>@<device>`. OpenSSH 10.2p1 writes `alice@leaf1's password: ` and
    `(alice@leaf1) Password: `, measured against an `x/crypto/ssh` server for plan 9a; L54
    measures it per platform.
  - **Other prompts.** Any other prompt, a jump host's, is asked of the terminal as ssh would ask
    it: a password with echo off, and a yes/no question with echo on.
  - **A second ask.** A second ask for the device's password, which ssh makes when the device
    refuses the token and offers another method, ends the connection before ssh answers it. No
    second or empty password reaches the device's failed-login counters.
  - **Exit.** ssh's exit status is `port49 ssh`'s. A 255 is explained: before the token was sent,
    or after it.
  - Task 6.
- **11. The in-session warning** (decision 33).
  - **Before ssh starts.** Within `session.ceiling_warning` of the device's ceiling, `port49 ssh`
    says so, as `port49 token` does.
  - **During the session.** For a session that outlives that moment, it says so once, on the
    terminal, at that moment.
  - **After a refresh.** `port49 refresh` in another terminal extends the session in place (§5.6).
    The agent keeps the last refresh's per-device answer and serves it on `GET /status` as
    `sessions`. When the warning is due, `port49 ssh` asks first. A refresh that extended this
    device's session, and reached it, moves the warning to the new moment, so the line never
    names a ceiling that has moved.
  - **Where it matters.** EOS, NX-OS and Junos show port49's `server_msg` warning nowhere (§15
    L34), so there this line is the warning.
  - Task 6.
- **12. The lab.** L53 (host keys per platform) and L54 (`port49 ssh` per platform), both open.
  Until each closes, no doc says which console command shows a device's key, that a scan leaves
  no trace on a device, or which authentication method a platform takes. Task 8.
- **13. Hardware-backed client keys, for plan 9c** (pre-flight Q2), all without cgo.
  - **PKCS#11 through `github.com/ebitengine/purego`.** It covers YubiKey PIV, smartcards and HSMs.
    The module is `dlopen`ed at run time with `CGO_ENABLED=0`, and CI tests it against SoftHSM2.
  - **TPM 2.0 through `github.com/google/go-tpm`.** It is pure Go. CI tests it against `swtpm` over
    the MS-simulator protocol, never `go-tpm-tools`' simulator, which is cgo.
  - **The macOS Secure Enclave through purego**, behind a spike task on a macOS host.
  - **What was checked (2026-10-09, from the module cache):**
    - cgo: `go-piv/piv-go/v2` v2.6.0 on Linux and macOS, `miekg/pkcs11` v1.1.2, `crypto11`
      v1.6.8 and `google/go-pkcs11` v0.3.0;
    - pure Go: `go-tpm` v0.9.8;
    - no cgo on Tier 1: `purego` v0.11.1, "beta software" by its README.
  - **Unverified, and 9c's first task measures it:** whether a module that starts threads
    (`libykcs11`) behaves under purego.
  - **What goes back to Ryan.** If the spike shows a persistent Secure Enclave key needs an
    entitlement an unsigned `port49` cannot have, macOS is served through PKCS#11, a YubiKey. The
    Secure Enclave is dropped only then, and only by Ryan, as is any other route the spike or 9c's
    measurement rules out.
- **14. Inventory-carried host keys and the Python and Ansible clients, for plan 9d** (pre-flight
  Q5).
  - **What moves to 9d:** both. Inventory's host-key fingerprint (design §17's MAY) goes through the
    bundle into the mint item, and `port49 ssh` checks it beside its pins.
  - **Why after L53:** its format follows what L53 shows devices present.
  - **Why the clients go with it:** third-party clients (Ansible's `network_cli`, Netmiko over
    paramiko) look a host key up by address. They can verify one only once the mint says which key
    to expect.
  - **Until then:** 9a's Netmiko example verifies against port49's own pins, written under the
    address for the one connection (Task 7).
```

- [ ] **Step 2: §5.7, the `mint` event and the `no_grants_matched` row**

Replace

```markdown
| `mint` | broker | which grants matched, which roles composed, which blob resulted |
```

with

```markdown
| `mint` | broker | which grants matched, which roles composed, which blob resulted. Every record a sweep page writes (`POST /v1/tokens` by `scope`) carries `sweep: {scope, after}` (§13 decision 42 ruling 4) |
```

Replace

```markdown
| `no_grants_matched` | `mint`: no declared grant for this principal selects the device. `refresh`:
```

with

```markdown
| `no_grants_matched` | `mint`: no declared grant for this principal selects the device; or, on a sweep page by `scope`, the page holds no device: the scope is not declared, selects no device the principal holds a grant on, or the page is past the end, which are one answer and one record carrying `sweep` and no device (§13 decision 42 ruling 2). `refresh`:
```

- [ ] **Step 3: §12, the agent's new commands**

After the `port49 refresh` paragraph, which ends `` `port49 explain` prints a subject's
ceiling on a device.`` (`grep -n "ceiling on a device\.$"`), insert a blank line and:

```markdown
**`port49 login`** takes `--broker`, `--broker-ca`, `--cert` and `--key` from the per-user config
file, `$XDG_CONFIG_HOME/port49/config.yaml`, for each one its flags leave out. It reads the file
only when nobody but the operator or root can write it or any directory above it (§13 decision
42 ruling 6).

**`port49 devices trust [--fingerprint SHA256:…] [--address ADDR] [--port N] [--replace] DEVICE`**
pins the SSH host key the device presents, in `$XDG_CONFIG_HOME/port49/known_hosts` under its
inventory name.
- **The address.** One mint through the agent gives it; `--address` is the alternative.
- **When it pins.** Only against a `--fingerprint` the operator verified on the device's console,
  or a `yes` typed at a terminal.
- **An existing pin.** It is replaced only with `--replace` (decision 42 rulings 7–9).

**`port49 ssh [--port N] [--ssh PATH] [--ssh-config FILE] [-v] DEVICE [-- COMMAND…]`** mints a
token through the agent and logs in with the operator's OpenSSH (8.5 or later).
- **Host keys.** It refuses a device with no pinned key before minting, and hands ssh the pin as
  the only key it accepts.
- **The token** goes only to the device's own password prompt, once, through ssh's askpass.
- **Exit and warnings.** It exits with ssh's status, and warns on the terminal within
  `session.ceiling_warning` of the device's ceiling (decision 42 rulings 10 and 11).

**`port49 workload token … --scope NAME`** mints, page by page, every device the scope selects on
which the workload holds a grant, in place of a device list (decision 42 rulings 1–5).
```

- [ ] **Step 4: §15, L53 and L54 after L52**

After the row that begins `| **L52** |` (`grep -n "^| \*\*L52\*\*"`), insert:

```markdown
| **L53** | The SSH host key each platform presents to `port49 devices trust`'s scan (plan 9a), and what the scan does to the device. The key: the host-key algorithm negotiated with a client offering every algorithm `x/crypto/ssh` knows but DSA, which OpenSSH 10 cannot use; whether a console command shows the same key or a fingerprint of it, which command, and in what form (OpenSSH base64, SHA-256, hex DER, MD5), so an operator can verify it out of band; whether the key is the same after a reload with the configuration saved, the device shown to have gone down and come back. The scan, a key exchange abandoned before authentication: whether it reaches port49 as any TACACS+ exchange, writes a device log line, or counts against the device's login-attempt or ban limits (IOS-XE `login block-for`, NX-OS `aaa authentication rejected`: a limit of two failures set, three scans, then a login; valid only where a control of two refused logins does trip the limit). | §13 decision 42 rulings 9 and 12; the operator docs' "verify the key on the console" (plan 13) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open — added 2026-10-09 |
| **L54** | `port49 ssh` against each platform (plan 9a): which authentication method the device takes under `PreferredAuthentications keyboard-interactive,password` with public-key authentication off; that ssh's prompt for it names `<username>@<device>`, so port49's askpass answers it once and the login succeeds at the first try; that a command after `--` runs and its exit status is `port49 ssh`'s; that a pinned key the device does not hold is refused by ssh before any TACACS+ exchange, with the minted token never presented. | §13 decision 42 rulings 10 and 11 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | open — added 2026-10-09 |
```

- [ ] **Step 5: Design §17, the surface and the minting text**

Replace

```
POST  /v1/tokens          mint, one device or many
```

with

```
POST  /v1/tokens          mint, one device or many, or a page of a scope's (plan 9a)
```

After the paragraph that ends `the caller usually\nneeds it to connect.` (`grep -n "needs it to connect\.$"`),
insert a blank line and:

```markdown
As built (plan 9a; policy engine spec §13 decision 42 rulings 1–4): a sweep names `scope` in place
of `devices`, and `after` to continue. Each page holds, in inventory-name order and up to
`batch_max`, the devices the scope selects on which the caller holds a grant, and carries `next`
while more remain. An undeclared scope, a scope selecting no device the caller holds a grant on,
and a page past the end are one answer, `results: []`, so a sweep is no enumeration oracle.
```

After the paragraph that ends `a security event in the sync diff (policy engine spec, §10).`
(`grep -n "security event in the sync diff"`), insert a blank line and:

```markdown
As built (plan 9a; policy engine spec §13 decision 42 rulings 7–10):
- **Pinning.** `port49 devices trust` pins a device's key under its inventory name, against a
  fingerprint the operator verified on the console or a `yes` typed at a terminal.
- **Connecting.** `port49 ssh` runs the operator's OpenSSH with that pin as the only key accepted
  for the device's name (`HostKeyAlias`). A device with no pin is refused before a token is minted.
  An address moved to another host fails at the key exchange, before the token is sent.
- **Inventory's own fingerprints**, the MAY above, are plan 9d's, once lab L53 has shown what
  devices present.
```

In the Client libraries text, replace

```markdown
when nothing was minted and a run again will not change that; `examples/oxidized/` drives
Oxidized with it.
```

with

```markdown
when nothing was minted and a run again will not change that; `examples/oxidized/` drives
Oxidized with it. As built (plan 9a): `--scope NAME` mints every device a scope selects that the
workload holds a grant on, following the broker's pages.
```

- [ ] **Step 6: Check and commit**

Run: `grep -c "decision 42" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md`
Expected: at least 8 in the spec and 2 in the design.

Run: `grep -n "^| \*\*L5[34]\*\*" docs/design/2026-08-23-policy-engine-spec.md`
Expected: two rows, each ending `| open — added 2026-10-09 |`.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md \
  tests/ssh-compat/2026-10-09-openssh-askpass.md tests/ssh-compat/2026-10-09-openssh-askpass
git commit -m "docs(spec): decision 42, sweeps by scope, the config file and port49 ssh; L53 and L54 opened"
```

---

### Task 2: Mint by scope: the page, the empty answer, the record

**Files:**
- Create: `internal/policy/sweep.go`, `internal/policy/sweep_test.go`, `internal/broker/sweep_test.go`
- Modify: `internal/policy/load.go` (two fields on `Policy`), `internal/broker/api/api.go`,
  `internal/decision/log.go`, `internal/token/minter.go`, `internal/broker/broker.go`

**Interfaces:**
- Consumes: decision 42 rulings 1–4 (Task 1).
- Produces:
  - `func (p *Policy) SweepPage(m Member, scope, after string, limit int, now time.Time) (devices []string, next string)`
  - `api.MintRequest{Devices []string "devices,omitempty"; Scope string "scope,omitempty"; After string "after,omitempty"; …}`
  - `api.MintResponse.Next string "next,omitempty"`
  - `decision.Sweep{Scope string "scope"; After string "after,omitempty"}` and `decision.Record.Sweep *Sweep "sweep,omitempty"`
  - `token.Request.Sweep *decision.Sweep`
  - in `internal/broker`: `func sweepOf(req api.MintRequest) *decision.Sweep` and `func sweepRequestError(req api.MintRequest) string`

- [ ] **Step 1: Write the failing policy tests**

Create `internal/policy/sweep_test.go`:

```go
package policy

import (
	"slices"
	"testing"
)

// sweepYAML grants alice on the edge site alone. inventory() puts srx-fw-04,
// srx-fw-05 and srx-fw-22 at site edge, srx-lab-01 at site lab, and the rest
// elsewhere.
const sweepYAML = `
scopes:
  - {name: all_devices, match: {}}
  - {name: edge, match: {site: [edge]}}
  - {name: campus, match: {site: [campus]}}
roles: [{name: ro, privilege: readonly, permit: ["show **"]}]
subjects:
  - {name: fw_ops, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 5m}
grants:
  - {subject: fw_ops, scope: edge, roles: [ro]}
`

var sweepAlice = MemberOf("user:alice@corp.example.com")

// A sweep lists the devices its scope selects on which the member holds a
// grant, by name, and nothing else: all_devices from a caller granted one
// site is that site (decision 42 ruling 1).
func TestASweepListsOnlyGrantedDevicesTheScopeSelects(t *testing.T) {
	p := mustParse(t, sweepYAML)
	for _, scope := range []string{"all_devices", "edge"} {
		got, next := p.SweepPage(sweepAlice, scope, "", 10, now)
		if want := []string{"srx-fw-04", "srx-fw-05", "srx-fw-22"}; !slices.Equal(got, want) || next != "" {
			t.Errorf("%s: %v next %q, want %v", scope, got, next, want)
		}
	}
}

// An undeclared scope, a declared one selecting no granted device, and an
// unknown principal all answer an empty page (decision 42 ruling 2).
func TestAnUndeclaredScopeAndAnUngrantedOneAnswerAlike(t *testing.T) {
	p := mustParse(t, sweepYAML)
	for name, c := range map[string]struct {
		m     Member
		scope string
	}{
		"undeclared":        {sweepAlice, "nope"},
		"no granted device": {sweepAlice, "campus"},
		"unknown principal": {MemberOf("user:mallory@corp.example.com"), "edge"},
	} {
		if got, next := p.SweepPage(c.m, c.scope, "", 10, now); got != nil || next != "" {
			t.Errorf("%s: %v next %q", name, got, next)
		}
	}
}

// Pages are by name, after the cursor, and the last page names no next.
// A cursor that names no device starts at the next name after it.
func TestASweepPagesByName(t *testing.T) {
	p := mustParse(t, sweepYAML)
	got, next := p.SweepPage(sweepAlice, "edge", "", 2, now)
	if !slices.Equal(got, []string{"srx-fw-04", "srx-fw-05"}) || next != "srx-fw-05" {
		t.Fatalf("page 1: %v next %q", got, next)
	}
	got, next = p.SweepPage(sweepAlice, "edge", next, 2, now)
	if !slices.Equal(got, []string{"srx-fw-22"}) || next != "" {
		t.Fatalf("page 2: %v next %q", got, next)
	}
	got, _ = p.SweepPage(sweepAlice, "edge", "srx-fw-045", 2, now)
	if !slices.Equal(got, []string{"srx-fw-05", "srx-fw-22"}) {
		t.Fatalf("a cursor between names: %v", got)
	}
	if got, next := p.SweepPage(sweepAlice, "edge", "srx-fw-22", 2, now); got != nil || next != "" {
		t.Fatalf("past the end: %v next %q", got, next)
	}
}

// An expired grant selects nothing, as it mints nothing.
func TestAnExpiredGrantSweepsNothing(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: edge, match: {site: [edge]}}]
roles: [{name: ro, privilege: readonly, permit: ["show **"]}]
subjects: [{name: fw_ops, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 5m}]
grants: [{subject: fw_ops, scope: edge, roles: [ro], expires: 2020-01-01}]
`)
	if got, _ := p.SweepPage(sweepAlice, "edge", "", 10, now); got != nil {
		t.Fatalf("an expired grant: %v", got)
	}
}

// A page walks the member's own granted devices and nothing else, so an
// undeclared scope and a declared one selecting no granted device cost the
// same, and neither walks the inventory (decision 42 ruling 2, "nor a timing
// oracle"). A member with no grant walks nothing.
func TestASweepVisitsOnlyGrantedDevices(t *testing.T) {
	p := mustParse(t, sweepYAML)
	_, _, undeclared := p.sweepPage(sweepAlice, "nope", "", 10, now)
	_, _, ungranted := p.sweepPage(sweepAlice, "campus", "", 10, now)
	_, _, granted := p.sweepPage(sweepAlice, "edge", "", 10, now)
	if undeclared != 3 || ungranted != 3 || granted != 3 {
		t.Fatalf("visits: undeclared %d, ungranted %d, granted %d; want 3, alice's three edge devices, each",
			undeclared, ungranted, granted)
	}
	if _, _, none := p.sweepPage(MemberOf("user:mallory@corp.example.com"), "all_devices", "", 10, now); none != 0 {
		t.Fatalf("a member with no grant visited %d devices", none)
	}
	if n := len(inventory()); n <= 3 {
		t.Fatalf("the inventory has %d devices: the test needs more than alice's three to mean anything", n)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/policy/ -run 'Sweep|UndeclaredScope|ExpiredGrantSweeps' -count=1`
Expected: FAIL to build, `p.SweepPage undefined`.

- [ ] **Step 3: Write `SweepPage`**

In `internal/policy/load.go`, in `type Policy struct`, right after the `devIndex` field
(`devIndex map[string]admission.Device`), add:

```go
	// sweepOnce and sweep memoize sweepIndex: every inventory name sorted,
	// and each declared scope's selection in that order, once per policy
	// (decision 42).
	sweepOnce sync.Once
	sweep     *sweepIndex
```

Create `internal/policy/sweep.go`:

```go
package policy

import (
	"slices"
	"sort"
	"time"
)

// sweepIndex is what a sweep walks, built once per policy: every inventory
// name, sorted, and for each declared scope the positions in names of the
// devices it selects, ascending. A position orders as its name does.
type sweepIndex struct {
	names  []string
	scopes map[string][]int32
}

// SweepPage is one page of a mint by scope (design §17; spec §13 decision 42
// ruling 1): the devices scope selects on which m holds a grant unexpired at
// now, in the byte order of their names, after the name after, at most limit
// of them. next is the page's last name when more remain, "" at the end.
//
// A scope this policy does not declare, a declared one selecting no device m
// holds a grant on, and a page past the end are all an empty page: one
// answer, so a sweep tells a caller nothing about devices it holds no grant
// on, or about which scopes exist (ruling 2). Nor does its cost: see
// sweepPage.
func (p *Policy) SweepPage(m Member, scope, after string, limit int, now time.Time) (devices []string, next string) {
	devices, next, _ = p.sweepPage(m, scope, after, limit, now)
	return devices, next
}

// sweepPage is SweepPage, and how many devices it visited. It walks only the
// devices m holds an unexpired grant on, after after: the union of those
// grants' scopes, merged in name order from the index. The swept scope only
// filters that walk, and an undeclared one is walked as a scope selecting
// nothing. So the walk, and the time it takes, is set by m's own grants,
// never by which scopes exist or by how many inventory names lie in a range
// the caller chose (ruling 2; pre-flight I-1).
func (p *Policy) sweepPage(m Member, scope, after string, limit int, now time.Time) (devices []string, next string, visited int) {
	x := p.sweepIndex()
	start := sort.SearchStrings(x.names, after)
	if start < len(x.names) && x.names[start] == after {
		start++
	}
	// Each of m's unexpired grants' scopes, once, from start on.
	var lists [][]int32
	held := map[string]bool{}
	for _, sub := range p.subjectsOf(m) {
		for _, g := range p.grants {
			if g.Subject != sub.Name || held[g.Scope] || (!g.Expires.IsZero() && !now.IsZero() && !now.Before(g.Expires)) {
				continue
			}
			held[g.Scope] = true
			sel := x.scopes[g.Scope]
			from := sort.Search(len(sel), func(i int) bool { return sel[i] >= int32(start) })
			lists = append(lists, sel[from:])
		}
	}
	swept := x.scopes[scope] // nil for an undeclared scope
	for limit > 0 {
		// The lowest position at the head of any list, taken off each.
		lo := int32(-1)
		for _, l := range lists {
			if len(l) > 0 && (lo < 0 || l[0] < lo) {
				lo = l[0]
			}
		}
		if lo < 0 {
			break
		}
		for i, l := range lists {
			if len(l) > 0 && l[0] == lo {
				lists[i] = l[1:]
			}
		}
		visited++
		if _, ok := slices.BinarySearch(swept, lo); !ok {
			continue
		}
		if len(devices) == limit {
			return devices, devices[limit-1], visited
		}
		devices = append(devices, x.names[lo])
	}
	return devices, "", visited
}

// sweepIndex builds the index once: a Policy is one bundle, never changed
// once loaded. Every declared scope is indexed at once, so the first sweep
// after a load costs the same whichever scope it names.
func (p *Policy) sweepIndex() *sweepIndex {
	p.sweepOnce.Do(func() {
		x := &sweepIndex{names: make([]string, 0, len(p.devIndex)), scopes: make(map[string][]int32, len(p.scopes))}
		for name := range p.devIndex {
			x.names = append(x.names, name)
		}
		sort.Strings(x.names)
		for sname, s := range p.scopes {
			var sel []int32
			for i, name := range x.names {
				if s.Selects(p.devIndex[name]) {
					sel = append(sel, int32(i))
				}
			}
			x.scopes[sname] = sel
		}
		p.sweep = x
	})
	return p.sweep
}
```

A device is granted here exactly when `composeAll` would find a grant for it: an unexpired grant
of one of m's subjects whose scope selects it. The broker then mints each listed device as a
device named, so an item's answer never rests on this walk.

- [ ] **Step 4: Run the policy tests to verify they pass**

Run: `go test ./internal/policy/ -run 'Sweep|UndeclaredScope|ExpiredGrantSweeps' -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Write the failing broker tests**

Create `internal/broker/sweep_test.go`:

```go
package broker

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

// sweepPolicy grants alice on site dc1 alone.
const sweepPolicy = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc, match: {site: [dc1]}}
  - {name: lab, match: {site: [lab]}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
grants:
  - {subject: netops, scope: dc, roles: [network_admin], max_privilege: admin}
`

// newSweepFixture is the fixture (batch_max 4) with five dc1 devices and one
// lab device beside leaf1, nx1 and bare, which carry no site.
func newSweepFixture(t *testing.T) *fixture {
	t.Helper()
	dev := func(name, site, addr string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: map[string]string{"site": site}}
	}
	return newFixtureWith(t, 8, sweepPolicy, dev("dc-a", "dc1", "10.1.0.1"), dev("dc-b", "dc1", "10.1.0.2"),
		dev("dc-c", "dc1", "10.1.0.3"), dev("dc-d", "dc1", "10.1.0.4"), dev("dc-e", "dc1", "10.1.0.5"),
		dev("lab-1", "lab", "10.9.0.1"))
}

// A sweep pages the granted devices its scope selects by name, batch_max at
// a time, each answered as a named device is, and every record names the
// sweep (decision 42 rulings 1 and 4).
func TestASweepPagesTheGrantedDevicesByName(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	first := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, ""))
	var names []string
	for _, it := range first.Results {
		if it.Verdict != "permit" || it.Login == "" || it.Address == "" {
			t.Fatalf("each item is a named device's permit: %+v", it)
		}
		names = append(names, it.Device)
	}
	if strings.Join(names, ",") != "dc-a,dc-b,dc-c,dc-d" || first.Next != "dc-d" || first.Subject != "netops" {
		t.Fatalf("page 1: %v next %q subject %q", names, first.Next, first.Subject)
	}
	last := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc","after":"dc-d"}`, ""))
	if len(last.Results) != 1 || last.Results[0].Device != "dc-e" || last.Next != "" {
		t.Fatalf("page 2: %+v next %q", last.Results, last.Next)
	}
	// all_devices from a caller granted dc1 is dc1: never lab-1, leaf1, nx1 or bare.
	all := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"all_devices"}`, ""))
	for _, it := range all.Results {
		if !strings.HasPrefix(it.Device, "dc-") {
			t.Fatalf("a sweep listed %s, which alice holds no grant on", it.Device)
		}
	}
	for _, r := range eventsOf(f.records(t), "mint") {
		sw, _ := r["sweep"].(map[string]any)
		if sw["scope"] == nil {
			t.Fatalf("a sweep's record without its sweep: %v", r)
		}
	}
}

// An undeclared scope and a declared one selecting no granted device are
// one answer, byte for byte, and one record each with no device (decision 42
// ruling 2).
func TestASweepIsNoEnumerationOracle(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	undeclared := f.post(ctx, f.state(f.alice), `{"scope":"nope"}`, "")
	ungranted := f.post(ctx, f.state(f.alice), `{"scope":"lab"}`, "")
	pastTheEnd := f.post(ctx, f.state(f.alice), `{"scope":"dc","after":"dc-e"}`, "")
	if undeclared.Code != 200 || undeclared.Body.String() != ungranted.Body.String() ||
		undeclared.Body.String() != pastTheEnd.Body.String() {
		t.Fatalf("three answers:\n%s\n%s\n%s", answer(undeclared), answer(ungranted), answer(pastTheEnd))
	}
	if resp := decodeMint(t, undeclared); resp.Results == nil || len(resp.Results) != 0 || resp.Next != "" {
		t.Fatalf("an empty page is results: [] and no next: %s", undeclared.Body.String())
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 3 {
		t.Fatalf("one record per empty page: %v", mints)
	}
	for _, r := range mints {
		if r["verdict"] != "deny" || r["reason"] != "no_grants_matched" || r["device"] != nil || r["sweep"] == nil {
			t.Fatalf("an empty page's record: %v", r)
		}
	}
}

// A malformed sweep is refused whole, and writes no record.
func TestMalformedSweepsAreRefusedWhole(t *testing.T) {
	f := newSweepFixture(t)
	for name, body := range map[string]string{
		"devices and a scope":  `{"scope":"dc","devices":["dc-a"]}`,
		"after with no scope":  `{"after":"dc-a"}`,
		"after with devices":   `{"devices":["dc-a"],"after":"dc-a"}`,
		"a scope with a space": `{"scope":"d c"}`,
		"a control character":  `{"scope":"dc","after":"dc\u0007"}`,
		"a 254-byte scope":     `{"scope":"` + strings.Repeat("s", 254) + `"}`,
	} {
		if w := f.post(context.Background(), f.state(f.alice), body, ""); w.Code != 400 {
			t.Errorf("%s: %s", name, answer(w))
		}
	}
	if recs := f.records(t); len(recs) != 0 {
		t.Fatalf("a malformed sweep writes no record: %v", recs)
	}
}

// A page retried under its key is replayed: the same tokens, and no device
// minted twice (decision 42 ruling 3).
func TestASweepPageRetriedUnderItsKeyIsReplayed(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	a := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, "page-1"))
	b := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, "page-1"))
	if len(a.Results) != 4 || len(b.Results) != 4 {
		t.Fatalf("results: %d and %d", len(a.Results), len(b.Results))
	}
	for i := range a.Results {
		if a.Results[i].Login != b.Results[i].Login {
			t.Fatalf("%s was minted again on the retry", a.Results[i].Device)
		}
	}
	c, err := f.st.Candidates(ctx, store.TokenKey{NAS: "dc-a", Username: "alice"})
	if err != nil || len(c) != 1 {
		t.Fatalf("dc-a holds %d unspent tokens (%v), want 1", len(c), err)
	}
}

// A refusal of a whole sweep page names the sweep too, here the mint gate's
// (decision 42 ruling 4).
func TestASweepPageRefusedWholeNamesTheSweep(t *testing.T) {
	f := newSweepFixture(t)
	f.b.MintGate = func(*policy.Policy) error { return errors.New("not yet judged") }
	w := f.post(context.Background(), f.state(f.alice), `{"scope":"dc","after":"dc-a"}`, "")
	mints := eventsOf(f.records(t), "mint")
	if w.Code != 503 || len(mints) != 1 {
		t.Fatalf("%s\nrecords %v", answer(w), mints)
	}
	if sw, _ := mints[0]["sweep"].(map[string]any); sw["scope"] != "dc" || sw["after"] != "dc-a" {
		t.Fatalf("the refusal's record: %v", mints[0])
	}
}
```

- [ ] **Step 6: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'Sweep' -count=1`
Expected: FAIL to build, `unknown field Next in struct literal` or `first.Next undefined`.

- [ ] **Step 7: The wire, the record and the minter**

In `internal/broker/api/api.go`, replace the `MintRequest` type with:

```go
// MintRequest is POST /v1/tokens: Devices by name, or a page of Scope's
// (spec §13 decision 42), continued after After. TTLSeconds is a request,
// not an instruction: the broker clamps it to the subject's token_ttl.
type MintRequest struct {
	Devices    []string `json:"devices,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	After      string   `json:"after,omitempty"`
	Enable     bool     `json:"enable"`
	TTLSeconds int      `json:"ttl_seconds"`
	Purpose    string   `json:"purpose"`
}
```

In `MintResponse`, after `Results []MintItem `json:"results"``, add:

```go
	// Next is a sweep page's last device when more remain: the next page's
	// after. Absent at a sweep's end, and on a mint by name.
	Next string `json:"next,omitempty"`
```

In `internal/decision/log.go`, in `type Record struct`, after `Mint *Mint `json:"mint,omitempty"``, add:

```go
	// Sweep names the sweep a mint record's device came from, when the
	// request was by scope (spec §13 decision 42 ruling 4).
	Sweep *Sweep `json:"sweep,omitempty"`
```

and after `type Mint struct { … }`, add:

```go
// Sweep is a mint record's sweep: the scope and the page's cursor.
type Sweep struct {
	Scope string `json:"scope"`
	After string `json:"after,omitempty"`
}
```

In `internal/token/minter.go`, in `type Request struct`, after the `OIDC *decision.OIDC` field, add:

```go
	// Sweep is the sweep this device was minted by, copied onto the permit
	// record; nil for a mint by name (spec §13 decision 42 ruling 4).
	Sweep *decision.Sweep
```

and in the permit record's literal (`log.Emit(decision.Record{TS: m.now(), Event: decision.EventMint, …`),
after `Policy:     r.Policy,`, add `Sweep:      r.Sweep,`.

- [ ] **Step 8: The broker**

In `internal/broker/broker.go`, in `tokens`, replace

```go
	if len(req.Devices) == 0 || len(req.Devices) > b.BatchMax {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"name between 1 and %d devices per request; page a larger sweep (design §17)", b.BatchMax))
		return
	}
```

with

```go
	if req.Scope != "" || req.After != "" {
		if msg := sweepRequestError(req); msg != "" {
			writeError(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
	} else if len(req.Devices) == 0 || len(req.Devices) > b.BatchMax {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"name between 1 and %d devices per request, or a scope; page a larger sweep (design §17)", b.BatchMax))
		return
	}
```

The `seen` loop that follows is unchanged: a sweep's `req.Devices` is empty there.

After the `// No token exists that a logout cannot find (Ruling 11).` block, which ends at its
closing `}`, and before `// Every device's record is reserved before the first is minted`, insert:

```go
	// A sweep's page is resolved here, from the policy in force now, so the
	// reservation below holds each of its devices; each is minted under the
	// hold against the policy held, as a named device is (decision 42 ruling
	// 1). An empty page is one answer whatever made it so (ruling 2).
	var next string
	if req.Scope != "" {
		pol := b.Policy.Load()
		req.Devices, next = pol.SweepPage(m, req.Scope, req.After, b.BatchMax, now)
		if len(req.Devices) == 0 {
			b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
				Reason: decision.NoGrantsMatched, Principal: principal,
				Auth:  &decision.Auth{Method: c.cred.Method, Directory: directoryAuth(answer), OIDC: c.auth().OIDC},
				Sweep: sweepOf(req)})
			resp := api.MintResponse{Principal: principal, Results: []api.MintItem{}}
			resp.Subject, resp.Subjects = subjectNames(pol, m)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}
```

At the end of `tokens`, replace

```go
	release()
	if b.revokedSince(w, r, c, resp.Results) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
```

with

```go
	release()
	if b.revokedSince(w, r, c, resp.Results) {
		return
	}
	resp.Next = next
	writeJSON(w, http.StatusOK, resp)
}

// sweepRequestError is why a request naming scope or after is malformed, or
// "" (decision 42 ruling 1): a scope in place of devices, after only beside
// a scope, each written as an inventory name is.
func sweepRequestError(req api.MintRequest) string {
	switch {
	case req.Scope == "":
		return "after continues a sweep: name its scope (design §17)"
	case len(req.Devices) > 0:
		return "name devices or a scope, not both (design §17)"
	case !deviceName(req.Scope) || (req.After != "" && !deviceName(req.After)):
		return fmt.Sprintf("a scope, and a sweep's after, is 1 to %d printable ASCII characters", maxDeviceName)
	}
	return ""
}

// sweepOf is the sweep block a mint record carries, nil for a mint by name
// (decision 42 ruling 4).
func sweepOf(req api.MintRequest) *decision.Sweep {
	if req.Scope == "" {
		return nil
	}
	return &decision.Sweep{Scope: req.Scope, After: req.After}
}
```

In `mintOne`, in the `deny` closure's record literal, after `Device: &decision.Device{Name: name, Platform: platform}`,
add `, Sweep: sweepOf(req)` (inside the literal, before its closing `}`). In the `b.Minter.Mint`
call's `token.Request{…}` literal, after `Log: buf`, add `, Sweep: sweepOf(req)`.

In `tokens`, the five request-level refusals each write a `decision.Record` that ends
`Principal: principal, Auth: c.auth()})`:
- the directory refusal after `b.memberFor`;
- `noteOwner`'s `StoreUnavailable`;
- the `Reserve` failure's `StoreUnavailable`;
- `heldCollision`'s refusal;
- the `MintGate` refusal.

In each, replace that ending with `Principal: principal, Auth: c.auth(), Sweep: sweepOf(req)})`
(`grep -n "Principal: principal, Auth: c.auth()})" internal/broker/broker.go` finds six at
`d6bc054`: the five in `tokens`, and one in a later function, which has no `req` and stays as it
is). The empty-page record above already carries `Sweep`.

- [ ] **Step 9: Run the tests to verify they pass, and the packages around them**

Run: `go test ./internal/broker/ ./internal/policy/ ./internal/token/ ./internal/decision/ ./internal/broker/api/ -count=1`
Expected: PASS. `TestMalformedBatchesAreRefusedWhole` still passes: its "no devices" body
(`{"devices":[]}`) names no scope and is refused by the unchanged branch.

Run: `go test -race ./internal/broker/ -run 'Sweep|Mint|Idempotency' -count=1`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
gofmt -l internal/ && go vet ./internal/...
git add internal/policy/sweep.go internal/policy/sweep_test.go internal/policy/load.go \
  internal/broker/api/api.go internal/decision/log.go internal/token/minter.go \
  internal/broker/broker.go internal/broker/sweep_test.go
git commit -m "feat(broker): mint by scope, paged by name, with no enumeration oracle (decision 42)"
```

---

### Task 3: `port49 workload token --scope`, and Oxidized's `PORT49_SCOPE`

**Files:**
- Modify: `internal/workload/client.go`, `internal/workload/client_test.go`,
  `cmd/port49/workload.go`, `cmd/port49/workload_test.go`, `cmd/port49/main.go` (usage only),
  `examples/oxidized/port49-oxidized-run`, `examples/oxidized/run_test.go`

**Interfaces:**
- Consumes: `api.MintRequest.Scope` and `After`, and `api.MintResponse.Next` (Task 2).
- Produces: `workload.MintOptions.Scope string`. `(*workload.Client).Mint` sweeps when `Scope`
  is set, and a `next` that does not advance is a `*workload.DecodeError`.

- [ ] **Step 1: Write the failing client tests**

Append to `internal/workload/client_test.go`:

```go
// sweepPages answers each sweep request with the page its after names.
func sweepPages(pages map[string]api.MintResponse) func(http.ResponseWriter, api.MintRequest) {
	return func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(pages[req.After])
	}
}

func permitted(names ...string) []api.MintItem {
	var out []api.MintItem
	for _, n := range names {
		out = append(out, api.MintItem{Device: n, Verdict: "permit", Username: "svc-oxidized", Login: "TOKEN" + n})
	}
	return out
}

// A sweep follows next, each page under its own key, naming the scope and
// no device list (decision 42 ruling 3).
func TestASweepFollowsNextEachPageUnderItsOwnKey(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){sweepPages(map[string]api.MintResponse{
		"":  {Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized", Results: permitted("a", "b"), Next: "b"},
		"b": {Principal: "spiffe://corp.example.com/host/oxidized-01", Results: permitted("c")},
	})}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Scope: "dc", TTL: time.Minute})
	if err != nil || len(resp.Results) != 3 || resp.Results[2].Device != "c" || resp.Subject != "svc_oxidized" {
		t.Fatalf("%d results, subject %q: %v", len(resp.Results), resp.Subject, err)
	}
	if len(f.bodies) != 2 || f.bodies[0].Scope != "dc" || f.bodies[0].After != "" || f.bodies[1].After != "b" ||
		len(f.bodies[0].Devices) != 0 || f.keys[0] == f.keys[1] || f.bodies[1].TTLSeconds != 60 {
		t.Fatalf("keys %v bodies %+v", f.keys, f.bodies)
	}
}

// A broker whose next does not advance is a fault, never a loop.
func TestASweepThatDoesNotAdvanceStops(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){sweepPages(map[string]api.MintResponse{
		"":  {Results: permitted("a"), Next: "a"},
		"a": {Results: permitted("b"), Next: "a"},
	})}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Scope: "dc"})
	var de *DecodeError
	if !errors.As(err, &de) || len(resp.Results) != 2 || len(f.bodies) != 2 {
		t.Fatalf("err %v, %d results, %d requests", err, len(resp.Results), len(f.bodies))
	}
}

// An empty sweep is no error: the caller says what it means.
func TestAnEmptySweepIsNoError(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){sweepPages(map[string]api.MintResponse{
		"": {Principal: "spiffe://corp.example.com/host/oxidized-01", Results: []api.MintItem{}},
	})}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Scope: "nope"})
	if err != nil || len(resp.Results) != 0 || len(f.bodies) != 1 {
		t.Fatalf("err %v, %d results, %d requests", err, len(resp.Results), len(f.bodies))
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/workload/ -run 'Sweep' -count=1`
Expected: FAIL to build, `unknown field Scope in struct literal of type MintOptions`.

- [ ] **Step 3: Write the sweep**

In `internal/workload/client.go`, replace `type MintOptions struct { … }` with:

```go
// MintOptions is one run's mint: Devices by name, or every device Scope
// selects that the workload holds a grant on (spec §13 decision 42).
type MintOptions struct {
	Devices []string
	Scope   string
	Enable  bool
	TTL     time.Duration
	Purpose string
}
```

At the top of `Mint`, after `deadline := c.cfg.Now().Add(c.cfg.Deadline)`, add:

```go
	if o.Scope != "" {
		return c.sweep(ctx, deadline, o)
	}
```

and after `Mint`, add:

```go
// sweep mints o.Scope's pages, each under its own Idempotency-Key, following
// the broker's next until it names none (decision 42 ruling 3). A next that
// does not advance past the page's after is the broker's fault, a
// *DecodeError, never a loop. A page the deadline ends is a *TemporaryError
// with the pages before it returned; it names no unminted device, since a
// sweep's devices are the broker's to list.
func (c *Client) sweep(ctx context.Context, deadline time.Time, o MintOptions) (api.MintResponse, error) {
	out := api.MintResponse{Results: []api.MintItem{}}
	after := ""
	for {
		body, err := json.Marshal(api.MintRequest{Scope: o.Scope, After: after, Enable: o.Enable,
			TTLSeconds: int(o.TTL / time.Second), Purpose: o.Purpose})
		if err != nil {
			return out, err
		}
		key, err := newKey()
		if err != nil {
			return out, err
		}
		var resp api.MintResponse
		if err := c.do(ctx, deadline, http.MethodPost, "/v1/tokens", body, key, &resp); err != nil {
			return out, err
		}
		if out.Principal == "" {
			out.Principal, out.Subject, out.Subjects = resp.Principal, resp.Subject, resp.Subjects
		}
		out.Results = append(out.Results, resp.Results...)
		if resp.Next == "" {
			return out, nil
		}
		if resp.Next <= after || len(resp.Results) == 0 {
			return out, &DecodeError{Msg: fmt.Sprintf("the broker's sweep of %s did not advance past %q", o.Scope, after)}
		}
		after = resp.Next
	}
}
```

- [ ] **Step 4: Run the client tests to verify they pass**

Run: `go test ./internal/workload/ -count=1 -race`
Expected: PASS, the existing tests included.

- [ ] **Step 5: Write the failing CLI tests**

Append to `cmd/port49/workload_test.go`:

```go
// --scope sweeps every page and writes one line per permitted device.
func TestWorkloadTokenSweepsAScope(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01"}
		item := func(d, tok string) api.MintItem {
			return api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1", Platform: "arista_eos",
				Username: "svc", Login: tok, ExpiresAt: "2026-10-09T03:00:00Z"}
		}
		switch req.After {
		case "":
			resp.Results, resp.Next = []api.MintItem{item("leaf1", "T1")}, "leaf1"
		case "leaf1":
			resp.Results = []api.MintItem{item("leaf2", "T2")}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "backup_targets"), &out, &errb)
	if code != 0 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc\tT1\t2026-10-09T03:00:00Z\n"+
		"leaf2\t10.0.0.1\tarista_eos\tsvc\tT2\t2026-10-09T03:00:00Z\n" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A sweep that selects nothing for the workload is final, exit 77, with one
// message whether the scope exists or not (decision 42 rulings 2 and 5).
func TestAnEmptySweepIsFinal(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Results: []api.MintItem{}})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "nope"), &out, &errb)
	if code != exitFinal || out.Len() != 0 || !strings.Contains(errb.String(),
		"port49 workload token: scope nope: no device it selects is one you hold a grant on, or no scope has that name") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// --scope with a device list is usage.
func TestAScopeAndDevicesTogetherIsUsage(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "dc", "leaf1"), &out, &errb); code != 2 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
```

- [ ] **Step 6: Run them to verify they fail**

Run: `go test ./cmd/port49/ -run 'Sweep|AScopeAndDevices' -count=1`
Expected: FAIL: `flag provided but not defined: -scope`, exit 2.

- [ ] **Step 7: The CLI**

In `cmd/port49/workload.go`'s `workloadToken`, after the `out := fs.String("out", …)` line, add:

```go
	scope := fs.String("scope", "", "mint every device this scope selects that the workload holds a grant on, "+
		"in place of DEVICE... and --devices-file (decision 42)")
```

Replace

```go
	if len(devices) == 0 || (*format != "tsv" && *format != "json") {
```

with

```go
	if (len(devices) == 0) == (*scope == "") || (*format != "tsv" && *format != "json") {
```

Replace the `Mint` call and the `switch` after it, from `resp, err := c.Mint(` through the
`switch`'s closing brace, with:

```go
	resp, err := c.Mint(context.Background(), workload.MintOptions{Devices: devices, Scope: *scope, Enable: *enable,
		TTL: *ttl, Purpose: *purpose})
	code := 0
	var te *workload.TemporaryError
	switch {
	case errors.As(err, &te) && *scope != "":
		fmt.Fprintf(stderr, "%s: %s: the sweep of scope %s stopped after %d devices; run again\n", cmd,
			safe(err.Error()), safe(*scope), len(resp.Results))
		code = exitTemporary
	case errors.As(err, &te):
		fmt.Fprintf(stderr, "%s: %s: %d of %d devices were not minted; run again\n", cmd, safe(err.Error()),
			len(te.Unminted), len(devices))
		code = exitTemporary
	case err != nil && *scope != "":
		fmt.Fprintf(stderr, "%s: %s: the sweep of scope %s stopped after %d devices\n", cmd, safe(err.Error()),
			safe(*scope), len(resp.Results))
		code = 1
	case err != nil:
		// A final answer, perhaps after earlier pages minted: those are
		// still written (pre-flight I-1).
		fmt.Fprintf(stderr, "%s: %s: %d of %d devices were not minted\n", cmd, safe(err.Error()),
			len(devices)-len(resp.Results), len(devices))
		code = 1
	case *scope != "" && len(resp.Results) == 0:
		// One message for an undeclared scope and an ungranted one: the
		// broker never tells them apart (decision 42 ruling 2).
		fmt.Fprintf(stderr, "%s: scope %s: no device it selects is one you hold a grant on, or no scope has that name\n",
			cmd, safe(*scope))
		return exitFinal
	}
```

In `cmd/port49/main.go`'s usage, replace

```
                        [--deadline DURATION] [DEVICE...]
```

with

```
                        [--deadline DURATION] [--scope NAME | DEVICE...]
```

- [ ] **Step 8: Run the CLI tests to verify they pass**

Run: `go test ./cmd/port49/ -run 'Workload|Sweep|Scope|ExitCodes|FinalRefusal' -count=1`
Expected: PASS.

- [ ] **Step 9: The Oxidized wrapper takes `PORT49_SCOPE`: the failing test**

In `examples/oxidized/run_test.go`:
- Add `scope string` to `type scenario struct`.
- In `runCase`'s fake `script`, add this as the line after `#!/usr/bin/env bash`:

  ```bash
  printf '%s\n' "$@" > "$FAKE_ARGS"
  ```
- Append to `cmd.Env`: `"FAKE_ARGS="+filepath.Join(dir, "args")`.
- After the `cmd.Env = append(…)` statement, add:

```go
	if c.scope != "" {
		cmd.Env = append(cmd.Env, "PORT49_SCOPE="+c.scope)
	}
```

Append the test:

```go
// PORT49_SCOPE replaces the node list: port49 is asked for the scope's
// devices, and the nodes file is not read (decision 42 ruling 5).
func TestAScopeReplacesTheNodeList(t *testing.T) {
	code, stderr, calls, db := runCase(t, scenario{tsv: minted, exit: 0, scope: "backup_targets"})
	args, err := os.ReadFile(filepath.Join(filepath.Dir(db), "args"))
	if err != nil || !strings.Contains(string(args), "--scope\nbackup_targets\n") ||
		strings.Contains(string(args), "--devices-file") {
		t.Fatalf("exit %d args %q stderr %s", code, args, stderr)
	}
	if len(calls) == 0 || calls[0] != "GET /reload" {
		t.Fatalf("calls %v", calls)
	}
}
```

Run: `go test ./examples/oxidized/ -run TestAScopeReplacesTheNodeList -count=1`
Expected: FAIL: the args hold `--devices-file`.

- [ ] **Step 10: The wrapper**

In `examples/oxidized/port49-oxidized-run`, in the `# Environment:` block, after the
`OXIDIZED_NODES` line, add:

```bash
#   PORT49_SCOPE        a policy scope: mint every device it selects that this host
#                       holds a grant on, in place of OXIDIZED_NODES (port49 plan 9a)
```

Replace

```bash
status=0
"$port49" workload token --broker "$PORT49_BROKER" --broker-ca "$PORT49_BROKER_CA" \
  --cert "$PORT49_CERT" --key "$PORT49_KEY" --devices-file "$nodes" \
```

with

```bash
targets=(--devices-file "$nodes")
if [ -n "${PORT49_SCOPE:-}" ]; then targets=(--scope "$PORT49_SCOPE"); fi
status=0
"$port49" workload token --broker "$PORT49_BROKER" --broker-ca "$PORT49_BROKER_CA" \
  --cert "$PORT49_CERT" --key "$PORT49_KEY" "${targets[@]}" \
```

In `examples/oxidized/README.md`, replace

```markdown
The wrapper's environment is documented at the top of the script. `OXIDIZED_NODES` is a file of
device names, one a line.
```

with

```markdown
The wrapper's environment is documented at the top of the script. `OXIDIZED_NODES` is a file of
device names, one a line. `PORT49_SCOPE` names a policy scope in its place: the wrapper then asks
port49 for every device the scope selects that this host holds a grant on, page by page, and
reads no nodes file (policy engine spec §13 decision 42). A scope that selects nothing for this
host, and a scope name that does not exist, both exit 77 with one message. L49 ran with a nodes
file; a sweep was not part of it.
```

- [ ] **Step 11: Run every test this task touches, and commit**

Run: `go test ./internal/workload/ ./cmd/port49/ ./examples/oxidized/ -count=1`
Expected: PASS.

```bash
gofmt -l internal cmd examples && go vet ./...
git add internal/workload cmd/port49/workload.go cmd/port49/workload_test.go cmd/port49/main.go examples/oxidized
git commit -m "feat(workload): port49 workload token --scope sweeps by the broker's pages; Oxidized takes PORT49_SCOPE"
```

---

### Task 4: The per-user config file

**Files:**
- Create: `internal/userconfig/userconfig.go`, `internal/userconfig/userconfig_test.go`,
  `cmd/port49/config_test.go`
- Modify: `cmd/port49/main.go` (`sessionFlags`, `login`, `agentMain`, usage),
  `cmd/port49/main_test.go` (`TestMain`)

**Interfaces:**
- Consumes: decision 42 ruling 6 (Task 1).
- Produces, in package `userconfig`:
  - `func Dir() string` and `func Path() string`;
  - `type File struct{ Broker, BrokerCA, Cert, Key string }`;
  - `func Load(path string) (f File, ok bool, err error)`;
  - `func ReadPrivate(path string, max int64, what string) ([]byte, error)`;
  - `func WritePrivate(path string, data []byte, what string) error`.

  In `cmd/port49`: `func (s *sessionFlags) fill(fs *flag.FlagSet) error`.

- [ ] **Step 1: Write the failing package tests**

Create `internal/userconfig/userconfig_test.go`:

```go
package userconfig

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002, the default on Ubuntu, a t.TempDir is
// group-writable, which ReadPrivate refuses to read from.
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// private writes body as name in a fresh 0700 directory.
func private(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(privateDir(t), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Relative paths are the file's directory's; ~/ is the home directory.
func TestLoadResolvesPaths(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	p := private(t, "config.yaml", "broker: https://b.example:8443\nbroker_ca: ca.pem\ncert: ~/.port49/a.pem\nkey: /k.pem\n")
	f, ok, err := Load(p)
	if err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if f.Broker != "https://b.example:8443" || f.BrokerCA != filepath.Join(filepath.Dir(p), "ca.pem") ||
		f.Cert != "/home/alice/.port49/a.pem" || f.Key != "/k.pem" {
		t.Fatalf("%+v", f)
	}
}

// No file is no config, and no error.
func TestAMissingFileIsNoFile(t *testing.T) {
	if _, ok, err := Load(filepath.Join(t.TempDir(), "config.yaml")); ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
}

// Whoever can write the file or its directory chooses the broker the
// operator trusts: every such file is refused, never read (decision 42
// ruling 6).
func TestAFileOthersCouldWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a group-writable file: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(p), 0o700) })
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "directory holding the port49 config file") {
		t.Fatalf("a world-writable directory: %v", err)
	}
}

// A directory higher up that others can write is refused too: they could
// rename the one below it and put their own in its place. A sticky one, as
// /tmp is, cannot be used so, and is read through (decision 42 ruling 6).
func TestADirectoryAboveOthersCanWriteIsRefused(t *testing.T) {
	top := filepath.Join(privateDir(t), "shared")
	dir := filepath.Join(top, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("broker: https://b.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(top, 0o700) })
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), top+" is writable by others") {
		t.Fatalf("a world-writable directory two up: %v", err)
	}
	if err := os.Chmod(top, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Load(p); err != nil || !ok {
		t.Fatalf("a sticky directory two up: ok %v err %v", ok, err)
	}
}

// The broker CA the file names is refused when others can write it: whoever
// can chooses which broker the operator trusts.
func TestABrokerCAOthersCanWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "broker_ca: ca.pem\n")
	ca := filepath.Join(filepath.Dir(p), "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), ca+" is writable by others") {
		t.Fatalf("a group-writable CA: %v", err)
	}
}

func TestAFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, the file is root's, and a root-owned file is accepted")
	}
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	prev := getuid
	getuid = func() int { return os.Getuid() + 1 }
	t.Cleanup(func() { getuid = prev })
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "not owned by you") {
		t.Fatalf("another user's file: %v", err)
	}
}

func TestASymlinkIsRefused(t *testing.T) {
	p := private(t, "real.yaml", "broker: https://b.example:8443\n")
	link := filepath.Join(filepath.Dir(p), "config.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a symlink: %v", err)
	}
}

func TestAnUnknownKeyOrASecondDocumentIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":     "brokr: https://b.example:8443\n",
		"second document": "broker: https://b.example:8443\n---\nbroker: https://c.example:8443\n",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// WritePrivate makes the directory 0700 and the file 0600, and ReadPrivate
// reads it back.
func TestWritePrivateThenReadPrivate(t *testing.T) {
	p := filepath.Join(privateDir(t), "port49", "known_hosts")
	if err := WritePrivate(p, []byte("x\n"), "pinned host keys file"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	di, derr := os.Stat(filepath.Dir(p))
	if err != nil || derr != nil || fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("file %v dir %v (%v %v)", fi.Mode(), di.Mode(), err, derr)
	}
	raw, err := ReadPrivate(p, 64, "pinned host keys file")
	if err != nil || string(raw) != "x\n" {
		t.Fatalf("%q %v", raw, err)
	}
	if _, err := ReadPrivate(filepath.Join(filepath.Dir(p), "none"), 64, "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
	if _, err := ReadPrivate(p, 1, "pinned host keys file"); err == nil {
		t.Fatal("a file over max was read")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/userconfig/ -count=1`
Expected: FAIL to build, `no Go files` or `undefined: Load`.

- [ ] **Step 3: Write the package**

Create `internal/userconfig/userconfig.go`:

```go
// Package userconfig is the operator's own files under
// $XDG_CONFIG_HOME/port49 (spec §13 decision 42, ruling 6): config.yaml,
// which gives `port49 login` its broker, broker CA, certificate and key; and
// the private-file reading and writing it shares with the pinned host keys
// (internal/hostkeys). Whoever can write these files chooses which broker the
// operator trusts and which device keys `port49 ssh` accepts, so a file, or a
// directory holding one, that anyone else can write is refused, never read.
// It is keyfile's rule for a private key, for writing rather than reading,
// and unlike internal/fence it holds on macOS too.
package userconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// getuid is os.Getuid, swapped in tests: no second uid exists to own a file.
var getuid = os.Getuid

// Dir is $XDG_CONFIG_HOME/port49, else ~/.config/port49.
func Dir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "port49")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "port49")
	}
	return filepath.Join(".config", "port49")
}

// Path is the config file's default path.
func Path() string { return filepath.Join(Dir(), "config.yaml") }

// File is config.yaml. Every key is optional; `port49 login` takes each one
// its flags leave out. Paths are resolved by Load: relative to the file's
// directory, and ~/ the home directory.
type File struct {
	Broker   string `yaml:"broker"`
	BrokerCA string `yaml:"broker_ca"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
}

// maxFile bounds config.yaml.
const maxFile = 64 << 10

// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string) (f File, ok bool, err error) {
	raw, err := ReadPrivate(path, maxFile, "port49 config file")
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s holds a second YAML document; port49 reads one", path)
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key} {
		if *p, err = resolve(base, *p); err != nil {
			return File{}, false, fmt.Errorf("%s: %w", path, err)
		}
	}
	// The CA this file names pins the broker as the file does, so it is held
	// to the same line: nobody else may write it. A missing one is left to
	// the read that follows, which says so.
	if f.BrokerCA != "" {
		if fi, err := os.Stat(f.BrokerCA); err == nil && fi.Mode().Perm()&0o022 != 0 {
			return File{}, false, fmt.Errorf("%s is writable by others (mode %v); whoever can write the broker CA "+
				"chooses which broker port49 trusts: chmod go-w %s", f.BrokerCA, fi.Mode().Perm(), f.BrokerCA)
		}
	}
	return f, true, nil
}

// resolve is p as Load reads it: ~ and ~/ from the home directory, a relative
// path from base.
func resolve(base, p string) (string, error) {
	switch {
	case p == "":
		return "", nil
	case p == "~" || strings.HasPrefix(p, "~/"):
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(h, strings.TrimPrefix(p, "~")), nil
	case filepath.IsAbs(p):
		return p, nil
	}
	return filepath.Join(base, p), nil
}

// ReadPrivate reads path, at most max bytes, refusing it unless it is a
// regular file of its own (a symlink is refused, not followed) that this
// user or root owns and nobody else can write, and every directory above it
// is held to dirsOwnedAlone. A missing file is an error errors.Is(err,
// fs.ErrNotExist) reports. what names the file in a refusal.
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; the %s must be one", path, what)
	}
	if err := ownedAlone(path, fi, what); err != nil {
		return nil, err
	}
	if err := dirsOwnedAlone(filepath.Dir(path), what); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is over %d bytes; a %s is never that large", path, max, what)
	}
	return raw, nil
}

// ownedAlone refuses what fi describes unless this user or root owns it and
// neither its group nor others can write it. A directory with the sticky bit
// set, as /tmp has, is the exception: there nobody can rename or replace an
// entry they do not own, which is all a directory above the file is checked
// for. Root owning a file is OpenSSH's StrictModes rule too: root can write
// anything, so trusting it trusts nobody new.
func ownedAlone(path string, fi fs.FileInfo, what string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) != getuid() && st.Uid != 0) {
		return fmt.Errorf("%s is not owned by you (uid %d); whoever owns the %s chooses what port49 trusts, "+
			"so it is refused", path, getuid(), what)
	}
	if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
	return nil
}

// dirsOwnedAlone holds dir and each directory above it to ownedAlone, up to
// the home directory or /: one that someone else can write lets them rename
// the directory below it and put their own in its place (OpenSSH's
// StrictModes walk). The walk is of the path as written, each component
// stat'ed through any symlink.
func dirsOwnedAlone(dir, what string) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	for {
		di, err := os.Stat(d)
		if err != nil {
			return err
		}
		if err := ownedAlone(d, di, "directory holding the "+what); err != nil {
			return err
		}
		if d == home || d == filepath.Dir(d) {
			return nil
		}
		d = filepath.Dir(d)
	}
}

// WritePrivate replaces path with data at mode 0600, through a temporary
// file in its directory renamed over it, so a reader never sees half a file.
// The directory is made 0700 when missing, and refused as ReadPrivate
// refuses it.
func WritePrivate(path string, data []byte, what string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	di, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !di.IsDir() {
		return fmt.Errorf("%s is not a directory; the %s's directory must be one", dir, what)
	}
	if err := dirsOwnedAlone(dir, what); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after the rename there is nothing at name
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
```

- [ ] **Step 4: Run the package tests to verify they pass**

Run: `go test ./internal/userconfig/ -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Isolate the CLI tests from the developer's own config**

In `cmd/port49/main_test.go`, replace `TestMain` with:

```go
func TestMain(m *testing.M) {
	if os.Getenv(runCLIEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	// No test reads the developer's own ~/.config/port49 (plan 9a): every
	// default path under it lands in a directory of the test's.
	dir, err := os.MkdirTemp("", "p49cfg")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
```

- [ ] **Step 6: Write the failing CLI tests**

Create `cmd/port49/config_test.go`:

```go
package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/testpki"
)

const configBroker = "https://broker.example:8443"

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002, the default on Ubuntu, a t.TempDir is
// group-writable, and port49 reads no config or pins file below one
// (decision 42 ruling 6).
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// labConfig writes the lab PKI and a config.yaml naming it by relative path,
// in dir, and returns the config's path.
func labConfig(t *testing.T, dir, broker string) string {
	t.Helper()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := "broker: " + broker + "\nbroker_ca: " + testpki.LabCA + "\ncert: " + testpki.LabClientCert +
		"\nkey: " + testpki.LabClientKey + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// runningAgent is an agent socket whose session is the lab certificate's on
// configBroker, so login refreshes it rather than starting another.
func runningAgent(t *testing.T, dir string) (string, func() int32) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	p, n := countingRefreshStub(t, agent.Status{Broker: configBroker, CertFingerprint: agent.CertFingerprint(cert)},
		http.StatusOK, api.RefreshResponse{AuthTime: "2026-10-09T09:00:00Z", SessionEndsAt: "2026-10-09T21:00:00Z"})
	return p, n.Load
}

// login takes what its flags leave out from the config file, at the default
// path and at --config (decision 42 ruling 6).
func TestLoginTakesWhatItLacksFromTheConfigFile(t *testing.T) {
	xdg := privateDir(t)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dir := filepath.Join(xdg, "port49")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := labConfig(t, dir, configBroker)
	for name, args := range map[string][]string{
		"the default path": nil,
		"--config":         {"--config", cfg},
	} {
		sock, refreshes := runningAgent(t, dir)
		var out, errb bytes.Buffer
		code := run(append(append([]string{"login"}, args...), "--socket", sock), &out, &errb)
		if code != 0 || refreshes() != 1 ||
			!strings.HasPrefix(out.String(), "port49: already logged in to "+configBroker+"; refreshing\n") {
			t.Errorf("%s: code %d stdout %q stderr %q", name, code, out.String(), errb.String())
		}
	}
}

// A flag overrides the file's key.
func TestAFlagOverridesTheConfigFile(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, "https://elsewhere.example:8443")
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"login", "--config", cfg, "--broker", configBroker, "--socket", sock}, &out, &errb)
	if code != 0 || refreshes() != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A config file others could write is refused, exit 2, and nothing is
// asked of the agent.
func TestAConfigFileOthersCanWriteIsRefused(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	if err := os.Chmod(cfg, 0o664); err != nil {
		t.Fatal(err)
	}
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"login", "--config", cfg, "--socket", sock}, &out, &errb)
	if code != 2 || refreshes() != 0 || !strings.HasPrefix(errb.String(), "port49 login: "+cfg+" is writable by others") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A --config that names no file is refused; the default path missing is no
// file, and the flags are asked for.
func TestAMissingConfigFile(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"login", "--config", filepath.Join(t.TempDir(), "none.yaml"), "--socket",
		filepath.Join(t.TempDir(), "a.sock")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "none.yaml: no such file") {
		t.Fatalf("a named file: code %d stderr %q", code, errb.String())
	}
	// Named, it is checked even when every flag is given.
	errb.Reset()
	code = run([]string{"login", "--config", filepath.Join(t.TempDir(), "none.yaml"), "--broker", configBroker,
		"--broker-ca", "ca.pem", "--cert", "c.pem", "--key", "k.pem", "--socket",
		filepath.Join(t.TempDir(), "a.sock")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "none.yaml: no such file") {
		t.Fatalf("a named file beside every flag: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	code = run([]string{"login", "--socket", filepath.Join(t.TempDir(), "a.sock")}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "are all required") || !strings.Contains(errb.String(), "config.yaml") {
		t.Fatalf("the default path: code %d stderr %q", code, errb.String())
	}
}
```

- [ ] **Step 7: Run them to verify they fail**

Run: `go test ./cmd/port49/ -run 'ConfigFile|FlagOverrides|MissingConfig' -count=1`
Expected: FAIL: `flag provided but not defined: -config`, exit 2.

- [ ] **Step 8: The CLI reads the file**

In `cmd/port49/main.go`, add `"cmp"` and `"github.com/blanketfish/port49/internal/userconfig"` to the
imports. Replace `sessionFlags`, `register`, `args` and the first refusal in `config` as follows.

Replace

```go
// sessionFlags are what the agent needs to open the session. The key is read
// from a file: BORROWED AHEAD from plan 9, which holds it on a hardware token
// (design §7; plan 3, Question 1).
type sessionFlags struct{ broker, cert, key, brokerCA, socket string }
```

with

```go
// sessionFlags are what the agent needs to open the session, from the flags
// and, for any they leave out, the per-user config file (decision 42 ruling
// 6). The key is read from a file until plan 9c holds it on a hardware token
// (design §7; plan 3, Question 1).
type sessionFlags struct{ broker, cert, key, brokerCA, socket, configFile string }
```

The field is `configFile`, not `config`: `sessionFlags` already has a `config` method.

In `register`, after the `--socket` line, add:

```go
	fs.StringVar(&s.configFile, "config", userconfig.Path(), "your port49 config file: broker, broker_ca, cert and "+
		"key, each overridden by its flag")
```

After `register`, add:

```go
// fill takes from the config file each of --broker, --broker-ca, --cert and
// --key the command line left out (decision 42 ruling 6). A missing file at
// the default path is no file; one --config names must be there, and is
// read and checked even when every flag is given.
func (s *sessionFlags) fill(fs *flag.FlagSet) error {
	named := false
	fs.Visit(func(f *flag.Flag) { named = named || f.Name == "config" })
	if !named && s.broker != "" && s.cert != "" && s.key != "" && s.brokerCA != "" {
		return nil
	}
	f, ok, err := userconfig.Load(s.configFile)
	switch {
	case err != nil:
		return err
	case !ok && named:
		return fmt.Errorf("%s: no such file", s.configFile)
	case !ok:
		return nil
	}
	s.broker, s.brokerCA = cmp.Or(s.broker, f.Broker), cmp.Or(s.brokerCA, f.BrokerCA)
	s.cert, s.key = cmp.Or(s.cert, f.Cert), cmp.Or(s.key, f.Key)
	return nil
}
```

In `config`, replace

```go
		return agent.Config{}, errors.New("--broker, --cert, --key and --broker-ca are all required")
```

with

```go
		return agent.Config{}, fmt.Errorf("--broker, --cert, --key and --broker-ca are all required, as flags "+
			"or in %s", s.configFile)
```

In `login`, after `if err := fs.Parse(args); err != nil { return 2 }`, add:

```go
	if err := sf.fill(fs); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
```

In `agentMain`, after its `fs.Parse`, add the same with `"port49 agent:"`. The agent `login`
starts is given every value as a flag (`sf.args()`), so it never reads the file.

In the usage, replace

```
  port49 login --broker URL --cert FILE --key FILE --broker-ca FILE [--socket PATH]
```

with

```
  port49 login [--config FILE] [--broker URL] [--cert FILE] [--key FILE] [--broker-ca FILE] [--socket PATH]
               (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml)
```

- [ ] **Step 9: Run every CLI test to verify they pass**

Run: `go test ./cmd/port49/ -count=1`
Expected: PASS. `TestLoginRefusesWhatItCanCheckFirst` still finds `all required`.

- [ ] **Step 10: Commit**

```bash
gofmt -l internal cmd && go vet ./...
git add internal/userconfig cmd/port49/main.go cmd/port49/main_test.go cmd/port49/config_test.go
git commit -m "feat(login): a per-user config file gives port49 login what its flags leave out (decision 42 ruling 6)"
```

---

### Task 5: Pinned host keys and `port49 devices trust`

**Files:**
- Create: `internal/hostkeys/hostkeys.go`, `internal/hostkeys/hostkeys_test.go`,
  `cmd/port49/mint.go`, `cmd/port49/trust.go`, `cmd/port49/trust_test.go`
- Modify: `cmd/port49/main.go` (`tokenCmd`, the `devices` case, usage)

**Interfaces:**
- Consumes: `userconfig.Dir`, `ReadPrivate` and `WritePrivate` (Task 4); decision 42 rulings 7–9.
- Produces, in package `hostkeys`:
  - `func Path() string` and `func ValidName(device string) bool`;
  - `func Lookup(path, device string) ([]ssh.PublicKey, error)`;
  - `func Pin(path, device string, key ssh.PublicKey, replace bool) error`, and `var ErrPinned`;
  - `func Scan(ctx context.Context, addr string) (ssh.PublicKey, error)`;
  - `func Fingerprint(k ssh.PublicKey) string`.

  In `cmd/port49`:
  - `func mintFailed(cmd, socket, device string, item api.MintItem, err error, stderr io.Writer) bool`;
  - `func ceilingWarning(socket string) time.Duration`;
  - `func warnNearCeiling(stderr io.Writer, device string, item api.MintItem, warn time.Duration) bool`;
  - `func devicesTrust(args []string, stdout, stderr io.Writer) int`.

- [ ] **Step 1: Write the failing `hostkeys` tests**

Create `internal/hostkeys/hostkeys_test.go`:

```go
package hostkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func same(a, b ssh.PublicKey) bool { return string(a.Marshal()) == string(b.Marshal()) }

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002 a t.TempDir is group-writable, and the pins are
// never read or written below one.
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// A pin is read back by its device's name alone; a second pin is refused
// without replace; replace removes the old key; other lines stay.
func TestPinThenLookup(t *testing.T) {
	path := filepath.Join(privateDir(t), "port49", "known_hosts")
	_, k1 := newKey(t)
	_, k2 := newKey(t)
	_, other := newKey(t)
	if err := Pin(path, "spine1", other, false); err != nil {
		t.Fatal(err)
	}
	if err := Pin(path, "leaf1", k1, false); err != nil {
		t.Fatal(err)
	}
	if got, err := Lookup(path, "leaf1"); err != nil || len(got) != 1 || !same(got[0], k1) {
		t.Fatalf("lookup: %v %v", got, err)
	}
	if err := Pin(path, "leaf1", k2, false); !errors.Is(err, ErrPinned) {
		t.Fatalf("a second pin without replace: %v", err)
	}
	if err := Pin(path, "leaf1", k2, true); err != nil {
		t.Fatal(err)
	}
	got, _ := Lookup(path, "leaf1")
	spine, _ := Lookup(path, "spine1")
	if len(got) != 1 || !same(got[0], k2) || len(spine) != 1 || !same(spine[0], other) {
		t.Fatalf("after replace: leaf1 %v spine1 %v", got, spine)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
}

// A pattern, a marker or a hashed line never pins a device by its name.
func TestLookupReadsExactNamesAndNoMarkers(t *testing.T) {
	_, k := newKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	dir := privateDir(t)
	path := filepath.Join(dir, "known_hosts")
	body := "# the operator's comment\nleaf* " + line + "\n@revoked leaf1 " + line + "\nleaf1,leaf2 " + line + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Lookup(path, "leaf1"); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := Lookup(filepath.Join(dir, "none"), "leaf1"); err != nil || got != nil {
		t.Fatalf("a missing file pins nothing: %v %v", got, err)
	}
}

// Two trust runs at once both keep their pin: Pin holds a lock across its
// read and its write.
func TestConcurrentPinsLoseNothing(t *testing.T) {
	path := filepath.Join(privateDir(t), "port49", "known_hosts")
	var wg sync.WaitGroup
	for i := range 8 {
		_, k := newKey(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Pin(path, fmt.Sprintf("leaf%d", i), k, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := range 8 {
		if got, err := Lookup(path, fmt.Sprintf("leaf%d", i)); err != nil || len(got) != 1 {
			t.Errorf("leaf%d: %v %v", i, got, err)
		}
	}
}

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{
		"leaf1": true, "core-sw01.dc1": true, "srx_fw_04": true, strings.Repeat("a", 253): true,
		"": false, "*": false, "leaf*": false, "a,b": false, "!x": false, "@cert-authority": false,
		"|1|abc": false, "[leaf1]:22": false, "-leaf": false, ".leaf": false, "leaf 1": false,
		"leaf?": false, strings.Repeat("a", 254): false,
	} {
		if ValidName(name) != ok {
			t.Errorf("ValidName(%q) = %v", name, !ok)
		}
	}
}

// Scan reads the key the server presents and offers no credential: no
// authentication callback of the server's ever runs.
func TestScanReadsTheKeyAndSendsNoCredential(t *testing.T) {
	signer, pub := newKey(t)
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
	got, err := Scan(context.Background(), ln.Addr().String())
	<-done
	if err != nil || !same(got, pub) || auths.Load() != 0 {
		t.Fatalf("key %v err %v, %d auth attempts", got, err, auths.Load())
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/hostkeys/ -count=1`
Expected: FAIL to build, `undefined: Pin`.

- [ ] **Step 3: Write the package**

Create `internal/hostkeys/hostkeys.go`:

```go
// Package hostkeys pins the SSH host key each device presents (design §17;
// spec §13 decision 42, rulings 7–9). The pins live in an OpenSSH known_hosts
// file of port49's own, $XDG_CONFIG_HOME/port49/known_hosts, one line per
// key, whose host field is the device's inventory name. `port49 ssh` hands it
// to ssh with the device's name as HostKeyAlias, so a key is checked against
// the device it was pinned for, never against whatever address inventory
// gives today. The file is held to userconfig's rule: whoever can write it
// chooses which keys port49 accepts.
package hostkeys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blanketfish/port49/internal/userconfig"
)

// what names the file in a refusal.
const what = "pinned host keys file"

// maxFile bounds the file: a line a key, a fleet of them.
const maxFile = 4 << 20

// Path is the pinned host keys file's default path.
func Path() string { return filepath.Join(userconfig.Dir(), "known_hosts") }

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// ValidName reports whether device can be a known_hosts host field and an
// ssh destination as written (decision 42 ruling 8): letters, digits, '.',
// '_' and '-', starting with a letter or a digit, 253 at most. known_hosts
// reads '*', '?', '!', ',' and '[' as patterns, and a leading '@' or '|' as
// a marker or a hash, so a name holding one could pin a key for other
// devices.
func ValidName(device string) bool { return validName.MatchString(device) }

// ErrPinned is a device that already has a pinned key.
var ErrPinned = errors.New("hostkeys: a key is already pinned for this device")

// Fingerprint is k's SHA-256 fingerprint as OpenSSH prints it: SHA256:base64.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// Lookup is every key pinned for device: lines with no marker whose host
// field is device and nothing else. A missing file pins nothing.
func Lookup(path, device string) ([]ssh.PublicKey, error) {
	raw, err := userconfig.ReadPrivate(path, maxFile, what)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for rest := raw; len(rest) > 0; {
		marker, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if marker == "" && slices.Equal(hosts, []string{device}) {
			keys = append(keys, key)
		}
		rest = next
	}
	return keys, nil
}

// Pin writes key as device's pinned key. A device with a pin already is
// ErrPinned unless replace is set, which removes every key pinned for it
// first. Every other line, another device's or one the operator wrote, is
// kept as it was.
func Pin(path, device string, key ssh.PublicKey, replace bool) error {
	if !ValidName(device) {
		return fmt.Errorf("hostkeys: %q is not a name port49 pins (decision 42 ruling 8)", device)
	}
	unlock, err := lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	raw, err := userconfig.ReadPrivate(path, maxFile, what)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var kept []string
	pinned := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if line == "" {
			continue
		}
		marker, hosts, _, _, _, perr := ssh.ParseKnownHosts([]byte(line))
		if perr == nil && marker == "" && slices.Equal(hosts, []string{device}) {
			pinned = true
			if replace {
				continue
			}
		}
		kept = append(kept, strings.TrimSuffix(line, "\n")+"\n")
	}
	if pinned && !replace {
		return ErrPinned
	}
	kept = append(kept, device+" "+string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)))+"\n")
	return userconfig.WritePrivate(path, []byte(strings.Join(kept, "")), what)
}

// lock takes an exclusive flock on the lock file at path, made 0600 beside
// the pins file, so two trust runs never lose a pin between one's read and the
// other's write. The returned func lets it go.
func lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// scanTimeout bounds a scan: the connect and the key exchange.
var scanTimeout = 15 * time.Second

// errScanned ends the handshake once the key is read.
var errScanned = errors.New("hostkeys: the key is read; the connection goes no further")

// Scan connects to addr (host:port), reads the host key the server presents
// in the key exchange, and closes the connection before authentication: no
// username is offered and no credential is sent (decision 42 ruling 9; what
// a device does with that is §15 L53's). Every algorithm x/crypto/ssh knows is
// offered, the insecure ones included, since a scan only reads a public key
// the operator then verifies on the device's console. Two host-key
// algorithms are not: certificates, since port49 pins plain keys, and DSA,
// since OpenSSH 10 has none and `port49 ssh` could never accept a DSA pin. A
// DSA-only device is refused at the scan: no common host-key algorithm.
func Scan(ctx context.Context, addr string) (ssh.PublicKey, error) {
	sup, weak := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	hostKeys := slices.DeleteFunc(append(sup.HostKeys, weak.HostKeys...), func(a string) bool {
		return strings.Contains(a, "-cert-v01@") || a == ssh.InsecureKeyAlgoDSA
	})
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "port49-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errScanned
		},
		HostKeyAlgorithms: hostKeys,
		Config: ssh.Config{
			KeyExchanges: append(sup.KeyExchanges, weak.KeyExchanges...),
			Ciphers:      append(sup.Ciphers, weak.Ciphers...),
			MACs:         append(sup.MACs, weak.MACs...),
		},
		Timeout: scanTimeout,
	}
	d := net.Dialer{Timeout: scanTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(scanTimeout))
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, nil
	}
	return nil, fmt.Errorf("%s presented no host key: %w", addr, err)
}
```

- [ ] **Step 4: Run the package tests to verify they pass**

Run: `go test ./internal/hostkeys/ -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Factor `tokenCmd`'s refusals and warning into `mint.go`, word for word**

Create `cmd/port49/mint.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
)

// mintFailed says, under cmd's prefix, why a mint through the agent gave no
// usable token, and reports whether it did. These are `port49 token`'s words,
// shared by `port49 devices trust` and `port49 ssh`.
func mintFailed(cmd, socket, device string, item api.MintItem, err error, stderr io.Writer) bool {
	var ie *agent.ItemError
	switch {
	case errors.As(err, &ie):
		// The broker could not decide this device. Whatever else the item
		// carries is not printed.
		fmt.Fprintf(stderr, "%s: %s: %s\n", cmd, device, unprefixed(ie))
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "%s: no agent at %s; run `port49 login`\n", cmd, socket)
	case err != nil:
		// An ended session says to log in and why: an expired certificate
		// has to be renewed before a login will work. A revocation says
		// since when and who lifts it instead.
		fmt.Fprintf(stderr, "%s: %s\n", cmd, unprefixed(err))
	case item.Verdict != "permit":
		// The item's detail, when it has one, says what to do: a session
		// past its ceiling is told to refresh (pre-flight M12).
		detail := ""
		if item.Detail != "" {
			detail = ": " + item.Detail
		}
		fmt.Fprintf(stderr, "%s: %s: %s %s%s\n", cmd, device, item.Verdict, item.Reason, detail)
	case item.Login == "":
		// Printed, it would be an empty password to whatever reads stdout.
		fmt.Fprintf(stderr, "%s: %s: the broker answered permit with no token\n", cmd, device)
	default:
		return false
	}
	return true
}

// ceilingWarning is the broker's session.ceiling_warning as the agent holds
// it; zero when the agent does not say.
func ceilingWarning(socket string) time.Duration {
	st, err := agent.NewClient(socket).Status(context.Background())
	if err != nil || st.CeilingWarningSeconds <= 0 {
		return 0
	}
	return time.Duration(st.CeilingWarningSeconds) * time.Second
}

// warnNearCeiling says on stderr, and reports, that item's device session
// ends within warn: the warning a platform that does not show server_msg
// never gives (decision 33; spec §15 L34). On stderr, so --json's stdout stays
// one object (pre-flight M12).
func warnNearCeiling(stderr io.Writer, device string, item api.MintItem, warn time.Duration) bool {
	exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt)
	if err != nil || warn <= 0 {
		return false
	}
	left := time.Until(exp)
	if left > warn {
		return false
	}
	fmt.Fprintf(stderr, "port49: your session on %s ends at %s (%s); run 'port49 refresh'\n", device,
		item.SessionExpiresAt, timeLeft(left))
	return true
}
```

In `cmd/port49/main.go`'s `tokenCmd`, replace everything from
`item, err := agent.NewClient(*socket).Token(context.Background(),` through the end of the
ceiling-warning block (the `if exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt); err == nil { … }`
statement), with:

```go
	item, err := agent.NewClient(*socket).Token(context.Background(),
		agent.TokenRequest{Device: device, Enable: *enable, TTLSeconds: int(*ttl / time.Second)})
	if mintFailed("port49 token", *socket, device, item, err, stderr) {
		return 1
	}
	// The device's own ceiling, said where the operator is looking, for a
	// platform that does not show the server_msg warning (decision 33).
	// Before the --json and plain prints, so both get it.
	warnNearCeiling(stderr, device, item, ceilingWarning(*socket))
```

Run: `go test ./cmd/port49/ -run 'Token|Denial|ItemError|EndedSession|PermitWithNoToken|Warns|SessionExpired' -count=1`
Expected: PASS, every message unchanged.

- [ ] **Step 6: Write the failing `trust` tests**

Create `cmd/port49/trust_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hostkeys"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// trustRig swaps the scan for one that presents key and counts its calls,
// the terminal for tty and answer, and returns the pins file to use.
func trustRig(t *testing.T, key ssh.PublicKey, tty bool, answer string) (known string, scans *atomic.Int32, addr *string) {
	t.Helper()
	scans, addr = new(atomic.Int32), new(string)
	prevScan, prevTTY, prevAnswer := trustScan, trustIsTerminal, trustAnswer
	trustScan = func(_ context.Context, a string) (ssh.PublicKey, error) {
		scans.Add(1)
		*addr = a
		if key == nil {
			return nil, errors.New("connection refused")
		}
		return key, nil
	}
	trustIsTerminal = func() bool { return tty }
	trustAnswer = strings.NewReader(answer)
	t.Cleanup(func() { trustScan, trustIsTerminal, trustAnswer = prevScan, prevTTY, prevAnswer })
	return filepath.Join(privateDir(t), "known_hosts"), scans, addr
}

var leafPermit = api.MintItem{Device: "leaf1", Verdict: "permit", Username: "alice", Login: "LOGINTOKEN",
	Address: "172.100.100.11", Platform: "arista_eos"}

func pinnedFor(t *testing.T, known, device string) []ssh.PublicKey {
	t.Helper()
	keys, err := hostkeys.Lookup(known, device)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// With the fingerprint the operator verified, trust pins it; the address is
// the mint's (decision 42 ruling 9).
func TestTrustPinsTheFingerprintYouVerified(t *testing.T) {
	key := testHostKey(t)
	known, _, addr := trustRig(t, key, false, "")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint",
		hostkeys.Fingerprint(key), "leaf1"}, &out, &errb)
	if code != 0 || *addr != "172.100.100.11:22" || len(pinnedFor(t, known, "leaf1")) != 1 ||
		!strings.Contains(out.String(), "pinned ssh-ed25519 "+hostkeys.Fingerprint(key)+" for leaf1") {
		t.Fatalf("code %d addr %q stdout %q stderr %q", code, *addr, out.String(), errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "LOGINTOKEN") {
		t.Fatal("the mint's token was printed")
	}
}

// A different fingerprint pins nothing, and says the address may be wrong.
func TestTrustRefusesAFingerprintThatDiffers(t *testing.T) {
	known, _, _ := trustRig(t, testHostKey(t), false, "")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint",
		hostkeys.Fingerprint(testHostKey(t)), "leaf1"}, &out, &errb)
	if code != 1 || len(pinnedFor(t, known, "leaf1")) != 0 || !strings.Contains(errb.String(), "nothing pinned") ||
		!strings.Contains(errb.String(), "check inventory's address for leaf1") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// In a script, without --fingerprint, nothing is pinned: a key is never
// pinned unseen.
func TestTrustOnAScriptWithoutAFingerprintPinsNothing(t *testing.T) {
	known, _, _ := trustRig(t, testHostKey(t), false, "yes\n")
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "leaf1"}, &out, &errb); code != 2 ||
		len(pinnedFor(t, known, "leaf1")) != 0 || !strings.Contains(errb.String(), "pass --fingerprint") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// On a terminal it asks, and pins on yes alone.
func TestTrustAsksOnATerminal(t *testing.T) {
	for answer, pinned := range map[string]bool{"yes\n": true, "no\n": false, "y\n": false, "": false} {
		known, _, _ := trustRig(t, testHostKey(t), true, answer)
		sock := fakeAgent(t, http.StatusOK, leafPermit)
		var out, errb bytes.Buffer
		code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "leaf1"}, &out, &errb)
		if (code == 0) != pinned || (len(pinnedFor(t, known, "leaf1")) == 1) != pinned ||
			!strings.Contains(out.String(), "Pin it? [yes/no]: ") {
			t.Errorf("answer %q: code %d stdout %q stderr %q", answer, code, out.String(), errb.String())
		}
	}
}

// An existing pin is replaced only with --replace, and is never scanned for
// without it.
func TestTrustNeverReplacesWithoutReplace(t *testing.T) {
	old, key := testHostKey(t), testHostKey(t)
	known, scans, _ := trustRig(t, key, false, "")
	if err := hostkeys.Pin(known, "leaf1", old, false); err != nil {
		t.Fatal(err)
	}
	sock := fakeAgent(t, http.StatusOK, leafPermit)
	args := []string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint", hostkeys.Fingerprint(key)}
	var out, errb bytes.Buffer
	if code := run(append(args, "leaf1"), &out, &errb); code != 1 || scans.Load() != 0 ||
		!strings.Contains(errb.String(), "already pinned") {
		t.Fatalf("without --replace: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run(append(args, "--replace", "leaf1"), &out, &errb); code != 0 {
		t.Fatalf("with --replace: code %d stderr %q", code, errb.String())
	}
	if got := pinnedFor(t, known, "leaf1"); len(got) != 1 || hostkeys.Fingerprint(got[0]) != hostkeys.Fingerprint(key) {
		t.Fatalf("pinned %v", got)
	}
}

// A device the caller holds no grant on is refused at the mint, and is never
// scanned: trust is no oracle.
func TestTrustWithoutAGrantLearnsNothing(t *testing.T) {
	known, scans, _ := trustRig(t, testHostKey(t), false, "")
	sock := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--socket", sock, "--known-hosts", known, "--fingerprint", "SHA256:x",
		"leaf1"}, &out, &errb); code != 1 || scans.Load() != 0 ||
		!strings.Contains(errb.String(), "port49 devices trust: leaf1: deny no_grants_matched") {
		t.Fatalf("code %d scans %d stderr %q", code, scans.Load(), errb.String())
	}
}

// --address skips the mint: no agent needed.
func TestTrustWithAnAddressMintsNothing(t *testing.T) {
	key := testHostKey(t)
	known, _, addr := trustRig(t, key, false, "")
	var out, errb bytes.Buffer
	code := run([]string{"devices", "trust", "--socket", filepath.Join(t.TempDir(), "none.sock"), "--known-hosts", known,
		"--address", "192.0.2.7", "--port", "2222", "--fingerprint", hostkeys.Fingerprint(key), "leaf1"}, &out, &errb)
	if code != 0 || *addr != "192.0.2.7:2222" {
		t.Fatalf("code %d addr %q stderr %q", code, *addr, errb.String())
	}
}

// A name known_hosts would read as a pattern is refused before anything.
func TestTrustRefusesANameThatIsAPattern(t *testing.T) {
	known, scans, _ := trustRig(t, testHostKey(t), false, "")
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "trust", "--known-hosts", known, "leaf*"}, &out, &errb); code != 2 ||
		scans.Load() != 0 || !strings.Contains(errb.String(), "letters, digits") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
```

- [ ] **Step 7: Run them to verify they fail**

Run: `go test ./cmd/port49/ -run Trust -count=1`
Expected: FAIL to build, `undefined: trustScan`.

- [ ] **Step 8: Write `port49 devices trust`**

Create `cmd/port49/trust.go`:

```go
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/hostkeys"
)

// trustScan reads a device's host key; a test swaps it.
var trustScan = hostkeys.Scan

// trustIsTerminal and trustAnswer are the operator's terminal; tests swap
// them.
var (
	trustIsTerminal           = func() bool { return isTerminal(os.Stdin) }
	trustAnswer     io.Reader = os.Stdin
)

// trustTTL is the lifetime trust asks for the token whose mint gives it the
// address: the token is never used, and expires at it (decision 42 ruling 9).
const trustTTL = 60 * time.Second

// devicesTrust is `port49 devices trust` (design §17; decision 42 rulings
// 7–9): it reads the host key a device presents and pins it under the
// device's inventory name, only against a fingerprint the operator verified
// or a yes typed at a terminal.
func devicesTrust(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 devices trust"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fingerprint := fs.String("fingerprint", "", "the SHA256:... fingerprint you read on the device's console; "+
		"the key is pinned only if the device presents it")
	address := fs.String("address", "", "the device's address, when you know it; otherwise one mint through "+
		"your agent asks the broker")
	port := fs.Int("port", 22, "the device's SSH port")
	replace := fs.Bool("replace", false, "replace the device's pinned key, once you have verified its new key "+
		"on its console")
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	knownHosts := fs.String("known-hosts", hostkeys.Path(), "the pinned host keys file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device := fs.Arg(0)
	if !hostkeys.ValidName(device) {
		fmt.Fprintf(stderr, "%s: %q: port49 pins devices named with letters, digits, '.', '_' and '-' only, "+
			"since known_hosts reads other characters as patterns (decision 42 ruling 8); port49 token still "+
			"serves it\n", cmd, device)
		return 2
	}
	pinned, err := hostkeys.Lookup(*knownHosts, device)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if len(pinned) > 0 && !*replace {
		fmt.Fprintf(stderr, "%s: %s is already pinned (%s); pass --replace to pin another key, once you have "+
			"verified the device's new key on its console\n", cmd, device, hostkeys.Fingerprint(pinned[0]))
		return 1
	}
	addr := *address
	if addr == "" {
		item, err := agent.NewClient(*socket).Token(context.Background(),
			agent.TokenRequest{Device: device, TTLSeconds: int(trustTTL / time.Second)})
		if mintFailed(cmd, *socket, device, item, err, stderr) {
			return 1
		}
		if addr = item.Address; addr == "" {
			fmt.Fprintf(stderr, "%s: inventory gives %s no address; pass --address\n", cmd, device)
			return 1
		}
	}
	target := net.JoinHostPort(addr, strconv.Itoa(*port))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := trustScan(ctx, target)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", cmd, device, err)
		return 1
	}
	fp := hostkeys.Fingerprint(key)
	fmt.Fprintf(stdout, "%s at %s presents %s %s\n", device, target, key.Type(), fp)
	switch {
	case *fingerprint != "" && *fingerprint != fp:
		fmt.Fprintf(stderr, "%s: %s presents %s, not the %s you verified: nothing pinned; the address inventory "+
			"gives may not be %s's, so check inventory's address for %s before anything else\n", cmd, device, fp,
			*fingerprint, device, device)
		return 1
	case *fingerprint == "" && !trustIsTerminal():
		fmt.Fprintf(stderr, "%s: nothing pinned: pass --fingerprint with the fingerprint you read on %s's console; "+
			"a key is never pinned unseen (design §17)\n", cmd, device)
		return 2
	case *fingerprint == "":
		fmt.Fprintf(stdout, "Compare it with the key %s's console shows. Pin it? [yes/no]: ", device)
		line, _ := bufio.NewReader(trustAnswer).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Fprintf(stderr, "%s: nothing pinned\n", cmd)
			return 1
		}
	}
	if err := hostkeys.Pin(*knownHosts, device, key, *replace); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	fmt.Fprintf(stdout, "pinned %s %s for %s in %s\n", key.Type(), fp, device, *knownHosts)
	return 0
}
```

In `cmd/port49/main.go`'s `run`, in `case "devices":`, before the `check-config` branch, add:

```go
		if len(args) > 1 && args[1] == "trust" {
			return devicesTrust(args[2:], stdout, stderr)
		}
```

In the usage, after the `port49 devices capabilities` line, add:

```
  port49 devices trust [--fingerprint SHA256:...] [--address ADDR] [--port N] [--replace] [--known-hosts FILE]
                       [--socket PATH] DEVICE
                (pins the SSH host key DEVICE presents, against the fingerprint you verified on its console)
```

- [ ] **Step 9: Run every CLI test to verify they pass**

Run: `go test ./cmd/port49/ ./internal/hostkeys/ -count=1`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
gofmt -l internal cmd && go vet ./...
git add internal/hostkeys cmd/port49/mint.go cmd/port49/trust.go cmd/port49/trust_test.go cmd/port49/main.go
git commit -m "feat(agent): port49 devices trust pins a device's SSH host key under its inventory name (decision 42)"
```

---

### Task 6: `port49 ssh`, its askpass, and the in-session warning

**Files:**
- Create: `cmd/port49/ssh.go`, `cmd/port49/ssh_test.go`, `cmd/port49/sshserver_test.go`
- Modify: `internal/agent/agent.go` and `agent_test.go` (`Status.Sessions`), `cmd/port49/main.go`
  (`main`, `run`'s first lines, the `ssh` case, usage), `cmd/port49/main_test.go` (`TestMain`),
  `go.mod` (`golang.org/x/term` direct)

**Interfaces:**
- Consumes:
  - `hostkeys.Path`, `ValidName` and `Lookup` (Task 5);
  - `mintFailed`, `ceilingWarning` and `warnNearCeiling` (Task 5);
  - `agent.NewClient(...).Token`, `.Status` and `agent.PrivateDir`;
  - `api.RefreshedSession` (`internal/broker/api/refresh.go`, unchanged);
  - decision 42 rulings 7, 10 and 11.
- Produces:
  - in `internal/agent`: `Status.Sessions []api.RefreshedSession "sessions,omitempty"`, the last
    refresh's answer;
  - in `cmd/port49`:
    - `const askpassEnv = "PORT49_ASKPASS"` and `func askpassCall(args []string) (string, bool)`;
    - `func sshCmd(args []string, stdout, stderr io.Writer) int`;
    - `func askpassMain(sock string, args []string, stdout, stderr io.Writer) int` and
      `func askEchoes(prompt, hint string) bool`;
    - `func sshVersion(bin string) ([2]int, error)` and `func atLeast(v, floor [2]int) bool`;
    - `func sshArgs(o sshOptions) []string`, `func sshValue(v string) string` and
      `func ownPrompt(prompt, username, device string) bool`;
    - `type askpassServer`, with `setKill`;
    - `func warnInSession(stderr io.Writer, socket, device string, item api.MintItem, warn time.Duration) (stop func())`
      and `var sshAfterFunc = time.AfterFunc`.

  Task 8 runs the built binary.

- [ ] **Step 1: The agent keeps the last refresh's answer, and `/status` carries it**

Append to `internal/agent/agent_test.go`:

```go
// /status carries the last refresh's answer per device, so port49 ssh's
// in-session warning follows a refresh made in another terminal (decision 42
// ruling 11).
func TestStatusCarriesTheLastRefreshsSessions(t *testing.T) {
	r := newRealRig(t)
	status := func() Status {
		w := httptest.NewRecorder()
		r.a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/status", nil))
		var st Status
		if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := status(); len(st.Sessions) != 0 {
		t.Fatalf("before any refresh: %+v", st.Sessions)
	}
	r.advance(30 * time.Minute)
	out, err := r.a.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st := status(); len(st.Sessions) != 1 || st.Sessions[0] != out.Sessions[0] || st.Sessions[0].Device != "leaf1" {
		t.Fatalf("after a refresh: %+v, the broker said %+v", st.Sessions, out.Sessions)
	}
}
```

Run: `go test ./internal/agent/ -run TestStatusCarriesTheLastRefreshsSessions -count=1`
Expected: FAIL to build, `st.Sessions undefined`.

In `internal/agent/agent.go`:
- In `type Status struct`, after `CeilingWarningSeconds int `json:"ceiling_warning_seconds"``, add:

  ```go
  	// Sessions is the last refresh's answer per live context, absent before
  	// one: what `port49 ssh` reads when its in-session warning is due, so a
  	// `port49 refresh` in another terminal moves it (decision 42 ruling 11).
  	Sessions []api.RefreshedSession `json:"sessions,omitempty"`
  ```
- In `type Agent struct`, after the `ceilingWarning time.Duration` field, add:

  ```go
  	// refreshed is the last refresh's per-context answer, for GET /status.
  	// A refresh replaces it whole, never edits it.
  	refreshed []api.RefreshedSession
  ```
- In `refreshOnce`, replace

  ```go
  	a.mu.Lock()
  	a.deadline = ends
  	a.mu.Unlock()
  ```

  with

  ```go
  	a.mu.Lock()
  	a.deadline = ends
  	a.refreshed = out.Sessions
  	a.mu.Unlock()
  ```
- In `Handler`'s `GET /status`, replace

  ```go
  		a.mu.Lock()
  		warn := a.ceilingWarning
  		a.mu.Unlock()
  		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
  			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
  			CeilingWarningSeconds: int(warn / time.Second)})
  ```

  with

  ```go
  		a.mu.Lock()
  		warn, sessions := a.ceilingWarning, a.refreshed
  		a.mu.Unlock()
  		writeJSON(w, http.StatusOK, Status{Broker: a.broker, CertFingerprint: a.fingerprint,
  			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes(),
  			CeilingWarningSeconds: int(warn / time.Second), Sessions: sessions})
  ```

Run: `go test ./internal/agent/ -count=1 -race`
Expected: PASS.

- [ ] **Step 2: The test device: an SSH server that records what it is sent**

Create `cmd/port49/sshserver_test.go`:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// deviceSSH stands in for a device's SSH server. It takes the methods it is
// given, records every password or keyboard-interactive answer sent to it in
// order, accepts want, and answers an exec request with "ran: <command>"
// after hold, exit status 0.
type deviceSSH struct {
	port  int
	key   ssh.PublicKey
	mu    sync.Mutex
	tried []string
	conns int
}

func startDeviceSSH(t *testing.T, methods []string, want string, hold time.Duration) *deviceSSH {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	d := &deviceSSH{key: signer.PublicKey()}
	check := func(answer string) error {
		d.mu.Lock()
		d.tried = append(d.tried, answer)
		d.mu.Unlock()
		if want != "" && answer == want {
			return nil
		}
		return errors.New("refused")
	}
	cfg := &ssh.ServerConfig{}
	for _, m := range methods {
		switch m {
		case "password":
			cfg.PasswordCallback = func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				return nil, check(string(p))
			}
		case "keyboard-interactive":
			cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				a, err := ch("", "", []string{"Password: "}, []bool{false})
				if err != nil || len(a) != 1 {
					return nil, errors.New("no answer")
				}
				return nil, check(a[0])
			}
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	d.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns++
			d.mu.Unlock()
			go d.serve(c, cfg, hold)
		}
	}()
	return d
}

func (d *deviceSSH) serve(c net.Conn, cfg *ssh.ServerConfig, hold time.Duration) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, rq, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range rq {
				if r.Type != "exec" {
					_ = r.Reply(r.Type == "pty-req" || r.Type == "env", nil)
					continue
				}
				_ = r.Reply(true, nil)
				var p struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &p)
				time.Sleep(hold)
				_, _ = fmt.Fprintf(ch, "ran: %s\n", p.Command)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}

// attempts is every answer the device was sent, in order.
func (d *deviceSSH) attempts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.tried)
}

func (d *deviceSSH) connections() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}
```

- [ ] **Step 3: Write the failing `port49 ssh` tests**

Create `cmd/port49/ssh_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hostkeys"
)

// sshTestBin is the system's OpenSSH, 8.5 or later, or the test is skipped:
// port49 ssh runs the real ssh, and the test box has 10.2p1.
func sshTestBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh on PATH: port49 ssh runs the system's OpenSSH")
	}
	v, err := sshVersion(p)
	if err != nil || !atLeast(v, minSSH) {
		t.Skipf("ssh is %v (%v): port49 ssh needs OpenSSH 8.5 or later", v, err)
	}
	return p
}

// sshRig is one port49 ssh run's world: an agent that answers each mint
// from items and its status from status, counting mints; the device's key
// pinned (unless pin is nil); an empty ssh_config; and the flags that reach
// them.
type sshRig struct {
	mints *atomic.Int32
	flags []string
	sock  string

	mu     sync.Mutex
	items  []api.MintItem // the nth mint answers items[n], the last one after that
	status agent.Status
}

// set makes the agent answer status, and, when items are given, the mints
// from them in turn.
func (r *sshRig) set(status agent.Status, items ...api.MintItem) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	if len(items) > 0 {
		r.items = items
	}
}

func newSSHRig(t *testing.T, dev *deviceSSH, item api.MintItem, warn int, pin ssh.PublicKey) *sshRig {
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
	known := filepath.Join(dir, "known_hosts")
	if pin != nil {
		if err := hostkeys.Pin(known, "leaf1", pin, false); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.flags = []string{"--socket", r.sock, "--ssh", sshTestBin(t), "--ssh-config", cfg, "--known-hosts", known,
		"--port", strconv.Itoa(dev.port)}
	return r
}

func (r *sshRig) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb lockedBuffer
	code := run(append(append([]string{"ssh"}, r.flags...), args...), &out, &errb)
	return code, out.String(), errb.String()
}

var sshPermit = api.MintItem{Device: "leaf1", Verdict: "permit", Address: "127.0.0.1", Platform: "arista_eos",
	Username: "alice", Login: "LOGINTOKEN"}

// tokenNowhere fails t if the minted token is in anything port49 ssh printed
// (Global Constraints).
func tokenNowhere(t *testing.T, printed ...string) {
	t.Helper()
	for _, s := range printed {
		if strings.Contains(s, "LOGINTOKEN") {
			t.Errorf("the token was printed: %q", s)
		}
	}
}

// The token reaches the device's own prompt, once, by either method, and the
// command after -- runs; the token is never printed.
func TestPortSSHLogsInWithTheTokenAndRunsTheCommand(t *testing.T) {
	for _, method := range []string{"keyboard-interactive", "password"} {
		dev := startDeviceSSH(t, []string{method}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		code, out, errb := r.run(t, "leaf1", "--", "show", "version")
		if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
			t.Errorf("%s: code %d stdout %q stderr %q attempts %q", method, code, out, errb, dev.attempts())
		}
		tokenNowhere(t, out, errb)
	}
}

// The token is in the askpass's answer to ssh and nowhere else: not in ssh's
// argv, not in its environment, not on port49 ssh's stdout or stderr; and
// the askpass socket is gone once port49 ssh returns (Global Constraints). A
// fake ssh records its argv and environment, then runs the askpass as ssh
// would, with the device's prompt.
func TestTheTokenIsNeverInArgvOrTheEnvironment(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	dir := t.TempDir()
	at := func(name string) string { return filepath.Join(dir, name) }
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -V ]; then echo 'OpenSSH_10.2p1, OpenSSL 3.5.5' >&2; exit 0; fi\n" +
		"printf '%s\\n' \"$@\" > '" + at("argv") + "'\n" +
		"env > '" + at("env") + "'\n" +
		"exec \"$SSH_ASKPASS\" \"alice@leaf1's password: \" > '" + at("answer") + "'\n"
	if err := os.WriteFile(at("ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = at("ssh")
	code, out, errb := r.run(t, "leaf1")
	read := func(name string) string {
		b, err := os.ReadFile(at(name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if answer := read("answer"); code != 0 || answer != "LOGINTOKEN\n" {
		t.Fatalf("code %d answer %q stderr %q", code, answer, errb)
	}
	for name, s := range map[string]string{"argv": read("argv"), "environment": read("env")} {
		if strings.Contains(s, "LOGINTOKEN") {
			t.Errorf("the token is in ssh's %s", name)
		}
	}
	tokenNowhere(t, out, errb)
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(r.sock), "askpass-*.sock")); len(left) != 0 {
		t.Fatalf("the askpass socket outlived port49 ssh: %v", left)
	}
}

// A host presenting another key than the pin never sees the token: ssh stops
// at the key exchange, the askpass is never asked, and port49 ssh says how
// to re-pin (decision 42 ruling 7; Review Focus 1).
func TestAHostWithAnotherKeyNeverSeesTheToken(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, testHostKey(t))
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 || !strings.Contains(errb, "Host key verification failed") ||
		!strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "run 'port49 devices trust --replace leaf1'") {
		t.Fatalf("code %d stdout %q stderr %q attempts %q", code, out, errb, dev.attempts())
	}
	tokenNowhere(t, out, errb)
}

// With no pin, nothing is minted and ssh never starts (Review Focus 2).
func TestNoPinnedKeyMintsNothing(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, nil)
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || r.mints.Load() != 0 || dev.connections() != 0 ||
		!strings.Contains(errb, "no host key is pinned for leaf1") {
		t.Fatalf("code %d mints %d conns %d stderr %q", code, r.mints.Load(), dev.connections(), errb)
	}
}

// No agent, an ended session, an unreachable broker: no ssh starts, and the
// agent's words say why (Review Focus 2).
func TestNoTokenNoSSH(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   any
		want   string
	}{
		"session over": {http.StatusGone, api.Error{Error: "session_over",
			Detail: "agent: the session is over; run `port49 login`"}, "the session is over"},
		"broker unreachable": {http.StatusBadGateway, api.Error{Error: "broker_error",
			Detail: "agent: the broker at https://b:8443 is unreachable: dial tcp: connection refused"}, "is unreachable"},
	} {
		dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		r.flags[1] = agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_ = json.NewEncoder(w).Encode(c.body)
		}))
		code, _, errb := r.run(t, "leaf1")
		if code != 1 || dev.connections() != 0 || !strings.Contains(errb, c.want) {
			t.Errorf("%s: code %d conns %d stderr %q", name, code, dev.connections(), errb)
		}
	}
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	r.flags[1] = filepath.Join(t.TempDir(), "gone", "agent.sock")
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || dev.connections() != 0 || !strings.Contains(errb, "port49 ssh: no agent at ") {
		t.Fatalf("no agent: code %d conns %d stderr %q", code, dev.connections(), errb)
	}
}

// A device that refuses the token and offers the other method is not sent a
// second or an empty password: port49 ssh ends the connection (decision 42
// ruling 10; Review Focus 3).
func TestTheTokenIsPresentedOnce(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive", "password"}, "", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" ||
		!strings.Contains(errb, "leaf1 asked for the password again after it was sent the token") {
		t.Fatalf("code %d attempts %q stderr %q", code, dev.attempts(), errb)
	}
	tokenNowhere(t, out, errb)
}

// A token that expired before the device asked for it is never sent: port49
// ssh mints once more through the agent and answers the prompt with that
// token, still once (decision 42 ruling 10; pre-flight I-3).
func TestATokenExpiredBeforeThePromptIsMintedAgain(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	stale, fresh := sshPermit, sshPermit
	stale.Login, stale.ExpiresAt = "STALETOKEN", time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	fresh.ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, stale, 0, dev.key)
	r.set(agent.Status{}, stale, fresh)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" ||
		r.mints.Load() != 2 {
		t.Fatalf("code %d stdout %q stderr %q attempts %q mints %d", code, out, errb, dev.attempts(), r.mints.Load())
	}
	tokenNowhere(t, out, errb)
}

// With no fresh token to be had, nothing is sent, ssh is ended, and port49
// ssh says the token expired before the device asked, never that policy
// refused it.
func TestATokenExpiredBeforeThePromptIsNeverSent(t *testing.T) {
	dev := startDeviceSSH(t, []string{"keyboard-interactive"}, "LOGINTOKEN", 0)
	stale := sshPermit
	stale.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, stale, 0, dev.key)
	r.set(agent.Status{}, stale, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 255 || len(dev.attempts()) != 0 ||
		!strings.Contains(errb, "past its expires_at ("+stale.ExpiresAt+"), and a fresh mint answered deny no_grants_matched") ||
		strings.Contains(errb, "port49 explain") {
		t.Fatalf("code %d attempts %q stderr %q", code, dev.attempts(), errb)
	}
	tokenNowhere(t, out, errb)
}

// An OpenSSH older than 8.5 is refused before a mint: 8.4p1's
// keyboard-interactive prompt names no host (decision 42 ruling 10).
func TestAnOldOpenSSHIsRefusedBeforeAMint(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	old := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(old, []byte("#!/bin/sh\necho 'OpenSSH_8.4p1 Debian-5+deb11u3, OpenSSL 1.1.1w' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[3] = old
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || r.mints.Load() != 0 || !strings.Contains(errb, "is OpenSSH 8.4; port49 ssh needs 8.5 or later") {
		t.Fatalf("code %d mints %d stderr %q", code, r.mints.Load(), errb)
	}
}

// A port49 that ssh's children run, inheriting askpassEnv, is no command:
// it says why rather than run one under port49 ssh's socket (decision 42
// ruling 10).
func TestAPort49UnderSSHIsNoCommand(t *testing.T) {
	t.Setenv(askpassEnv, filepath.Join(t.TempDir(), "askpass.sock"))
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unset "+askpassEnv) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// Within the ceiling warning at start, the warning comes before ssh runs
// (decision 42 ruling 11; Review Focus 5).
func TestTheCeilingWarningBeforeSSHStarts(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 1800, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || !strings.HasPrefix(errb, "port49: your session on leaf1 ends at "+item.SessionExpiresAt) {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	tokenNowhere(t, out, errb)
}

// fastWarning makes the in-session warning's first timer fire after 300ms,
// whatever it was armed for, and any later one at its real time; it returns
// what each was armed for. The session's ceiling is hours out, so no margin
// of a busy -race run decides the test.
func fastWarning(t *testing.T) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var armed []time.Duration
	prev := sshAfterFunc
	sshAfterFunc = func(d time.Duration, f func()) *time.Timer {
		mu.Lock()
		defer mu.Unlock()
		armed = append(armed, d)
		if len(armed) == 1 {
			return time.AfterFunc(300*time.Millisecond, f)
		}
		return time.AfterFunc(d, f)
	}
	t.Cleanup(func() { sshAfterFunc = prev })
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(armed)
	}
}

// A session that outlives the warning's moment gets the warning on the
// terminal at it, once (decision 42 ruling 11; Review Focus 5).
func TestTheCeilingWarningComesInSession(t *testing.T) {
	armed := fastWarning(t)
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 3*time.Second)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 3600, dev.key)
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Count(errb, "\r\nport49: your session on leaf1 ends at "+item.SessionExpiresAt) != 1 {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	if a := armed(); len(a) != 1 || a[0] < 59*time.Minute || a[0] > time.Hour {
		t.Fatalf("armed %v, want once, an hour before the ceiling", a)
	}
	tokenNowhere(t, out, errb)
}

// A port49 refresh in another terminal moves the ceiling: when the warning
// is due, the agent's last refresh says so, and the warning waits for the
// new moment instead of naming the old one (decision 42 ruling 11;
// pre-flight I-2).
func TestARefreshInSessionMovesTheWarning(t *testing.T) {
	armed := fastWarning(t)
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 3*time.Second)
	item := sshPermit
	item.SessionExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	later := time.Now().Add(5 * time.Hour).UTC().Format(time.RFC3339)
	r := newSSHRig(t, dev, item, 3600, dev.key)
	r.set(agent.Status{CeilingWarningSeconds: 3600, Sessions: []api.RefreshedSession{
		{Device: "spine1", Username: "alice", Outcome: "extended", SessionExpires: later},
		{Device: "leaf1", Username: "alice", Outcome: "extended", SessionExpires: later},
	}})
	code, out, errb := r.run(t, "leaf1", "--", "show", "version")
	if code != 0 || strings.Contains(errb, "your session on leaf1 ends at") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
	if a := armed(); len(a) != 2 || a[1] < 3*time.Hour+59*time.Minute || a[1] > 4*time.Hour {
		t.Fatalf("armed %v, want a second time, an hour before the new ceiling", a)
	}
	tokenNowhere(t, out, errb)
}

// The askpass answers the device's own prompt with the token once, a second
// own prompt never, and any other prompt from the terminal (decision 42
// ruling 10).
func TestAskpassAnswersTheDevicesPromptOnce(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var killed atomic.Int32
	srv := &askpassServer{ln: ln, token: "LOGINTOKEN", username: "alice", device: "leaf1"}
	srv.setKill(func() { killed.Add(1) })
	go srv.serve()
	t.Cleanup(func() { ln.Close() })
	prev := askTerminal
	askTerminal = func(prompt string, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, "JUMPPASS\n")
		return 0
	}
	t.Cleanup(func() { askTerminal = prev })
	ask := func(prompt string) (int, string) {
		var out, errb strings.Builder
		code := askpassMain(sock, []string{prompt}, &out, &errb)
		return code, out.String()
	}
	if code, out := ask("bob@jump's password: "); code != 0 || out != "JUMPPASS\n" {
		t.Fatalf("a jump host's prompt: %d %q", code, out)
	}
	if code, out := ask("(alice@leaf1) Password: "); code != 0 || out != "LOGINTOKEN\n" {
		t.Fatalf("the device's prompt: %d %q", code, out)
	}
	if code, out := ask("alice@leaf1's password: "); code != 1 || out != "" || killed.Load() != 1 {
		t.Fatalf("the device's prompt again: %d %q, killed %d", code, out, killed.Load())
	}
	if code := askpassMain(sock, nil, io.Discard, io.Discard); code != 1 {
		t.Fatal("no prompt was answered")
	}
}

func TestOwnPrompt(t *testing.T) {
	for prompt, own := range map[string]bool{
		"alice@leaf1's password: ":       true,
		"(alice@leaf1) Password: ":       true,
		"(alice@leaf1) Enter token: ":    true,
		"alice@leaf10's password: ":      false,
		"(alice@leaf10) Password: ":      false,
		"bob@leaf1's password: ":         false,
		"alice@jump's password: ":        false,
		"Enter passphrase for key 'x': ": false,
	} {
		if ownPrompt(prompt, "alice", "leaf1") != own {
			t.Errorf("ownPrompt(%q) = %v", prompt, !own)
		}
	}
}

// A yes/no question is answered with echo on, a password never.
func TestAskEchoes(t *testing.T) {
	for _, c := range []struct {
		prompt, hint string
		echo         bool
	}{
		{"Are you sure you want to continue connecting (yes/no/[fingerprint])? ", "", true},
		{"Allow use of key /home/alice/.ssh/id_ed25519?", "confirm", true},
		{"bob@jump's password: ", "", false},
		{"(bob@jump) Password: ", "none", false},
	} {
		if askEchoes(c.prompt, c.hint) != c.echo {
			t.Errorf("askEchoes(%q, %q) = %v", c.prompt, c.hint, !c.echo)
		}
	}
}

// The command line forces what decision 42 ruling 10 lists, in this order;
// the destination follows --. The file's path and the address are quoted,
// with % doubled, since ssh expands % tokens and splits on whitespace there.
func TestSSHArgs(t *testing.T) {
	got := sshArgs(sshOptions{config: "/c", knownHosts: "/k", device: "leaf1", address: "10.0.0.1", username: "alice",
		port: 2222, verbose: true, command: []string{"show", "version"}})
	want := `-F /c -o HostName="10.0.0.1" -o HostKeyAlias=leaf1 -o UserKnownHostsFile="/k" ` +
		"-o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o CheckHostIP=no " +
		"-o VerifyHostKeyDNS=no -o KnownHostsCommand=none -o PubkeyAuthentication=no " +
		"-o PreferredAuthentications=keyboard-interactive,password -o KbdInteractiveAuthentication=yes " +
		"-o PasswordAuthentication=yes -o NumberOfPasswordPrompts=1 -o BatchMode=no -o ControlMaster=no " +
		"-o ControlPath=none -o ForwardAgent=no -v -l alice -p 2222 -- leaf1 show version"
	if strings.Join(got, " ") != want {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
	odd := sshArgs(sshOptions{knownHosts: "/home/a b/%d/known_hosts", device: "leaf1", address: "fe80::1%eth0",
		username: "alice"})
	if s := strings.Join(odd, " "); !strings.Contains(s, `-o HostName="fe80::1%%eth0"`) ||
		!strings.Contains(s, `-o UserKnownHostsFile="/home/a b/%%d/known_hosts"`) {
		t.Fatalf("got %s", s)
	}
}
```

- [ ] **Step 4: Run them to verify they fail**

Run: `go test ./cmd/port49/ -run 'PortSSH|NeverInArgv|AnotherKey|NoPinned|NoTokenNoSSH|PresentedOnce|ExpiredBeforeThePrompt|OldOpenSSH|UnderSSH|CeilingWarning|RefreshInSession|Askpass|OwnPrompt|AskEchoes|SSHArgs' -count=1`
Expected: FAIL to build, `undefined: sshVersion`.

- [ ] **Step 5: Write `port49 ssh`**

Create `cmd/port49/ssh.go`:

```go
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hostkeys"
	"github.com/blanketfish/port49/internal/printsafe"
)

// askpassEnv names the socket `port49 ssh` answers its token on. ssh runs
// port49 itself as SSH_ASKPASS, with this set, for each prompt it would
// otherwise read from the terminal (decision 42 ruling 10).
const askpassEnv = "PORT49_ASKPASS"

// askpassCall reports whether ssh ran this port49 as `port49 ssh`'s askpass,
// and the socket to ask: askpassEnv names it, SSH_ASKPASS_REQUIRE is force,
// and the one argument is ssh's prompt. A port49 that ssh's children run
// otherwise (a ProxyCommand, a Match exec) inherits askpassEnv but is not
// one (decision 42 ruling 10).
func askpassCall(args []string) (string, bool) {
	sock := os.Getenv(askpassEnv)
	return sock, sock != "" && os.Getenv("SSH_ASKPASS_REQUIRE") == "force" && len(args) == 1
}

// minSSH is the oldest OpenSSH port49 ssh runs (decision 42 ruling 10,
// measured in tests/ssh-compat/2026-10-09-openssh-askpass.md). 8.0 to 8.3
// ignore SSH_ASKPASS_REQUIRE=force and take the terminal's prompt; 8.4, and
// the no-terminal route on the others, pass a keyboard-interactive prompt as
// the server's bare text, naming no host, so the askpass could not tell the
// device's prompt from a jump host's. 8.5 names it. 8.5 is also the first
// with KnownHostsCommand, which port49 ssh turns off.
var minSSH = [2]int{8, 5}

// maxPrompt bounds a prompt the askpass relays: ssh's own text and a
// device's keyboard-interactive one.
const maxPrompt = 4 << 10

// askpassMargin is how long before the token's expires_at the device's prompt
// must come for the token to be sent: the time to reach the device, and for
// it to ask port49d, which refuses a token past it.
const askpassMargin = 5 * time.Second

var sshVersionRE = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

// sshVersion is bin's OpenSSH major and minor version, from `ssh -V`.
func sshVersion(bin string) ([2]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	m := sshVersionRE.FindSubmatch(out)
	if m == nil {
		if err != nil {
			return [2]int{}, fmt.Errorf("%s -V: %v", bin, err)
		}
		return [2]int{}, fmt.Errorf("%s -V names no OpenSSH version: %s", bin, printsafe.Line(string(out), 200))
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	return [2]int{major, minor}, nil
}

// atLeast reports whether version v is floor or later.
func atLeast(v, floor [2]int) bool { return v[0] > floor[0] || v[0] == floor[0] && v[1] >= floor[1] }

// sshOptions is one ssh run's command line.
type sshOptions struct {
	config, knownHosts, device, address, username string
	port                                          int
	verbose                                       bool
	command                                       []string
}

// sshValue is v as an -o value ssh reads back as v: each '%' doubled, since
// ssh expands %-tokens in HostName and UserKnownHostsFile (an IPv6 zone's
// "%eth0" would be refused), and the whole double-quoted, since ssh splits a
// value on whitespace. A value holding '"' cannot be written so; sshCmd
// refuses one first.
func sshValue(v string) string { return `"` + strings.ReplaceAll(v, "%", "%%") + `"` }

// sshArgs is ssh's command line (decision 42 ruling 10). Every -o here comes
// before the operator's ssh_config is read, and ssh takes an option's first
// value, so none of them can be undone there; the rest of ssh_config
// (ProxyJump, algorithms, User for a jump host) applies as usual.
func sshArgs(o sshOptions) []string {
	var a []string
	if o.config != "" {
		a = append(a, "-F", o.config)
	}
	for _, opt := range []string{
		"HostName=" + sshValue(o.address),
		"HostKeyAlias=" + o.device,
		"UserKnownHostsFile=" + sshValue(o.knownHosts),
		"GlobalKnownHostsFile=/dev/null",
		"StrictHostKeyChecking=yes",
		"UpdateHostKeys=no",
		"CheckHostIP=no",
		"VerifyHostKeyDNS=no",
		"KnownHostsCommand=none",
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
	} {
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

// ownPrompt reports whether prompt is ssh asking for the device's own
// password: "<user>@<device>'s password: " for the password method,
// "(<user>@<device>) <the device's text>" for keyboard-interactive, where
// <device> is the HostKeyAlias (OpenSSH 8.5p1, 8.9p1 and 10.2p1, measured
// for plan 9a; §15 L54 per platform). A jump host's prompt names the jump
// host.
func ownPrompt(prompt, username, device string) bool {
	who := username + "@" + device
	return prompt == who+"'s password: " || strings.HasPrefix(prompt, "("+who+") ")
}

// askpassServer answers ssh's askpass for one `port49 ssh`: the token, once,
// to the device's own prompt; "not ours" to any other, so the askpass asks
// the terminal as ssh would have; and, to the device's prompt asked again,
// nothing, after kill has ended ssh, so the token is presented once and no
// second or empty password follows it. A device prompt that comes when the
// token is within askpassMargin of expiresAt, or past it, is answered with a
// fresh mint's token from remint, or not at all (pre-flight I-3).
type askpassServer struct {
	ln               net.Listener
	token            string
	username, device string
	expiresAt        time.Time // the token's expires_at; zero when the broker gave none
	remint           func() (api.MintItem, error)

	mu       sync.Mutex
	served   bool
	repeated bool
	expired  string    // why a device prompt that came too late got no token
	askedAt  time.Time // when that prompt came
	kill     func()
}

// setKill sets what ends ssh before a refusal is answered: OpenSSH's
// read_passphrase sends an empty password for an askpass that fails.
func (s *askpassServer) setKill(f func()) {
	s.mu.Lock()
	s.kill = f
	s.mu.Unlock()
}

// state is whether the token was served, whether the device's prompt came
// again, and, for a prompt that came after the token's expiry with no fresh
// token to send, why and when.
func (s *askpassServer) state() (served, repeated bool, expired string, askedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.served, s.repeated, s.expired, s.askedAt
}

// refuse ends ssh, then answers "X".
func (s *askpassServer) refuse(c net.Conn) {
	if s.kill != nil {
		s.kill()
	}
	_, _ = io.WriteString(c, "X\n")
}

// stale reports whether the token is too near its expires_at, or past it, to
// reach the device and be redeemed.
func (s *askpassServer) stale() bool {
	return !s.expiresAt.IsZero() && time.Until(s.expiresAt) < askpassMargin
}

// renew replaces a stale token with a fresh mint's, for the same username,
// and reports whether it did; when it did not, expired says why.
func (s *askpassServer) renew() bool {
	s.askedAt = time.Now()
	why := "no fresh one could be minted"
	if s.remint != nil {
		item, err := s.remint()
		switch {
		case err != nil:
			why = "a fresh mint failed: " + unprefixed(err)
		case item.Verdict != "permit" || item.Login == "":
			why = fmt.Sprintf("a fresh mint answered %s %s", item.Verdict, item.Reason)
		case item.Username != s.username:
			why = "a fresh mint names another username, " + printsafe.Line(item.Username, 64)
		default:
			s.token = item.Login
			s.expiresAt, _ = time.Parse(time.RFC3339, item.ExpiresAt)
			return true
		}
	}
	s.expired = why
	return false
}

func (s *askpassServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.answer(c)
	}
}

// answer reads one quoted prompt and writes "T <token>", "N" (not the
// device's) or "X" (the device's again, or the device's with no token fit to
// send).
func (s *askpassServer) answer(c net.Conn) {
	defer c.Close()
	// Room for a fresh mint (remint's own bound is 10s) before the reply.
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, maxPrompt)).ReadString('\n')
	if err != nil {
		return
	}
	prompt, err := strconv.Unquote(strings.TrimSuffix(line, "\n"))
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !ownPrompt(prompt, s.username, s.device):
		_, _ = io.WriteString(c, "N\n")
	case s.served:
		s.repeated = true
		s.refuse(c)
	case s.stale() && !s.renew():
		s.refuse(c)
	default:
		s.served = true
		_, _ = io.WriteString(c, "T "+s.token+"\n")
	}
}

// askpassMain is port49 run by ssh as SSH_ASKPASS (askpassEnv set): it asks
// `port49 ssh` for the answer to the one prompt ssh passes and prints it for
// ssh. A prompt that is not the device's own is asked of the terminal (a jump
// host's password). The device's prompt asked a second time is refused,
// exit 1.
func askpassMain(sock string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "port49 askpass: ssh runs this with one prompt; it is not a command to type")
		return 1
	}
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: port49 ssh is not answering at %s: %v\n", sock, err)
		return 1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := io.WriteString(c, strconv.Quote(args[0])+"\n"); err != nil {
		fmt.Fprintf(stderr, "port49 askpass: %v\n", err)
		return 1
	}
	reply, err := bufio.NewReader(io.LimitReader(c, 1<<10)).ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: port49 ssh did not answer: %v\n", err)
		return 1
	}
	switch reply = strings.TrimSuffix(reply, "\n"); {
	case strings.HasPrefix(reply, "T "):
		fmt.Fprintln(stdout, strings.TrimPrefix(reply, "T "))
		return 0
	case reply == "N":
		return askTerminal(args[0], stdout, stderr)
	}
	fmt.Fprintf(stderr, "port49 askpass: not answering %q: port49 ssh presents its token once, to the device's "+
		"own prompt\n", printsafe.Line(args[0], 200))
	return 1
}

// askEchoes reports whether the answer to prompt is shown as it is typed: a
// yes/no question, as ssh asks of a jump host's unknown key (it passes no hint
// for that one), or one ssh marks a confirmation (SSH_ASKPASS_PROMPT=confirm).
// Never a password.
func askEchoes(prompt, hint string) bool {
	return hint == "confirm" || strings.Contains(prompt, "(yes/no")
}

// askTerminal asks the controlling terminal for the answer to prompt, as ssh
// would have without SSH_ASKPASS_REQUIRE: a jump host's password, with echo
// off, or a yes/no question, with echo on (askEchoes), typed by the
// operator. A test swaps it.
var askTerminal = func(prompt string, stdout, stderr io.Writer) int {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: answering %q needs a terminal: %v\n", printsafe.Line(prompt, 200), err)
		return 1
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	if askEchoes(prompt, os.Getenv("SSH_ASKPASS_PROMPT")) {
		line, err := bufio.NewReader(tty).ReadString('\n')
		if err != nil && line == "" {
			return 1
		}
		fmt.Fprintln(stdout, strings.TrimRight(line, "\r\n"))
		return 0
	}
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprint(tty, "\r\n")
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, string(pw))
	return 0
}

// listenAskpass opens the askpass socket in the agent socket's directory,
// which agent.PrivateDir holds at 0700 and owned by this user: whoever can
// reach the socket can already mint as this operator.
func listenAskpass(agentSocket string) (net.Listener, string, error) {
	dir := filepath.Dir(agentSocket)
	if err := agent.PrivateDir(dir); err != nil {
		return nil, "", err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "askpass-"+hex.EncodeToString(b[:])+".sock")
	if len(path) > 107 {
		return nil, "", fmt.Errorf("the askpass socket %s is too long for a Unix socket; pass a shorter --socket", path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, "", err
	}
	return ln, path, nil
}

// withoutAskpass is env with no SSH_ASKPASS, SSH_ASKPASS_REQUIRE or
// askpassEnv of the caller's.
func withoutAskpass(env []string) []string {
	var out []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "SSH_ASKPASS=") || strings.HasPrefix(kv, "SSH_ASKPASS_REQUIRE=") ||
			strings.HasPrefix(kv, askpassEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// sshAfterFunc arms the in-session warning's timer; a test swaps it so no
// test waits on, or races, a real ceiling.
var sshAfterFunc = time.AfterFunc

// warnInSession writes the ceiling warning once, on the terminal ssh draws
// on, when the device's session comes within warn of its ceiling, and
// returns the func that stops it. None is armed when there is no ceiling, or
// when the moment has passed and the warning was said before ssh started
// (decision 42 ruling 11).
//
// When the moment comes it asks the agent first: a `port49 refresh` in
// another terminal may have moved the ceiling (§5.6), and then the warning
// waits for the new moment rather than name a ceiling that has moved
// (pre-flight I-2).
func warnInSession(stderr io.Writer, socket, device string, item api.MintItem, warn time.Duration) (stop func()) {
	exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt)
	if err != nil || warn <= 0 || time.Until(exp.Add(-warn)) <= 0 {
		return func() {}
	}
	var mu sync.Mutex
	stopped := false
	var t *time.Timer
	var fire func()
	fire = func() {
		later, moved := refreshedCeiling(socket, device, item.Username)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case stopped:
		case moved && later.After(exp):
			exp = later
			t = sshAfterFunc(time.Until(exp.Add(-warn)), fire)
		default:
			fmt.Fprintf(stderr, "\r\nport49: your session on %s ends at %s (%s); run 'port49 refresh'\r\n", device,
				exp.UTC().Format(time.RFC3339), timeLeft(time.Until(exp)))
		}
	}
	mu.Lock()
	t = sshAfterFunc(time.Until(exp.Add(-warn)), fire)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		t.Stop()
	}
}

// refreshedCeiling is the device session's ceiling as the agent's last
// refresh extended it, if that refresh did and reached the device: what a
// `port49 refresh` in another terminal moved (decision 42 ruling 11). An
// agent that does not answer moves nothing, and the warning is said.
func refreshedCeiling(socket, device, username string) (time.Time, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := agent.NewClient(socket).Status(ctx)
	if err != nil {
		return time.Time{}, false
	}
	for _, s := range st.Sessions {
		if s.Device == device && s.Username == username && s.Outcome == "extended" && !s.Unreached {
			if at, err := time.Parse(time.RFC3339, s.SessionExpires); err == nil {
				return at, true
			}
		}
	}
	return time.Time{}, false
}

// exitCode is ssh's exit status; 255 for an ssh port49 ssh ended or that
// died by a signal, as ssh's own failures are.
func exitCode(err error) int {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode()
	}
	return 255
}

// sshCmd is `port49 ssh` (design §17; decision 42 rulings 7, 10 and 11).
func sshCmd(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 ssh"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	ttl := fs.Duration("ttl", 0, "ask for this token lifetime; the broker clamps it to your policy's token_ttl")
	port := fs.Int("port", 0, "the device's SSH port (default: ssh's, 22 unless your ssh_config says otherwise)")
	bin := fs.String("ssh", "ssh", "the OpenSSH client to run, 8.5 or later")
	sshConfig := fs.String("ssh-config", "", "an ssh_config to read in place of ~/.ssh/config (ssh -F)")
	knownHosts := fs.String("known-hosts", hostkeys.Path(), "the pinned host keys file")
	verbose := fs.Bool("v", false, "ssh -v: say each step of the connection and its authentication")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device, command := fs.Arg(0), fs.Args()[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if !hostkeys.ValidName(device) {
		fmt.Fprintf(stderr, "%s: %q: port49 ssh takes devices named with letters, digits, '.', '_' and '-' only "+
			"(decision 42 ruling 8); use `port49 token` and your own ssh for it\n", cmd, device)
		return 2
	}
	if strings.ContainsAny(*knownHosts, "\"\n") {
		fmt.Fprintf(stderr, "%s: --known-hosts %q holds a '\"' or a newline, which ssh cannot be handed; "+
			"name the file by another path\n", cmd, *knownHosts)
		return 2
	}
	pinned, err := hostkeys.Lookup(*knownHosts, device)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if len(pinned) == 0 {
		fmt.Fprintf(stderr, "%s: no host key is pinned for %s: verify its key on its console and run 'port49 "+
			"devices trust %s' first; a key never seen is never accepted (design §17)\n", cmd, device, device)
		return 1
	}
	path, err := exec.LookPath(*bin)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	v, err := sshVersion(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if !atLeast(v, minSSH) {
		fmt.Fprintf(stderr, "%s: %s is OpenSSH %d.%d; port49 ssh needs 8.5 or later, the first whose prompts name "+
			"the device they ask for. Run `port49 token %s` and your own ssh instead\n", cmd, path, v[0], v[1], device)
		return 1
	}
	mint := func(ctx context.Context) (api.MintItem, error) {
		return agent.NewClient(*socket).Token(ctx, agent.TokenRequest{Device: device, TTLSeconds: int(*ttl / time.Second)})
	}
	item, err := mint(context.Background())
	mintedAt := time.Now()
	if mintFailed(cmd, *socket, device, item, err, stderr) {
		return 1
	}
	if item.Address == "" || item.Username == "" || strings.ContainsAny(item.Address, "\"\n") {
		fmt.Fprintf(stderr, "%s: the broker gives %s no address and username ssh can be handed; tell the operator\n",
			cmd, device)
		return 1
	}
	warn := ceilingWarning(*socket)
	warnNearCeiling(stderr, device, item, warn)
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	ln, sockPath, err := listenAskpass(*socket)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, unprefixed(err))
		return 1
	}
	defer os.Remove(sockPath)
	defer ln.Close()
	expiresAt, _ := time.Parse(time.RFC3339, item.ExpiresAt)
	srv := &askpassServer{ln: ln, token: item.Login, username: item.Username, device: device, expiresAt: expiresAt,
		remint: func() (api.MintItem, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return mint(ctx)
		}}

	c := exec.Command(path, sshArgs(sshOptions{config: *sshConfig, knownHosts: *knownHosts, device: device,
		address: item.Address, username: item.Username, port: *port, verbose: *verbose, command: command})...)
	c.Env = append(withoutAskpass(os.Environ()), "SSH_ASKPASS="+self, "SSH_ASKPASS_REQUIRE=force",
		askpassEnv+"="+sockPath)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, stdout, stderr
	// The terminal sends ^C and ^\ to ssh too; port49 ssh outlives them to
	// report ssh's status. A TERM or HUP sent to port49 alone goes on to ssh.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		fmt.Fprintf(stderr, "%s: starting %s: %v\n", cmd, path, err)
		return 1
	}
	// Served only once the kill is set: an ask that comes before waits in
	// the listener's backlog, so no refusal is ever answered with ssh left
	// running to send an empty password.
	srv.setKill(func() { _ = c.Process.Kill() })
	go srv.serve()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	stopWarn := warnInSession(stderr, *socket, device, item, warn)
	err = c.Wait()
	stopWarn()
	code := exitCode(err)
	served, repeated, expired, askedAt := srv.state()
	switch {
	case expired != "":
		// A timing fault, never policy's: the device asked after the
		// token's expiry, as behind a slow jump host (pre-flight I-3).
		fmt.Fprintf(stderr, "%s: %s asked for the token %s after it was minted, past its expires_at (%s), and %s; "+
			"nothing was sent to %s, and ssh was ended. Run `port49 ssh %s` again; a slow jump host login is the "+
			"usual cause\n", cmd, device, askedAt.Sub(mintedAt).Round(time.Second), item.ExpiresAt, expired, device,
			device)
		return 255
	case repeated:
		fmt.Fprintf(stderr, "%s: %s asked for the password again after it was sent the token; port49 ssh ended the "+
			"connection, so no second or empty password reached it; `port49 explain --device %s` says whether "+
			"your policy permits you, and port49d's decision log says why the device refused\n", cmd, device, device)
		return 255
	case code == 255 && served:
		fmt.Fprintf(stderr, "%s: %s was sent the token and the connection failed (ssh exit 255, its message is "+
			"above); if it says Permission denied, `port49 explain --device %s` says whether your policy permits "+
			"you, and port49d's decision log says why the device refused\n", cmd, device, device)
	case code == 255:
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above); if ssh says the host key changed, the address inventory gives for %s may not "+
			"be the device: verify the key on its console, then run 'port49 devices trust --replace %s'\n", cmd,
			device, device, device)
	}
	return code
}
```

In `cmd/port49/main.go`, replace

```go
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
```

with

```go
func main() {
	// ssh runs port49 itself as its askpass, with askpassEnv naming `port49
	// ssh`'s socket (decision 42 ruling 10).
	if sock, ok := askpassCall(os.Args[1:]); ok {
		os.Exit(askpassMain(sock, os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
```

In `run`, replace its first lines,

```go
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
```

with

```go
func run(args []string, stdout, stderr io.Writer) int {
	// A port49 that ssh's children run (a ProxyCommand, a Match exec) under
	// `port49 ssh` inherits askpassEnv. It is not the askpass, and runs no
	// command there either: it says why (decision 42 ruling 10).
	if os.Getenv(askpassEnv) != "" {
		fmt.Fprintf(stderr, "port49: %s is set, so this port49 was started under port49 ssh's ssh (a ProxyCommand "+
			"or Match exec?) and is not its askpass; unset %s to run a port49 command there\n", askpassEnv, askpassEnv)
		return 2
	}
	if len(args) == 0 {
```

Then add a case before `case "agent":`:

```go
	case "ssh":
		return sshCmd(args[1:], stdout, stderr)
```

In the usage, after the `port49 identity` line, add:

```
  port49 ssh [--ttl DURATION] [--port N] [--ssh PATH] [--ssh-config FILE] [--known-hosts FILE] [-v]
             [--socket PATH] DEVICE [-- COMMAND...]
             (mints through your agent and runs your OpenSSH, 8.5 or later; DEVICE's key must be pinned
             first with port49 devices trust; exits with ssh's status)
```

In `cmd/port49/main_test.go`'s `TestMain`, as its first statement, add:

```go
	// The test binary is port49 ssh's askpass in the ssh tests, as port49
	// is in production.
	if sock, ok := askpassCall(os.Args[1:]); ok {
		os.Exit(askpassMain(sock, os.Args[1:], os.Stdout, os.Stderr))
	}
```

Run: `go mod tidy && git diff go.mod go.sum`
Expected: `golang.org/x/term v0.45.0` moves into the direct `require` block; `go.sum` unchanged.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/port49/ -run 'PortSSH|NeverInArgv|AnotherKey|NoPinned|NoTokenNoSSH|PresentedOnce|ExpiredBeforeThePrompt|OldOpenSSH|UnderSSH|CeilingWarning|RefreshInSession|Askpass|OwnPrompt|AskEchoes|SSHArgs' -count=1 -v`
Expected: PASS, none skipped on the test box (OpenSSH 10.2p1).

Run: `go test -race ./cmd/port49/ ./internal/agent/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -l cmd internal && go vet ./...
git add cmd/port49/ssh.go cmd/port49/ssh_test.go cmd/port49/sshserver_test.go cmd/port49/main.go \
  cmd/port49/main_test.go internal/agent/agent.go internal/agent/agent_test.go go.mod go.sum
git commit -m "feat(agent): port49 ssh logs in through the operator's OpenSSH with a pinned key and a one-time askpass (decision 42)"
```

---

### Task 7: The Netmiko integration example, and design §17's examples made true

**Files:**
- Create: `examples/netmiko/port49_netmiko.py`, `examples/netmiko/test_port49_netmiko.py`,
  `examples/netmiko/example_test.go`, `examples/netmiko/README.md`
- Modify: `docs/design/2026-08-21-port49-design.md` §17 "Integration examples"

**Interfaces:**
- Consumes: `port49 token --json` (unchanged); the pins file's format (Task 5); decision 42 ruling 7.
- Produces: `port49_netmiko.connect(device, enable=False, port49="port49", pins=None)`.

- [ ] **Step 1: Write the failing example test**

Create `examples/netmiko/test_port49_netmiko.py`:

```python
"""The Netmiko example's test (plan 9a, Task 7): a fake port49 and a fake
Netmiko, so it runs with neither installed."""

import json
import os
import stat
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

captured = {}


class FakeConnectHandler:
    def __init__(self, **kw):
        captured.update(kw)
        with open(kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(kw["alt_key_file"]).st_mode)


sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=FakeConnectHandler)

import port49_netmiko  # noqa: E402

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


class Example(unittest.TestCase):
    def setUp(self):
        captured.clear()
        self.dir = tempfile.mkdtemp()
        self.pins = os.path.join(self.dir, "known_hosts")
        with open(self.pins, "w", encoding="ascii") as f:
            f.write("leaf* " + KEY + "\n@revoked leaf1 " + KEY + "\nleaf1 " + KEY + "\n")
        os.chmod(self.pins, 0o600)  # whatever the umask: a group-writable file is refused
        self.argv = os.path.join(self.dir, "argv")
        item = {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
                "username": "alice", "login": "LOGINTOKEN"}
        self.port49 = os.path.join(self.dir, "port49")
        with open(self.port49, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + self.argv + "'\necho '" + json.dumps(item) + "'\n")
        os.chmod(self.port49, 0o755)

    def test_it_logs_in_with_the_token_and_checks_the_pinned_key(self):
        port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        self.assertEqual(captured["host"], "10.0.0.11")
        self.assertEqual(captured["username"], "alice")
        self.assertEqual(captured["password"], "LOGINTOKEN")
        self.assertEqual(captured["device_type"], "arista_eos")
        self.assertTrue(captured["ssh_strict"])
        self.assertFalse(captured["system_host_keys"])
        self.assertFalse(captured["use_keys"])
        self.assertFalse(captured["allow_agent"])
        # The pin, and only the exact name's unmarked line, under the address.
        self.assertEqual(captured["known_hosts"], "10.0.0.11 " + KEY + "\n")
        self.assertEqual(captured["mode"], 0o600)
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        with open(self.argv, encoding="ascii") as f:
            self.assertEqual(f.read(), "token\n--json\nleaf1\n")

    def test_no_pin_mints_nothing(self):
        with self.assertRaises(RuntimeError):
            port49_netmiko.connect("spine1", port49=self.port49, pins=self.pins)
        self.assertFalse(os.path.exists(self.argv))

    def test_a_pins_file_others_can_write_mints_nothing(self):
        os.chmod(self.pins, 0o664)
        with self.assertRaises(RuntimeError):
            port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        self.assertFalse(os.path.exists(self.argv))


if __name__ == "__main__":
    unittest.main()
```

Create `examples/netmiko/example_test.go`:

```go
// Package netmiko holds the Netmiko example's test: its own Python test, run
// when python3 is installed (plan 9a, Task 7).
package netmiko

import (
	"os/exec"
	"testing"
)

func TestTheNetmikoExample(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed: the example's own test needs it")
	}
	if out, err := exec.Command(py, "test_port49_netmiko.py", "-v").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
```

Run: `go test ./examples/netmiko/ -count=1`
Expected: FAIL: `ModuleNotFoundError: No module named 'port49_netmiko'`.

- [ ] **Step 2: Write the example**

Create `examples/netmiko/port49_netmiko.py`:

```python
"""Netmiko through port49 (design §17, "Integration examples"; plan 9a).

`port49 token --json DEVICE` mints through your agent and prints the
broker's answer on stdout: the username to present beside the token, the
token, the device's address and its platform. The token is never in argv or
the environment.

The device's SSH host key is checked against the key port49 pinned for it
with `port49 devices trust DEVICE`; a key never seen is never accepted
(design §17). Netmiko looks a key up by the address it connects to, so the
pin, which port49 keeps under the device's inventory name, is written under
the address the broker gave, to a private temporary file for this one
connection.
"""

import json
import os
import stat
import subprocess
import tempfile

# port49's platform names to Netmiko's device types.
DEVICE_TYPES = {
    "arista_eos": "arista_eos",
    "cisco_nxos": "cisco_nxos",
    "cisco_iosxe": "cisco_xe",
    "juniper_junos": "juniper_junos",
}


def pins_path():
    """port49's pinned host keys file: $XDG_CONFIG_HOME/port49/known_hosts."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "port49", "known_hosts")


def check_private(path):
    """Refuse a pins file, or its directory, that anyone but you or root can write, as port49 itself does
    (policy engine spec §13 decision 42 ruling 6): whoever can write it chooses which keys are accepted.
    port49 also checks every directory above; this example checks the file and its own directory only."""
    for p in (path, os.path.dirname(os.path.abspath(path))):
        st = os.lstat(p)
        if p == path and not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"{p} is not a regular file; port49's pins are read only from one")
        if st.st_uid not in (os.getuid(), 0) or st.st_mode & 0o022:
            raise RuntimeError(f"{p} can be written by someone other than you; port49 refuses it, and so does this example")


def pinned_keys(device, pins=None):
    """The keys pinned for device: lines whose host field is its name alone, with no marker."""
    pins = pins or pins_path()
    check_private(pins)
    keys = []
    with open(pins, encoding="ascii") as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 3 and fields[0] == device:
                keys.append(fields[1] + " " + fields[2])
    return keys


def token(device, enable=False, port49="port49"):
    """The broker's answer for device, minted through your agent."""
    cmd = [port49, "token", "--json"] + (["--enable"] if enable else []) + [device]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def connect(device, enable=False, port49="port49", pins=None):
    """A Netmiko connection to device, logged in with a fresh token."""
    from netmiko import ConnectHandler

    keys = pinned_keys(device, pins)
    if not keys:
        raise RuntimeError(f"no host key is pinned for {device}: run 'port49 devices trust {device}' first")
    tok = token(device, enable, port49)
    fd, known = tempfile.mkstemp(prefix="port49-", suffix=".known_hosts")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            for k in keys:
                f.write(f"{tok['address']} {k}\n")
        return ConnectHandler(
            device_type=DEVICE_TYPES[tok["platform"]],
            host=tok["address"],
            username=tok["username"],
            password=tok["login"],
            secret=tok.get("enable", ""),
            ssh_strict=True,           # a key not in the file is refused
            system_host_keys=False,    # ~/.ssh/known_hosts is not consulted
            alt_host_keys=True,
            alt_key_file=known,
            use_keys=False,            # spec §15 L51: refused keys count against the device's limit
            allow_agent=False,
        )
    finally:
        os.unlink(known)
```

`tempfile.mkstemp` creates the file 0600.

Create `examples/netmiko/README.md`:

```markdown
# Netmiko through port49

`port49_netmiko.connect("leaf1")` logs in to `leaf1` with a fresh token from your agent
(`port49 login` first), as the username the broker says, at the address inventory gives.

Pin the device's key once, with `port49 devices trust leaf1`, comparing the fingerprint with the
device's console. The example refuses a device with no pin, and Netmiko refuses a key other than
the pin. It refuses a pins file, or its directory, that anyone but you or root can write, as
port49 does; port49 also checks every directory above, which this example does not. Public-key
authentication and the SSH agent are off, since a refused key counts against the device's
login-attempt limit (policy engine spec §15, L51).

Unlike `port49 ssh`, which presents the token once and ends the connection rather than answer a
second prompt, Netmiko's paramiko may present the token a second time: after the device refuses
it by `password`, paramiko can try `keyboard-interactive` with the same token. That is not
measured; a refused token is refused again, one more refused attempt against the device's limits.

Its test runs with neither port49 nor Netmiko installed: `python3 test_port49_netmiko.py`.
```

- [ ] **Step 3: Run the example's test to verify it passes**

Run: `go test ./examples/netmiko/ -count=1 -v`
Expected: PASS (`Ran 3 tests … OK` in the output).

- [ ] **Step 4: Design §17's examples say what is built**

In `docs/design/2026-08-21-port49-design.md`, replace

````markdown
```python
# Netmiko / Python — the mint returns the username to present alongside the
# token pair, so the caller never hardcodes it (policy engine spec, §2).
tok  = port49.token(device)
conn = ConnectHandler(device_type="arista_eos", host=device,
                      username=tok.username,
                      password=tok.login, secret=tok.enable)
```

```bash
# Shell / SSH. Note the token is passed on a file descriptor rather than in
# argv: an argument is visible in `ps` to every user on the host.
port49 ssh "$DEVICE" -- "show running-config"
```
````

with

````markdown
```python
# Netmiko / Python (examples/netmiko, plan 9a). The mint returns the username to
# present beside the token, so the caller never hardcodes it (policy engine
# spec, §2). The device's key is checked against port49's pin for it.
conn = port49_netmiko.connect(device)
```

```bash
# Shell / SSH (plan 9a). The token is never in argv, which every user on the
# host can read in `ps`, nor in the environment: ssh asks port49's askpass,
# which takes it from `port49 ssh` over a socket only this user can reach.
port49 ssh "$DEVICE" -- "show running-config"
```
````

and replace

```markdown
# Ansible
```

with

```markdown
# Ansible (plan 9d: the lookup plugin, once the mint carries the device's host-key fingerprint)
```

- [ ] **Step 5: Commit**

```bash
go vet ./examples/...
git add examples/netmiko docs/design/2026-08-21-port49-design.md
git commit -m "docs(examples): Netmiko through port49 with the pinned host key; design §17's examples say what is built"
```

---

### Task 8: Lab L53 and L54 on five platforms

**Files:**
- Create: `tests/lab/l53_l54_test.go` (`//go:build lab`), `tests/lab/l53_unit_test.go`
  (`//go:build lab`)
- Create, by the run: `tests/lab/results/L53-<platform>.md`, `tests/lab/results/L54-<platform>.md`,
  and their evidence through `make evidence`
- Modify: `Makefile` (`lab-ssh`), `tests/lab/README.md` (a "port49 ssh" section),
  `docs/design/2026-08-23-policy-engine-spec.md` §15 (L53, L54 statuses) and any text the results
  contradict

**Interfaces:**
- Consumes: `bin/port49` (`make build`); `hostkeys.Scan` and `Fingerprint`.
- Consumes from the lab harness: `eachPlatform`, `l29Agent`, `l29Mint`, `l29Packets` (and its
  `l29Packet.at`), `l.login`, `l.sshCLI`, `l.dial`, `l.mark`, `l.recordsSince`, `l.capture`,
  `l.flushCapture`, `l.capAbs`, `l.result`, `l.waitDeviceReady`, `sliceUser`, `root`,
  `trimForNote`, `str`.
- **The capture.** `l.capture(t, name)` writes `<name>-<platform>.pcap`, and a note cites the last
  capture started, so the run takes one, `L53L54`, for both notes. A note whose capture holds no
  device traffic fails (`stoppedCaptureLine`); the console logins put TACACS+ in this one. Each
  step's TACACS+ count is taken from its own time window of it.
- Produces: the two rows' notes. Task 1's rule holds: until they close, no doc names a console
  command or calls a scan invisible.

The lab runs on the SER8 (memory: lab runs allowed; lab stays single-occupant). It is gated by
`PORT49_LAB_SSH=1`, since it reloads each device. A plain `make lab` skips it.

- [ ] **Step 1: The classifier and its unit test**

Create `tests/lab/l53_unit_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// l53Shown recognises the key in a console command's output: its OpenSSH
// base64 blob, its SHA256 fingerprint, its DER as hex (IOS-XE's `show crypto
// key mypubkey rsa`), its MD5 fingerprint, or none of them.
func TestL53ShownReadsEachForm(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	blob := base64.StdEncoding.EncodeToString(k.Marshal())
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := ssh.NewPublicKey(&rk.PublicKey)
	spki, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	var grouped strings.Builder // IOS-XE's form: upper-case hex, 8 digits a group, 8 groups a line
	for i, c := range strings.ToUpper(hex.EncodeToString(spki)) {
		if i > 0 && i%8 == 0 {
			grouped.WriteString(map[bool]string{true: "\n  ", false: " "}[i%64 == 0])
		}
		grouped.WriteRune(c)
	}
	md5 := ssh.FingerprintLegacyMD5(r)
	for _, c := range []struct {
		out  string
		k    ssh.PublicKey
		want string
	}{
		{"ssh-ed25519 " + blob + " root@leaf1\n", k, "base64 key"},
		{"Fingerprint: " + ssh.FingerprintSHA256(k) + "\n", k, "SHA256 fingerprint"},
		{"ssh-ed25519 " + blob[:20] + "\n" + blob[20:] + "\n", k, "base64 key"},
		{"Key name: leaf1.lab\n Key Data:\n  " + grouped.String() + "\n", r, "hex DER key"},
		{"bitcount:2048 fingerprint:\n" + md5 + "\n", r, "MD5 fingerprint"},
		{"fingerprint " + strings.ToUpper(strings.ReplaceAll(md5, ":", "")) + "\n", r, "MD5 fingerprint"},
		{"RSA key fingerprint is 9b:2a:..., other key\n", k, ""},
		{strings.Repeat("x", 100), k, ""},
		{"Key Data:\n  " + grouped.String() + "\n", k, ""},
	} {
		if got := l53Shown(c.out, c.k); got != c.want {
			t.Errorf("l53Shown(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}
```

The third case is a blob a terminal wrapped across lines. The hex DER case is laid out as IOS-XE
prints a key; the last case is another key's DER, which names nothing.

- [ ] **Step 2: The lab test**

Create `tests/lab/l53_l54_test.go`:

```go
//go:build lab

package lab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blanketfish/port49/internal/hostkeys"
)

// l53Console is, per platform, the console commands that may show the SSH
// host key or its fingerprint. Which one does, and in what form, is what L53
// measures: each runs, its output goes into the note, and l53Shown names the
// form it holds the scanned key in, if any.
var l53Console = map[string][]string{
	"arista_eos": {"show management ssh hostkey ed25519 public", "show management ssh hostkey ecdsa-nistp256 public",
		"show management ssh hostkey rsa public"},
	"cisco_nxos":  {"show ssh key"},
	"cisco_iosxe": {"show ip ssh", "show crypto key mypubkey rsa"},
	"juniper_vjunos-router": {"file show /etc/ssh/ssh_host_ed25519_key.pub", "file show /etc/ssh/ssh_host_ecdsa_key.pub",
		"file show /etc/ssh/ssh_host_rsa_key.pub"},
	"juniper_vsrx": {"file show /etc/ssh/ssh_host_ed25519_key.pub", "file show /etc/ssh/ssh_host_ecdsa_key.pub",
		"file show /etc/ssh/ssh_host_rsa_key.pub"},
}

// l53Reload is, per platform, the lines that save the configuration and
// reload, each with the prompt that may follow it ("" for none expected) and
// the answer to give. A prompt that differs fails the step with the
// transcript in the note: fix the prompt here, never the claim.
var l53Reload = map[string][][3]string{
	"arista_eos":            {{"write memory", "", ""}, {"reload now", "", ""}},
	"cisco_nxos":            {{"copy running-config startup-config", "", ""}, {"reload", "(y/n)", "y"}},
	"cisco_iosxe":           {{"write memory", "", ""}, {"reload", "[confirm]", ""}},
	"juniper_vjunos-router": {{"request system reboot", "[yes,no]", "yes"}},
	"juniper_vsrx":          {{"request system reboot", "[yes,no]", "yes"}},
}

// l53Uptime is, per platform, a command whose output says how long the
// device has been up or when it booted. It is read before and after the
// reload, so the note shows the device went down (pre-flight I-6).
var l53Uptime = map[string]string{
	"arista_eos":            "show version",
	"cisco_nxos":            "show version",
	"cisco_iosxe":           "show version",
	"juniper_vjunos-router": "show system uptime",
	"juniper_vsrx":          "show system uptime",
}

var l53UptimeLine = regexp.MustCompile(`(?im)^.*(uptime|booted).*$`)

// l53Log is, per platform, the command that shows the device's own log. It
// is read after the scan, and the note keeps its last 30 lines, so a line the
// scan wrote is there to see.
var l53Log = map[string]string{
	"arista_eos":            "show logging",
	"cisco_nxos":            "show logging logfile",
	"cisco_iosxe":           "show logging",
	"juniper_vjunos-router": "show log messages",
	"juniper_vsrx":          "show log messages",
}

// l53Limits is, for each platform the L53 row names a login-attempt limit
// for, the configuration lines that set a limit of two failures in 60s, and
// the lines that remove it. A prompt that differs fails the step: fix the
// lines here, never the claim.
var l53Limits = map[string][2][]string{
	"cisco_iosxe": {{"configure terminal", "login block-for 60 attempts 2 within 60", "end"},
		{"configure terminal", "no login block-for", "end"}},
	"cisco_nxos": {{"configure terminal", "aaa authentication rejected 2 in 60 ban 60", "end"},
		{"configure terminal", "no aaa authentication rejected 2 in 60 ban 60", "end"}},
}

var l53Space = regexp.MustCompile(`\s+`)

// l53Shown is the form out holds k in: "base64 key" (the OpenSSH blob, a
// terminal's line wrapping removed), "SHA256 fingerprint", "hex DER key"
// (the key's DER as hex, in any case and grouping, as IOS-XE prints an RSA
// key), "MD5 fingerprint" (with colons or without), or "".
func l53Shown(out string, k ssh.PublicKey) string {
	flat := l53Space.ReplaceAllString(out, "")
	upper := strings.ToUpper(flat)
	md5 := ssh.FingerprintLegacyMD5(k)
	switch {
	case strings.Contains(flat, base64.StdEncoding.EncodeToString(k.Marshal())):
		return "base64 key"
	case strings.Contains(out, ssh.FingerprintSHA256(k)):
		return "SHA256 fingerprint"
	}
	for _, der := range l53DER(k) {
		if strings.Contains(upper, der) {
			return "hex DER key"
		}
	}
	if strings.Contains(strings.ToLower(out), md5) ||
		strings.Contains(upper, strings.ToUpper(strings.ReplaceAll(md5, ":", ""))) {
		return "MD5 fingerprint"
	}
	return ""
}

// l53DER is k's DER as upper-case hex: the PKIX SubjectPublicKeyInfo, and for
// RSA the PKCS #1 key it wraps, which a device may print alone.
func l53DER(k ssh.PublicKey) []string {
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	var out []string
	if der, err := x509.MarshalPKIXPublicKey(ck.CryptoPublicKey()); err == nil {
		out = append(out, strings.ToUpper(hex.EncodeToString(der)))
	}
	if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
		out = append(out, strings.ToUpper(hex.EncodeToString(x509.MarshalPKCS1PublicKey(rk))))
	}
	return out
}

// l53Tail is the last n lines of s.
func l53Tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// l53WaitDown waits until addr has refused or dropped two connection
// attempts in a row, within bound: the device went down. A VM still
// answering SSH right after its reload command would otherwise be scanned
// before it reloaded, and its old key reported as surviving (pre-flight I-6).
func l53WaitDown(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	failed := 0
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			if failed++; failed == 2 {
				return nil
			}
		} else {
			c.Close()
			failed = 0
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s still accepted connections %s after the reload command: the device never went down", addr, within)
}

// l53Configure sends lines in one CLI session, each answered by a prompt.
func l53Configure(t *testing.T, l *lab, sock string, lines []string) {
	t.Helper()
	c, err := l.sshCLI(sliceUser, mustToken(t, sock, l.p.node))
	if err != nil {
		t.Fatalf("configuration session: %v", err)
	}
	defer c.Close()
	for _, line := range lines {
		if out, err := c.sendExpect(line, 30*time.Second, "#"); err != nil {
			t.Fatalf("%q: %v\n%s", line, err, trimForNote(out))
		}
	}
}

// l53Limit measures whether scans count against the login-attempt limit
// lim[0] sets: three scans, then a login with a fresh token. Then the
// control, two refused logins and a login with a fresh token, which the
// limit must refuse for the measurement to mean anything. It waits out the
// limit's 60s, then removes it with lim[1].
func l53Limit(t *testing.T, l *lab, sock, addr string, lim [2][]string) (note string, inForce bool) {
	t.Helper()
	l53Configure(t, l, sock, lim[0])
	for i := range 3 {
		if _, err := hostkeys.Scan(context.Background(), addr); err != nil {
			t.Errorf("scan %d with the limit set: %v", i+1, err)
		}
	}
	_, afterScans := l.login(sliceUser, mustToken(t, sock, l.p.node), "show version")
	for range 2 {
		if c, err := l.dial("l53-control", "not-a-token", 30*time.Second); err == nil {
			c.Close()
		}
	}
	_, afterControl := l.login(sliceUser, mustToken(t, sock, l.p.node), "show version")
	time.Sleep(75 * time.Second)
	l53Configure(t, l, sock, lim[1])
	outcome := func(err error) string {
		if err == nil {
			return "it succeeded"
		}
		return fmt.Sprintf("it was refused (%v)", err)
	}
	return fmt.Sprintf("With `%s` set: three scans, then a login with a fresh token: %s. The control, two refused "+
		"logins as `l53-control` and then a login with a fresh token: %s.", lim[0][1], outcome(afterScans),
		outcome(afterControl)), afterControl != nil
}

// TestL53L54PortSSH measures L53 and L54 on each selected platform: the
// scan and what it leaves, the console's view of the key, the login-attempt
// limit where the row names one, port49 ssh with the key pinned through
// port49 devices trust, port49 ssh against a wrong pin, and the key after a
// reload, in that order (the reload last, since it takes the device away
// for its boot budget). Once both notes are written, it asserts each claim
// decision 42 relies on (pre-flight I-8), so "the lab test passed" means
// they held.
func TestL53L54PortSSH(t *testing.T) {
	if os.Getenv("PORT49_LAB_SSH") != "1" {
		t.Skip("L53 and L54 reload each device: run them with `make lab-ssh` (PORT49_LAB_SSH=1)")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		port49 := filepath.Join(root, "bin", "port49")
		sock, stopAgent := l29Agent(t)
		defer stopAgent()
		xdg := t.TempDir()
		// Only this user may write above the pins file, whatever the
		// lab host's umask (decision 42 ruling 6).
		if err := os.Chmod(xdg, 0o700); err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), "XDG_CONFIG_HOME="+xdg)
		// An empty ssh_config: the lab host's own ~/.ssh/config does not
		// shape what is measured.
		sshConfig := filepath.Join(xdg, "ssh_config")
		if err := os.WriteFile(sshConfig, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		addr := l.p.addr + ":22"
		var l53, l54 []string
		say := func(note *[]string, format string, args ...any) { *note = append(*note, fmt.Sprintf(format, args...)) }

		// One capture for the run, so each note points at device traffic;
		// each step counts the TACACS+ packets in its own window of it.
		stopCap := l.capture(t, "L53L54")
		defer stopCap()
		tacacsIn := func(from, to time.Time) int {
			l.flushCapture(t)
			pkts, err := l29Packets(l.capAbs, l.p.addr)
			if err != nil {
				t.Fatalf("reading the capture: %v", err)
			}
			n := 0
			for _, p := range pkts {
				if !p.at.Before(from) && !p.at.After(to) {
					n++
				}
			}
			return n
		}

		// L53: the scan, and what it leaves behind.
		off := l.mark()
		scanFrom := time.Now()
		key, err := hostkeys.Scan(context.Background(), addr)
		if err != nil {
			t.Fatalf("scan %s: %v", addr, err)
		}
		say(&l53, "The scan read a `%s` key, %s.", key.Type(), hostkeys.Fingerprint(key))
		time.Sleep(10 * time.Second)
		say(&l53, "Within 10s of the scan: %d decision records, and %d TACACS+ packets to or from the device in the "+
			"capture.", len(l.recordsSince(off)), tacacsIn(scanFrom, time.Now()))

		// L53: the console. One minted token, one login: every candidate
		// command, the uptime, and the device's log after the scan.
		cmds := append(append([]string{}, l53Console[l.p.name]...), l53Uptime[l.p.name], l53Log[l.p.name])
		outs, err := l.login(sliceUser, mustToken(t, sock, l.p.node), cmds...)
		if err != nil || len(outs) != len(cmds) {
			t.Fatalf("console session: %v (%d of %d outputs)", err, len(outs), len(cmds))
		}
		consoleFP := ""
		for i, cmd := range l53Console[l.p.name] {
			form := l53Shown(outs[i], key)
			if form == "" {
				form = "not this key"
			} else if consoleFP == "" {
				consoleFP = hostkeys.Fingerprint(key)
			}
			say(&l53, "`%s`: %s.\n\n```\n%s\n```", cmd, form, trimForNote(outs[i]))
		}
		say(&l53, "Before the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(outs[len(cmds)-2], -1))
		say(&l53, "The device's log after the scan, `%s`, its last 30 lines:\n\n```\n%s\n```", l53Log[l.p.name],
			trimForNote(l53Tail(outs[len(cmds)-1], 30)))

		// L53: the device's login-attempt limit, where the row names one.
		if lim, ok := l53Limits[l.p.name]; ok {
			note, inForce := l53Limit(t, l, sock, addr, lim)
			say(&l53, "%s", note)
			if !inForce {
				t.Errorf("%s: the control did not trip the limit, so whether a scan counts against it is unmeasured "+
					"here", l.p.name)
			}
		}

		// L54: port49 devices trust, then port49 ssh with a command.
		fp := consoleFP
		if fp == "" {
			fp = hostkeys.Fingerprint(key) // no console form matched: the scan's own, and the note says so
			say(&l53, "No console command showed this key; the trust step below used the scan's fingerprint.")
		}
		trust := exec.Command(port49, "devices", "trust", "--socket", sock, "--fingerprint", fp, l.p.node)
		trust.Env = env
		if out, err := trust.CombinedOutput(); err != nil {
			t.Fatalf("port49 devices trust: %v\n%s", err, out)
		}
		off = l.mark()
		run := exec.Command(port49, "ssh", "-v", "--socket", sock, "--ssh-config", sshConfig, l.p.node, "--",
			"show version")
		run.Env = env
		var stdout, stderr strings.Builder
		run.Stdout, run.Stderr = &stdout, &stderr
		err = run.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		methods := regexp.MustCompile(`Next authentication method: (\S+)`).FindAllStringSubmatch(stderr.String(), -1)
		var tried []string
		for _, m := range methods {
			tried = append(tried, m[1])
		}
		asked := strings.Count(stderr.String(), "read_passphrase: requested to askpass")
		version := strings.Contains(strings.ToLower(stdout.String()), "version")
		say(&l54, "`port49 ssh %s -- show version` exited %d; methods ssh tried: %v; askpass asked %d times; "+
			"`show version` output %s.", l.p.node, code, tried, asked,
			map[bool]string{true: "present", false: "absent"}[version])
		redeems := 0
		for _, r := range l.recordsSince(off) {
			if str(r, "event") == "redeem" {
				redeems++
			}
		}
		say(&l54, "Redeem records for the login: %d.", redeems)

		// L54: a wrong pin, never presented. The session above has ended
		// and its accounting landed before the window opens.
		wrong, _, _ := ed25519.GenerateKey(rand.Reader)
		wk, _ := ssh.NewPublicKey(wrong)
		if err := hostkeys.Pin(filepath.Join(xdg, "port49", "known_hosts"), l.p.node, wk, true); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		off = l.mark()
		wrongFrom := time.Now()
		bad := exec.Command(port49, "ssh", "--socket", sock, "--ssh-config", sshConfig, l.p.node, "--", "show version")
		bad.Env = env
		badOut, _ := bad.CombinedOutput()
		time.Sleep(10 * time.Second)
		wrongTACACS := tacacsIn(wrongFrom, time.Now())
		var wrongOther []string
		for _, r := range l.recordsSince(off) {
			if e := str(r, "event"); e != "mint" && e != "blob" {
				wrongOther = append(wrongOther, e)
			}
		}
		say(&l54, "Against a wrong pin: %d TACACS+ packets to or from the device in the capture; records other than "+
			"mint and blob: %v. port49 ssh said:\n\n```\n%s\n```", wrongTACACS, wrongOther, trimForNote(string(badOut)))

		// L53: the key after a reload, with the configuration saved. The
		// device must be seen to go down before it is waited for.
		c, err := l.sshCLI(sliceUser, mustToken(t, sock, l.p.node))
		if err != nil {
			t.Fatalf("reload session: %v", err)
		}
		for _, step := range l53Reload[l.p.name] {
			want := []string{"#", ">", step[1]}
			if step[1] == "" {
				want = []string{"#", ">"}
			}
			out, _ := c.sendExpect(step[0], 3*time.Minute, want...)
			if step[1] != "" && strings.Contains(out, step[1]) {
				_ = c.send(step[2])
			}
		}
		c.Close()
		if err := l53WaitDown(addr, 10*time.Minute); err != nil {
			t.Fatalf("after the reload command: %v", err)
		}
		if err := l.waitDeviceReady(l.p.boot); err != nil {
			t.Fatalf("after the reload: %v", err)
		}
		if up, err := l.login(sliceUser, mustToken(t, sock, l.p.node), l53Uptime[l.p.name]); err == nil && len(up) == 1 {
			say(&l53, "After the reload, `%s` says: %q.", l53Uptime[l.p.name], l53UptimeLine.FindAllString(up[0], -1))
		}
		after, err := hostkeys.Scan(context.Background(), addr)
		switch {
		case err != nil:
			say(&l53, "**The scan after the reload failed**: %v", err)
		case hostkeys.Fingerprint(after) == hostkeys.Fingerprint(key):
			say(&l53, "After a reload with the configuration saved, the device seen down and back, the key is the "+
				"same (%s).", hostkeys.Fingerprint(after))
		default:
			say(&l53, "**After a reload the key changed**: %s, then %s.", hostkeys.Fingerprint(key), hostkeys.Fingerprint(after))
		}

		l.result(t, "L53", "The SSH host key the device presents to port49 devices trust's scan, the console's view of "+
			"it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).", strings.Join(l53, "\n\n"))
		l.result(t, "L54", "port49 ssh against the device: the method, the askpass, the command, and a wrong pin "+
			"(policy engine spec §15, L54).", strings.Join(l54, "\n\n"))

		// The claims decision 42 rests on, asserted once the notes are written.
		if code != 0 || !version {
			t.Errorf("port49 ssh -- show version: exit %d, show version %v; want 0 and present", code, version)
		}
		if asked != 1 {
			t.Errorf("the askpass was asked %d times; want once", asked)
		}
		if wrongTACACS != 0 || len(wrongOther) != 0 {
			t.Errorf("a wrong pin reached the device's authentication: %d TACACS+ packets, records %v", wrongTACACS,
				wrongOther)
		}
	})
}

// mustToken mints one token for device through the agent at sock.
func mustToken(t *testing.T, sock, device string) string {
	t.Helper()
	said, tok := l29Mint(sock, device)
	if tok == "" {
		t.Fatalf("no token for %s: %s", device, said)
	}
	return tok
}
```

If a helper named above has another signature in the harness (`trimForNote` is
`tests/lab/transport_test.go`'s, `str` is `harness_test.go`'s), use it as it is: do not write a
second copy.

- [ ] **Step 3: The make target and the lab README**

In `Makefile`, add `lab-ssh` to the `.PHONY` line, after `lab-oxidized`. After the `lab-oxidized`
target, add:

```makefile
# L53 and L54 (plan 9a): port49 devices trust and port49 ssh against each
# platform, one at a time as `make lab` runs them. Each device is reloaded
# once, so this is its own target. Needs containerlab, the images and
# `make build`.
lab-ssh:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-ssh platform: $$p ==="; \
	  if ! PORT49_LAB_SSH=1 PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL53L54PortSSH' -count=1 -v -timeout 90m; then \
	    echo "=== lab-ssh platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done
```

In `tests/lab/README.md`, add a section `## port49 ssh (L53, L54)` saying: `make build && make
lab-ssh`; each device is reloaded once; the notes go to `tests/lab/results/L53-*.md` and
`L54-*.md`; the run's capture is `tests/lab/captures/L53L54-<platform>.pcap` and goes through
`make evidence` like every other. On IOS-XE and NX-OS the run sets a login-attempt limit for about
two minutes and removes it; a run stopped in that window leaves it set (`no login block-for`, `no
aaa authentication rejected 2 in 60 ban 60`).

Run: `make lab-unit`
Expected: PASS, `TestL53ShownReadsEachForm` among them.

- [ ] **Step 4: Run the lab**

Run, on the SER8, with a stall watchdog running beside it (memory: lab run watchdog):
`make build && make lab-ssh`
Expected:
- each platform writes `L53-<platform>.md` and `L54-<platform>.md`, and the test passes: its
  closing assertions hold (`port49 ssh` exits 0 with `show version` present, the askpass asked
  once, and the wrong pin makes no TACACS+ packet and no record but `mint` and `blob`), and on
  IOS-XE and NX-OS the limit's control tripped;
- every note's reload line follows a device seen down and back, with its uptime before and after.

Then `make evidence`. A platform that fails stops the loop: read its note, fix the harness's
prompt or command, and run that platform again with `PORT49_LAB_PLATFORMS=<sel> make lab-ssh`.

- [ ] **Step 5: Close what was measured, and fix what it contradicts**

For each row, follow CLAUDE.md's lab-register rules 3 and 4:
- **All five platforms measured:** edit the Status to `closed — measured <date>;
  tests/lab/results/L53-*.md` (L54 alike), with a one-paragraph summary as L51's row has.
- **A clause unmeasured on any platform** (a console command that shows no key; a reload that did
  not come back): the row stays open, and its Status says which.

Then:
- If the results contradict decision 42's text, fix the text, cite the note, and say so in the
  commit message. Example: a platform whose prompt does not name `<user>@<device>`, which would
  mean the askpass never answers it.
- **`port49 ssh`'s 255 message after the token was sent** points at policy ("if it says
  Permission denied, `port49 explain`…"). A device that sends no `exit-status` makes ssh exit 255
  after a command that ran. If L54 shows a platform doing so, word that message for it, citing
  the note, as its own `fix(agent):` commit before this one (pre-flight M-12).
- Copy the raw captures to the main checkout before removing a lab worktree (memory: lab captures
  live in worktrees).

```bash
git add tests/lab/l53_l54_test.go tests/lab/l53_unit_test.go tests/lab/results/L53-*.md tests/lab/results/L54-*.md \
  tests/lab/evidence Makefile tests/lab/README.md docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L53 and L54 (port49 ssh and host keys on five platforms)"
```

If either row stays open, the commit message says `measure` instead of `close`, and names the
clauses that stay open.

---

### Task 9: The roadmap's as-built entry

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 9" and the status paragraph)

- [ ] **Step 1: Write the as-built entry**

Under `## Plan 9 — Agent in full (§19 step 9)`, after the 9a outline, add `### Plan 9a — As
built`. Its body is three short bullet lists:
- **Built:** the commits, the test counts from `make test`, and L53 and L54's status.
- **Carried:** to 9b, 9c, 9d or the pre-beta review, each with its reason.
- **Operator-facing notes:** this plan's "Operator notes" section, corrected to what the lab
  measured.

In the status paragraph, the line that ends `Next: 9–11. 12–13 not yet.`, add the date 9a
executed and its branch.

- [ ] **Step 2: Verify the branch and commit**

Run: `make test && make vet`
Expected: PASS, and `gofmt` lists nothing.

Run: `make test-race`
Expected: PASS.

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap, plan 9a as built"
```
