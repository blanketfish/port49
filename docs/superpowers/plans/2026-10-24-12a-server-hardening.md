# Server Hardening Implementation Plan (plan 12a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close plan 12's server-code items before any deployment artifact is written:
- secrets named by `secret_ref:` (`env:` or `file:`), replacing every `*_env` secret key;
- the device key sets moved into the policy file, with port49d.yaml bounding which secrets a policy may name;
- one YAML document per file;
- an egress proxy for the source-of-truth client;
- a global connection cap that sheds at Accept;
- an etcd version floor checked at start;
- the broker start's paged loads surviving a compaction;
- a cross-broker check that every broker issues from the same CA;
- the write fence walking every ancestor directory.

**Architecture:**
- A new package, `internal/secretref`, parses a `secret_ref` and resolves it from the environment or from a file read through the write fence (`fence.ReadSecret`: links followed only inside one directory, owner and mode checked). A secret store (Vault, a cloud secret manager) reaches port49 as a file its own agent renders.
  - `config` resolves port49d.yaml's and port49-broker.yaml's secrets at load.
  - `inventory` resolves port49-inventory.yaml's secrets at load.
  - port49d resolves the policy's key secrets at start and before every policy swap, only inside the allowance port49d.yaml declares (`key_secret_refs`). It holds each secret once per process, keyed by its reference, and retries a policy refused for a secret it could not read.
- A second new package, `internal/keyset`, holds the key-set schema and its checks. Both the policy file (the normal home of `keys:`) and port49d.yaml (only with no policy) use it.
- The other items are local changes:
  - `yamlfault.OneDocument` at each loader;
  - `internal/egress` for the proxy;
  - `server.Slots` for the global cap, taken after Accept and shed when full;
  - `etcd.Store.EndpointVersions` and `BelowFloor` for the version floor;
  - a `meta/issuer` record in the directory store for the issuing CA;
  - an ancestor walk in `fence.resolvePolicyPath`.

**Tech Stack:** Go 1.26 standard library (`net/http`, `crypto/tls`, `syscall`), `gopkg.in/yaml.v3` and `go.etcd.io/etcd/client/v3` (both already in go.mod). No new module.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §10, "Version sets, and no cutover", "Retirement is enforced", "Connectors and sync cadence", "How a daemon refreshes its snapshot";
  - §13 decision 31 (the source's token and webhook secret);
  - decision 32 (the global cap);
  - decision 43 ruling 14 (the issuing CA);
  - decision 51 (the stores);
  - decision 53, which Task 1 writes.
- `docs/design/2026-08-21-port49-design.md`:
  - §11, "Listener limits": "limits are per source before they are global";
  - §13: "Run etcd 3.5.8 or later (3.4.24 on 3.4)".
- The roadmap: `docs/superpowers/plans/README.md`, "Plan 12 — Deployment", and the plan 12 inventory `.superpowers/sdd/plan12-inputs.md` (theme B, and the code items of theme A).

## Rulings this plan is written under (team lead and Ryan, 2026-10-24)

1. Plan 12 is three plans, each merged before the next is written:
   - 12a, this plan, is server code;
   - 12b is deployment artifacts (systemd, container, Kubernetes/Helm), release and publishing;
   - 12c is per-platform reference configurations, alert rules and lab rows.
2. 12a covers inventory theme B and the code items of theme A. Deployment files, CI and reference configurations are 12b's and 12c's ("Leaves for later").
3. **The issuing CA's key stays on each broker's own disk or state volume** (Ryan): never in the store, never a read-only Secret. The store records only fingerprints, and a broker whose CA differs from the record refuses to start.
4. **The global connection cap is in**, because the design already specifies it:
   - design §11: "limits are per source before they are global… A global cap reached first would turn a single flapping box into an outage";
   - decision 32: "plan 12 owns the global cap" (its backlog wait is the broker listener's; port49d's TACACS+ cap sheds, ruling 8 below);
   - the roadmap's plan 1 carry: "The cap itself, its sizing, and its alarm are this plan's". The alarm is 12c's.
5. **No deprecation before beta.**
   - `secret_env`, `password_env`, `token_secret_env`, `webhook_secret_env`, port49-broker.yaml's `key_refs`, and port49d.yaml's `keys:` beside a policy are removed outright.
   - A file still naming an old key is refused, naming the key and its replacement (`yamlfault.Replaced`, as `receipt_ttl` is refused). There is no alias and no warning: nothing old is ever loaded.
6. **`secret_ref` is `env:` and `file:` only** (Ryan, 2026-10-25). No `vault:` scheme: a secret store reaches port49 as a file rendered by Vault Agent, External Secrets or the Secrets Store CSI driver. port49 does not reimplement a secret-store client.
7. **Accepted (team lead, 2026-10-25):** port49d.yaml's `keys:` stays only for a port49d with no policy, and the issuing-CA check runs only for port49-broker on etcd. Decision 53 rulings 3 and 10 state why.
8. **Pre-flight rulings (team lead, 2026-10-25):**
   - **The global cap sheds** (design §11, "Accept-queue pressure sheds load rather than queueing it"). At the cap port49d accepts, then resets at once: counted in `port49_connections_shed_total{reason="global_cap"}`, said when shedding begins and then rate-limited. The device moves to its next server. The listeners hold no slot: only accepted connections count.
   - **A reload's own reset takes no strike** (spec §10): a connection whose version a reload retired or removed is reset with one record and no strike.
   - **A policy refused for a secret it could not read is retried**, at every reload trigger and every `keyRetryInterval` (30s), until it loads or the policy changes, and said rate-limited. No SIGHUP is needed.
   - **port49d.yaml bounds what a policy may name** (`key_secret_refs: {env_prefix, file_dir}`): a security ruling, decision 53 ruling 12.
   - **A `file:` key may be a link resolving inside `file_dir`** (Kubernetes Secret and CSI volumes), owned by root or port49d's user, with no world bit; group-read is allowed.

## Global Constraints

- **Toolchain.** Go 1.26+, module `github.com/blanketfish/port49`; `gofmt` and `go vet` clean; no cgo; no new module.
- **snake_case** for every data key: `secret_ref`, `password_secret_ref`, `token_secret_ref`, `webhook_secret_ref`, `key_secret_refs.env_prefix`, `key_secret_refs.file_dir`, `limits.max_connections`, the `meta/issuer` record's JSON.
- **Reason codes** come only from spec §5.7 (`internal/decision/reasons.go`). This plan adds none: every refusal it adds is a start or reload line, or an existing record (`matches_retired`, `device_unknown`).
- **Warnings and report codes** come only from spec §12. This plan adds no report code; `port49 policy test`'s existing `keys:` and `report:` lines change source (the policy, not port49d.yaml). The two operator lines the global cap says (shedding begun, still shedding) are written into §12 by Task 1 before Task 11 emits them.
- **Secrets never printed.** No secret, proxy password or secret file content appears in an error, a line, a log record, a metric or a test failure message. A test that compares a secret reports a mismatch and the lengths, never either value. A test that asserts a fixture secret is absent from an error or a line checks that first and fails naming what leaked, never printing the text; only once the text is known clean may a later assertion print it (re-review N10). A `secret_ref` is printed only once it parses; one that does not is refused by its key. A secret type prints as `<redacted>` under every fmt verb (`sot.Secret`'s rule).
- **Metrics:** no device identity in a label. New: `port49_connections_max` (gauge, no label) and `port49_connections_shed_total{reason}` (counter; one value, `global_cap`).
- **Darwin.** `make check-darwin` vets `./...` for darwin. Any Linux-only code stays in a `_linux.go` file, as `internal/fence` already does (`fence.ReadSecret` gets a refusing stub in `fence_other.go`, as `fence.Read` has); `syscall.Getrlimit` (Task 11) exists on both.
- **Files never read:** `*.env`, `*.keytab`, `*-key.pem`, `realm.json`, `router.db`, `/tmp/port49-lab-tokens.jsonl`, `tests/lab/logs/**`.
- **No lab run in this plan.** Lab test files whose generated configurations change (Tasks 4 and 6) are edited so `make lab-unit` passes. They run at the next `make lab-regress`, before beta.
- **Commits.** Conventional Commits, one per task, ending `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` with the implementing model's name. No `Claude-Session:` line and no claude.ai link.
- **Verification.** `make test && make vet` before each task's commit; report the real output.

## Design notes

### `secret_ref` (decision 53 ruling 1)

A secret is named, never written. One grammar serves every secret port49 reads:

| Form | Reads | Example |
|---|---|---|
| `env:NAME` | the environment variable NAME (letters, digits, `_`; not starting with a digit) | `env:PORT49_PROD_V3` |
| `file:/absolute/path` | the file, through `fence.ReadSecret` (below), at most 1 MiB; one trailing `\n` or `\r\n` dropped | `file:/run/secrets/prod_v3` |

**How a `file:` secret is read (decision 53 ruling 1; pre-flight I12).** `fence.ReadSecret(path, within, max)` is the policy file's fence with a reader's rule for the file:
- **Links** are followed, as the fence follows a ConfigMap's, only while every one resolves inside `within`: `file_dir` for a policy key (ruling 12), the reference's own directory for every other secret. A Kubernetes Secret or Secrets Store CSI volume (`name -> ..data/name -> ..2026_10_25_…/name`) passes; a link out of the directory is refused, naming both paths. Every link's directory and every ancestor is held to the fence's rule, a read-only mount excused, as for the policy file (Task 15).
- **The directory holding the file** is held to `Read`'s rule: owned by port49d's user or root and writable by nobody else, never excused by a read-only mount (a read-only bind of a host directory others can write is writable on the host). A ConfigMap's timestamped directory passes it, as measured (`tests/lab/results/configmap-mounts.md`); a Secret volume's uses the same atomic writer, and 12b measures it with `fsGroup`.
- **The file** is a regular file owned by port49d's user or root, writable by its owner alone, with no world bit. Group-read is allowed: `fsGroup` and an agent's `perms = "0440"` give it. Refused: "is mode -rw-r--r--: a secret file may be group-readable, never world-readable or writable by anyone but its owner - chmod 0440 or 0600 it".
- **Rotation without a restart** needs the directory mounted whole, not by `subPath`: kubelet updates `..data` in a whole-volume mount and never in a `subPath` one. The 12b hand-off says so for each shape.

`keyfile.ReadSecret` (owner-only, no link) stays for what it reads today: TLS keys and the keytab.

**No secret-store client (decision 53 ruling 5).** There is no `vault:` scheme and no `secrets:` block. Vault Agent, External Secrets, the Secrets Store CSI driver and systemd credentials already authenticate to a store, renew, and render a secret as a file; port49 reads that file by `file:` and does not reimplement any of them (Ryan, 2026-10-25).

**Why the trailing newline is dropped.** `echo secret > file` writes one, as do most Secret and credential tooling. A shared key with a stray `\n` validates no packet from any device, which is a fleet-wide key miss at 3am. A key that really ends in a newline cannot be typed into a device CLI either. The rule is the same for every `file:` reference, the encryption key's included (whose 32-byte check then holds).

**A reference that does not parse is refused by its key, never printed:** it is most likely the secret, pasted where its name goes. Once it parses, it is a name and is printed in every line about it.

It replaces every secret key named by an environment variable, outright (this plan's ruling 5, no deprecation):

| Was | Now |
|---|---|
| `keys.<ref>.<version>.secret_env: NAME` | `secret_ref: env:NAME` (and in the policy file, Task 6) |
| `encryption.current/previous.secret_env: NAME` | `secret_ref: env:NAME` |
| `broker.directory.bind.password_env: NAME` | `password_secret_ref: env:NAME` |
| port49-inventory.yaml `sync[].token_secret_env` | `token_secret_ref` |
| port49-inventory.yaml `sync[].webhook_secret_env` | `webhook_secret_ref` |

`site_env` is untouched: the site is not a secret.

### When a secret is read (decision 53 ruling 2)

| Secret | Read | A failure |
|---|---|---|
| encryption keys, keys in port49d.yaml (no policy) | `config.Load`/`LoadBroker`, once at start | refuses the start, naming the key and the reference |
| the directory bind password | when port49-broker opens the directory (`openDirectory`, at start or late); `LoadBroker` checks only that the reference parses | refuses the start, or ends the run at a late open, naming the key and the reference |
| the source token and webhook secret | `inventory.Load`, once at start | refuses the start |
| the policy's key secrets | at start, and before every swap that puts a policy in force, each only inside `key_secret_refs` | at start, refuses the start; at a reload, refuses the reload, the bundle and keys in force keep serving, and a read failure is retried (below) |

- **Each reference is read once per process and kept by its text.** A version's secret never changes (spec §10: a new secret is a new version). So a reload reads only versions it has not seen, and an inventory-only reload reads nothing.
- **A reload that names another reference for a version already in force is refused**: "add a version". Changing the secret behind a version would break every device on it at the next packet, with nothing in the diff to say why.
- **A secret no version in force names is dropped from memory at the swap.**
- **A reload refused because a key's secret could not be read is retried** (pre-flight I4), at every reload trigger (a policy or inventory change, SIGHUP) and every `keyRetryInterval`, 30 s, until the policy loads or the file changes to another version. 30 s is half kubelet's default Secret sync period (60 s), so a key a Secret volume or an agent renders is in force within about half a minute of its file appearing, and each try costs one open per unread reference. The first refusal is said in full; a retry that fails again is said at most once every 10 minutes, with the count of tries. A refusal for anything else (a reference outside the allowance, a re-keyed version, a policy that does not parse) is not retried: only a policy edit fixes it.

**What the operator sees at 3am:**
- **The secret store is down.**
  - Every running port49d keeps serving: it holds its secrets and reads nothing until a policy edit adds a version.
  - The agent that renders the files keeps the last ones it wrote, so a restarting port49d reads them and starts. A file the agent never wrote refuses the start, naming the key, the reference and the read's error, as an unset variable refuses one today.
  - A policy edit adding a version whose file is not there yet is refused once, with the reload's refusal line, which adds "tried again every 30s until it can be read or the policy changes". The policy in force keeps serving. When the agent writes the file, the next try puts the policy in force and says so; nobody sends a SIGHUP.
- **A secret file is mode 0644.** The start or the reload is refused with the fence's text: "is mode -rw-r--r--: a secret file may be group-readable, never world-readable … chmod 0440 or 0600 it, or, on a mounted volume, set the mode where it is rendered (Kubernetes `defaultMode` and `fsGroup`, Vault Agent's `perms`)". The file is named; the secret is not. A new mode is picked up at the next retry.

### Where a policy's key may point (decision 53 ruling 12; pre-flight I5)

Before this plan, only port49d.yaml's owners chose which secrets port49d reads. A policy that names its own key secrets would hand that choice to every writer of the policy repository: `secret_ref: env:PORT49_ENC_V2` (the encryption-at-rest key), the bind password's variable, or `file:` at the TLS listener key, the keytab or the issuing CA's key. Each could be put in force as a TACACS+ key for a device the writer controls, and the validated-or-missed answer is an oracle for guessing a low-entropy secret. port49d.yaml therefore bounds what a policy may name:

```yaml
# port49d.yaml
key_secret_refs:              # optional; these are the defaults
  env_prefix: PORT49_KEY_     # an env: key must be a variable starting with this
  file_dir: /run/port49/keys  # a file: key, and every link to it, must stay inside this directory
```

It is a top-level key, not under `policy:`, because a port49d on the memory store names its policy as `broker.policy_file`; it is read only when port49d has a policy.

- **A policy reference outside the allowance is refused** at start and at reload, naming the key, the version, the reference and the allowance: "keys.prod_key version 3 secret_ref env:PORT49_ENC_V2 is outside key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys)". It names no value: nothing is read. It is a policy fault, so it is not retried.
- **port49d.yaml's own secrets and key material may not sit inside the allowance** (re-review N1): an `encryption` or `broker.directory.bind` reference that matches `env_prefix` or lies under `file_dir`, any key file or keytab port49d.yaml names (`tls_listener.key_file`, `broker.tls_key_file`, `inventory_service.tls_key_file`, the bind's `tls_key_file` and `keytab_file`, each etcd identity's `key_file`), and the in-process broker's state directory (which holds `issuing-ca.key`) overlapping `file_dir` either way, is refused at load, since a policy could then name it. Paths are compared as written and again with links resolved, the way `fence.ReadSecret` resolves them, so a link either way hides no overlap.
- **`env_prefix`** is at least 4 characters of an environment variable name and ends in `_` (a prefix of PORT49_KEY would admit PORT49_KEYTAB_PASS); **`file_dir`** is absolute and clean. Both have defaults, so a fleet that follows them writes nothing.
- **`port49 policy test`** checks references against the defaults, or against `--config`'s `key_secret_refs` when given, so CI refuses what port49d would.
- **port49-broker** resolves no secret and holds no allowance: it reads key names alone.


### The key sets move into the policy file (decision 53 ruling 3)

Spec §10 put the key sets in port49d.yaml "rather than in the policy file, which CI and every operator can read… Moving key sets into the policy repository waits on secret references that name no secret (`secret_ref:`, plan 12)". With `secret_ref`, the policy file carries the key sets beside the `key_groups` that assign them:

```yaml
# policy.yaml
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: prod_key}
keys:
  prod_key:
    current: {version: 3, secret_ref: file:/run/port49/keys/prod_v3}
    accept:
      - {version: 2, secret_ref: file:/run/port49/keys/prod_v2, retire_after: 2026-12-01}
```

- **Rotation is policy edits.** Adding a version, setting `retire_after` and retiring a version are reviewed changes of the policy repository. Each is live at the next reload, with no restart. So `port49_key_version_devices` no longer resets at each rotation step: spec §10's "each step of a rotation restarts port49d" is removed.
- **port49d and port49-broker refuse a policy with no `keys:` block.** Write `keys: {}` for a fleet that is all TLS. The block is the one place port49 learns key names. Without it, every device a group assigns would be admitted with no key and every packet would miss, which is the misconfiguration `key_refs`/`Env.KeyRefs` caught before. A bare `keys:` (null) is refused in its own words: "keys: is empty; write `keys: {}` for a fleet all on TLS".
- **The key notices follow the policy** (spec §10, pre-flight I8): port49d says `keyset.Notices` (a version whose `retire_after` has passed, an `accept` version with none) at start and after every swap, and each swap that changes the key sets says one line naming the versions added, retired and removed, and that connections on a retired or removed version reset at their next packet.
- **A re-keyed version is caught in review too** (pre-flight M9): `port49 policy diff` fails a change that names another `secret_ref` for a version both files hold, since across a restart port49d has nothing to compare against.
- **A policy with `keys:` refuses a TCP device assigned a `key_ref` the block does not define**, as `Env.KeyRefs` did (`admission.RefusedUnknownKey`). An offline tool given a policy with no `keys:` resolves every device as before, so the policy test corpus without the block is unchanged.
- **port49-broker.yaml's `key_refs` is removed**: the broker reads the names from the policy and never resolves a secret.
- **port49d.yaml's `keys:` is refused beside a policy**, `keys: {}` included. It stays only for a port49d with no policy (plan 1's mode, the lab's harness), where the inventory's own key groups assign keys and there is no policy file to hold them. `port49 keys status` and `keys show` read the policy's key sets, so a port49d with no policy has neither: its versions are in port49d.yaml and its start lines.
- **The inventory service now judges admission with the policy's key names** (it loaded with `Env{}` before). A bundle it publishes is judged as port49d will judge it.

### Open connections across a key reload (decision 53 ruling 4; Task 7)

Spec §10 already ends a connection at the first packet past its version's `retire_after`: "holding a connection open never extends a key's life". A reload that retires or removes the version an open connection validated under ends it too, but as spec §10 ends every connection a reload takes away ("How a daemon refreshes its snapshot"): with no strike, since the change is port49d's and not the device's.
- One `unvalidated` record with diagnosis `matches_retired`, and a reset at the next packet. No strike and no decline window: the device is still admitted, so its next connection is served, and a device already re-provisioned with the new version is served at once.
- A version whose `retire_after` has passed is still struck, as spec §10 says; only a reload's withdrawal is not.
- The connection re-reads its key set at every packet after the first.

A reload that only adds a version changes nothing for open connections.

### The global connection cap (decision 53 ruling 8; Task 11)

- **`limits.max_connections`** is one slot pool across both TACACS+ listeners. Only accepted connections hold a slot: a listener waiting in `Accept` holds none, so the cap is N with two listeners, and `InUse()` is 0 when nothing is connected.
- **It sheds** (design §11: "Accept-queue pressure sheds load rather than queueing it. A request answered after the device has already given up is worse than a refused connection"). The slot is taken after `Accept` and after the per-source checks (`refused_cap`, `held_refused`, `declined_refused`), so the per-source limits bind first. When no slot is free the connection is reset at once, with no record, and the device takes its next server or method at the reset (L28: a reset is acted on at once, a FIN is not). Decision 32's backlog wait is the broker HTTPS listener's, where an agent retries, and stays.
- **The default is the process's open-file limit less 1024**, or half the limit where that is less. Go raises the soft limit to the hard one at start.
- **An explicit value must leave at least 256 descriptors** for the spool, the store, the decision log and the admin socket, or the start is refused.
- **What the operator sees:**
  - `port49_connections_max`;
  - `port49_connections_shed_total{reason="global_cap"}` for each connection shed, counted at the moment it is shed;
  - when shedding begins (the first shed after a minute with none), at once: "port49d: shedding: all N TACACS+ connection slots (limits.max_connections) are in use; each new connection is reset at Accept and the device tries its next server";
  - while it lasts, at most once a minute: "port49d: still shedding: M connections reset at Accept in the last minute; N of N slots in use".

  Both lines are spec §12's, written by Task 1.

  12c writes the alarm: open over max, sustained.
- **EMFILE stays counted as `accept_error`.** With the default it should no longer happen.

### The etcd version floor (decision 53 ruling 9; Task 12)

- **The check.** At a server start (port49d, port49-broker, and the broker's late directory open), after the store answers and the roles check passes, each configured endpoint is asked `Status` at once, each bounded by `call_timeout`. The offline paths (`offlineBroker`, behind `port49-broker`'s offline revoke, and `forget-issuer`) skip it: an emergency revoke against an old cluster must still run. A member below 3.4.24 (on 3.4), 3.5.8 (on 3.5) or 3.6 is a store fault, named with the endpoint, its version and the floor. At a start it refuses the start. At the late directory open (`openDirectoryLater`), where the process already serves from the marks it holds, `attempt`'s fault is said ("not followed yet") and retried every 5 s, as any store fault there is, so the directory is never followed below the floor (re-review N9).
- **An endpoint that does not answer** is said ("its version is unchecked until the next start"). The start does not wait for it: a dark member must not become a cold-start outage, the reason `RejectOldCluster` is off.

### The issuing CA record (decision 53 ruling 10; Task 14)

- **The record.** `meta/issuer` in the directory store (the one store when `stores` is shared) holds `{"current": "sha256:…", "previous": "sha256:…", "written_by": "...", "written_at": "..."}`: fingerprints only.
- **Who checks.** A port49-broker with `broker.identity.issuance` and a usable CA checks it when the directory store first answers: at start, or when the directory opens later (`openDirectoryLater`'s check, which already ends the run on a fault).

| The broker holds | The record | Result |
|---|---|---|
| any CA | none | records `{current, previous}` (create only); a lost race reads again and judges |
| current = record's current | | starts |
| previous = record's current, current is new | | a promotion (`rotate-issuer` ran here): rewrites the record at its revision, then starts |
| current = record's previous | | **refused**: "behind a promotion; copy issuing-ca.pem, issuing-ca.key and issuing-ca-previous.pem from the broker that promoted it" |
| anything else | | **refused**: "this broker's issuing CA (sha256:…) is not the one the store records (sha256:…, recorded by … at …); copy both files from a broker that holds it. If every broker lost it, `port49-broker forget-issuer` once, then `init-issuer` on one broker" |

- **No store in-process.** On the memory store there is one broker in-process, and no record. Decision 43's R4 ("never refuses the start: port49d answers device AAA in the same process") is about that in-process broker. port49-broker on etcd serves no device, so refusing it is safe.
- **Not checked:** a broker with no issuance, or a CA its files make unusable (issuance is already off there, and the start says why).
- **`port49-broker forget-issuer`** deletes the record and says which fingerprint it removed. The next broker start records its own.

### The write fence's ancestors (decision 53 ruling 11; Task 15)

Today the fence holds four things to its rule (owned by port49's user or root, not group- or other-writable): the file, its directory, the directory holding each link, and every link. It says "Directories above those are not walked".

- **The walk.** `resolvePolicyPath` now checks every directory it passes through.
- **Two excuses for an ancestor that others can write:**
  - its filesystem is read-only, as a link's directory already is;
  - its sticky bit is set (`/tmp`): others cannot rename what is below it, and the next component is checked in turn.
- **POSIX ACLs need nothing new**, which a test proves: a named entry that grants write is effective only through the ACL mask, and the mask is the group bits the mode check already refuses. NFSv4 ACLs are not read: 12b's install notes say not to keep the policy on NFS.

### The broker start survives a compaction (Task 13)

The marks and logouts loads read 500 records a page at one revision. A compaction between pages returns `store.ErrCompacted`, and today the start exits. Both loads now retry it, as the ledger load does: three loads, one `pagedLoad` helper. In the same pass:
- a followed logout whose reach keeps failing says its long remedy once per run of failures, not every retry;
- its entry in the failure count is dropped once the logout lapses.

## Review Focus

1. **A secret reaching output.** A secret file's content, a proxy URL with a password, a `%+v` of a config or resolver, a ref that is really a pasted secret, or a test failure message. Pinned by Task 3's `TestNoResolveErrorCarriesTheSecret` and `TestAnUnparsedRefIsNeverPrinted`, and Task 10's `TestABadProxyIsNeverPrinted` and `TestAMisreadProxyIsRefusedByTheTransport`.
2. **A policy naming a secret it should not reach** (pre-flight I5). The encryption key's variable, the bind password's, or a file outside `file_dir` (directly or through a link) must be refused before anything is read. Pinned by Task 6's `TestAPolicyKeyOutsideTheAllowanceIsRefused`, `TestAPolicyKeyLinkingOutOfTheDirectoryIsRefused` and `TestAConfigSecretInsideTheAllowanceIsRefused` (key files, keytab and state directory too, compared with links resolved), and Task 3's `TestALinkOutOfTheDirectoryIsRefused`.
3. **A trailing newline making a different key.** A `file:` secret written with `echo` must validate the same packets as the variable it replaced. Pinned by Task 3's `TestAFileSecretDropsOneTrailingNewline`, and by Task 4's `TestSecretsLoadFromFiles`, which takes a `file:` key written with a newline through to the keyring.
4. **A reload while the secret store is down, or that re-keys a version.** The keys in force must keep serving every open and new connection, the refusal must name the reference, and the policy must load by itself once the file appears. Pinned by Task 6's `TestAReloadWhoseSecretCannotBeReadKeepsTheKeysInForce`, `TestAReloadWaitingOnASecretLoadsOnceTheFileAppears` and `TestAReloadThatRekeysAVersionIsRefused`.
5. **A slot that is never released, or a cap that engages silently.** A shed that forgets the per-source slot, or a served connection that forgets the global one, shrinks a cap for good. A cap reached with no counter and no line is indistinguishable from a bug (design §11). Pinned by Task 11's `TestTheGlobalCapShedsAndSaysSo`, `TestIdleListenersHoldNoSlot` and `TestEveryRefusalAtAcceptReleasesItsSlots`.
6. **A legitimate rotation refused by the issuer check, or a check that is not wired.** A broker restarted after `rotate-issuer` promoted on it must start and update the record, and one restarted before its files were copied must be refused with the copy instruction; each of the three call sites must run it. Pinned by Task 14's `TestTheIssuerRecordFollowsARotation` and `TestASecondBrokerOnAnotherCAIsRefused`.
7. **A device struck for port49d's own reload.** Pinned by Task 7's `TestAReloadThatRetiresTheVersionEndsItsConnectionWithoutAStrike`.

---

## File structure

**Created**
- `internal/secretref/secretref.go`: `Ref`, `Parse`, `Resolver`, `New`, `Resolve`, `Secret`, `Allowance`.
- `internal/secretref/*_test.go`.
- `internal/keyset/keyset.go`: `Set`, `Version`, `Check`, `Notices`, `Sorted`, `Keyring`.
- `internal/keyset/keyset_test.go`.
- `internal/egress/egress.go`: `ProxyFor`, `Proxy`, `Describe`, `ErrBadProxy` (moved from `internal/oidc/keyset.go`).
- `internal/egress/egress_test.go`.
- `internal/port49d/livekeys.go`: `liveKeys`, `keyBuild`, `keyUnreadError`.
- `internal/port49d/keyretry.go`: `keyWait`, `keyRetryInterval`, `(*reloader).retryKeys`.
- `internal/port49d/livekeys_test.go`.
- `internal/port49d/fdlimit.go`: `openFileLimit`, `connectionCap`.
- `internal/port49d/connectioncap_test.go`.
- `internal/port49d/floor.go`: `checkFloor`.
- `internal/port49d/floor_test.go`.
- `internal/port49d/issuerrecord.go`: `checkIssuerRecord`, `heldIssuer`, `forgetIssuer`.
- `internal/port49d/issuerrecord_test.go`.
- `internal/daemon/server/slots.go`: `Slots`, the shed line's rate limit.
- `internal/daemon/server/slots_test.go`.
- `internal/store/etcd/version.go`: `VersionFloor`, `BelowFloor`, `EndpointVersion`, `EndpointVersions`.
- `internal/store/etcd/version_test.go`.
- `internal/store/etcd/issuer.go`: `IssuerRecord`, `IssuerRecord()`, `PutIssuerRecord`, `DeleteIssuerRecord`.
- `internal/store/etcd/issuer_test.go`.

**Modified**
- `docs/design/2026-08-23-policy-engine-spec.md` (§10, §12, §13 decisions 31, 43, 53).
- `docs/design/2026-08-21-port49-design.md` (§11, §13).
- `internal/yamlfault/yamlfault.go`; `internal/config/config.go`, `stores.go`, `directory.go`; `internal/admission/admission.go`; `internal/platform/redact.go`; `internal/devicemock/profile.go`; `tests/lab/cmd/lab-regress/manifest.go`.
- `internal/directory/config.go`, `conn.go`.
- `internal/policy/file.go`, `load.go`, `admit.go`; `internal/bundle/diff.go`; `internal/inventory/config.go`, `sync.go`, `webhook.go`; `internal/sot/client.go`.
- `internal/oidc/keyset.go`.
- `internal/testpki/compose.go` (the compose key variable's name).
- `internal/daemon/server/server.go`, `conn.go`; `internal/daemon/admin/admin.go`; `internal/daemon/limits/limits.go`; `internal/daemon/metrics/metrics.go`.
- `internal/issuer/issuer.go` (`CA.Previous`).
- `internal/port49d/main.go`, `reload.go`, `directory.go`, `identity.go`, `brokerd.go`, `runner.go`, `store.go`, `issuer.go`.
- `internal/fence/fence_linux.go` (`ReadSecret`, the ancestor walk), `fence_other.go` (`ReadSecret`'s stub).
- `cmd/port49/keys.go`, `policy.go` (`policyTest`, `policyDiff`), `inventory.go`; `cmd/port49-inventory/main.go`.
- Fixtures: `deploy/compose/config/*.yaml`, `examples/kubernetes/examples_test.go`, `tests/lab/port49d-lab.yaml`, `tests/qual/qual-policy.yaml`, and the Go tests and lab tests that write configurations (Tasks 4, 6, 9 list how to find each).
- `docs/superpowers/plans/README.md`.

---

### Task 1: Spec and design — decision 53, §10's key sets, §12's key commands and shedding lines, decisions 43 and 51, design §11 and §13

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

**Interfaces:**
- Produces: decision 53 rulings 1–12, cited by every later task's comments and commit messages; the §12 lines Task 11 says.

- [ ] **Step 1: Find every passage this plan changes.**

Run:
```bash
S=docs/design/2026-08-23-policy-engine-spec.md
grep -n 'secret_env\|token_secret_env\|webhook_secret_env\|password_env\|key_refs\|secret_ref' $S
grep -n "Keys are read only at start\|port49d.yaml's repository\|cross-replica check is carried\|waits on secret references" $S
grep -n 'policy test --config\|keys status --policy\|keys show --policy\|reads that$\|composition(s) answered fail-closed' $S
grep -n 'Listener limits\|Accept-queue pressure\|Run etcd 3.5.8' docs/design/2026-08-21-port49-design.md
```
Expected:
- the §10 key-set paragraph (`The key sets, \`retire_after\` included, live in port49d.yaml`), and the "Retirement is enforced" bullets with S:5163's "`port49 policy test --config` reports";
- the §10 inventory example (`token_secret_env`, `webhook_secret_env`, `webhook_listen` comment), and the webhook paragraph near "only for a source configured with `webhook_secret_env`";
- the "Version sets" example's two `secret_ref: vault:` lines;
- §12's `keys status` (~S:6421), `keys show` (~S:6432), `inventory diff`'s `--config` (~S:6676) and `policy test --config` (~S:6707) paragraphs, and the fail-closed composition report (`composition(s) answered fail-closed`);
- decision 31's "webhook secret named by `secret_env`-style keys";
- decision 43 ruling 14's "a cross-replica check is carried to plan 12";
- decision 51's port49-broker.yaml bullet (~S:7783: "an inventory, `key_refs:` (the names a policy may assign, no secrets)" and "it refuses `listen`, `keys:`");
- S:9871's "no `--password` flag and no `password_env`", which is about sign-in passwords and stays;
- design §11's per-NAS bullet and its "Accept-queue pressure sheds load" bullet, and §13's etcd line.

- [ ] **Step 2: Write decision 53** after decision 52, in the decisions' voice:

```markdown
**53. Server hardening for deployment: secret references, key sets in the policy, and the start
checks (plan 12a; Ryan and the team lead, 2026-10-24 and 2026-10-25).**

- **1. `secret_ref`.** A secret is named, never written: `env:NAME` (an environment variable) or
  `file:/absolute/path`, one trailing newline dropped. A file is read through the write fence
  (`fence.ReadSecret`): a link is followed only while it resolves inside one directory (the
  reference's own, or ruling 12's `file_dir`), every link's directory and ancestor is held to the
  fence's rule, and the file is owned by port49's user or root, writable by its owner alone, with
  no world bit; group-read is allowed, which Kubernetes Secret volumes and agents' `perms` give. A
  reference that does not parse is refused by its key and never printed. It replaces, outright,
  `secret_env` (`keys:`, `encryption:`), `broker.directory.bind.password_env` (now
  `password_secret_ref`), and port49-inventory.yaml's `token_secret_env` and `webhook_secret_env`
  (now `token_secret_ref`, `webhook_secret_ref`). A file that still names a removed key is refused
  naming its replacement, as `receipt_ttl` is: a refusal, not an alias.
- **2. When.** Configuration secrets are read at load, the bind password when the directory opens;
  the policy's key secrets at start and before every swap. Each reference is read once per process
  and kept by its text: a version's secret never changes, so a reload reads only versions it has
  not seen, and one naming another reference for a version in force is refused ("add a version").
  A failure at start refuses the start; at a reload it refuses the reload, and the bundle and keys
  in force keep serving. A reload refused because a secret could not be read is tried again at
  every reload trigger and every 30 s (half kubelet's default Secret sync), until it loads or the
  policy changes, said once and then at most every 10 minutes: an agent that renders the file a
  minute after the merge needs no SIGHUP on any replica.
- **3. `keys:` is the policy file's.** The key sets move beside `key_groups`; adding, retiring and
  extending a version are reviewed policy edits, live at the next reload. port49d and
  port49-broker refuse a policy with no `keys:` block (`keys: {}` for a fleet all on TLS; a bare
  `keys:` is refused as empty); a policy with one refuses a TCP device assigned a `key_ref` it does
  not define. port49-broker.yaml's `key_refs` is removed. port49d.yaml's `keys:` remains only for a
  port49d with no policy, and is refused beside one, `keys: {}` included: with no policy there is
  no policy file to hold the block (plan 1's mode, and the lab harness's, where the inventory's key
  groups assign the keys), and beside one two blocks would each claim to be in force. port49d says
  the key notices of §10 at start and after every swap, and each swap that changes the key sets
  says which versions it added, retired and removed. `port49 policy diff` fails a change that
  re-keys a version.
- **4. Open connections.** A reload that retires or removes the version an open connection
  validated under ends it at its next packet: one `unvalidated` record (`matches_retired`) and a
  reset, with no strike and no decline window, since the change is port49d's and not the device's
  (§10, "How a daemon refreshes its snapshot"). A version whose `retire_after` passes is still
  struck, as §10 says.
- **5. No secret-store client.** `env:` and `file:` are the only schemes (Ryan, 2026-10-25). A
  secret store reaches port49 as a file rendered by the store's own tooling (Vault Agent, External
  Secrets, the Secrets Store CSI driver, systemd credentials), which already authenticates, renews
  and caches: port49 does not reimplement a secret-store client. The rendered file keeps the last
  secret through a store outage, so a restart does not depend on the store answering.
- **6. One document.** Every file port49 reads as one YAML document refuses a second, in fixed text.
- **7. Egress.** The source-of-truth client honours `HTTPS_PROXY` and `NO_PROXY`, as the OIDC key
  fetch does; a value the transport would misread is refused, never dialled; and port49-inventory's
  start says how each source is reached.
- **8. The global connection cap sheds.** `limits.max_connections` is one pool across both TACACS+
  listeners, held by accepted connections only. It is taken after Accept and after the per-source
  checks, so those bind first (design §11); with no slot free the connection is reset at once and
  the device takes its next server, since "accept-queue pressure sheds load rather than queueing
  it" (design §11). Each shed counts in `port49_connections_shed_total{reason="global_cap"}`, and
  §12's shedding lines are said when shedding begins and then at most once a minute. Default: the
  open-file limit less 1024, or half of it where that is less; an explicit value must leave 256.
  `port49_connections_max`. Decision 32's backlog wait is the broker listener's and stays.
- **9. The etcd floor.** At each server start, after the roles check, every configured endpoint is
  asked its version at once, each within `call_timeout`. A member below 3.4.24, 3.5.8 or 3.6
  refuses the start; one that does not answer is said and left unchecked until the next start. At
  the broker's late directory open, where the process already serves from the marks it holds, a
  member below the floor is said and the open is tried again every 5 s, as any store fault there
  is. The offline paths (the offline revoke, `forget-issuer`) do not check it.
- **10. One issuing CA per store.** `meta/issuer`, in the directory store, records the current and
  previous CA fingerprints. A port49-broker with issuance records them when none is there, follows
  a promotion its own files show, and otherwise refuses to start when its current CA is not the
  recorded one. The CA key stays on each broker's own disk or state volume: never in the store,
  never a read-only Secret (Ryan, 2026-10-24). `port49-broker forget-issuer` removes the record.
  The check runs only for port49-broker on etcd. On the memory store the one broker runs inside
  port49d, so there is no second broker to disagree with and no store to hold a record; and
  decision 43's R4 (an issuance fault never refuses port49d's start, since port49d answers device
  AAA in the same process) still governs it. port49-broker on etcd serves no device, so refusing
  its start costs no AAA.
- **11. The fence walks every ancestor.** Each directory above the file is held to the fence's rule;
  one others can write passes only with its sticky bit set or on a read-only mount. POSIX ACLs are
  covered by the mode's group bits (the ACL mask); NFSv4 ACLs are not read.
- **12. port49d.yaml bounds what a policy may name (security).** A policy writer must not choose
  which of the host's secrets becomes a TACACS+ key: put in force for a device the writer
  controls, the encryption key, the bind password, the TLS key or the keytab would answer
  "validated or not" to guesses. `key_secret_refs` declares the allowance, with defaults
  `env_prefix: PORT49_KEY_` and `file_dir: /run/port49/keys`. A policy reference outside it is
  refused at start and at reload, naming the reference and the allowance, before anything is read,
  and is not retried. A port49d.yaml secret, key file or keytab inside the allowance, or a broker
  state directory overlapping `file_dir`, is refused at load, compared with links resolved.
  `port49 policy test` checks the same allowance.
```

- [ ] **Step 3: Rewrite §10's key-set paragraph.** Replace the paragraph that begins "The key sets, `retire_after` included, live in port49d.yaml" with:

```markdown
The key sets, `retire_after` included, live in the policy file's `keys:` block beside the
`key_groups` that assign them, each version naming its secret by `secret_ref` (decision 53). The
file is read by CI and every operator, and holds no secret: a reference names where port49d reads
it, inside the allowance port49d.yaml declares (`key_secret_refs`, decision 53 ruling 12).
Retirement and extension are therefore reviewed changes of the policy repository, in force at the
next reload. port49d.yaml carries `keys:` only when port49d runs with no policy.
```

In "Retirement is enforced":
- replace "Keys are read only at start, so each step of a rotation restarts port49d, and every restart resets the count to 0 until devices reconnect." with "Keys reload with the policy, so a rotation's steps no longer restart port49d; a restart still resets the count to 0 until devices reconnect.";
- replace "Retirement and extension are both reviewed changes, of port49d.yaml's repository (above)" with "Retirement and extension are both reviewed changes of the policy repository (above)";
- replace "port49d says at start, and `port49 policy test --config` reports," with "port49d says at start and after every reload, and `port49 policy test` reports,";
- after "The device sees the same reset a reload's withdrawal sends (below, …)" sentence, add: "A reload that retires or removes the version an open connection speaks resets it at its next packet with no strike, as every reload's withdrawal does (decision 53 ruling 4); only the date strikes."

The version-set example writes `secret_ref: vault:port49/prod/v3` and `vault:port49/prod/v2`; replace them with `file:/run/port49/keys/prod_v3` and `file:/run/port49/keys/prod_v2`, and add after the example: "A secret store such as Vault reaches port49 as a file its agent renders (Vault Agent, External Secrets, the Secrets Store CSI driver); port49 reads no store directly (decision 53 ruling 5)."

- [ ] **Step 4: The inventory example and the webhook text.** In the §10 port49-inventory.yaml example replace:

```yaml
    token_secret_env: PORT49_NETBOX_TOKEN         # read at start, never printed; secret_ref waits for plan 12
    webhook_secret_env: PORT49_NETBOX_WEBHOOK     # optional: turns the source's webhooks on
```
with
```yaml
    token_secret_ref: env:PORT49_NETBOX_TOKEN     # read at start, never printed (decision 53)
    webhook_secret_ref: env:PORT49_NETBOX_WEBHOOK # optional: turns the source's webhooks on
```
and the `webhook_listen` comment's `webhook_secret_env` with `webhook_secret_ref`. In the webhook paragraph ("only for a source configured with `webhook_secret_env`") and decision 31 ("webhook secret named by `secret_env`-style keys until plan 12's `secret_ref`") write `webhook_secret_ref` / "named by `token_secret_ref` and `webhook_secret_ref` (decision 53)".

- [ ] **Step 5: Decisions 43 and 51.**
  - Decision 43 ruling 14: replace "Each start prints the CA's fingerprint; a cross-replica check is carried to plan 12." with "Each start prints the CA's fingerprint, and a port49-broker on etcd checks it against the store's record (decision 53 ruling 10)."
  - Decision 51's port49-broker.yaml bullet (~S:7783): replace "an inventory, `key_refs:` (the names a policy may assign, no secrets) and `admin_socket`" with "an inventory and `admin_socket`, and takes the key names a policy may assign from the policy's own `keys:` block (decision 53 ruling 3)". Its list of refused keys keeps `keys:`.

- [ ] **Step 6: §12's key commands.**
  - **`keys status`** (~S:6421): the synopsis drops `--config <port49d.yaml>`; replace "It reads no secret: `--config` gives the key names, versions and dates." with "It reads no secret: the policy's `keys:` block gives the key names, versions and dates (decision 53 ruling 3); a port49d with no policy has no `keys status`."
  - **`keys show`** (~S:6432): the synopsis drops `[--config <port49d.yaml>]`; replace "and, with `--config`, which version to provision" with "and, from the policy's `keys:` block, which version to provision".
  - **`inventory diff`** (~S:6676): replace "`--config <port49d.yaml>` reads that bound and the `key_ref`s the file defines instead, no secret read, so a device assigned an undefined key is refused as port49d refuses it." with "`--config <port49d.yaml>` reads that bound instead. A device assigned a `key_ref` the policy's `keys:` block does not define is refused as port49d refuses it." Replace "Without `--config`, a bundle with no key groups admits only pinned devices, as port49d reads it, and every verdict says the `key_ref`s went unchecked against port49d.yaml." with "A bundle with no key groups admits only pinned devices, as port49d reads it."
  - **`policy test`** (~S:6707): replace the paragraph's head "**`port49 policy test --config <port49d.yaml>`** adds the key checks §10 requires of CI: it fails on a key group naming a `key_ref` the file does not define, and on a device assigned one." with "**`port49 policy test`** makes the key checks §10 requires of CI from the policy's own `keys:` block: it fails on a policy with no `keys:` block, which port49d and port49-broker refuse (decision 53 ruling 3), on a key group naming a `key_ref` the block does not define, on a device assigned one, and on a reference outside `key_secret_refs` (the defaults, or `--config <port49d.yaml>`'s; decision 53 ruling 12)." Replace "Without `--config` it still fails on every device admission refuses" with "It also fails on every device admission refuses".
  - **`policy diff`**: after "which counts the two together (§10)." add "It fails on a version both files hold whose `secret_ref` differs: a version's secret never changes, so add a version (decision 53 ruling 3)."
  - **The shedding lines.** After the fail-closed composition report paragraph (`grep -n 'composition(s) answered fail-closed' $S`), add:

```markdown
**Connection shedding.** At `limits.max_connections` port49d resets each new TACACS+ connection at
Accept (decision 53 ruling 8) and counts it in `port49_connections_shed_total{reason="global_cap"}`.
It says, when shedding begins (the first shed after a minute with none): `port49d: shedding: all N
TACACS+ connection slots (limits.max_connections) are in use; each new connection is reset at
Accept and the device tries its next server`, and while it lasts, at most once a minute:
`port49d: still shedding: M connections reset at Accept in the last minute; N of N slots in use`.
```

- [ ] **Step 7: Design §11 and §13.** In design §11 "Listener limits", after the per-NAS bullet, add:

```markdown
- **A global cap** (`limits.max_connections`) bounds the connections both listeners hold together,
  sized from the open-file limit so the spool and the store keep descriptors. Only accepted
  connections hold a slot. It is taken after Accept and after the per-source checks, which bind
  first; at the cap a connection is reset at once and counted, and the device takes its next
  server, as the "Accept-queue pressure sheds load" bullet requires (policy engine spec §13
  decision 53 ruling 8).
```

In §13, after "**Run etcd 3.5.8 or later** (3.4.24 on 3.4).", add "port49d and port49-broker refuse to start against a member below it (policy engine spec §13 decision 53 ruling 9)."

- [ ] **Step 8: Check the edits**

Run:
```bash
S=docs/design/2026-08-23-policy-engine-spec.md
grep -n '^\*\*53\.' $S; grep -n 'secret_env\|password_env\|key_refs' $S; grep -n 'secret_ref: vault:' $S
grep -n 'policy test --config\|keys status --policy.*--config\|went unchecked against' $S; grep -c 'decision 53' $S
grep -c 'global cap' docs/design/2026-08-21-port49-design.md; grep -n 'shedding' $S
```
Expected:
- one line for decision 53;
- `secret_env`, `password_env` and `key_refs` only inside decision 53's ruling 1 and 3, which name what they replace, and S:9871's `password_env` (sign-in passwords, unrelated);
- no `secret_ref: vault:` line, and no line from the third grep;
- at least `8`; at least `2`; the two shedding lines.

- [ ] **Step 9: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 53, server hardening for deployment (plan 12a)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: One YAML document per file

**Files:**
- Modify: `internal/yamlfault/yamlfault.go`, `internal/yamlfault/yamlfault_test.go`
- Modify: `internal/config/config.go` (`load` :829, `MaxSessionAge` :700, `InventoryBound` :718, `RevocationsFile` :745, `KeySets` :1659, `InventoryServiceOf` :2004), `internal/config/stores.go` (`StoresBlocks` :220), `internal/config/config_test.go`
- Modify: `internal/admission/admission.go` (`ParseFile` :463), `internal/admission/admission_test.go`
- Modify: `internal/platform/redact.go` (`LoadRedactions` :86), its test file
- Modify: `internal/devicemock/profile.go` (`Load` :278), its test file
- Modify: `tests/lab/cmd/lab-regress/manifest.go` (:54), `manifest_test.go`

**Interfaces:**
- Produces: `var yamlfault.ErrSecondDocument error`; `func yamlfault.OneDocument(dec *yaml.Decoder) error`; `func config.decodeFile(raw []byte, f *fileConfig) error` (unexported).

- [ ] **Step 1: Write the failing tests.**

`internal/yamlfault/yamlfault_test.go`:
```go
// OneDocument refuses anything after the first document, and quotes none of
// it: a second document that does not even parse is still refused as one.
func TestOneDocumentRefusesASecondDocument(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want error
	}{
		{"a: 1\n", nil},
		{"", nil},
		{"a: 1\n---\nb: 2\n", ErrSecondDocument},
		{"a: 1\n---\n[unclosed\n", ErrSecondDocument},
	} {
		dec := yaml.NewDecoder(strings.NewReader(c.raw))
		var v map[string]any
		if err := dec.Decode(&v); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("%q: the first document: %v", c.raw, err)
		}
		err := OneDocument(dec)
		if !errors.Is(err, c.want) || (err != nil && strings.Contains(err.Error(), "unclosed")) {
			t.Errorf("%q: %v, want %v", c.raw, err, c.want)
		}
	}
}
```

`internal/config/config_test.go`:
```go
// A second YAML document in port49d.yaml is refused, not ignored, by Load and
// by every reader of the file's bytes (plan 6b final review Minor 7;
// decision 53 ruling 6). The refusal quotes nothing after the separator.
func TestASecondYAMLDocumentIsRefused(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	raw := fmt.Sprintf(sample, invPath) + "---\nlimits: {per_nas_connections: 9999}\n"
	p := write(t, "port49d.yaml", raw)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "more than one YAML document") ||
		strings.Contains(err.Error(), "9999") {
		t.Fatalf("Load: %v", err)
	}
	for name, read := range map[string]func([]byte) error{
		"MaxSessionAge":      func(b []byte) error { _, err := MaxSessionAge(b); return err },
		"InventoryBound":     func(b []byte) error { _, err := InventoryBound(b); return err },
		"RevocationsFile":    func(b []byte) error { _, err := RevocationsFile(b); return err },
		"KeySets":            func(b []byte) error { _, err := KeySets(b); return err },
		"InventoryServiceOf": func(b []byte) error { _, err := InventoryServiceOf(b); return err },
		"StoresBlocks":       func(b []byte) error { _, err := StoresBlocks(b); return err },
	} {
		if err := read([]byte(raw)); err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
```

`internal/admission/admission_test.go`:
```go
// The inventory is one document: a device list after `---` is refused,
// never silently dropped from admission.
func TestASecondInventoryDocumentIsRefused(t *testing.T) {
	raw := "devices:\n  - {name: a, platform: arista_eos, addresses: [10.0.0.1]}\n---\ndevices:\n" +
		"  - {name: b, platform: arista_eos, addresses: [10.0.0.2]}\n"
	if _, err := ParseFile([]byte(raw), "inv.yaml"); err == nil ||
		!strings.Contains(err.Error(), "more than one YAML document") {
		t.Fatalf("%v", err)
	}
}
```

Add the same shape of test for `platform.LoadRedactions` (`"default: [{pattern: x}]\n---\nother: []\n"`; read the field names from `internal/platform/redact.go`'s `Redaction` type first), for `devicemock.Load` (append `---\n` and a copy of the first document to a fixture profile under `internal/devicemock/testdata/`, written to `t.TempDir()`), and for `loadManifestFile` (append `---\nentries: []\n` to a manifest written to `t.TempDir()`).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/yamlfault/ ./internal/config/ ./internal/admission/ ./internal/platform/ ./internal/devicemock/ -run 'Second|OneDocument' -count=1 && go test -tags lab ./tests/lab/cmd/lab-regress/ -run Second -count=1`
Expected: FAIL: `undefined: OneDocument`, and each loader accepts the file.

- [ ] **Step 3: Implement.** In `internal/yamlfault/yamlfault.go` (add `io` to the imports):

```go
// ErrSecondDocument is a file holding a YAML document after its first.
var ErrSecondDocument = errors.New("holds more than one YAML document")

// OneDocument refuses a document after the one dec has decoded: a single
// Decode ignores everything past a `---`, and an ignored block is a file that
// reads one way and runs another (decision 53 ruling 6). A second document
// that does not parse is still a second document. It quotes nothing.
func OneDocument(dec *yaml.Decoder) error {
	var next yaml.Node
	if err := dec.Decode(&next); errors.Is(err, io.EOF) {
		return nil
	}
	return ErrSecondDocument
}
```

In `internal/config/config.go`, add beside `decodeFault`:

```go
// decodeFile decodes raw, a port49d.yaml, into f as strictly as Load does:
// an unknown key is refused, and so is a second YAML document, which a single
// Decode would ignore (decision 53 ruling 6). Neither error quotes the file.
func decodeFile(raw []byte, f *fileConfig) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(f); err != nil && err != io.EOF {
		return fmt.Errorf("%w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	if err := yamlfault.OneDocument(dec); err != nil {
		return fmt.Errorf("%w; port49d.yaml is one document: remove the `---` and everything after it", err)
	}
	return nil
}
```

Replace each of the seven decode blocks with it, keeping each caller's prefix:
- `load`: `if err := decodeFile(raw, &f); err != nil { return Config{}, fmt.Errorf("config: %s: %w", path, err) }`
- `MaxSessionAge`, `InventoryBound`, `RevocationsFile`, `KeySets`, `InventoryServiceOf`, `StoresBlocks`: `if err := decodeFile(raw, &f); err != nil { return <zero>, fmt.Errorf("config: %w", err) }`

In `admission.ParseFile`, after the decode block:
```go
	if err := yamlfault.OneDocument(dec); err != nil {
		return Inventory{}, fmt.Errorf("admission: %s%w; the inventory is one document", at, err)
	}
```
In `platform.LoadRedactions`, after the decode: `if err := yamlfault.OneDocument(dec); err != nil { return nil, fmt.Errorf("the redaction table %w", err) }`. In `devicemock.Load`, after `dec.Decode(&p)`: `if err := yamlfault.OneDocument(dec); err != nil { return nil, fmt.Errorf("%s: %w; a profile is one document", path, err) }`. The profile's credential scan runs over `yaml.Unmarshal`'s first document only, so the refusal is what keeps a second document from carrying an unscanned credential. In `loadManifestFile`, after the decode: `if err := yamlfault.OneDocument(dec); err != nil { return m, fmt.Errorf("%s: %w", path, err) }`.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/yamlfault/ ./internal/config/ ./internal/admission/ ./internal/platform/ ./internal/devicemock/ -count=1 && go test -tags lab ./tests/lab/cmd/lab-regress/ -count=1`
Expected: PASS. The existing `TestLoadRefusesUnknownKeys` and every decode-error test keep their text: `decodeFile` keeps the old wording.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/yamlfault internal/config internal/admission internal/platform internal/devicemock tests/lab/cmd/lab-regress
git commit -m "fix: every single-document YAML loader refuses a second document

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 3: `internal/secretref` — the grammar, `env:` and `file:`, and the fence's secret read

**Files:**
- Create: `internal/secretref/secretref.go`, `internal/secretref/secretref_test.go`
- Modify: `internal/fence/fence_linux.go` (`ReadSecret`), `internal/fence/fence_other.go` (its stub), `internal/fence/fence_linux_test.go`

**Interfaces:**
- Produces:
  - `type Ref struct { Scheme, Name string }` and `func (r Ref) String() string`;
  - `const SchemeEnv = "env"; SchemeFile = "file"` (the only two: decision 53 ruling 5);
  - `func Parse(s string) (Ref, error)`: the error never contains `s`;
  - `type Secret struct{ p *[]byte }` with `Bytes() []byte`, printing `<redacted>` under every verb and in JSON;
  - `type Resolver struct` and `func New() *Resolver`;
  - `func (r *Resolver) Resolve(ref Ref, within string) (Secret, error)`: `within` is the directory a `file:` reference and its links must stay inside, `""` for the reference's own directory;
  - `func (r *Resolver) ResolveText(at, text string) (Ref, Secret, error)`: Parse then Resolve within the reference's own directory, every error prefixed by `at` (a key path such as `encryption.current.secret_ref`) and never quoting `text` unless it parsed;
  - `type Allowance struct { EnvPrefix string \`yaml:"env_prefix"\`; FileDir string \`yaml:"file_dir"\` }`, `var DefaultAllowance = Allowance{EnvPrefix: "PORT49_KEY_", FileDir: "/run/port49/keys"}`, `func (a Allowance) WithDefaults() Allowance`, `func (a Allowance) Check() error` and `func (a Allowance) Allows(ref Ref) bool` (decision 53 ruling 12; Task 6 uses them);
  - `func fence.ReadSecret(path, within string, max int64) ([]byte, error)`.

- [ ] **Step 1: Write the failing tests** in `internal/secretref/secretref_test.go`:

```go
package secretref

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Ref
	}{
		{"env:PORT49_PROD_V3", Ref{Scheme: SchemeEnv, Name: "PORT49_PROD_V3"}},
		{"file:/run/secrets/prod_v3", Ref{Scheme: SchemeFile, Name: "/run/secrets/prod_v3"}},
	} {
		got, err := Parse(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: %+v, %v", c.in, got, err)
		}
	}
	if got, _ := Parse("env:PORT49_PROD_V3"); got.String() != "env:PORT49_PROD_V3" {
		t.Errorf("String: %q", got.String())
	}
}

// A reference that does not parse is most likely the secret itself, pasted
// where its name goes: every refusal is the one fixed text, which quotes
// nothing of the input (decision 53 ruling 1).
func TestAnUnparsedRefIsNeverPrinted(t *testing.T) {
	for _, in := range []string{
		"hunter2-shared-key", "env:", "env:1BAD", "env:HAS SPACE", "file:relative/path", "file:/a/../b",
		"vault:port49/prod/v3", "ldap:x", "",
		"file:/ok\x00/nul",
	} {
		_, err := Parse(in)
		if err == nil || err.Error() != errShape.Error() {
			t.Errorf("%q: %v, want the fixed refusal", in, err)
		}
	}
}

// The spec writes a reference unquoted inside a flow mapping; yaml.v3 must
// read it whole.
func TestARefDecodesUnquotedInAFlowMapping(t *testing.T) {
	var v struct {
		Ref string `yaml:"secret_ref"`
	}
	if err := yaml.Unmarshal([]byte(`{version: 3, secret_ref: file:/run/secrets/prod_v3}`), &v); err != nil ||
		v.Ref != "file:/run/secrets/prod_v3" {
		t.Fatalf("%q, %v", v.Ref, err)
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("T_SECRETREF_ENV", "shared-key")
	r := New()
	_, s, err := r.ResolveText("keys.k.current.secret_ref", "env:T_SECRETREF_ENV")
	if err != nil || string(s.Bytes()) != "shared-key" {
		t.Fatalf("got %d bytes, want 10; %v", len(s.Bytes()), err)
	}
	if _, _, err := r.ResolveText("keys.k.current.secret_ref", "env:T_SECRETREF_UNSET"); err == nil ||
		!strings.Contains(err.Error(), "keys.k.current.secret_ref env:T_SECRETREF_UNSET") ||
		!strings.Contains(err.Error(), "not set") {
		t.Fatalf("an unset variable: %v", err)
	}
}

// echo writes a newline; a key with one validates no device's packet. One
// trailing newline is dropped, LF or CRLF, and nothing else is touched.
func TestAFileSecretDropsOneTrailingNewline(t *testing.T) {
	r := New()
	dir := t.TempDir()
	for body, want := range map[string]string{
		"shared-key\n": "shared-key", "shared-key\r\n": "shared-key", "shared-key": "shared-key",
		"shared-key\n\n": "shared-key\n", " spaced \n": " spaced ",
	} {
		p := filepath.Join(dir, fmt.Sprintf("s%d", len(body)))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, s, err := r.ResolveText("k", "file:"+p)
		if err != nil || string(s.Bytes()) != want {
			// lengths only: a failure message never prints a secret
			t.Errorf("a %d-byte body: got %d bytes, want %d; %v", len(body), len(s.Bytes()), len(want), err)
		}
	}
}

// A secret file is read through the fence: a mode the world can read is
// refused, naming the file and never its content; group-read is allowed,
// as fsGroup and an agent's perms give it (decision 53 ruling 1).
func TestAFileSecretTheWorldCanReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	r := New()
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o440: true, 0o644: false, 0o660: false,
		0o604: false} {
		p := filepath.Join(dir, fmt.Sprintf("s%o", mode))
		if err := os.WriteFile(p, []byte("hunter2-in-a-file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := r.ResolveText("k", "file:"+p)
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("mode %o: the refusal carries the file's content", mode)
			continue
		}
		if (err == nil) != ok || (err != nil && !strings.Contains(err.Error(), "chmod 0440 or 0600")) {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
}

// The allowance (decision 53 ruling 12): an env: reference by prefix, a
// file: one by directory, and its own shape.
func TestAllowance(t *testing.T) {
	a := Allowance{}.WithDefaults()
	for text, want := range map[string]bool{
		"env:PORT49_KEY_PROD_V3": true, "env:PORT49_ENC_V2": false, "env:PORT49_KEY": false,
		"file:/run/port49/keys/prod_v3": true, "file:/run/port49/keys/a/b": true, "file:/run/port49/keysx/k": false,
		"file:/run/port49/keys": false, "file:/etc/port49/tls-key.pem": false,
	} {
		ref, err := Parse(text)
		if err != nil || a.Allows(ref) != want {
			t.Errorf("%s: %v %v", text, a.Allows(ref), err)
		}
	}
	for _, bad := range []Allowance{{EnvPrefix: "P", FileDir: "/k"}, {EnvPrefix: "PORT49_", FileDir: "keys"},
		{EnvPrefix: "PORT 49", FileDir: "/k"}, {EnvPrefix: "PORT49_", FileDir: "/k/../x"}} {
		if bad.Check() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestAnEmptySecretIsRefused(t *testing.T) {
	t.Setenv("T_SECRETREF_EMPTY", "")
	p := filepath.Join(t.TempDir(), "s")
	os.WriteFile(p, []byte("\n"), 0o600)
	r := New()
	for _, text := range []string{"env:T_SECRETREF_EMPTY", "file:" + p} {
		if _, _, err := r.ResolveText("k", text); err == nil || !strings.Contains(err.Error(), "empty") &&
			!strings.Contains(err.Error(), "not set") {
			t.Errorf("%s: %v", text, err)
		}
	}
}

// No resolve error, for any scheme, carries the secret it was reading or the
// value it found (Review Focus 1).
func TestNoResolveErrorCarriesTheSecret(t *testing.T) {
	r := New()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("hunter2-in-a-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ResolveText("k", "file:"+p); err == nil {
		t.Fatal("a world-readable file was read")
	} else if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("a refused file's content is in the refusal")
	}
	t.Setenv("T_SECRETREF_SHOWN", "hunter2-shown")
	_, s, _ := r.ResolveText("k", "env:T_SECRETREF_SHOWN")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, s), "hunter2") {
			t.Fatalf("a Secret printed its value under %s", verb)
		}
	}
	if b, _ := json.Marshal(struct{ S Secret }{s}); strings.Contains(string(b), "hunter2") {
		t.Fatal("a Secret printed its value as JSON")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "hunter2") {
		t.Fatal("the resolver printed a secret under %+v")
	}
}
```

`internal/fence/fence_linux_test.go`:
```go
// secretVolume lays a secret out as a Kubernetes Secret or CSI volume does,
// in the configMap layout: dir/k -> ..data/k, ..data -> ..2026_…, the file
// 0440 in the timestamped directory. It returns dir.
func secretVolume(t *testing.T) string {
	t.Helper()
	dir := configMap(t) // policy.yaml in it stands for any file
	stamped, _ := filepath.EvalSymlinks(filepath.Join(dir, "..data"))
	if err := os.WriteFile(filepath.Join(stamped, "k"), []byte("s3cret\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/k", filepath.Join(dir, "k")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A secret volume's chain of links is followed while it stays inside the
// directory, so a key added to a whole-volume mount is read with no restart
// (decision 53 ruling 1).
func TestASecretLinkInsideTheDirectoryIsFollowed(t *testing.T) {
	dir := secretVolume(t)
	if raw, err := ReadSecret(filepath.Join(dir, "k"), dir, 1<<20); err != nil || len(raw) != 7 {
		t.Fatalf("%d bytes, %v", len(raw), err)
	}
}

// A link that leaves the directory is refused, naming both paths: a policy
// writer who can place a link must not reach the host's other secrets
// (Review Focus 2; decision 53 ruling 12).
func TestALinkOutOfTheDirectoryIsRefused(t *testing.T) {
	dir := secretVolume(t)
	other := filepath.Join(t.TempDir(), "tls-key.pem")
	if err := os.WriteFile(other, []byte("hunter2-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret(filepath.Join(dir, "out"), dir, 1<<20)
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the target's content")
	}
	if err == nil || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), "outside "+dir) {
		t.Fatalf("%v", err)
	}
	if _, err := ReadSecret(other, dir, 1<<20); err == nil {
		t.Fatal("a file outside the directory was read")
	}
}

// The file is held to a reader's rule: owned by us or root, written by its
// owner alone, no world bit; another owner is refused.
func TestASecretFileOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every file it writes")
	}
	dir := secretVolume(t)
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if fi.Mode().IsRegular() {
			return uint32(os.Geteuid() + 1), true // the Vault Agent injector's uid 100, say
		}
		return real(fi)
	}
	if _, err := ReadSecret(filepath.Join(dir, "k"), dir, 1<<20); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/secretref/ ./internal/fence/ -count=1`
Expected: FAIL to build: package `secretref` has no Go files; `ReadSecret` undefined in `fence`.

- [ ] **Step 3: Implement** `internal/secretref/secretref.go`:

```go
// Package secretref names and reads the secrets port49 holds (spec §13
// decision 53): `secret_ref: env:NAME` or `file:/path`. A reference is a
// name, so a file that carries one — the policy file, which CI and every
// operator read — carries no secret. A reference that does not parse is
// refused without being printed: it is most likely the secret, pasted where
// its name goes. A secret store reaches port49 as a file its own agent
// renders: port49 holds no secret-store client (ruling 5).
package secretref

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blanketfish/port49/internal/fence"
)

const (
	SchemeEnv  = "env"
	SchemeFile = "file"
)

// Ref is a parsed secret_ref. Name is the variable for env:, the absolute
// path for file:.
type Ref struct{ Scheme, Name string }

// String is the reference as port49 prints it.
func (r Ref) String() string { return r.Scheme + ":" + r.Name }

var (
	envName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	errShape  = errors.New("is not a secret reference: write env:NAME or file:/absolute/path")
	maxRefLen = 1024
)

// Parse reads s. Its error never quotes s.
func Parse(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || len(s) > maxRefLen || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return Ref{}, errShape
	}
	switch scheme {
	case SchemeEnv:
		if envName.MatchString(rest) {
			return Ref{Scheme: SchemeEnv, Name: rest}, nil
		}
	case SchemeFile:
		if filepath.IsAbs(rest) && filepath.Clean(rest) == rest {
			return Ref{Scheme: SchemeFile, Name: rest}, nil
		}
	}
	return Ref{}, errShape
}

// Secret is a resolved secret. It prints as <redacted> under every fmt verb
// and in JSON; Bytes is the one way to the value, at the one place that uses
// it. The value sits behind a pointer, so a Secret reached through an
// unexported field prints as an address (sot.Secret's rule).
type Secret struct{ p *[]byte }

func newSecret(b []byte) Secret { return Secret{&b} }

// Bytes is the value; nil for none.
func (s Secret) Bytes() []byte {
	if s.p == nil {
		return nil
	}
	return *s.p
}

func (Secret) Format(f fmt.State, _ rune)   { io.WriteString(f, "<redacted>") }
func (Secret) String() string               { return "<redacted>" }
func (Secret) GoString() string             { return "<redacted>" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }

// maxSecret bounds a file: read: a shared key or a token is far smaller.
const maxSecret = 1 << 20

// Resolver reads references: env: from the environment, file: through the
// write fence (fence.ReadSecret).
type Resolver struct {
	lookupEnv func(string) (string, bool)
	readFile  func(path, within string, max int64) ([]byte, error)
}

// New is the process's resolver.
func New() *Resolver {
	return &Resolver{lookupEnv: os.LookupEnv, readFile: fence.ReadSecret}
}

// Resolve reads ref. A file: reference, and every link on its way, must stay
// inside within, or inside its own directory when within is "". An error
// names the reference and why, never a value.
func (r *Resolver) Resolve(ref Ref, within string) (Secret, error) {
	var raw []byte
	switch ref.Scheme {
	case SchemeEnv:
		v, ok := r.lookupEnv(ref.Name)
		if !ok {
			return Secret{}, fmt.Errorf("%s: the variable is not set", ref)
		}
		raw = []byte(v)
	case SchemeFile:
		if within == "" {
			within = filepath.Dir(ref.Name)
		}
		b, err := r.readFile(ref.Name, within, maxSecret)
		if err != nil {
			return Secret{}, fmt.Errorf("%s: %w", ref, err)
		}
		raw = trimOneNewline(b)
	default:
		return Secret{}, errShape
	}
	if len(raw) == 0 {
		return Secret{}, fmt.Errorf("%s: the secret is empty", ref)
	}
	return newSecret(raw), nil
}

// ResolveText parses text and resolves it; every error begins with at, the
// key that holds it, and quotes text only once it has parsed.
func (r *Resolver) ResolveText(at, text string) (Ref, Secret, error) {
	ref, err := Parse(text)
	if err != nil {
		return Ref{}, Secret{}, fmt.Errorf("%s %w", at, err)
	}
	s, err := r.Resolve(ref, "")
	if err != nil {
		return Ref{}, Secret{}, fmt.Errorf("%s %w", at, err)
	}
	return ref, s, nil
}

// Allowance is where a policy's key references may point (decision 53
// ruling 12): port49d.yaml's key_secret_refs. A policy writer must not
// choose which of the host's secrets becomes a TACACS+ key.
type Allowance struct {
	EnvPrefix string `yaml:"env_prefix"`
	FileDir   string `yaml:"file_dir"`
}

// DefaultAllowance is the allowance a port49d.yaml that names none gets.
var DefaultAllowance = Allowance{EnvPrefix: "PORT49_KEY_", FileDir: "/run/port49/keys"}

// WithDefaults fills what a is missing from DefaultAllowance.
func (a Allowance) WithDefaults() Allowance {
	if a.EnvPrefix == "" {
		a.EnvPrefix = DefaultAllowance.EnvPrefix
	}
	if a.FileDir == "" {
		a.FileDir = DefaultAllowance.FileDir
	}
	return a
}

// Check refuses an allowance too wide to bound anything: a prefix shorter
// than 4 characters or not a variable name's start, a directory not absolute
// and clean.
func (a Allowance) Check() error {
	if len(a.EnvPrefix) < 4 || !envName.MatchString(a.EnvPrefix) {
		return fmt.Errorf("env_prefix %q must be at least 4 characters of an environment variable name", a.EnvPrefix)
	}
	if !filepath.IsAbs(a.FileDir) || filepath.Clean(a.FileDir) != a.FileDir || a.FileDir == "/" {
		return fmt.Errorf("file_dir %q must be an absolute, clean path below /", a.FileDir)
	}
	return nil
}

// Allows reports whether ref is inside a: an env: variable longer than the
// prefix and starting with it, or a file: path below the directory. A link
// inside the directory is held to it at the read (fence.ReadSecret).
func (a Allowance) Allows(ref Ref) bool {
	switch ref.Scheme {
	case SchemeEnv:
		return len(ref.Name) > len(a.EnvPrefix) && strings.HasPrefix(ref.Name, a.EnvPrefix)
	case SchemeFile:
		return strings.HasPrefix(ref.Name, a.FileDir+"/")
	}
	return false
}

// String is the allowance as a refusal names it.
func (a Allowance) String() string {
	return fmt.Sprintf("env: variables starting %s, file: under %s", a.EnvPrefix, a.FileDir)
}

// trimOneNewline drops one trailing LF or CRLF (decision 53 ruling 1).
func trimOneNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}
```

`internal/fence/fence_linux.go`, beside `Read`:
```go
// ReadSecret reads a secret file a `file:` reference names (spec §13
// decision 53 rulings 1 and 12). It is Read's fence with a reader's rule for
// the file. A link is followed, as a ConfigMap's is, only while the path
// resolves inside within: a Kubernetes Secret or CSI volume's
// name -> ..data/name chain does, and a link out of the directory, to the
// TLS key or the keytab, is refused. Every link's directory (and, decision 53
// ruling 11, every ancestor) is held to the fence's rule by
// resolvePolicyPath; the directory holding the file to Read's, never excused
// by a read-only mount. The file must be owned by this process's user or
// root, writable by its owner alone, and carry no world bit: group-read is
// allowed, which fsGroup and an agent's perms = "0440" give. No error
// carries the file's bytes.
func ReadSecret(path, within string, max int64) ([]byte, error) {
	target, err := resolvePolicyPath(path)
	if err != nil {
		return nil, err
	}
	w, err := resolvePolicyPath(within)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(target, w+"/") {
		return nil, fmt.Errorf("%s resolves to %s, outside %s: a secret file, and every link to it, stays "+
			"inside that directory", path, target, w)
	}
	dir, base := filepath.Dir(target), filepath.Base(target)
	d, di, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := syscall.Openat(int(d.Fd()), base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: target, Err: err}
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	return readChecked(f, target, max, "secret file", func(fi fs.FileInfo) error {
		if err := ownedByUsOrRoot("the secret file "+target, fi); err != nil {
			return err
		}
		if perm := fi.Mode().Perm(); perm&0o027 != 0 {
			return fmt.Errorf("%s is mode %v: a secret file may be group-readable, never world-readable or "+
				"writable by anyone but its owner - chmod 0440 or 0600 it, or, on a mounted volume, set the "+
				"mode where it is rendered (Kubernetes defaultMode and fsGroup, Vault Agent's perms)", target, perm)
		}
		return writableByUsAlone("the directory "+dir, di)
	})
}
```
`fence_other.go` gains the stub, refusing as `Read` does: `func ReadSecret(path, _ string, max int64) ([]byte, error) { return Read(path, max, "secret file") }`.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/secretref/ ./internal/fence/ -count=1 -v && make check-darwin`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/secretref internal/fence
git commit -m "feat: secret_ref references, env: and file:, read through the write fence (decision 53)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: port49d.yaml and port49-broker.yaml read every secret by `secret_ref`

**Files:**
- Modify: `internal/config/config.go`, `internal/config/directory.go`, `internal/config/*_test.go`, `internal/yamlfault/yamlfault.go` and its test (`Replaced`)
- Modify: `internal/directory/config.go` (`Bind.PasswordEnv`), `internal/directory/conn.go` (`LoadCredentials`), `internal/directory/*_test.go`
- Modify: `internal/port49d/directory.go:37` and `:110`
- Modify (fixtures): every file `git grep -lw 'secret_env\|password_env' -- ':!docs/' ':!tests/lab/results/' ':!tests/lab/evidence/'` lists, except `internal/inventory/` and `internal/sot/` (Task 9's)

**Interfaces:**
- Consumes: `secretref.Parse`, `secretref.New`, `(*Resolver).ResolveText` (Task 3).
- Produces:
  - `config.KeyVersion.SecretRef string \`yaml:"secret_ref"\`` (replacing `SecretEnv`);
  - `encKeyYAML.SecretRef`;
  - `Config.Secrets *secretref.Resolver`: the resolver Load built, for port49d's policy keys (Task 6) and the directory's bind password;
  - `directory.Bind.PasswordRef string` (replacing `PasswordEnv`);
  - `func directory.LoadCredentials(b Bind, resolve func(ref string) ([]byte, error)) (*Credentials, error)`;
  - `func (c Config) ResolveSecret(ref string) ([]byte, error)`: `c.Secrets.ResolveText`, for `LoadCredentials`; a `Config` with no resolver (built by hand, as `internal/port49d/directory_test.go` builds them) uses `secretref.New()`;
  - `func yamlfault.Replaced(raw []byte, replaced map[string]string) error`: a removed key anywhere in the file refused naming its replacement, as `receipt_ttl` and `staleSeedKeys` are (decision 53 ruling 1); `internal/inventory` uses it too (Task 9);
  - `Config.secrets` stays a `map[string]string`, keyed by the reference's text. `Parse` accepts only `env:NAME` and a clean absolute `file:` path, so a reference's text is its one spelling and nothing is canonicalised.

- [ ] **Step 1: Write the failing tests** in `internal/config/config_test.go`. First change the fixtures: `sampleHead`'s three `secret_env: T_PROD_Vn` become `secret_ref: env:T_PROD_Vn`, and `sample`'s encryption line becomes `current: {id: v2, secret_ref: env:PORT49_ENC_V2}`. Then add:

```go
// Every secret in port49d.yaml is named by secret_ref (decision 53 ruling 1):
// a file: key and a file: encryption key load as their variables did.
func TestSecretsLoadFromFiles(t *testing.T) {
	setSecrets(t)
	dir := t.TempDir()
	enc := filepath.Join(dir, "enc")
	os.WriteFile(enc, []byte("22222222222222222222222222222222\n"), 0o600)
	k3 := filepath.Join(dir, "k3")
	os.WriteFile(k3, []byte("three\n"), 0o600)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(strings.Replace(fmt.Sprintf(sample, invPath), "env:PORT49_ENC_V2", "file:"+enc, 1),
		"env:T_PROD_V3", "file:"+k3, 1)
	c, err := Load(write(t, "port49d.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Keyring()["prod_key"].Versions[0].Secret; string(got) != "three" {
		t.Fatalf("the file: key: got %d bytes, want 5", len(got)) // never the value
	}
	if _, err := c.EncryptionKeys(); err != nil {
		t.Fatalf("the file: encryption key: %v", err)
	}
}

// secret_env and password_env are gone: refused, naming the replacement and
// the line, never loaded (no deprecation before beta: a refusal, not an
// alias). An operator upgrading four files at once is told what to write.
func TestARemovedSecretKeyIsRefusedNamingItsReplacement(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "secret_ref: env:T_PROD_V3", "secret_env: T_PROD_V3", 1)
	_, err := Load(write(t, "port49d.yaml", body))
	if err == nil || !strings.Contains(err.Error(), "secret_env was replaced by secret_ref") ||
		!strings.Contains(err.Error(), "line ") {
		t.Fatalf("%v", err)
	}
}

// A secret pasted where the reference goes is refused by its key, unprinted.
func TestAPastedSecretInSecretRefIsNotPrinted(t *testing.T) {
	setKeyEnv(t)
	invPath := write(t, "inventory.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, invPath), "env:PORT49_ENC_V2", "hunter2hunter2hunter2hunter2hunt", 1)
	_, err := Load(write(t, "port49d.yaml", body))
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the pasted secret")
	}
	if err == nil || !strings.Contains(err.Error(), "encryption.current.secret_ref") {
		t.Fatalf("%v", err)
	}
}
```

In `internal/directory`'s tests, replace each `PasswordEnv: "X"` with `PasswordRef: "env:X"` and each `LoadCredentials(b, getenv)` call with `LoadCredentials(b, func(ref string) ([]byte, error) { ... })` built from the same map the test's `getenv` used.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/config/ ./internal/directory/ -count=1`
Expected: FAIL: `secret_ref` is an unknown field; `PasswordRef` is undefined.

- [ ] **Step 3: Implement.**

1. `config.go` types: `KeyVersion.SecretEnv` → `SecretRef string \`yaml:"secret_ref"\``; `encKeyYAML.SecretEnv` → `SecretRef string \`yaml:"secret_ref"\``; `Config` gains:

```go
	// Secrets is the resolver Load built (decision 53): how port49d reads
	// its policy's key secrets at each swap, and the directory's bind
	// password at start. Nil before Load.
	Secrets *secretref.Resolver
```

2. In `load`, before the decode, beside `staleSeedKeys`:

```go
	if err := yamlfault.Replaced(raw, map[string]string{
		"secret_env":   "secret_ref (write secret_ref: env:NAME)",
		"password_env": "password_secret_ref (write password_secret_ref: env:NAME)",
	}); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
```
and set `Secrets: secretref.New()` in the `Config` literal. `hasPrevious` becomes `f.Encryption.Previous.SecretRef != ""`. `yamlfault.Replaced`, in `internal/yamlfault/yamlfault.go` beside `OneDocument`, walks the file's `yaml.Node` tree and refuses the first mapping key it finds in `replaced`: `fmt.Errorf("line %d: %s was replaced by %s (decision 53 ruling 1)", key.Line, key.Value, replaced[key.Value])`. A file that does not parse returns nil: the strict decode reports it. Test it in `yamlfault_test.go` with a nested key and a key that is only a value (`x: secret_env`, not refused).

3. Add the one place a secret is read:

```go
// resolveInto reads the secret text names, at key at, into c.secrets under
// that text.
func (c *Config) resolveInto(at, text string) error {
	_, s, err := c.Secrets.ResolveText(at, text)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	c.secrets[text] = string(s.Bytes())
	return nil
}

// ResolveSecret reads one secret_ref for a reader outside Load: the
// directory's bind password, read when the directory opens.
func (c Config) ResolveSecret(text string) ([]byte, error) {
	res := c.Secrets
	if res == nil {
		res = secretref.New() // a Config built by hand, as tests build one
	}
	_, s, err := res.ResolveText("broker.directory.bind.password_secret_ref", text)
	return s.Bytes(), err
}
```

4. The encryption loop in `load` keeps its checks, reworded from `secret_env` to `secret_ref`, and drops the `envName` check (Parse refuses by key and quotes nothing). The `os.LookupEnv` block is replaced by:

```go
		if err := c.resolveInto(k.what+".secret_ref", k.ref.SecretRef); err != nil {
			return Config{}, err
		}
		if s := c.secrets[k.ref.SecretRef]; len(s) != 32 {
			return Config{}, fmt.Errorf("config: %s (id %q): the secret %s names must be exactly 32 bytes for "+
				"AES-256, got %d", k.what, k.ref.ID, k.ref.SecretRef, len(s))
		}
```
`EncryptionKeys` reads `c.secrets[c.encCurrent.SecretRef]`.

5. `resolveKeys`: for each version, `c.resolveInto(fmt.Sprintf("keys.%s version %d secret_ref", ref, v.Version), v.SecretRef)`, so `Keyring()` finds `c.secrets[v.SecretRef]`. `checkKeySets` replaces the `SecretEnv == ""` and `envName` checks with:

```go
			if v.SecretRef == "" {
				return nil, fmt.Errorf("config: key %s version %d: secret_ref is required", ref, v.Version)
			}
			if _, err := secretref.Parse(v.SecretRef); err != nil {
				return nil, fmt.Errorf("config: key %s version %d: secret_ref %w", ref, v.Version, err)
			}
```

6. `Keyring()`: `c.secrets[ks.Current.SecretRef]`, and likewise for each version.

7. `directory.go`: `bindYAML.PasswordEnv` → `PasswordSecretRef string \`yaml:"password_secret_ref"\``. `checkBind` keeps its shape: `simple` requires `bind_dn` and `password_secret_ref`, and `secretref.Parse` must accept the latter. The `getenv(...) == ""` check is replaced by the start's read in `port49d/directory.go`. Move the site check: the password must not be read from the site's variable. Refuse when `PasswordSecretRef == "env:"+or(y.SiteEnv, "PORT49_SITE")`, worded "site_env %s is also the password's variable: the site is logged, a password never is". `directory.Bind.PasswordEnv` → `PasswordRef`.

8. `internal/directory/conn.go`:

```go
func LoadCredentials(b Bind, resolve func(ref string) ([]byte, error)) (*Credentials, error) {
	…
	case "simple":
		pw, err := resolve(b.PasswordRef)
		if err != nil {
			return nil, err
		}
		c.password, c.who = string(pw), b.BindDN
```
`internal/port49d/directory.go:37`: `directory.LoadCredentials(d.Bind, cfg.ResolveSecret)`. Line 110's start line: "its password is read from %s", with `d.Bind.PasswordRef`.

9. `brokerRefusals` is unchanged in this task.

10. **Fixtures.** For each file `git grep -lw 'secret_env\|password_env' -- ':!docs/' ':!tests/lab/results/' ':!tests/lab/evidence/' ':!internal/inventory/' ':!internal/sot/' ':!cmd/port49-inventory/'` lists, edit:
    - `secret_env: NAME` → `secret_ref: env:NAME`;
    - `password_env: NAME` → `password_secret_ref: env:NAME`;
    - Go struct literals `SecretEnv:` → `SecretRef: "env:…"`.

    The list includes `deploy/compose/config/port49d.yaml`, `deploy/compose/config/port49-broker.yaml` (and its commented directory block), `examples/kubernetes/examples_test.go`, `tests/lab/port49d-lab.yaml`, `tests/lab/*.go` and `internal/port49d/*_test.go`. `-w` keeps `token_secret_env` and `webhook_secret_env` out: they are Task 9's.

11. Messages: grep `internal/config` for "secret_env" in error text and reword each to `secret_ref`; tests asserting the old words change with them.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/config/ ./internal/directory/ ./internal/port49d/ ./examples/... -count=1 && make lab-unit`
Expected: PASS.

- [ ] **Step 5: Check nothing still names the old keys**

Run: `git grep -nw 'secret_env\|password_env\|SecretEnv\|PasswordEnv' -- ':!docs/' ':!tests/lab/results/' ':!tests/lab/evidence/' ':!internal/inventory/' ':!internal/sot/' ':!cmd/port49-inventory/'`
Expected: only the `yamlfault.Replaced` call in `internal/config/config.go`, `yamlfault`'s test and `TestARemovedSecretKeyIsRefusedNamingItsReplacement`.

- [ ] **Step 6: Verify and commit**

Run `make test && make vet`, then:
```bash
git add -A internal/config internal/directory internal/yamlfault internal/port49d deploy examples tests/lab
git commit -m "feat: port49d.yaml and port49-broker.yaml name every secret by secret_ref

secret_env and password_env are removed outright (decision 53 ruling 1).

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: `internal/keyset`, and the policy file's `keys:` block

**Files:**
- Create: `internal/keyset/keyset.go`, `internal/keyset/keyset_test.go`
- Modify: `internal/config/config.go` (move `KeySet`, `KeyVersion`, `checkKeySets`, `checkKeyRefs`, `allVersions`, `sortedKeySets` out; `Config.Keys` becomes `map[string]keyset.Set`), `cmd/port49/keys.go`, `cmd/port49/policy.go`, `cmd/port49/inventory.go` (type names only)
- Modify: `internal/policy/file.go` (`file.Keys`), `internal/policy/load.go` (a Parse step, `Policy.keys`, `yamlfault.Replaced` for `secret_env`), `internal/policy/admit_test.go` or a new `internal/policy/keys_test.go`

**Interfaces:**
- Produces:

```go
package keyset
type Version struct {
	Version     int       `yaml:"version"`
	SecretRef   string    `yaml:"secret_ref"`
	RetireAfter string    `yaml:"retire_after"`
	RetireAt    time.Time `yaml:"-"`
}
type Set struct {
	Current Version   `yaml:"current"`
	Accept  []Version `yaml:"accept"`
	Retired []Version `yaml:"retired"`
}
func (s Set) All() []Version                                        // current, accept…, retired…
func Check(sets map[string]Set, raw []byte) (map[string]Set, error) // no secret read; RetireAt filled; errors unprefixed
var ErrBadRef error                                                 // wraps a secret_ref Parse refuses
func Sorted(sets map[string]Set) []string
func Notices(sets map[string]Set, now time.Time) []string           // no retire_after; retire_after passed
func Keyring(sets map[string]Set, secret func(secretRef string) []byte) map[string]keyring.Set
```
  `Keyring` calls `secret` with each version's `SecretRef` exactly as the set holds it: a reference has one spelling (Task 4), so `config` and port49d's `liveKeys` both look secrets up by that text.
  - `func (p *policy.Policy) KeySets() map[string]keyset.Set`: a copy; nil when the file has no `keys:`;
  - `func (p *policy.Policy) KeysDeclared() bool`.

  This task changes no admission: Task 6 does.

- [ ] **Step 1: Write the failing tests.**

`internal/keyset/keyset_test.go`: move `internal/config`'s tests of `checkKeySets` and `checkKeyRefs` (`grep -n 'func Test.*Key' internal/config/config_test.go`; the ones calling `KeySets(` or checking version numbering, `retire_after` and a non-name key) here, as tests of `Check`. Keep the ones that load a whole port49d.yaml in `config`. Add:

```go
// Keyring orders each set current, accept, retired, with RetireAt and the
// retired flag, and takes each secret by its version's reference.
func TestKeyring(t *testing.T) {
	sets, err := Check(map[string]Set{"k": {
		Current: Version{Version: 3, SecretRef: "env:K3"},
		Accept:  []Version{{Version: 2, SecretRef: "env:K2", RetireAfter: "2026-12-01"}},
		Retired: []Version{{Version: 1, SecretRef: "env:K1"}}}}, []byte("keys:\n  k: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ring := Keyring(sets, func(ref string) []byte { return []byte("s-" + ref) })
	vs := ring["k"].Versions
	if len(vs) != 3 || vs[0].Number != 3 || string(vs[0].Secret) != "s-env:K3" || vs[1].RetireAt.IsZero() ||
		!vs[2].Retired {
		t.Fatalf("got %d versions, wrong numbers, dates or flags (secrets not printed)", len(vs))
	}
}
```

`internal/policy/keys_test.go`:
```go
package policy

// The policy carries its key sets beside key_groups (decision 53 ruling 3):
// names, versions, dates and references, never a secret.
const keyed = keyGrouped + `
keys:
  prod_key:
    current: {version: 3, secret_ref: file:/run/secrets/prod_v3}
    accept:
      - {version: 2, secret_ref: env:PROD_V2, retire_after: 2026-12-01}
  campus_key:
    current: {version: 1, secret_ref: file:/run/secrets/campus}
`

func TestThePolicyCarriesItsKeySets(t *testing.T) {
	p, err := Parse([]byte(keyed), env())
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeysDeclared() || len(p.KeySets()) != 2 || p.KeySets()["prod_key"].Accept[0].RetireAt.IsZero() {
		t.Fatalf("%+v", p.KeySets())
	}
	if q, _ := Parse([]byte(keyGrouped), env()); q.KeysDeclared() || q.KeySets() != nil {
		t.Fatal("a policy with no keys: declares none")
	}
	if q, _ := Parse([]byte(keyGrouped+"keys: {}\n"), env()); !q.KeysDeclared() {
		t.Fatal("keys: {} is declared, and empty")
	}
	// A bare keys: is refused in its own words, not taken for "no block"
	// (pre-flight M8).
	if _, err := Parse([]byte(keyGrouped+"keys:\n"), env()); err == nil || !strings.Contains(err.Error(), "keys: {}") {
		t.Fatalf("a bare keys: %v", err)
	}
}

func TestAKeySetThePolicyCannotUseIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"no ref":     "keys:\n  k:\n    current: {version: 1}\n",
		"pasted":     "keys:\n  k:\n    current: {version: 1, secret_ref: hunter2hunter2}\n",
		"twice":      "keys:\n  k:\n    current: {version: 1, secret_ref: env:A}\n    accept: [{version: 1, secret_ref: env:B}]\n",
		"not a name": "keys:\n  \"hunter2 hunter2\":\n    current: {version: 1, secret_ref: env:A}\n",
	} {
		_, err := Parse([]byte(good+body), env())
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the refusal carries the secret", name)
		}
	}
	// A reference that does not parse may be the secret itself, now in the
	// policy repository: the refusal says to rotate it (pre-flight M12).
	_, err := Parse([]byte(good+"keys:\n  k:\n    current: {version: 1, secret_ref: hunter2hunter2}\n"), env())
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatal("a pasted secret: accepted, or printed in the refusal")
	}
	if !strings.Contains(err.Error(), "rotate it") {
		t.Fatalf("%v", err)
	}
	// A block moved verbatim from port49d.yaml names its replacement, not an
	// unknown field (re-review N6).
	_, err = Parse([]byte(good+"keys:\n  k:\n    current: {version: 1, secret_env: PORT49_KEY_K}\n"), env())
	if err == nil || !strings.Contains(err.Error(), "secret_env was replaced by secret_ref") {
		t.Fatalf("%v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/keyset/ ./internal/policy/ -run 'Key' -count=1`
Expected: FAIL: package `keyset` has no Go files; `p.KeysDeclared` undefined.

- [ ] **Step 3: Implement.**
  - Create `internal/keyset/keyset.go` with the package doc "Package keyset is the device key sets of spec §10: versions, dates and secret references, never a secret (decision 53)". Move these from `internal/config/config.go`, with these changes:
    - `checkKeySets` becomes `Check`;
    - `checkKeyRefs` becomes the unexported `checkNames` that `Check` calls;
    - `allVersions` becomes `Set.All`, and `sortedKeySets` becomes `Sorted`;
    - the notice loop from `resolveKeys` becomes `Notices`;
    - `Config.Keyring`'s body becomes `Keyring`.
  - Errors lose the `config: ` prefix. The `secret_ref` Parse check from Task 4 moves with `Check`.
  - In `config`, `Keys map[string]keyset.Set`. `resolveKeys` calls `keyset.Check`, wrapping errors in `config: `, and appends `keyset.Notices` to `c.Notices`. `Keyring()` is `keyset.Keyring(c.Keys, func(ref string) []byte { return []byte(c.secrets[ref]) })`, and `KeySets(raw)` returns `map[string]keyset.Set`. `cmd/port49` takes `keyset.Set` wherever it took `config.KeySet`.
  - `internal/policy/file.go`: `file` gains `Keys map[string]keyset.Set \`yaml:"keys"\`` with the comment "the key sets (decision 53 ruling 3): names, versions, dates and references, never a secret".
  - `internal/policy/load.go`: `Policy` gains:

```go
	// keys are the file's key sets (decision 53 ruling 3), nil when it has no
	// keys: block; keysDeclared tells `keys: {}` from none.
	keys         map[string]keyset.Set
	keysDeclared bool
```
  - In `Parse`, after `refusedKeys`, refuse a removed key by name, as port49d.yaml does (re-review N6): an upgrading operator moving port49d.yaml's block verbatim would otherwise read "an unknown field":

```go
	if err := yamlfault.Replaced(raw, map[string]string{
		"secret_env": "secret_ref (write secret_ref: env:NAME)",
	}); err != nil {
		return nil, err
	}
```
  - Add a Parse step `p.buildKeys` before `p.admit` in the step list:

```go
// buildKeys checks the file's key sets (spec §10; decision 53 ruling 3). It
// reads no secret: port49d resolves each reference when it puts the policy
// in force.
func (p *Policy) buildKeys(f file) error {
	if f.Keys == nil {
		if bareKeys(p.raw) {
			return errors.New("keys: is empty; write `keys: {}` for a fleet all on TLS, or the key sets " +
				"(decision 53 ruling 3)")
		}
		return nil // no keys: block
	}
	sets, err := keyset.Check(f.Keys, p.raw)
	if errors.Is(err, keyset.ErrBadRef) {
		// It may be the secret itself, pasted where its name goes: it is in
		// the policy repository now, and in CI's history.
		return fmt.Errorf("keys: %w; if what you wrote there is the secret, it is now in the policy "+
			"repository: rotate it (add a version with a new secret)", err)
	}
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	p.keys, p.keysDeclared = sets, true
	return nil
}

// KeySets are the policy's key sets, a copy; nil when it declares none.
func (p *Policy) KeySets() map[string]keyset.Set {
	if !p.keysDeclared {
		return nil
	}
	return maps.Clone(p.keys)
}

// KeysDeclared is whether the file has a keys: block, `keys: {}` included.
func (p *Policy) KeysDeclared() bool { return p.keysDeclared }
```
yaml.v3 decodes `keys: {}` to an empty, non-nil map, and a bare `keys:` (null) to nil, which `TestThePolicyCarriesItsKeySets` pins. `bareKeys(raw)` decodes the file loosely (`map[string]any`, as `refusedKeys` does) and reports a `keys` key whose value is nil. `keyset.Check` returns a non-nil map for a non-nil input, and wraps a reference `secretref.Parse` refuses in `keyset.ErrBadRef` (`var ErrBadRef = errors.New("...")`, wrapped with `%w` beside the fixed `secretref` text) so the policy can add its rotate advice; port49d.yaml's refusal says nothing of rotating, since that file is private.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/keyset/ ./internal/policy/ ./internal/config/ ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/keyset internal/config internal/policy cmd/port49
git commit -m "feat: internal/keyset, and the policy file's keys: block (decision 53 ruling 3)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 6: port49d and port49-broker take their keys from the policy

**Files:**
- Create: `internal/port49d/livekeys.go`, `internal/port49d/livekeys_test.go`
- Modify: `internal/policy/load.go` (remove `Env.KeyRefs`), `internal/policy/admit.go` (`admit`, `AdmissionAssessed`, the comments naming `Env.KeyRefs`)
- Modify: `internal/bundle/diff.go` (`KeyRefsFile`), `internal/bundle/bundle.go:108` comment
- Create: `internal/port49d/keyretry.go`, `internal/port49d/keyretry_test.go`
- Modify: `internal/config/config.go` (`KeyRefs()`, `keyRefs`, `checkKeyRefList`, `fileConfig.KeyRefs` removed; `keys:` beside a policy refused, `keys: {}` included; `key_secret_refs` added and checked; `key_refs` added to `yamlfault.Replaced`'s map; `brokerRefusals`' `keys:` entry reworded and `key_secret_refs` refused for the broker role)
- Create: `internal/config/allowance.go` (`secretsApart`, `ownSecretRefs`, `ownKeyPaths`, `within`)
- Modify: `internal/port49d/startguard.go` (`guardAtStart` compiles the recorded policy with `compileBundle`), `internal/port49d/startguard_test.go`
- Modify: `internal/port49d/directory.go` (`policyEnv`), `internal/port49d/main.go` (`parseBundle` split from `compileBundle`, `startPolicy`, the key wiring at :1181 and :1203, the admin server at :1344, the key notices at start), `internal/port49d/reload.go` (the four `r.swap(` sites, `swap`, `load`'s and `loadBoth`'s refusal branches, `poll`, the `KeyRefsFile` rewrite at :1484)
- Modify: `cmd/port49/policy.go` (`loadWith` removed) and `cmd/port49/inventory.go:110` (`Env.KeyRefs`), so `cmd/port49` compiles; Task 8 finishes both
- Modify: `internal/daemon/server/server.go` (`Deps.Keys`), `internal/daemon/admin/admin.go` (`Server.Keys`)
- Modify: `internal/inventory/sync.go:523` comment
- Modify (fixtures): every port49d or port49-broker test configuration that has a policy and a `keys:` block, every test using `Env{KeyRefs: …}` (`internal/broker/explain_api_test.go`, `internal/broker/refresh_test.go`, `internal/config/broker_role_test.go`, `internal/policy/generic_test.go` among them), `tests/qual/qual-policy.yaml`, and `internal/testpki/compose.go` (Step 3, item 9)

**Interfaces:**
- Consumes: `keyset.Keyring`, `(*policy.Policy).KeySets`, `KeysDeclared` (Task 5); `Config.Secrets` (Task 4).
- Produces:
  - `server.Deps.Keys func(keyRef string) keyring.Set`, replacing the map, and `func (d Deps) keysFor(ref string) keyring.Set` (nil-safe);
  - `admin.Server.Keys func() map[string]keyring.Set`;
  - `type keyBuild struct { sets map[string]keyring.Set; refs map[string]map[int]string }`;
  - `func newLiveKeys(res *secretref.Resolver, allow secretref.Allowance) *liveKeys`;
  - `func (k *liveKeys) build(pol *policy.Policy) (keyBuild, error)`: a secret that could not be read is a `*keyUnreadError`, anything else (outside the allowance, re-keyed) a plain error;
  - `type keyUnreadError struct{ err error }` with `Error` and `Unwrap`;
  - `func keyChanges(old, new map[string]keyset.Set) string`: the swap's key line, `""` when the sets are the same;
  - `config.Config.KeySecretRefs secretref.Allowance` (port49d.yaml's top-level `key_secret_refs`, defaulted and checked at load);
  - `keyWait`, `keyRetryInterval`, `keyRetrySayEvery`, `func (r *reloader) retryKeys(ctx context.Context, trigger string)`, `func (r *reloader) waitForKeys(v, trigger string, err error) (say bool, note string)` in `keyretry.go`;
  - `func (k *liveKeys) put(b keyBuild)`;
  - `func compileBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error)`: `bundle.Parse` with `parseBundle`'s wrapping and no `keys:` requirement, for a policy recorded before the upgrade;
  - `func (k *liveKeys) Set(ref string) keyring.Set`;
  - `func (k *liveKeys) All() map[string]keyring.Set`;
  - `reloader.keys *liveKeys`;
  - `func (r *reloader) swap(pol *policy.Policy, kb keyBuild) time.Time`.

- [ ] **Step 1: Write the failing tests.**

`internal/port49d/livekeys_test.go`:
```go
package port49d

// The policy's keys are read at build, once per reference: a second build of
// the same policy reads nothing, and one that adds a version reads only it
// (decision 53 ruling 2).
func TestLiveKeysReadEachReferenceOnce(t *testing.T) {
	dir := t.TempDir()
	k3, k4 := filepath.Join(dir, "k3"), filepath.Join(dir, "k4")
	os.WriteFile(k3, []byte("three\n"), 0o600)
	os.WriteFile(k4, []byte("four\n"), 0o600)
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: dir})
	pol := keyedPolicy(t, "keys:\n  k:\n    current: {version: 3, secret_ref: file:"+k3+"}\n")
	kb, err := k.build(pol)
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	if string(k.Set("k").Versions[0].Secret) != "three" {
		t.Fatal("version 3's secret is not the file's") // never print a secret
	}
	os.Remove(k3) // held: a rebuild of the version in force does not read it again
	pol2 := keyedPolicy(t, "keys:\n  k:\n    current: {version: 4, secret_ref: file:"+k4+"}\n"+
		"    accept: [{version: 3, secret_ref: file:"+k3+", retire_after: 2099-01-01}]\n")
	kb, err = k.build(pol2)
	if err != nil {
		t.Fatalf("a held version was read again: %v", err)
	}
	k.put(kb)
	if vs := k.Set("k").Versions; len(vs) != 2 || string(vs[0].Secret) != "four" || string(vs[1].Secret) != "three" {
		t.Fatalf("%d versions, or a secret not its file's", len(vs))
	}
}

// A version's secret never changes: a policy naming another reference for a
// version in force is refused, with both references named (Review Focus 4).
func TestAReloadThatRekeysAVersionIsRefused(t *testing.T) {
	t.Setenv("T_LK_A", "a")
	t.Setenv("T_LK_B", "b")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: t.TempDir()})
	kb, _ := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_A}\n"))
	k.put(kb)
	_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_B}\n"))
	if err == nil || !strings.Contains(err.Error(), "env:T_LK_A") || !strings.Contains(err.Error(), "env:T_LK_B") ||
		!strings.Contains(err.Error(), "add a version") {
		t.Fatalf("%v", err)
	}
}
```
```go
// A policy names only what port49d.yaml allows (Review Focus 2; decision 53
// ruling 12): the encryption key's variable, the bind password's, and a file
// outside file_dir are each refused before anything is read, naming the
// reference and the allowance, never a value.
func TestAPolicyKeyOutsideTheAllowanceIsRefused(t *testing.T) {
	t.Setenv("PORT49_ENC_V2", "hunter2hunter2hunter2hunter2hunt")
	t.Setenv("PORT49_BIND_PASSWORD", "hunter2-bind")
	tls := filepath.Join(t.TempDir(), "tls-key.pem")
	os.WriteFile(tls, []byte("hunter2-key"), 0o600)
	allow := secretref.Allowance{}.WithDefaults()
	k := newLiveKeys(secretref.New(), allow)
	for _, ref := range []string{"env:PORT49_ENC_V2", "env:PORT49_BIND_PASSWORD", "file:" + tls} {
		_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: "+ref+"}\n"))
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the refusal carries the secret", ref)
			continue
		}
		var unread *keyUnreadError
		if err == nil || errors.As(err, &unread) || !strings.Contains(err.Error(), ref) ||
			!strings.Contains(err.Error(), "outside key_secret_refs") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}
```

```go
// A reference inside file_dir that links out of it is refused by the read
// liveKeys makes (re-review N2): Allows checks the text alone, and the text
// is inside. The refusal names both paths and reads nothing.
func TestAPolicyKeyLinkingOutOfTheDirectoryIsRefused(t *testing.T) {
	dir := safeDir(t)
	tls := filepath.Join(t.TempDir(), "tls-key.pem")
	if err := os.WriteFile(tls, []byte("hunter2-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Symlink(tls, out); err != nil {
		t.Fatal(err)
	}
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: file:"+out+"}\n"))
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the target's content")
	}
	if err == nil || !strings.Contains(err.Error(), out) || !strings.Contains(err.Error(), tls) {
		t.Fatalf("%v", err)
	}
}
```

Write `keyedPolicy(t, keys string) *policy.Policy` in the test file: `policy.Parse([]byte(<the package's smallest valid policy body, from an existing test helper such as the one directory_test.go's buildPolicy uses>+keys), policy.Env{})`.

A reload test in `internal/port49d/reload_test.go`, on `newReloadRig` (`reload_test.go:49`), whose `minimalPolicy` (`broker_test.go:108`) gains the `runKeys` block in Step 3 item 9:
```go
// A reload whose new version cannot be read is refused, said with the
// reference, and the keys in force keep serving (Review Focus 4; decision 53
// ruling 2).
func TestAReloadWhoseSecretCannotBeReadKeepsTheKeysInForce(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	dir := safeDir(t)
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	missing := filepath.Join(dir, "absent")
	rig.write(t, strings.Replace(minimalPolicy, runKeys, "keys:\n  k:\n    current: {version: 2, secret_ref: file:"+
		missing+"}\n    accept: [{version: 1, secret_ref: env:PORT49_KEY_RUN, retire_after: 2099-01-01}]\n", 1))
	rig.with(func() { rig.r.poll(context.Background()) })
	rig.with(func() { rig.r.poll(context.Background()) })
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")); n != 1 {
		t.Fatalf("refused reloads: %v\n%s", n, rig.out.String())
	}
	if !strings.Contains(rig.out.String(), "keys.k version 2 secret_ref file:"+missing) {
		t.Fatalf("the refusal does not name the reference:\n%s", rig.out.String())
	}
	if vs := rig.r.keys.Set("k").Versions; len(vs) != 1 || vs[0].Number != 1 || string(vs[0].Secret) != "run-test-secret" {
		t.Fatalf("the keys in force changed: %d versions", len(vs))
	}
}
```

`internal/port49d/keyretry_test.go`:
```go
// A reload refused because a key's file is not there yet is tried again
// every keyRetryInterval, said once, and put in force when the file appears,
// with no SIGHUP (Review Focus 4; decision 53 ruling 2).
func TestAReloadWaitingOnASecretLoadsOnceTheFileAppears(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	dir := safeDir(t)
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	v2 := filepath.Join(dir, "v2")
	rig.write(t, strings.Replace(minimalPolicy, runKeys, "keys:\n  k:\n    current: {version: 2, secret_ref: file:"+
		v2+"}\n    accept: [{version: 1, secret_ref: env:PORT49_KEY_RUN, retire_after: 2099-01-01}]\n", 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "tried again every 30s") {
		t.Fatalf("the refusal does not say it is retried:\n%s", rig.out.String())
	}
	rig.now = rig.now.Add(keyRetryInterval)
	rig.with(func() { rig.r.poll(context.Background()) })
	if n := strings.Count(rig.out.String(), "policy reload ("); n != 1 {
		t.Fatalf("a retry inside keyRetrySayEvery was said again (%d refusals):\n%s", n, rig.out.String())
	}
	if err := os.WriteFile(v2, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.now = rig.now.Add(keyRetryInterval)
	rig.with(func() { rig.r.poll(context.Background()) })
	if vs := rig.r.keys.Set("k").Versions; len(vs) != 2 || vs[0].Number != 2 {
		t.Fatalf("the policy did not load once its file appeared: %d versions\n%s", len(vs), rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatal("port49_policy_file_refused still 1")
	}
}

// A refusal that is the policy's own fault (outside the allowance) is not
// retried: only an edit fixes it.
func TestAPolicyFaultIsNotRetried(t *testing.T)
```
In the second test, the policy names `env:PORT49_ENC_V2`; after `pollTwice` and two `keyRetryInterval` steps the output holds one refusal and `rig.r.keyWait.v` is `""`.

A key-line test in `internal/port49d/reload_test.go`:
```go
// A swap that changes the key sets says which versions it added, retired and
// removed, and the notices of spec §10 (pre-flight I8).
func TestASwapSaysItsKeyChanges(t *testing.T)
```
It sets `PORT49_KEY_RUN` and `PORT49_KEY_RUN2`, and gives the rig its keys as the two reload tests above do: `rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{}.WithDefaults())`, built from the rig's policy and put (re-review N5: `swap` says nothing while `r.keys` is nil). It swaps (`swapTo`) from `minimalPolicy` to one whose `k` adds version 2 (`env:PORT49_KEY_RUN2`) as current and keeps 1 in `accept` with no `retire_after`, then asserts the output holds "keys: k: version 2 added" and "key k version 1 has no retire_after". It then swaps to the same policy with one role's `permit` changed, and asserts the notice is said a second time and the "keys: k:" line is not (re-review N4: the notices follow every reload, the key line only a change).
That the server reads its keys through `liveKeys.Set` at every Accept is Task 6's wiring (`deps.Keys = keysFor`) and Task 7's per-packet read. `TestThePolicyOnlyDaemonAdmitsALogin` (`broker_test.go:513`) logs a device in end to end on the migrated fixtures, which proves the wiring.

`internal/policy/admit_test.go`: rewrite the tests that set `e.KeyRefs` (`TestKeyGroupsInThePolicyAssignAndAdmit`, `TestAKeyRefPort49dDoesNotHoldRefusesTheDevice` and the others `grep -n KeyRefs internal/policy/*_test.go` lists). Each drops `e.KeyRefs` and appends a `keys:` block defining the same names to its policy body. The refusal text they assert changes to the new wording below.

`internal/port49d/broker_test.go`, a start refusal:
```go
// A policy with no keys: block is refused at start, by port49d and by
// port49-broker: it is the one place port49 learns key names (decision 53
// ruling 3).
func TestAPolicyWithNoKeysBlockRefusesTheStart(t *testing.T)
```
It writes `writeRunConfig`'s policy without the block and asserts `run` returns an error containing "declares no keys: block" (use `runExpectingRefusal`, `broker_test.go:484`). A second case starts port49d on a policy with a `keys:` block and asserts the start says "key k version 1 has no retire_after" when its `accept` version has none (the notices at start, pre-flight I8).

`internal/port49d/startguard_test.go`, the first start after the upgrade (pre-flight M14):
```go
// The bundle last judged before the upgrade was recorded with no keys:
// block. The first start after the upgrade is still judged against it: the
// guard compiles the recorded policy and never refuses it for a block it
// predates, so a new file that takes a device out of service is refused.
func TestTheFirstStartAfterTheUpgradeIsJudgedAgainstAPolicyWithNoKeysBlock(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.MaxRemovedPercent = 20
	inv := cfg.Inventory
	before := strings.Replace(minimalPolicy, runKeys, "", 1) // as recorded before the upgrade
	if strings.Contains(before, "keys:") {
		t.Fatal("the recorded policy must have no keys: block")
	}
	good, err := parseBundle(cfg, []byte(minimalPolicy), inv)
	if err != nil {
		t.Fatal(err)
	}
	none, err := parseBundle(cfg, []byte(quarantiningLeaf1), inv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now()
	recorded := judgedAt{rec: etcdstore.JudgedRecord{Bundle: "b-before-upgrade", Policy: []byte(before)}, ok: true}
	if refused, said := guardAtStart(ctx, cfg, recorded, good, now); refused != nil || said != "" {
		t.Fatalf("the same policy with its keys: block added is judged and passes: %v %q", refused, said)
	}
	refused, said := guardAtStart(ctx, cfg, recorded, none, now)
	var sr *startRefusal
	if !errors.As(refused, &sr) || sr.bundle != "b-before-upgrade" || said != "" {
		t.Fatalf("a file quarantining leaf1 is refused against the pre-upgrade record: %v %q", refused, said)
	}
}
```
The file gains a `strings` import. Before the fix both cases return `nil` and "does not compile against the inventory in force", since `parseBundle` refuses the recorded policy for its missing block. Mutation: point `guardAtStart` back at `parseBundle`; the test turns red.

`internal/config/config_test.go`:
```go
// keys: beside a policy is refused: the policy's keys: block is the one in
// force (decision 53 ruling 3); and port49-broker.yaml's key_refs is gone.
func TestKeysBesideAPolicyIsRefused(t *testing.T)
```
It loads a port49d.yaml with `policy: {file: …}`, a `stores` etcd block (or a `broker:` block, whichever an existing config test that loads a policy uses: `grep -n 'policy: {file' internal/config/*_test.go`), and `keys:`; then the same with `keys: {}` (pre-flight M10). Each expects "keys: is the policy file's". It then loads a port49-broker.yaml with `key_refs: [k]` and expects "key_refs was replaced by the policy's keys: block".

```go
// A port49d.yaml secret a policy could name is refused (decision 53 ruling
// 12): the allowance and port49d.yaml's own secrets never meet.
func TestAConfigSecretInsideTheAllowanceIsRefused(t *testing.T)
```
It loads a port49d.yaml with a policy whose `encryption.current.secret_ref` is `env:PORT49_KEY_ENC` and expects "is inside key_secret_refs"; then `key_secret_refs: {env_prefix: P}` and expects "env_prefix"; then `key_secret_refs` in a port49-broker.yaml and expects the broker-role refusal. Then, each with a policy (re-review N1):
- `broker.directory.bind.password_secret_ref: env:PORT49_KEY_BIND`: "is inside key_secret_refs";
- `encryption.current.secret_ref: file:<real>/enc`, where `file_dir` is a link to `<real>`: refused, though no text matches;
- `tls_listener.key_file` under `file_dir`: "tls_listener.key_file … overlaps key_secret_refs.file_dir";
- `broker.directory.bind.keytab_file` at a link inside `file_dir`: refused;
- the in-process broker's state directory equal to `file_dir`, and `file_dir` below it: each refused;
- a `tls_listener.key_file` beside `file_dir` (`<dir>x/key.pem` for `file_dir: <dir>`): loads.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/port49d/ ./internal/policy/ ./internal/config/ -run 'LiveKeys|Rekeys|KeysBlock|UpgradeIsJudged|KeysBeside|KeepsTheKeysInForce|KeyGroups|KeyRef|Allowance|FileAppears|NotRetried|KeyChanges|LinkingOut' -count=1`
Expected: FAIL: `newLiveKeys` undefined; `Env.KeyRefs` still compiles; the policy with no `keys:` starts.

- [ ] **Step 3: Implement.**

1. **policy.** Delete `Env.KeyRefs`. In `admit`, the unknown-key refusal becomes:

```go
		if r.Refused == "" && d.EffectiveTransport() != admission.TransportTLS && p.keysDeclared {
			if _, ok := p.keys[r.KeyRef]; !ok {
				// A refused entry carries no key_ref, since a reader takes one as
				// admitted; the text names the key instead (Task 3 review M3).
				r.Refused, r.Refusal = fmt.Sprintf("is assigned key_ref %s, which the policy's keys: block does not "+
					"define, so it fails closed (spec §10)", r.KeyRef), admission.RefusedUnknownKey
				r.KeyRef = ""
			}
		}
```
`AdmissionAssessed` returns `len(p.keyGroups) > 0 || p.keysDeclared`. Update the comments on `admit`, `AdmissionRefusals` and `AdmissionAssessed` that name `Env.KeyRefs` or "port49d.yaml".

2. **bundle.** `KeyRefsFile = "the key sets the policy file's keys: block defines"`. In `internal/port49d/reload.go`, remove the `{bundle.KeyRefsFile, …"port49-broker.yaml"…}` rewrite pair, since both processes now read the same file, and its test entry (`grep -n KeyRefsFile internal/port49d/*_test.go`).

3. **config.**
   - Delete `fileConfig.KeyRefs`, `Config.keyRefs`, `checkKeyRefList` and `Config.KeyRefs()`.
   - In `load`, replace the role branch that calls `checkKeyRefList`/`resolveKeys` with:

```go
	switch {
	case f.Keys != nil && c.Policy != nil: // `keys: {}` too (pre-flight M10)
		return Config{}, fmt.Errorf("config: keys: is the policy file's when port49d has a policy (spec §10; "+
			"decision 53 ruling 3): move the block into %s and remove it here", c.Policy.File)
	case role == RoleDaemon && c.Policy == nil:
		if err := resolveKeys(&c, raw); err != nil {
			return Config{}, err
		}
	}
```
   - Replace the old branch where it stands (just after `checkStores` and the seed-token check). It already runs after the `switch` that sets `c.Policy`.
   - `brokerRefusals`' `keys:` entry reads "device keys are the policy file's keys: block", and it gains `key_secret_refs` ("port49-broker reads key names, never a key's secret"). Delete the default-role check "key_refs is port49-broker.yaml's" (the field is gone). The `yamlfault.Replaced` map (Task 4) gains `"key_refs": "the policy's keys: block (decision 53 ruling 3)"`.
   - **The allowance** (decision 53 ruling 12). `fileConfig` gains `KeySecretRefs *secretref.Allowance \`yaml:"key_secret_refs"\``, and `Config` gains `KeySecretRefs secretref.Allowance` ("where a policy's key references may point; DefaultAllowance's values where port49d.yaml names none"). In `load`, for port49d's role, after the encryption keys are read:

```go
	allow := secretref.Allowance{}
	if f.KeySecretRefs != nil {
		allow = *f.KeySecretRefs
	}
	c.KeySecretRefs = allow.WithDefaults()
	if err := c.KeySecretRefs.Check(); err != nil {
		return Config{}, fmt.Errorf("config: key_secret_refs: %w", err)
	}
	if c.Policy != nil {
		if err := secretsApart(f, c); err != nil {
			return Config{}, err
		}
	}
```
     In `internal/config/allowance.go`:

```go
// secretsApart refuses a secret or key material port49d.yaml names that a
// policy could name too (decision 53 ruling 12; re-review N1): the policy
// could put it in force as a device key. Each secret_ref is held to Allows,
// and a file: one to file_dir by path as well; each key file, and the
// broker's state directory, to file_dir by path.
func secretsApart(f fileConfig, c Config) error {
	allow := c.KeySecretRefs
	for at, text := range ownSecretRefs(f) { // encryption.current/previous, broker.directory.bind
		ref, err := secretref.Parse(text)
		if err != nil {
			continue // its own check refuses it
		}
		if allow.Allows(ref) || ref.Scheme == secretref.SchemeFile && within(ref.Name, allow.FileDir) {
			return fmt.Errorf("config: %s %s is inside key_secret_refs (%s), so a policy could name it as a "+
				"device key; name it outside (decision 53 ruling 12)", at, text, allow)
		}
	}
	for at, p := range ownKeyPaths(c) {
		if within(p.path, allow.FileDir) || p.dir && within(allow.FileDir, p.path) {
			return fmt.Errorf("config: %s %s overlaps key_secret_refs.file_dir %s, so a policy could name the "+
				"key material there as a device key; keep them apart (decision 53 ruling 12)", at, p.path,
				allow.FileDir)
		}
	}
	return nil
}

// within reports whether path is dir or below it, compared as written and
// again with links resolved, as fence.ReadSecret resolves them: a link
// either way must not hide an overlap.
func within(path, dir string) bool {
	return under(abs(path), abs(dir)) || under(resolved(path), resolved(dir))
}
```
     - `ownSecretRefs` returns the key path and reference text of each `secret_ref` port49d.yaml names, in a map.
     - `ownKeyPaths(c)` returns `map[string]keyPath` (`type keyPath struct{ path string; dir bool }`), keyed by the YAML path: `tls_listener.key_file`, `broker.tls_key_file`, `inventory_service.tls_key_file`, `broker.directory.bind.tls_key_file` and `.keytab_file`, each `stores.*.etcd` identity's `key_file` (`git grep -n 'yaml:"\(tls_\)\?key_file"\|keytab_file' internal/config` lists them), and, with a `broker:` block, `config.BrokerStateDir(c.Broker)` with `dir: true`. Empty paths are skipped.
     - `under(path, dir)` is `path == dir || strings.HasPrefix(path, dir+"/")` on clean paths. `abs` is `filepath.Abs`, kept as written on error. `resolved(p)` is `filepath.EvalSymlinks` of `p`, or, when `p` does not exist yet (a `file_dir` the agent has not created), of its nearest existing ancestor joined with the rest.

4. **Server and admin.** `server.Deps.Keys func(keyRef string) keyring.Set` (doc: "the key set in force for keyRef: the policy's, re-read at each reload (decision 53), or port49d.yaml's with no policy; nil holds none"). A nil map read safely and a nil func does not, so add:

```go
// keysFor is Keys(ref), or no key set when Keys is nil (a TLS-only or test
// Deps), as a nil map's read was.
func (d Deps) keysFor(ref string) keyring.Set {
	if d.Keys == nil {
		return keyring.Set{}
	}
	return d.Keys(ref)
}
```
   `conn` setup at `server.go:199` reads `cc.keys = d.keysFor(dev.KeyRef)`. `admin.Server.Keys func() map[string]keyring.Set`, and `admin.go:335` calls `keyring.Diagnose(s.Held, s.Keys(), …)`. Update `internal/daemon/server/server_test.go:217` and every other `Keys: map[...]...` in the tests to `Keys: func(ref string) keyring.Set { return m[ref] }`. `newTestServerWith` defines the map once.

5. **liveKeys**, `internal/port49d/livekeys.go`:

```go
package port49d

// liveKeys is the device keys in force (spec §10; decision 53 rulings 2, 3):
// the policy's key sets with each version's secret, built before every swap
// and put in force with it, so a reload that adds or retires a version
// reaches the next packet. Each reference is read once per process and held
// by its text: a version's secret never changes, so a build reads only the
// versions it has not seen. Nil holds no key: port49-broker's, which never
// answers a device.
type liveKeys struct {
	res   *secretref.Resolver
	allow secretref.Allowance // key_secret_refs: where a reference may point
	mu    sync.Mutex
	held map[string][]byte // reference text → secret
	in   atomic.Pointer[keyBuild]
}

// keyBuild is one policy's keys, ready to put in force: the keyring by
// key_ref, and each version's reference, by key_ref and version number.
type keyBuild struct {
	sets map[string]keyring.Set
	refs map[string]map[int]string
}

// keyUnreadError is a build refused because a secret could not be read: a
// file not rendered yet, an unset variable, a mode to fix. The reloader
// tries it again (decision 53 ruling 2); any other refusal is the policy's.
type keyUnreadError struct{ err error }

func (e *keyUnreadError) Error() string { return e.err.Error() }
func (e *keyUnreadError) Unwrap() error { return e.err }

func newLiveKeys(res *secretref.Resolver, allow secretref.Allowance) *liveKeys {
	if res == nil {
		// A Config built by hand, as tests build one, has no resolver:
		// env: and file: still read.
		res = secretref.New()
	}
	k := &liveKeys{res: res, allow: allow.WithDefaults(), held: map[string][]byte{}}
	k.in.Store(&keyBuild{sets: map[string]keyring.Set{}, refs: map[string]map[int]string{}})
	return k
}

// build reads every reference pol names that is not held, and refuses a
// version whose reference differs from the one in force for that version.
// It changes nothing in force; put does.
func (k *liveKeys) build(pol *policy.Policy) (keyBuild, error) {
	if k == nil {
		return keyBuild{}, nil
	}
	sets := pol.KeySets()
	in := k.in.Load()
	k.mu.Lock()
	defer k.mu.Unlock()
	b := keyBuild{refs: map[string]map[int]string{}}
	fresh := map[string][]byte{}
	for _, ref := range keyset.Sorted(sets) {
		b.refs[ref] = map[int]string{}
		for _, v := range sets[ref].All() {
			at := fmt.Sprintf("keys.%s version %d secret_ref", ref, v.Version)
			r, err := secretref.Parse(v.SecretRef) // keyset.Check parsed it already
			if err != nil {
				return keyBuild{}, fmt.Errorf("%s %w", at, err)
			}
			text := v.SecretRef // a reference's one spelling (Task 4)
			if !k.allow.Allows(r) {
				// Before anything is read: a policy writer must not choose which of
				// the host's secrets becomes a device key (decision 53 ruling 12).
				return keyBuild{}, fmt.Errorf("%s %s is outside key_secret_refs (%s): a policy names only the "+
					"secrets port49d.yaml allows it (decision 53 ruling 12)", at, text, k.allow)
			}
			if was, ok := in.refs[ref][v.Version]; ok && was != text {
				return keyBuild{}, fmt.Errorf("keys.%s version %d names secret_ref %s, and the policy in force names "+
					"%s for it: a version's secret never changes (spec §10), so add a version instead", ref, v.Version,
					text, was)
			}
			b.refs[ref][v.Version] = text
			if _, ok := k.held[text]; ok {
				continue
			}
			if _, ok := fresh[text]; ok {
				continue
			}
			s, err := k.res.Resolve(r, k.allow.FileDir)
			if err != nil {
				return keyBuild{}, &keyUnreadError{fmt.Errorf("%s %w", at, err)}
			}
			fresh[text] = s.Bytes()
		}
	}
	for text, s := range fresh {
		k.held[text] = s
	}
	b.sets = keyset.Keyring(sets, func(text string) []byte { return k.held[text] })
	return b, nil
}

// put puts b in force and lets go of every secret no version in it names.
func (k *liveKeys) put(b keyBuild) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	named := map[string]bool{}
	for _, vs := range b.refs {
		for _, text := range vs {
			named[text] = true
		}
	}
	for text := range k.held {
		if !named[text] {
			delete(k.held, text)
		}
	}
	k.in.Store(&b)
}

// Set is the key set in force for ref; the zero Set for one none defines.
func (k *liveKeys) Set(ref string) keyring.Set { return k.in.Load().sets[ref] }

// All is every key set in force.
func (k *liveKeys) All() map[string]keyring.Set { return k.in.Load().sets }
```
Building `keyBuild.sets` reads `k.held`, filled before it. A build that fails after reading some references leaves them unheld (`fresh` is dropped), so a later build reads them again.

Beside it, the swap's key line (pre-flight I8):
```go
// keyChanges is the line a swap says when it changes the key sets: each
// version added, retired (moved to retired) and removed, and what that does
// to open connections; "" when nothing changed.
func keyChanges(old, new map[string]keyset.Set) string
```
Its format: `keys: k: version 2 added; k: version 1 retired (connections on it reset at their next packet, with no strike)`, key_refs in `keyset.Sorted` order, versions ascending.

6. **port49d's start** (`internal/port49d/main.go`):
   - `parseBundle` splits in two. `compileBundle` is today's body: `bundle.Parse`, wrapped as `parseBundle` wraps it now. `parseBundle` calls it and then refuses a policy with no block. Every file port49d reads goes through `parseBundle`; only `guardAtStart` (`startguard.go:57`) calls `compileBundle`, since the policy meta/judged recorded may predate the upgrade and must still judge the first start after it (pre-flight M14). With no block declared, `admit` refuses no device for its key_ref (item 1), so the recorded policy admits what it admitted when it was judged, and a new file whose block omits a key a key group names counts those devices as removed. Update `guardAtStart`'s doc comment to say so.

```go
// compileBundle compiles raw against inv, with no keys: requirement: the
// start guard's reading of a policy recorded before the policy carried its
// keys (pre-flight M14). Every file port49d reads goes through parseBundle.
func compileBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := bundle.Parse(raw, inv, policyEnv(cfg))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, quotesCut{err})
	}
	return pol, nil
}

func parseBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := compileBundle(cfg, raw, inv)
	if err != nil {
		return nil, err
	}
	if !pol.KeysDeclared() {
		return nil, fmt.Errorf("%s %s: the policy declares no keys: block, so %s knows no key name (decision 53 "+
			"ruling 3); add the key sets beside key_groups, or `keys: {}` for a fleet all on TLS",
			policyKey(cfg), cfg.Policy.File, procOf(cfg))
	}
	return pol, nil
}
```
   - After `live` is set (`main.go` ~:1039) and only on port49d's role:

```go
	var dk *liveKeys
	if live != nil {
		dk = newLiveKeys(cfg.Secrets, cfg.KeySecretRefs)
		kb, err := dk.build(live.Load())
		if err != nil {
			stopSpool()
			<-spoolDone
			return fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, err)
		}
		dk.put(kb)
		// spec §10: a version whose retire_after has passed, an accept version
		// with none, said at start as config's notices were.
		for _, n := range keyset.Notices(live.Load().KeySets(), time.Now()) {
			fmt.Fprintf(stderr, "%s: %s\n", procOf(cfg), n)
		}
	}
```
   A start refused because a secret could not be read exits, as an unset variable did: systemd and Kubernetes restart it, and it starts once the file is there. Only a running port49d retries (item 7).
   - The key wiring at ~:1181 becomes:

```go
	keysFor, allKeys := keysOf(cfg, dk)
	seen := &keyring.Seen{}
	m.WatchKeys(func() []metrics.KeySample {
		var out []metrics.KeySample
		sets := allKeys()
		for _, ref := range slices.Sorted(maps.Keys(sets)) {
			for _, v := range sets[ref].Versions {
				out = append(out, metrics.KeySample{KeyRef: ref, Version: v.Number, Devices: seen.Count(ref, v.Number),
					RetireAt: v.RetireAt})
			}
		}
		return out
	}, time.Now)
```
     with:

```go
// keysOf is the key set lookups port49d serves from: the policy's in force
// (dk), or with no policy port49d.yaml's, read once at load.
func keysOf(cfg config.Config, dk *liveKeys) (func(string) keyring.Set, func() map[string]keyring.Set) {
	if dk != nil {
		return dk.Set, dk.All
	}
	ring := cfg.Keyring()
	return func(ref string) keyring.Set { return ring[ref] }, func() map[string]keyring.Set { return ring }
}
```
   - `deps.Keys = keysFor`; the admin server's `Keys: allKeys`; and `r.keys = dk` where the reloader is built (`main.go` ~:1482).
   - port49-broker's reloader (`brokerd.go:849`) leaves `keys` nil.

7. **The reloader** (`internal/port49d/reload.go`): `reloader` gains `keys *liveKeys`. `swap` takes the build:

```go
func (r *reloader) swap(pol *policy.Policy, kb keyBuild) time.Time {
	if r.beforeSwap != nil {
		r.beforeSwap(pol)
	}
	old := r.live.Load()
	// The keys go in force first (re-review N3): a connection accepted
	// between the two steps for a device the new policy assigns a new key_ref
	// finds its key set, and is not struck for port49d's own reload. Keys the
	// old policy alone named stay held a moment longer, which is harmless.
	r.keys.put(kb)
	r.live.Swap(pol)
	if r.keys != nil {
		if line := keyChanges(old.KeySets(), pol.KeySets()); line != "" {
			r.sayf("%s\n", line)
		}
		// spec §10: the notices after every reload, the keys changed or not,
		// so a retire_after that passes between two reloads is said at the
		// next one (re-review N4).
		for _, n := range keyset.Notices(pol.KeySets(), r.now()) {
			r.sayf("%s\n", n)
		}
	}
	…
```
   In each of the four paths that call `r.swap(pol)` (`grep -n 'r.swap(' internal/port49d/reload.go`), extend the error chain that ends before the swap with the key build. For example, in `loadBoth`:

```go
	pol, err := parseBundle(r.cfg, raw, inv)
	if err == nil {
		err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, fix)
	}
	…
	var kb keyBuild
	if err == nil {
		kb, err = r.keys.build(pol)
	}
	if err != nil {
		… (unchanged: the refusal is said and counted as the path does for any fault)
	}
	…
	now := r.swap(pol, kb)
```
   An inventory-only reload builds too: its policy bytes are those in force, every reference is held, and nothing is read.

   **The retry** (decision 53 ruling 2; pre-flight I4), in `internal/port49d/keyretry.go`:

```go
// keyRetryInterval is how often a policy refused because a key's secret
// could not be read is tried again: half kubelet's default Secret sync period
// (60s), so a key a Secret volume or an agent renders is in force within
// about half a minute of its file appearing, at the cost of one open per
// unread reference per try.
const keyRetryInterval = 30 * time.Second

// keyRetrySayEvery bounds how often a try that fails again is said.
const keyRetrySayEvery = 10 * time.Minute

// keyWait is a policy version refused because a key's secret could not be
// read. It is tried again until it loads or the file holds another version.
type keyWait struct {
	v     string    // the policy version waiting
	next  time.Time // when the poll tries it again
	said  time.Time // when its refusal was last said
	tries int       // tries since then
}

// waitForKeys records a refusal of version v for err and reports whether to
// say it, with the note to add: a key secret that could not be read is said
// in full the first time and on SIGHUP, and then at most every
// keyRetrySayEvery; any other refusal is said as before and not retried.
func (r *reloader) waitForKeys(v, trigger string, err error) (say bool, note string) {
	var unread *keyUnreadError
	if !errors.As(err, &unread) {
		r.keyWait = keyWait{}
		return true, ""
	}
	now := r.now()
	if r.keyWait.v != v {
		r.keyWait = keyWait{v: v, next: now.Add(keyRetryInterval), said: now}
		return true, fmt.Sprintf("; tried again every %v until it can be read or the policy changes",
			keyRetryInterval)
	}
	r.keyWait.tries++
	r.keyWait.next = now.Add(keyRetryInterval)
	if trigger != "SIGHUP" && now.Sub(r.keyWait.said) < keyRetrySayEvery {
		return false, ""
	}
	note = fmt.Sprintf("; still waiting: %d tries since %s, every %v", r.keyWait.tries,
		r.keyWait.said.UTC().Format(time.RFC3339), keyRetryInterval)
	r.keyWait.said, r.keyWait.tries = now, 0
	return true, note
}

// retryKeys tries the waiting policy again: at once for a trigger, else when
// due. A file that now holds another version ends the wait; the watch loads
// that one.
func (r *reloader) retryKeys(ctx context.Context, trigger string) {
	w := r.keyWait
	if w.v == "" {
		return
	}
	if w.v != r.refused {
		r.keyWait = keyWait{}
		return
	}
	if trigger == "" {
		if r.now().Before(w.next) {
			return
		}
		trigger = "key secret retry"
	}
	raw, v, err := policyVersion(r.cfg.Policy.File)
	if err != nil || v != w.v {
		r.keyWait = keyWait{}
		return
	}
	if r.load(ctx, trigger, raw, v, nil) {
		r.keyWait = keyWait{}
		r.retryInventory(ctx, trigger)
	}
}
```
   - `reloader` gains `keyWait keyWait`.
   - In `load`'s refusal branch (`reload.go` ~:1070), replace the counter, the line and `r.refused = v` with:

```go
		say, note := r.waitForKeys(v, trigger, err)
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		if say {
			r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
			r.sayf("policy reload (%s) refused; still serving %s (bundle %s): %s%s\n", trigger,
				old.Source, old.Bundle, refusalLine(r.procName(), err, false, old, pol), note)
		}
		return false
```
     and do the same in `loadBoth`'s refusal branch for the policy's half.
   - `poll` calls `r.retryKeys(ctx, "")` first. Each path that swaps an inventory in (`loadInventory`, `loadDocument`) calls `r.retryKeys(ctx, "inventory reloaded")` after its swap: a trigger tries at once. SIGHUP's `reload` already loads the policy file whatever it was.
   - The refusal line already names the key, version and reference (`TestAReloadWhoseSecretCannotBeReadKeepsTheKeysInForce`); the note says how it clears.

8. **Comments.** `internal/inventory/sync.go:523` becomes "The service judges admission with the policy's own key names (its keys: block), as port49d does". In `internal/port49d/directory.go`, `policyEnv` drops `KeyRefs: cfg.KeyRefs()`. In `cmd/port49`, `loadWith(keyRefs)` goes: `files.load()` is `bundle.Load(f.policy, f.inventory, policy.Env{})` (Task 8 removes the callers' `--config`; here make them compile by passing nothing).

9. **Fixtures.** Each place below now carries its keys in the policy:
   - **port49d tests.** `writeRunConfigWith` (`internal/port49d/broker_test.go:451`) drops its `keys:` block. Every policy body a port49d or port49-broker test writes gains:

```yaml
keys:
  k:
    current: {version: 1, secret_ref: env:PORT49_KEY_RUN}
```
     naming the key_refs its key groups use (`k` in most; `prod_key` where the inventory says so). Find them with `git grep -ln 'platform_set\|privilege_levels' -- 'internal/port49d/*_test.go'` and `git grep -n 'writePolicyFile\|PolicyFile:' -- 'internal/port49d/*_test.go'`.
     - A helper in `internal/port49d/daemon_test.go`, `const runKeys = "keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_RUN}\n"`, appended where a body lacks a top-level `keys:`, keeps this mechanical. `minimalPolicy` (`broker_test.go:108`) ends with it, since Task 6's reload test replaces it by text. A policy that is only parsed (the reload rig, `buildBroker`) reads no secret. Only a test that runs port49d's start, which builds `liveKeys`, needs the variable set: `writeRunConfigWith` sets `PORT49_KEY_RUN` beside `T_RUN_SECRET` (which a no-policy port49d.yaml's own `keys:` still names). The variable is inside the default allowance, so the tests run port49d with no `key_secret_refs`, as a fleet that keeps the defaults does.
     - Do not hide it in `writePolicyFile`: a test whose subject is a policy with no `keys:` must be able to write one.
   - **The qualification policy.** `tests/qual/qual-policy.yaml` gains `keys: {k: {current: {version: 1, secret_ref: env:PORT49_KEY_RUN}}}` (with the key_ref its key groups name). `TestQual` (`internal/port49d/qual_test.go:234`, `:513`, `:785`) feeds it to a real port49d, as do `make qual-fleet` and the lab vetting cells (`tests/lab/qual_evidence.go`); set `PORT49_KEY_RUN` wherever they set `T_RUN_SECRET`. Run `make qual` and update any golden that embeds the bundle hash (`git grep -n 'bundle' -- tests/qual internal/port49d/qual_test.go`).
   - **Other packages.** Tests that loaded with `policy.Env{KeyRefs: …}` (`git grep -n 'KeyRefs' -- '*_test.go'`: `internal/broker/refresh_test.go`, `internal/broker/explain_api_test.go`, `internal/bundle/diff_test.go`, `internal/config/broker_role_test.go`, `internal/policy/*_test.go` (`generic_test.go` among them), `internal/inventory/sync_test.go`, `cmd/port49/*_test.go`, `tests/lab/l29_unit_test.go`) drop the field and add the block to their policy.
   - **Deploy and examples.** `deploy/compose/config/policy.yaml` gains the block that `deploy/compose/config/port49d.yaml`'s `keys:` held, as `k` with `secret_ref: env:PORT49_KEY_TACACS`. The variable is renamed from `PORT49_TACACS_KEY` where it is made: `internal/testpki/compose.go:66` writes it into the generated `port49d.env`, and `internal/testpki/compose_test.go:57,61` and the smoke's key reader (`git grep -n PORT49_TACACS_KEY -- ':!docs/' ':!*.env'`) follow. No env file is read or edited by hand. The `keys:` block leaves `port49d.yaml`, and `key_refs: [k]` leaves `port49-broker.yaml`. Then:
     - `make compose-smoke` must still pass where Docker is available (the CI job runs it);
     - `examples/kubernetes/policy.yaml` gains a `keys:` block, and `examples_test.go`'s port49d.yaml loses its own, if the test loads the two together;
     - a lab configuration with a policy (`tests/lab/localbroker_test.go`, `l67_test.go`, `l69_test.go`, `l72_test.go`, `l74_test.go`, `l75_test.go`, `l33_test.go`, `tests/lab/l29/policy.yaml`, `tests/lab/quarantine-sync/*.yaml`: `git grep -ln 'policy_file\|policy:' -- tests/lab`) moves its `keys:` into the policy it writes, its variable renamed into the `PORT49_KEY_` prefix where the harness sets it.
   - `tests/lab/port49d-lab.yaml` has no policy: its `keys:` stays.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/... ./cmd/... ./examples/... -count=1 && make lab-unit && make qual`
Expected: PASS.

- [ ] **Step 5: Check nothing still reads keys from port49d.yaml beside a policy**

Before running it, reword the comments that still say `key_refs` for what is now the policy's `keys:` block: `internal/decision/log.go:435`, `internal/bundle/bundle.go:28`, `internal/bundle/diff.go:469` and `:489`, `internal/policy/load.go:46`, `internal/port49d/reload.go:76`.

Run: `git grep -n 'KeyRefs\|key_refs' -- '*.go' '*.yaml' ':!docs/' ':!tests/lab/results/'`
Expected: only `bundle.KeyRefsFile` and its uses, the `key_refs` entry in config's `yamlfault.Replaced` map, and `TestKeysBesideAPolicyIsRefused`.

- [ ] **Step 6: Verify and commit**

Run `make test && make vet`, then:
```bash
git add -A internal cmd deploy examples tests/lab tests/qual
git commit -m "feat: the device key sets are the policy's, read at every reload

port49d.yaml's keys: is refused beside a policy, port49-broker.yaml's key_refs
is removed, a reload that re-keys a version is refused, a policy names only
the secrets key_secret_refs allows, and a reload waiting on a secret file is
retried until it loads (decision 53 rulings 2, 3 and 12).

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 7: A reload that retires or removes a version ends its open connections

**Files:**
- Modify: `internal/daemon/server/conn.go` (`deobfuscate`, ~:480)
- Test: `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: `Deps.Keys func(string) keyring.Set` and `Deps.keysFor` (Task 6).

- [ ] **Step 1: Write the failing test** in `internal/daemon/server/server_test.go`, beside the `retire_after` tests (`grep -n 'retire_after\|pastDate\|matches_retired' internal/daemon/server/server_test.go`):

```go
// A reload that retires the version an open connection validated under ends
// it at its next packet: matches_retired and a reset, with no strike, since
// the change is port49d's (spec §10; decision 53 ruling 4). A device already
// on the new version is served at once. A reload that only adds a version
// changes nothing.
func TestAReloadThatRetiresTheVersionEndsItsConnectionWithoutAStrike(t *testing.T) {
	var log syncBuffer
	var mu sync.Mutex
	sets := map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{{Number: 2, Secret: []byte("k2")}}}}
	ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
		d.Keys = func(ref string) keyring.Set { mu.Lock(); defer mu.Unlock(); return sets[ref] }
	})
	c := dial(t, ts.addr, []byte("k2"))
	login := func(sid uint32, tok string) {
		c.sid, c.seq = sid, 1
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: "alice", Data: []byte(tok)}, wire.FlagSingleConnect)
		c.recv(t) // a reply: the connection still speaks version 2
	}
	login(100, "p49_e2e")
	mu.Lock()
	sets["prod_key"] = keyring.Set{Ref: "prod_key", Versions: []keyring.Version{{Number: 3, Secret: []byte("k3")},
		{Number: 2, Secret: []byte("k2")}}}
	mu.Unlock()
	login(101, "p49_second") // adding version 3 changed nothing for this connection
	mu.Lock()
	sets["prod_key"] = keyring.Set{Ref: "prod_key", Versions: []keyring.Version{{Number: 3, Secret: []byte("k3")},
		{Number: 2, Secret: []byte("k2"), Retired: true}}}
	mu.Unlock()
	// a third START is reset with no reply, and the record says matches_retired
	c.sid, c.seq = 102, 1
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: "alice", Data: []byte("p49_third")}, wire.FlagSingleConnect)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
		t.Fatalf("no matches_retired record: %s", log.String())
	}
	// No strike: the source is not held, and a device re-provisioned with
	// version 3 is served on its next connection, not refused at Accept.
	if ts.limits.Holding(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a reload's own withdrawal struck the device")
	}
	if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("key_miss_closed")); got != 0 {
		t.Fatalf("counted as a key miss: %v", got)
	}
	c3 := dial(t, ts.addr, []byte("k3"))
	c3.sid, c3.seq = 103, 1
	c3.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: "alice", Data: []byte("p49_fourth")})
	c3.recv(t)
}
```
A version whose `retire_after` passes is still struck, as spec §10 says: `TestAPacketPastItsDateIsClosedWithAReset` (`server_test.go:1866`) pins it and stays as it is. It must still pass after Step 3, and Step 3 must not change what it asserts.
The client calls (`c.send`, `c.recv`, the `AuthenStart` fields, how a single-connect flag is passed, and the second token `p49_second` put in the store first) are those of `TestSingleConnectServesTwoExchanges` (`server_test.go:989`). Copy its exact call shapes where they differ from the sketch above, and its `st.PutToken` calls for `p49_second`, `p49_third` and `p49_fourth`. Add a second case where the reload removes version 2 altogether: the same reset, and the same absence of a strike.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/daemon/server/ -run 'TestAReloadThatRetires|TestAPacketPastItsDate' -count=1`
Expected: FAIL: the third packet is answered, because the connection holds the set it was given at Accept.

- [ ] **Step 3: Implement.** In `deobfuscate`, at the top of the branch for packets after the first, before `if s.pastDate(s.d.Now())`:

```go
	// The key set in force for this device, read again at every packet: a
	// reload that retired or removed the version this connection speaks ends
	// it here (decision 53 ruling 4).
	s.keys = s.d.keysFor(s.dev.KeyRef)
	if s.withdrawnByReload(s.d.Now()) {
		// port49d's change, not the device's: one record and a reset, with no
		// strike, as every reload's withdrawal is (spec §10, "How a daemon
		// refreshes its snapshot"). The device is still admitted, so there is
		// no decline window either: its next connection is served, on the new
		// version or struck then for the old one.
		s.d.Metrics.KeyValidations.WithLabelValues(s.keys.Ref, strconv.Itoa(s.version),
			string(keyring.DiagMatchesRetired)).Inc()
		s.unvalidated(h, obf, keyring.DiagMatchesRetired, s.version)
		s.reset()
		return nil, false
	}
```
and beside `pastDate`:

```go
// withdrawnByReload reports whether a reload took the version this
// connection validated under out of service: removed it, or listed it as
// retired before its retire_after passed. A version past its date is
// pastDate's, and struck.
func (s *conn) withdrawnByReload(now time.Time) bool {
	for _, v := range s.keys.Versions {
		if v.Number == s.version {
			return v.Retired && (v.RetireAt.IsZero() || now.Before(v.RetireAt))
		}
	}
	return true
}
```
`pastDate` keeps its meaning (the date) and its comment.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/daemon/server/ -count=1`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/daemon/server
git commit -m "fix: a reload that retires a key version ends its open connections, with no strike

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 8: The CLIs read the key sets from the policy

**Files:**
- Modify: `cmd/port49/keys.go` (`readKeySets`, `keyRefsOf`, `statusKeys`, `keysStatus`, `keysShow`), `cmd/port49/policy.go` (`policyFiles.load`, `policyTest`, `keyReports`, `policyDiff`), `cmd/port49/inventory.go` (`--config`, the unchecked-key_refs verdict at :124–127), `cmd/port49/usage.go` or wherever `usage` is defined
- Modify: `internal/config/config.go` (`KeySets` deleted, and `KeySecretRefsOf`), `internal/config/config_test.go` (`KeySets`' entry in `TestASecondYAMLDocumentIsRefused` dropped)
- Test: `cmd/port49/keys_test.go`, `cmd/port49/policy_test.go`, `cmd/port49/inventory_test.go`

**Interfaces:**
- Consumes: `(*policy.Policy).KeySets`, `KeysDeclared` (Task 5); `keyset.Sorted`; `secretref.Allowance` (Task 3).
- Produces:
  - `func keyReports(p *policy.Policy, allow secretref.Allowance, now time.Time) []string`;
  - `func rekeyed(before, after *policy.Policy) []string`: `policy diff`'s re-keyed versions;
  - `func config.KeySecretRefsOf(raw []byte) (secretref.Allowance, error)`: port49d.yaml's `key_secret_refs`, defaulted and checked, decoded with `decodeFile` alone (no secret read, as `InventoryBound` reads its bound);
  - `func statusKeys(sets map[string]keyset.Set, now time.Time) []keystatus.Key` (type change only).

- [ ] **Step 1: Write the failing tests.** In `cmd/port49/policy_test.go`, change the tests that pass `--config` to `policy test` (`grep -n '"--config"' cmd/port49/policy_test.go`) to put the key sets in the policy they write and drop the flag. Add:

```go
// policy test reads the key sets from the policy itself (decision 53 ruling
// 3), and fails every policy port49d refuses for its keys: no keys: block,
// with or without key_groups, and a reference outside key_secret_refs.
func TestPolicyTestReadsTheKeysFromThePolicy(t *testing.T)
```
It runs `policyTest([]string{"--policy", p, "--inventory", inv}, …)`:
- on a policy with `key_groups` naming `k` and a `keys:` block whose `k` has an `accept` version with no `retire_after`: exit 0, with the `report: key k version 2 has no retire_after` line;
- on the same policy with no `keys:` block: exit 1, with a line beginning `keys: the policy declares no keys: block`;
- on a policy with no `keys:` block **and no `key_groups`** (devices pinned in the inventory, or all on TLS): exit 1 with the same line, since port49d refuses it too (pre-flight I7);
- on a policy whose `k` names `env:PORT49_ENC_V2`: exit 1, with "outside key_secret_refs";
- the same with `--config` naming a port49d.yaml whose `key_secret_refs.env_prefix` is `PORT49_ENC_`: exit 0. `--config` reads `key_secret_refs` alone.

```go
// policy diff fails a change that names another secret for a version both
// files hold (decision 53 ruling 3; pre-flight M9): across a restart port49d
// has nothing to compare it against.
func TestPolicyDiffRefusesARekeyedVersion(t *testing.T)
```
It writes `--old` with `k` version 1 at `env:PORT49_KEY_A` and `--new` with version 1 at `env:PORT49_KEY_B`, and expects exit 1 and a line beginning `REFUSED: keys: k version 1`.

In `cmd/port49/keys_test.go`, the `keys status` and `keys show` tests drop `--config` and put the key sets in the policy. Add a case: `keys status` on a policy with no `keys:` exits 1 with "the policy declares no keys: block; a port49d with no policy keeps its keys in port49d.yaml, and keys status reads only a policy's" (pre-flight M16: the no-policy mode, the lab harness's, has no `keys status`).

In `cmd/port49/inventory_test.go`, `TestInventoryDiffSaysTheKeyRefsWentUnchecked` is renamed `TestInventoryDiffChecksThePolicysKeyRefs`. It asserts that a device assigned a key_ref the policy's `keys:` does not define is refused, with no `--config` given, and that no verdict says "went unchecked against port49d.yaml" (pre-flight M17). `--config` still reads `inventory.max_removed_percent` alone.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'PolicyTest|Keys|InventoryDiff|PolicyDiff' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **`keys.go`.**
    - Delete `readKeySets`. `keyRefsOf` takes `map[string]keyset.Set` and is `keyset.Sorted`: replace its callers and delete it.
    - `keysStatus` drops `--config`, loads with `files.load()`, and passes `p.KeySets()` to `statusKeys`. When `!p.KeysDeclared()` it prints "port49 keys status: the policy declares no keys: block; a port49d with no policy keeps its keys in port49d.yaml, and keys status reads only a policy's" and returns 1.
    - `keysShow` drops `--config`: the versions are `p.KeySets()[ref]`.
  - **`policy.go`.**
    - `load` is `bundle.Load(f.policy, f.inventory, policy.Env{})` (Task 6 removed `loadWith`).
    - `policyTest`'s `--config` now reads `key_secret_refs` alone, through `config.KeySecretRefsOf`; with no `--config` the allowance is `secretref.DefaultAllowance`. Its doc comment's "given --config" clause says so. Every `keyReports` line fails the run, as the `keys:` lines did.
    - `keyReports`:

```go
// keyReports is what CI owes the key sets (spec §10; decision 53): a policy
// port49d would refuse for declaring none, whatever else it holds; a key
// group naming an undefined key_ref; a reference outside the allowance; and
// each accept version's retire_after.
func keyReports(p *policy.Policy, allow secretref.Allowance, now time.Time) []string {
	if !p.KeysDeclared() {
		// Not only with key_groups: devices pinned in the inventory, or all on
		// TLS, are refused by port49d too, so CI must not go green on it.
		return []string{"keys: the policy declares no keys: block, so port49d and port49-broker refuse it " +
			"(decision 53 ruling 3); add the key sets beside key_groups, or `keys: {}` for a fleet all on TLS"}
	}
	sets := p.KeySets()
	var out []string
	for _, ref := range keyset.Sorted(sets) {
		for _, v := range sets[ref].All() {
			if r, err := secretref.Parse(v.SecretRef); err == nil && !allow.Allows(r) {
				out = append(out, fmt.Sprintf("keys: key %s version %d secret_ref %s is outside key_secret_refs "+
					"(%s), so port49d refuses the policy (decision 53 ruling 12)", ref, v.Version, v.SecretRef, allow))
			}
		}
	}
	for _, g := range p.KeyGroups() {
		if _, ok := sets[g.KeyRef]; !ok {
			out = append(out, fmt.Sprintf("keys: key group %s names key_ref %s, which the policy's keys: block does "+
				"not define; every device it matches fails closed", g, g.KeyRef))
		}
	}
	for _, ref := range keyset.Sorted(sets) {
		… (the accept loop, unchanged)
	}
	return out
}
```
  - **`policyDiff`.** After the admission lines, before `d.Unresolved`:

```go
	// A version's secret never changes (spec §10): a change that names
	// another reference for a version both files hold is caught here, since
	// across a restart port49d has nothing to compare it against.
	for _, line := range rekeyed(before, after) {
		fmt.Fprintln(stdout, "REFUSED: keys: "+line)
	}
```
    `rekeyed` walks `keyset.Sorted(after.KeySets())` and each version's `SecretRef` against the same key_ref and version in `before.KeySets()`, returning `k version 1 names secret_ref env:B, and the old policy env:A: a version's secret never changes, so add a version (decision 53 ruling 3)` for each that differs. A `REFUSED:` line already fails the diff.
  - **`inventory.go`.** `inventory diff --config` reads only `config.InventoryBound`. The `KeySets` read and the `refs` variable go, and the `--config` flag's help says "port49d.yaml, for inventory.max_removed_percent". The verdict at :124–127 that says the key_refs "went unchecked against port49d.yaml" is deleted: the policy's `keys:` block checks them now.
  - **`config.KeySets`** is deleted, now that nothing calls it (no deprecation before beta), with its entry in `TestASecondYAMLDocumentIsRefused` (Task 2). `config.KeySecretRefsOf` is added beside `InventoryBound`, decoding with `decodeFile`.
  - **`usage`.** Remove `--config` from `keys status` and `keys show`; `policy test`'s `--config` reads `key_secret_refs` alone.

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add cmd/port49 internal/config
git commit -m "feat: port49 policy test, keys status and keys show read the policy's key sets

policy test fails a policy with no keys: block and a reference outside
key_secret_refs; policy diff fails a re-keyed version (decision 53).

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 9: port49-inventory names its source secrets by `token_secret_ref` and `webhook_secret_ref`

**Files:**
- Modify: `internal/inventory/config.go` (`sourceYAML`, `fileConfig`, `secretFromEnv`, `sotSource`, the "for a file source" refusal at :285), `internal/inventory/webhook.go:60`, `internal/sot/client.go:95`
- Modify: `cmd/port49-inventory/main.go` (pass the resolver), tests in `internal/inventory/`, `internal/sot/`, `cmd/port49-inventory/`, `tests/lab/sot_e2e_test.go` and any lab file `git grep -ln 'token_secret_env\|webhook_secret_env' -- tests/lab ':!tests/lab/results/'` lists

**Interfaces:**
- Consumes: `secretref.New`, `(*Resolver).ResolveText` (Task 3).
- Produces:
  - `sourceYAML.TokenSecretRef string \`yaml:"token_secret_ref"\``;
  - `sourceYAML.WebhookSecretRef string \`yaml:"webhook_secret_ref"\``;
  - `func secretFrom(res *secretref.Resolver, key, text string, min, max int) (sot.Secret, error)`, replacing `secretFromEnv`.

- [ ] **Step 1: Write the failing tests** in `internal/inventory/config_test.go`. Change every fixture's `token_secret_env: NAME` to `token_secret_ref: env:NAME` and every `webhook_secret_env: NAME` to `webhook_secret_ref: env:NAME`. Then add:

```go
// A source's token may come from a file, read as a private key (decision 53
// ruling 1), and token_secret_env is gone.
func TestASourceTokenFromAFile(t *testing.T)
```
It writes the token to a 0600 file with a trailing newline, loads a config naming `token_secret_ref: file:<path>`, and asserts `c.Sync[0].Token.Reveal()` has no newline (comparing lengths, never printing the value). It then loads the same config with `token_secret_env:` and expects "token_secret_env was replaced by token_secret_ref": `inventory.Load` calls `yamlfault.Replaced(raw, map[string]string{"token_secret_env": "token_secret_ref (write token_secret_ref: env:NAME)", "webhook_secret_env": "webhook_secret_ref (write webhook_secret_ref: env:NAME)"})` before its decode, prefixing `port49-inventory: `.

```go
// A token's text is checked as before (1 to 512 printable characters, no
// space), whatever its source, and the check quotes no part of it.
func TestASourceTokenOfTheWrongShapeIsNotPrinted(t *testing.T)
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/inventory/ ./internal/sot/ ./cmd/port49-inventory/ -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.** In `internal/inventory/config.go`:

```go
// secretFrom reads the secret text names, at key key (sync[i].token_secret_ref),
// and holds it to the shape a source's secret has: min to max printable
// characters with no space. Nothing of the value is quoted.
func secretFrom(res *secretref.Resolver, key, text string, min, max int) (sot.Secret, error) {
	if text == "" {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s is required", key)
	}
	_, s, err := res.ResolveText(key, text)
	if err != nil {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %w", err)
	}
	v := string(s.Bytes())
	if len(v) < min || len(v) > max || strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s names a secret that is not %d to %d printable "+
			"characters without a space", key, min, max)
	}
	return sot.NewSecret(v), nil
}
```
- `Load` builds `res := secretref.New()` after the decode and passes it to `sotSource`, whose signature becomes `sotSource(res, i, s)`.
- Rename the keys in every message: the :285 refusal, `webhook_listen`'s two refusals, `webhook.go:60` ("the webhook's secret in the source must be the value webhook_secret_ref names"), and `sot/client.go:95` ("the source is asked with the token token_secret_ref names").
- Delete `secretFromEnv` and `envNameShape` if nothing else uses it (`git grep -n envNameShape`).

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/inventory/ ./internal/sot/ ./cmd/port49-inventory/ -count=1 && make lab-unit`
Expected: PASS.

- [ ] **Step 5: Check, verify and commit**

Run: `git grep -n 'token_secret_env\|webhook_secret_env\|TokenSecretEnv\|WebhookSecretEnv' -- ':!docs/' ':!tests/lab/results/' ':!tests/lab/evidence/'`
Expected: only the `yamlfault.Replaced` map in `internal/inventory/config.go` and `TestASourceTokenFromAFile`.

Run `make test && make vet`, then:
```bash
git add -A internal/inventory internal/sot cmd/port49-inventory tests/lab
git commit -m "feat: port49-inventory reads its source secrets by token_secret_ref and webhook_secret_ref

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 10: The source-of-truth client honours an egress proxy

**Files:**
- Create: `internal/egress/egress.go`, `internal/egress/egress_test.go`
- Modify: `internal/oidc/keyset.go` (delete `errBadProxy`, `parseProxy`, `ProxyFor`, `DescribeProxy`; `NewClient`'s transport uses `egress.Proxy`), `internal/oidc/*_test.go` (move the proxy tests to `egress`), `internal/port49d/identity.go:284-293`
- Modify: `internal/sot/client.go` (`newClient`), `internal/sot/client_test.go`
- Modify: `cmd/port49-inventory/main.go` (a start line per source)

**Interfaces:**
- Produces:
  - `var egress.ErrBadProxy error`;
  - `func egress.ProxyFor(target string) (*url.URL, error)`;
  - `func egress.Proxy(req *http.Request) (*url.URL, error)`: the environment's proxy, held to `parseProxy` first, so a value the transport would misread is refused with `ErrBadProxy`, never dialled;
  - `func egress.Describe(u *url.URL) string`;
  - in `sot`, `var proxy = egress.Proxy`, swapped in tests.

- [ ] **Step 1: Write the failing tests.**

`internal/egress/egress_test.go`: move `internal/oidc`'s tests of `ProxyFor`, `parseProxy` and `DescribeProxy` (`grep -n 'ProxyFor\|DescribeProxy\|parseProxy' internal/oidc/*_test.go`) here, renamed to the new names. Add:

```go
// A proxy URL the transport cannot read is refused in fixed words: the
// value carries a password (Review Focus 1).
func TestABadProxyIsNeverPrinted(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:hunter2#x@proxy:3128")
	_, err := ProxyFor("https://netbox.example.com")
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the proxy password")
	}
	if !errors.Is(err, ErrBadProxy) {
		t.Fatalf("%v", err)
	}
}

// A value net/url reads without error but wrongly — a '/' in the password
// makes the host "u:123" — is refused by the transport's Proxy too, so the
// transport never dials a host nobody configured, with part of the password
// in its DNS lookup (pre-flight I10; identity.go:288's F3).
func TestAMisreadProxyIsRefusedByTheTransport(t *testing.T) {
	for _, v := range []string{"http://u:123/x@proxy:3128", "http://user:pa?ss@proxy:3128", "http://user:hunter2#x@proxy:3128"} {
		t.Setenv("HTTPS_PROXY", v)
		req, _ := http.NewRequest(http.MethodGet, "https://netbox.example.com/api/", nil)
		u, err := Proxy(req)
		if !errors.Is(err, ErrBadProxy) || u != nil || strings.Contains(err.Error(), "123") {
			t.Errorf("%q: %v %v", v, u, err)
		}
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	req, _ := http.NewRequest(http.MethodGet, "https://netbox.example.com/api/", nil)
	if u, err := Proxy(req); err != nil || u == nil || u.Host != "proxy.example.com:3128" {
		t.Fatalf("a good proxy: %v %v", u, err)
	}
}
```
`http.ProxyFromEnvironment` reads the environment once per process, which would make the test's second value invisible, so `Proxy` reads `HTTPS_PROXY` itself for the check and builds the answer with `httpproxy.FromEnvironment().ProxyFunc()` (`golang.org/x/net/http/httpproxy`). `golang.org/x/net` is already in `go.mod` (v0.58.0, indirect); `go mod tidy` marks it direct, and no module is added.

`internal/sot/client_test.go`:
```go
// connectProxy is an HTTP CONNECT proxy that counts its tunnels.
func connectProxy(t *testing.T) (*url.URL, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		n.Add(1)
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		down, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		go func() { io.Copy(up, down); up.Close() }()
		io.Copy(down, up)
		down.Close()
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, &n
}

// Through an egress proxy the source is reached by CONNECT, its certificate
// still checked against ca_file, read at the dial (decision 53 ruling 7).
func TestASourceIsReachedThroughTheProxy(t *testing.T) {
	pu, tunnels := connectProxy(t)
	was := proxy
	t.Cleanup(func() { proxy = was })
	proxy = http.ProxyURL(pu)
	srv, ca := sottest.TLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	cl, err := newClient(srv.URL, ca, NewSecret(token), "netbox")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err != nil || tunnels.Load() != 1 {
		t.Fatalf("%v; tunnels %d", err, tunnels.Load())
	}
	// A CA that does not issue the source's certificate is refused through
	// the tunnel as it is directly.
	cl, _ = newClient(srv.URL, writeCA(t), NewSecret(token), "netbox")
	if err := cl.getJSON(context.Background(), cl.at("/api/status/", nil), &v); err == nil {
		t.Fatal("a source the CA file does not trust was read through the proxy")
	}
}
```
Keep the existing direct-dial tests, including the one that a rotated CA reaches the next dial (`client_test.go:234`). Add the same rotation through the proxy.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/egress/ ./internal/sot/ -count=1`
Expected: FAIL: package `egress` has no Go files; `proxy` undefined in `sot`.

- [ ] **Step 3: Implement.**
  - **`internal/egress/egress.go`.** Package doc: "Package egress is how port49 reaches the outside for a fetch it makes: the environment's proxy (HTTPS_PROXY, NO_PROXY), described for a start line, never with its credentials (decision 53 ruling 7)." Move `errBadProxy` (exported as `ErrBadProxy`), `parseProxy`, `ProxyFor` and `DescribeProxy` (as `Describe`) here unchanged except for the names. Add:

```go
// Proxy is a transport's Proxy: the environment's, held to parseProxy
// first. A value the transport would misread — a '/', '?' or '#' in the
// password moving the credentials into the path, the query or the host — is
// refused, never dialled: dialled, it reaches a host nobody configured, and
// its DNS lookup can carry part of the password. An error the transport
// would print, which quotes the value, is replaced by ErrBadProxy too.
func Proxy(req *http.Request) (*url.URL, error) {
	raw := os.Getenv("HTTPS_PROXY")
	if raw == "" {
		raw = os.Getenv("https_proxy")
	}
	if raw != "" {
		if _, err := parseProxy(raw); err != nil {
			return nil, ErrBadProxy
		}
	}
	u, err := httpproxy.FromEnvironment().ProxyFunc()(req.URL)
	if err != nil {
		return nil, ErrBadProxy
	}
	return u, nil
}
```
  - **`internal/oidc`.** `NewClient` sets `tr.Proxy = egress.Proxy`. `internal/port49d/identity.go` calls `egress.ProxyFor` and `egress.Describe`.
  - **`internal/sot/client.go`.** The transport moves from `DialTLSContext` to a proxy-capable shape. A proxied HTTPS request never calls `DialTLSContext`: the transport dials the proxy with `DialContext`, sends CONNECT, then handshakes with `TLSClientConfig`. So the CA must be read at the handshake:

```go
// proxy is the transport's proxy (egress.Proxy); a variable for the tests.
var proxy = egress.Proxy

…
	dialer := &net.Dialer{Timeout: dialTimeout}
	tr := &http.Transport{
		Proxy:       proxy,
		DialContext: dialer.DialContext,
		// The CA file is read at each handshake, direct or through the
		// proxy's tunnel, so a rotated CA needs no restart. InsecureSkipVerify
		// only hands verification to VerifyConnection, which verifies the
		// chain against that pool and the name against the source's host:
		// RootCAs is never nil, so never the host's roots unless the CA file
		// is the host's bundle.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				pool, err := readCA(caFile)
				if err != nil {
					return err
				}
				if len(cs.PeerCertificates) == 0 {
					return errors.New("the source sent no certificate")
				}
				inter := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
					DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
				return err
			}},
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: 2 * time.Minute, MaxIdleConnsPerHost: 2,
		IdleConnTimeout:       90 * time.Second}
```
    Keep `readCA` as it is.
  - **`cmd/port49-inventory/main.go`.** After the sources are built, say for each netbox or nautobot source how it is reached:

```go
	for _, s := range cfg.Sync {
		if s.URL == "" {
			continue
		}
		how := "directly (no HTTPS_PROXY)"
		if u, err := egress.ProxyFor(s.URL); err == nil {
			how = egress.Describe(u)
		} else {
			how = "with an HTTPS_PROXY that does not parse as a proxy URL (percent-encode '#', '/', '?' and '%' in " +
				"its password): every sync of it fails until it is fixed"
		}
		fmt.Fprintf(stderr, prefix+"source %s is fetched %s\n", s.Name, how)
	}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/egress/ ./internal/oidc/ ./internal/sot/ ./internal/port49d/ ./cmd/port49-inventory/ -count=1`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/egress internal/oidc internal/sot internal/port49d cmd/port49-inventory
git commit -m "feat: the source-of-truth client honours HTTPS_PROXY, as the OIDC fetch does

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 11: The global connection cap, shed at Accept

**Files:**
- Create: `internal/daemon/server/slots.go`, `internal/daemon/server/slots_test.go`, `internal/port49d/fdlimit.go`, `internal/port49d/connectioncap_test.go`
- Modify: `internal/daemon/server/server.go` (`Deps.Slots`, `Serve`), `internal/daemon/limits/limits.go` (`Config.MaxConnections`), `internal/config/config.go` (`limitsYAML.MaxConnections`, `daemonDefaults`, `checkPositive` or beside it), `internal/daemon/metrics/metrics.go` (`ConnectionsMax`, `ConnectionsShed`), `internal/port49d/main.go` (Deps, the start line), `internal/daemon/server/conn.go:33-43` (the `unadmittedHeaderDeadline` comment)

**Interfaces:**
- Consumes: spec §12's two shedding lines (Task 1).
- Produces:
  - `type server.Slots struct`;
  - `func server.NewSlots(n int, now func() time.Time) *Slots`;
  - `func (s *Slots) TryAcquire() (release func(), ok bool)`: never waits;
  - `func (s *Slots) Shed() (line string)`: counts one shed and returns the line to say now, `""` when the rate limit holds it;
  - `func (s *Slots) Cap() int` and `func (s *Slots) InUse() int`;
  - `server.Deps.Slots *Slots`: nil is no cap;
  - `limits.Config.MaxConnections int`: 0 is "size it at start";
  - `func port49d.connectionCap(set int, nofile uint64) (int, error)`;
  - `func port49d.openFileLimit() uint64`;
  - `metrics.Metrics.ConnectionsMax prometheus.Gauge` (`port49_connections_max`) and `metrics.Metrics.ConnectionsShed *prometheus.CounterVec` (`port49_connections_shed_total{reason}`).

- [ ] **Step 1: Write the failing tests.**

`internal/daemon/server/slots_test.go`:
```go
// A slot is taken without waiting, released once however often release is
// called, and a full pool says no at once: the cap sheds, it never queues
// (design §11; decision 53 ruling 8).
func TestSlots(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSlots(1, func() time.Time { return now })
	if s.InUse() != 0 {
		t.Fatal("a new pool holds a slot")
	}
	r1, ok := s.TryAcquire()
	if !ok || s.InUse() != 1 {
		t.Fatal("the first slot")
	}
	if _, ok := s.TryAcquire(); ok {
		t.Fatal("a full pool gave a slot")
	}
	r1()
	r1() // twice frees once
	if s.InUse() != 0 {
		t.Fatal("a double release freed two, or none")
	}
	var none *Slots
	if r, ok := none.TryAcquire(); !ok {
		t.Fatal("a nil Slots is no cap")
	} else {
		r()
	}
}

// The first shed after a quiet minute is said at once; more within the
// minute are counted and said once a minute after, with their number.
func TestTheShedLineIsSaidWhenSheddingBeginsAndThenOncePerMinute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSlots(2, func() time.Time { return now })
	if l := s.Shed(); !strings.Contains(l, "shedding: all 2 TACACS+ connection slots") {
		t.Fatalf("the first shed: %q", l)
	}
	now = now.Add(10 * time.Second)
	if l := s.Shed(); l != "" {
		t.Fatalf("a second shed inside the minute was said: %q", l)
	}
	now = now.Add(55 * time.Second) // 65s after the run began, 55s after the last shed
	if l := s.Shed(); !strings.Contains(l, "still shedding: 2 connections reset at Accept in the last minute") {
		t.Fatalf("a minute on: %q", l)
	}
	now = now.Add(2 * time.Minute)
	if l := s.Shed(); !strings.Contains(l, "shedding: all 2") {
		t.Fatalf("after a quiet minute shedding begins again: %q", l)
	}
}
```

`internal/daemon/server/server_test.go`:
```go
// At the cap a new connection is accepted and reset at once, counted and
// said while the slot is still held, and the device can take its next server;
// when the slot frees, the next connection is served (design §11; decision
// 53 ruling 8; Review Focus 5).
func TestTheGlobalCapShedsAndSaysSo(t *testing.T) {
	var log syncBuffer
	var said syncBuffer
	defer func(w io.Writer) { stdlog.SetOutput(w) }(stdlog.Writer())
	stdlog.SetOutput(&said)
	st := memory.New(time.Now)
	slots := NewSlots(1, time.Now)
	ts := newTestServerWith(t, &log, st, nil, func(d *Deps) { d.Slots = slots })
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	first := dial(t, ts.addr, []byte("k2")) // holds the one slot, idle
	if !waitFor(t, func() bool { return slots.InUse() == 1 }) {
		t.Fatal("the first connection holds no slot")
	}
	second := dial(t, ts.addr, []byte("k2"))
	second.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the second connection at the cap: %v, want a reset at once", err)
	}
	// Counted and said while the first still holds its slot.
	if got := testutil.ToFloat64(ts.metrics.ConnectionsShed.WithLabelValues("global_cap")); got != 1 {
		t.Fatalf("port49_connections_shed_total{reason=global_cap} = %v with the cap held", got)
	}
	if !strings.Contains(said.String(), "shedding: all 1 TACACS+ connection slots") {
		t.Fatalf("no shedding line with the cap held:\n%s", said.String())
	}
	first.conn.Close()
	if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
		t.Fatal("the slot was not freed")
	}
	third := dial(t, ts.addr, []byte("k2"))
	third.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: "alice", Data: []byte("p49_e2e")})
	third.recv(t) // served once the slot frees
}

// A listener waiting in Accept holds no slot: with nothing connected the
// pool is empty, and with two listeners sharing a pool of 2, one connection
// on each is served and a third is shed (I1).
func TestIdleListenersHoldNoSlot(t *testing.T) {
	var log syncBuffer
	slots := NewSlots(2, time.Now)
	var deps Deps
	ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
		d.Slots = slots
		d.Limits = roomyLimits() // per-source room for three, so the global cap binds
		deps = *d
	})
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); Serve(ctx, ln2, deps) }()
	t.Cleanup(func() { cancel(); <-served })
	time.Sleep(50 * time.Millisecond) // both loops are in Accept
	if n := slots.InUse(); n != 0 {
		t.Fatalf("%d slots held with nothing connected", n)
	}
	a := dial(t, ts.addr, []byte("k2"))
	b := dial(t, ln2.Addr().String(), []byte("k2"))
	if !waitFor(t, func() bool { return slots.InUse() == 2 }) {
		t.Fatalf("one connection on each listener: %d slots in use", slots.InUse())
	}
	c := dial(t, ln2.Addr().String(), []byte("k2"))
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the third connection: %v, want shed", err)
	}
	a.conn.Close()
	b.conn.Close()
}

// No refusal at Accept leaves a slot behind: the per-source refusals take
// none, and a shed frees its per-source slot (Review Focus 5).
func TestEveryRefusalAtAcceptReleasesItsSlots(t *testing.T) {
	var log syncBuffer
	slots := NewSlots(4, time.Now)
	ts := newTestServerWith(t, &log, memory.New(time.Now), nil, func(d *Deps) {
		d.Slots = slots
		d.Limits = slowBackoff() // as the key-miss test at :1831 uses, to observe held_refused
	})
	// refused_cap: a third connection past the per-NAS cap of 2, as
	// TestPerNASCapRefusesThirdConnection (server_test.go:960) drives it.
	c1, c2 := dial(t, ts.addr, []byte("k2")), dial(t, ts.addr, []byte("k2"))
	c3 := dial(t, ts.addr, []byte("k2"))
	c3.conn.SetReadDeadline(time.Now().Add(time.Second))
	c3.conn.Read(make([]byte, 1))
	c1.conn.Close()
	c2.conn.Close()
	ts.slotFree(t)
	// held_refused: a key miss, then a connection inside its backoff, as
	// TestAKeyMissIsClosedAtOnceAndAHeldSourceRefusedAtAccept (:1831) drives it.
	miss := dial(t, ts.addr, []byte("not-the-key"))
	miss.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: "alice", Data: []byte("x")})
	closedAtOnce(t, miss)
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if !waitFor(t, func() bool { return slots.InUse() == 0 }) {
		t.Fatalf("%d slots still held with every connection closed", slots.InUse())
	}
	for _, ev := range []string{"refused_cap", "held_refused"} {
		if got := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues(ev)); got < 1 {
			t.Fatalf("the %s path was not taken: %v", ev, got)
		}
	}
}
```
Copy the exact `send` call of the key-miss test (`:1831`) for the miss. Add the `declined_refused` path the same way, from `TestAReloadBetweenAcceptsReAskAndUndeclineFailsClosed` (`:1576`). Add a fourth case to the same test: with `NewSlots(1, …)` and one connection holding it, a shed connection leaves the per-source slot free (`ts.slotFree(t)` passes once the holder closes). Write `roomyLimits()` beside `slowBackoff()` (`:812`): `newTestServerWith`'s limiter config with `PerNASConnections: 16`. `stdlog` is the standard `log` package, imported under that name since the test file's `log` is the decision log buffer.

`internal/port49d/connectioncap_test.go`:
```go
func TestConnectionCap(t *testing.T) {
	for _, c := range []struct {
		set    int
		nofile uint64
		want   int
		err    string
	}{
		{0, 1 << 20, 1<<20 - 1024, ""},
		{0, 1024, 512, ""},
		{0, 1 << 40, 1 << 20, ""}, // effectively unlimited: bounded
		{5000, 1 << 20, 5000, ""},
		{1000, 1024, 0, "leaves fewer than 256"},
	} {
		got, err := connectionCap(c.set, c.nofile)
		if got != c.want || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v: %d, %v", c, got, err)
		}
	}
}

// port49d's start sizes the cap, says it, and publishes it: the wiring the
// server tests cannot see (pre-flight I11).
func TestTheStartSaysAndPublishesTheCap(t *testing.T)
```
The second test redirects `stderr` to a `syncBuffer`, writes `writeRunConfigWith(t, b, inventory, "limits: {max_connections: 64}\n")` (the broker and inventory as `writeRunConfig` builds them), starts it with `startSplitDaemon(t, cfgPath, &out, 1)` (`daemon_test.go:33`), waits for "at most 64 TACACS+ connections at once (limits.max_connections)", reads the metrics address from the `port49d: metrics on` line as `TestAnIdleDaemonGoesDarkOnItsHealthChecks` (`daemon_test.go:223`) does, and asserts `scrapeGauge(t, addr, "port49_connections_max") == 64`.

`internal/config/config_test.go`: `limits.max_connections` accepts 0 and 64 to 1048576, and refuses 10 and -1.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/server/ ./internal/port49d/ ./internal/config/ -run 'Slots|ShedLine|GlobalCap|IdleListeners|ReleasesItsSlots|ConnectionCap|PublishesTheCap|MaxConnections' -count=1`
Expected: FAIL to build.

- [ ] **Step 3: Implement.**

`internal/daemon/server/slots.go`:
```go
package server

// Slots is port49d's global connection cap (design §11; decision 53 ruling
// 8): one pool across both TACACS+ listeners, held by accepted connections
// alone. It is taken after Accept and after the per-source checks, so those
// bind first, and a full pool sheds: the connection is reset at once and the
// device takes its next server, since "a request answered after the device
// has already given up is worse than a refused connection". Nil is no cap.
type Slots struct {
	c   chan struct{}
	now func() time.Time

	mu        sync.Mutex
	lastShed  time.Time // the last shed, to tell a new run of shedding
	said      time.Time // when a shedding line was last said
	sinceSaid int       // sheds since then
}

func NewSlots(n int, now func() time.Time) *Slots {
	return &Slots{c: make(chan struct{}, n), now: now}
}

// TryAcquire takes a slot if one is free, never waiting. release frees it
// once, however often it is called.
func (s *Slots) TryAcquire() (release func(), ok bool) {
	if s == nil {
		return func() {}, true
	}
	select {
	case s.c <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { <-s.c }) }, true
}

// shedQuiet is how long without a shed ends a run of shedding, and how often
// a run that goes on is said.
const shedQuiet = time.Minute

// Shed counts one shed connection and returns the line to say now (spec §12,
// "Connection shedding"): at once when shedding begins, then at most once a
// minute with the number shed since, so a cap that engages is seen the
// moment it bites and never silently (design §11).
func (s *Slots) Shed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	begins := s.lastShed.IsZero() || now.Sub(s.lastShed) >= shedQuiet
	s.lastShed = now
	s.sinceSaid++
	switch {
	case begins:
		s.said, s.sinceSaid = now, 0
		return fmt.Sprintf("port49d: shedding: all %d TACACS+ connection slots (limits.max_connections) are in "+
			"use; each new connection is reset at Accept and the device tries its next server", cap(s.c))
	case now.Sub(s.said) >= shedQuiet:
		n := s.sinceSaid
		s.said, s.sinceSaid = now, 0
		return fmt.Sprintf("port49d: still shedding: %d connections reset at Accept in the last minute; %d of %d "+
			"slots in use", n, len(s.c), cap(s.c))
	}
	return ""
}

func (s *Slots) Cap() int   { return cap(s.c) }
func (s *Slots) InUse() int { return len(s.c) }
```
`TestTheShedLineIsSaidWhenSheddingBeginsAndThenOncePerMinute` counts the first shed into the run: the "still shedding" line's count is the sheds since the last line, the one that began the run excluded (2 in the test: the one at +10 s and the one at +65 s). Match the code and the test to that.

In `Serve`, the slot is taken after the per-source checks and the decline window, before the single-connect count (`single_connect_second_connection`, `server.go:186`) and `d.Metrics.Connections.WithLabelValues("open").Inc()`, so a shed connection is counted as shed and nothing else (re-review N8). The per-source `release` is widened to free both:
```go
		// The global cap (decision 53 ruling 8), taken last so the per-source
		// limits bind first (design §11). A full pool sheds: reset at once, so
		// the device moves to its next server now rather than after its own
		// timeout (L28), counted, and said when shedding begins.
		slot, ok := d.Slots.TryAcquire()
		if !ok {
			release()
			d.Metrics.ConnectionsShed.WithLabelValues("global_cap").Inc()
			if line := d.Slots.Shed(); line != "" {
				log.Print(line)
			}
			reset(c)
			c.Close()
			continue
		}
		srcRelease := release
		release = func() { srcRelease(); slot() }
```
Every later use of `release` (the served goroutine's `defer release()`) now frees both. No path before this point takes a global slot, so the refusals above it need no change.

`limits.Config` gains `MaxConnections int` ("the global cap; 0 sizes it from the open-file limit at start (decision 53 ruling 8)"). `config.limitsYAML` gains `MaxConnections int \`yaml:"max_connections"\``. `daemonDefaults` copies it, and a check beside `checkPositive` reads:

```go
	if n := c.Limits.MaxConnections; n != 0 && (n < 64 || n > 1<<20) {
		return fmt.Errorf("config: limits.max_connections is %d: leave it out to size it from the open-file limit, "+
			"or set 64 to 1048576", n)
	}
```

`internal/port49d/fdlimit.go`:
```go
package port49d

// reserveFDs are the descriptors the global cap leaves for everything but
// TACACS+ connections when it is sized from the limit: the spool, the store's
// connections, the decision log, the admin socket and metrics, the policy and
// inventory reads. minReserveFDs is the least an explicit cap may leave.
const (
	reserveFDs    = 1024
	minReserveFDs = 256
	maxCap        = 1 << 20
)

// openFileLimit is RLIMIT_NOFILE's soft limit, which the Go runtime raises to
// the hard limit at start; 0 when it cannot be read.
func openFileLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return rl.Cur
}

// connectionCap is limits.max_connections resolved (decision 53 ruling 8).
// Unset, it is the limit less reserveFDs, or half the limit where that is
// less, and at most maxCap; set, it must leave minReserveFDs.
func connectionCap(set int, nofile uint64) (int, error) {
	if nofile == 0 {
		nofile = 4096 // unreadable: a cap a stock host sustains
	}
	if set != 0 {
		if uint64(set)+minReserveFDs > nofile {
			return 0, fmt.Errorf("limits.max_connections %d leaves fewer than %d of the open-file limit %d for "+
				"the spool, the store and the logs; lower it, or raise the limit (LimitNOFILE= under systemd)",
				set, minReserveFDs, nofile)
		}
		return set, nil
	}
	n := nofile / 2
	if nofile > 2*reserveFDs {
		n = nofile - reserveFDs
	}
	return int(min(n, maxCap)), nil
}
```
It uses `syscall.Getrlimit`, which Linux and darwin both provide. Check with `make check-darwin`.

In `internal/port49d/main.go`, before `deps` is built:
```go
	limit := openFileLimit()
	capN, err := connectionCap(cfg.Limits.MaxConnections, limit)
	if err != nil {
		stopSpool()
		<-spoolDone
		return fmt.Errorf("config: %w", err)
	}
	m.ConnectionsMax.Set(float64(capN))
	from := "limits.max_connections"
	if cfg.Limits.MaxConnections == 0 {
		from = fmt.Sprintf("the open-file limit %d, less what the spool, the store and the logs keep", limit)
	}
	fmt.Fprintf(stderr, "%s: at most %d TACACS+ connections at once (%s); past it each new connection is reset "+
		"at Accept\n", procOf(cfg), capN, from)
```
and `Slots: server.NewSlots(capN, time.Now)` in `deps`. The TLS listener's `td := deps` shares the same pointer, so the cap is one pool.

Add to `metrics.Metrics`:
- `ConnectionsMax`: `prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_connections_max", Help: "The global TACACS+ connection cap (limits.max_connections), across both listeners."})`;
- `ConnectionsShed`: `prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_connections_shed_total", Help: "TACACS+ connections reset at Accept because a cap was full, by reason (global_cap)."}, []string{"reason"})`, with `global_cap` pre-initialised to 0 so the alarm's series exists before the first shed.

Register both with the others. Rewrite `unadmittedHeaderDeadline`'s comment ("today the only global connection cap is EMFILE… This is not the global cap, which is plan 12") to say the global cap is `limits.max_connections`, and this deadline still frees an unadmitted source's slots sooner.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/daemon/... ./internal/port49d/ ./internal/config/ -count=1 -race && make check-darwin`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/daemon internal/port49d internal/config
git commit -m "feat: a global TACACS+ connection cap that sheds at Accept, limits.max_connections (decision 53 ruling 8)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 12: The etcd version floor at start

**Files:**
- Create: `internal/store/etcd/version.go`, `internal/store/etcd/version_test.go`, `internal/port49d/floor.go`, `internal/port49d/floor_test.go`
- Modify: `internal/port49d/store.go` (`attempt`: a `floor bool` parameter, and the check after `checkRoles`), and every `attempt` caller: `store.go:190`, `:358`, `:552` and `brokerd.go:178` pass `true`; `offline.go:254` and `:267` pass `false`

**Interfaces:**
- Produces:
  - `const etcd.VersionFloor = "3.4.24, 3.5.8 or 3.6"`;
  - `func etcd.BelowFloor(version string) bool`;
  - `type etcd.EndpointVersion struct { Endpoint, Version string; Err error }`;
  - `func (s *etcd.Store) EndpointVersions(ctx context.Context, endpoints []string, per time.Duration) []EndpointVersion`;
  - `func port49d.checkFloor(vs []etcdstore.EndpointVersion, what string, out io.Writer, proc string) error`;
  - `var port49d.endpointVersions = (*etcdstore.Store).EndpointVersions`, the seam the wiring test swaps;
  - `func attempt(ctx context.Context, cfg config.Config, ref storeRef, m *metrics.Metrics, out io.Writer, floor bool) (*etcdstore.Store, error)`.

- [ ] **Step 1: Write the failing tests.**

`internal/store/etcd/version_test.go`:
```go
func TestBelowFloor(t *testing.T) {
	for v, below := range map[string]bool{
		"3.4.23": true, "3.4.24": false, "3.4.30": false, "3.5.7": true, "3.5.8": false, "3.5.21": false,
		"3.6.0": false, "3.6.15": false, "3.7.0": false, "4.0.0": false, "3.3.25": true, "2.3.8": true,
		"3.6.0-alpha.0": false, "": true, "garbage": true, "3.5": true,
	} {
		if BelowFloor(v) != below {
			t.Errorf("%q: %v", v, !below)
		}
	}
}

// Each endpoint is asked its version, and the embedded server answers its own.
func TestEndpointVersionsAsksEachEndpoint(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	vs := s.EndpointVersions(context.Background(), []string{srv.Endpoint, "http://127.0.0.1:1"}, time.Second)
	if len(vs) != 2 || vs[0].Version == "" || BelowFloor(vs[0].Version) || vs[1].Err == nil {
		t.Fatalf("%+v", vs)
	}
}
```

`internal/port49d/floor_test.go`:
```go
// A member below the floor refuses the start, naming it; one that does not
// answer is said and does not hold the start (decision 53 ruling 9).
func TestTheFloorRefusesAnOldMemberAndSaysADarkOne(t *testing.T) {
	var out bytes.Buffer
	err := checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.6.15"},
		{Endpoint: "https://e2:2379", Err: errors.New("deadline")}}, "session store", &out, "port49d")
	if err != nil || !strings.Contains(out.String(), "https://e2:2379 did not answer") ||
		!strings.Contains(out.String(), "3.6.15") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	out.Reset()
	err = checkFloor([]etcdstore.EndpointVersion{{Endpoint: "https://e1:2379", Version: "3.6.15"},
		{Endpoint: "https://e3:2379", Version: "3.5.2"}}, "session store", &out, "port49d")
	if err == nil || !strings.Contains(err.Error(), "https://e3:2379") || !strings.Contains(err.Error(), "3.5.2") ||
		!strings.Contains(err.Error(), etcdstore.VersionFloor) {
		t.Fatalf("%v", err)
	}
}
```

The wiring (pre-flight I11), in `internal/port49d/floor_test.go`:
```go
// A server start against a member below the floor is refused as a store
// fault, and the offline path is not (decision 53 ruling 9; pre-flight M13).
func TestAStartAgainstAMemberBelowTheFloorIsRefused(t *testing.T) {
	was := endpointVersions
	t.Cleanup(func() { endpointVersions = was })
	endpointVersions = func(s *etcdstore.Store, ctx context.Context, eps []string, per time.Duration) []etcdstore.EndpointVersion {
		vs := was(s, ctx, eps, per)
		for i := range vs {
			vs[i].Version, vs[i].Err = "3.5.2", nil
		}
		return vs
	}
	cfgPath, _ := etcdSplit(t) // store_e2e_test.go:50
	out, err := runExpectingRefusal(t, cfgPath)
	if err == nil || !strings.Contains(err.Error()+out, "3.5.2, below the floor") {
		t.Fatalf("%v\n%s", err, out)
	}
}
```
`runExpectingRefusal` (`broker_test.go:492`) waits 10 s for `run` to return; a store fault at start returns, as the roles check's does (`grep -n 'storeFault' internal/port49d/*_test.go` for a test that asserts one, and match how it reads the refusal). For the offline half, call `attempt(ctx, cfg, sessionRef(cfg), m, &out, false)` on the same configuration with the hook in place and assert it opens.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/store/etcd/ ./internal/port49d/ -run 'Floor|EndpointVersions|BelowTheFloor' -count=1`
Expected: FAIL to build.

- [ ] **Step 3: Implement** `internal/store/etcd/version.go`:

```go
package etcd

// VersionFloor is the etcd release port49 requires (design §13; decision 53
// ruling 9): the feed fence rests on etcd never sending an event it has not
// delivered, which 3.4.24, 3.5.8 and every 3.6 guarantee.
const VersionFloor = "3.4.24, 3.5.8 or 3.6"

// BelowFloor reports whether version, as Status answers it, is older than the
// floor. One that does not parse is below it.
func BelowFloor(version string) bool {
	core, _, _ := strings.Cut(version, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return true
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return true
		}
		n[i] = v
	}
	switch {
	case n[0] != 3:
		return n[0] < 3
	case n[1] >= 6:
		return false
	case n[1] == 5:
		return n[2] < 8
	case n[1] == 4:
		return n[2] < 24
	}
	return true
}

// EndpointVersion is one endpoint's answer: its version, or why it gave none.
type EndpointVersion struct {
	Endpoint, Version string
	Err               error
}

// EndpointVersions asks every endpoint's Status at once, each bounded by per,
// so a dark member costs one per and holds nothing else (decision 53 ruling 9).
func (s *Store) EndpointVersions(ctx context.Context, endpoints []string, per time.Duration) []EndpointVersion {
	out := make([]EndpointVersion, len(endpoints))
	var wg sync.WaitGroup
	for i, ep := range endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, per)
			defer cancel()
			out[i].Endpoint = ep
			resp, err := s.ctx.Status(c, ep)
			if err != nil {
				out[i].Err = unavailable(err)
				return
			}
			out[i].Version = resp.Version
		}()
	}
	wg.Wait()
	return out
}
```

`internal/port49d/floor.go`:
```go
package port49d

// checkFloor judges the versions a start read (decision 53 ruling 9): a member
// below the floor is a store fault, every member at or above it is said in
// one line, and one that did not answer is said and left unchecked until
// the next start, never waited for.
func checkFloor(vs []etcdstore.EndpointVersion, what string, out io.Writer, proc string) error {
	var ok []string
	for _, v := range vs {
		switch {
		case v.Err != nil:
			fmt.Fprintf(out, "%s: %s: etcd at %s did not answer for its version (%v); it is unchecked against the "+
				"floor (%s) until the next start\n", proc, what, v.Endpoint, v.Err, etcdstore.VersionFloor)
		case etcdstore.BelowFloor(v.Version):
			return fmt.Errorf("%s: etcd at %s is version %s, below the floor port49 needs (%s): the feed fence "+
				"rests on a guarantee older releases do not make; upgrade the member", what, v.Endpoint,
				printsafe.Line(v.Version, 40), etcdstore.VersionFloor)
		default:
			ok = append(ok, v.Endpoint+" "+v.Version)
		}
	}
	if len(ok) > 0 {
		fmt.Fprintf(out, "%s: %s: etcd %s, at or above the floor (%s)\n", proc, what, strings.Join(ok, ", "),
			etcdstore.VersionFloor)
	}
	return nil
}
```

In `attempt` (`internal/port49d/store.go:804`), which gains the `floor bool` parameter, after the `checkRoles` block and before `if err != nil { s.Close() …`:
```go
	if err == nil && floor {
		err = checkFloor(endpointVersions(s, ctx, e.Endpoints, e.CallTimeout), ref.what(), out, procOf(cfg))
	}
```
`checkFloor`'s error flows into the existing `storeFault` branch: it is not `ErrUnavailable`. In `floor.go`:
```go
// endpointVersions asks the members their versions; a variable so a test can
// stand an old member in.
var endpointVersions = (*etcdstore.Store).EndpointVersions
```
The server starts pass `floor` true: port49d's store open (`store.go:190`), the directory opens (`:358`, `:552`) and the broker's (`brokerd.go:178`). The offline paths pass false (`offline.go:254`, `:267`): an emergency revoke against an old cluster must still run. Task 14's `forget-issuer` passes false too.

**Check that `Status` answers under port49's roles.** etcd checks the Maintenance API's `Status` against no key, but confirm it with an identity holding only the daemon's role. Use `openAs` (`internal/store/etcd/roles_test.go:39`) in `TestEndpointVersionsAsksEachEndpoint`, with `etcdtest.Start(t, etcdtest.Options{TLS: true})` and the roles the existing role tests set up. If it is refused, the floor would go unchecked in every production start: stop and report rather than accept "did not answer" as the steady state.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/store/etcd/ ./internal/port49d/ -count=1`
Expected: PASS. Existing etcd start tests now print the floor line; any test asserting the exact start output gains it.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/store/etcd internal/port49d
git commit -m "feat: refuse to start against an etcd member below 3.4.24, 3.5.8 or 3.6

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 13: The broker start survives a compaction, and a failing logout reach says its remedy once

**Files:**
- Modify: `internal/port49d/brokerd.go` (`openBroker`: the `retry` closure at :123, the ledger load :210, the marks load :225, the logouts load :266), `internal/port49d/runner.go` (`reachFollowed`, :1101)
- Test: `internal/port49d/brokerd_test.go`, `internal/port49d/runner_test.go`

**Interfaces:**
- Produces:
  - `func startRetry(ctx context.Context, out io.Writer, f func() error, also ...error) error`: the closure, made a function;
  - `func pagedLoad(ctx context.Context, out io.Writer, name string, f func() error) error`: `startRetry` with `store.ErrCompacted`, for the load `name` ("ledger", "marks", "logouts");
  - `var startRetryWait = 5 * time.Second`;
  - `var pagedLoadFault func(name string) error`: nil in production; a test sets it to put a compaction in front of a named load;
  - `var reachFailuresSeen func(n int)`: nil in production; `reachFollowed` calls it with the failure count's size after each event.

- [ ] **Step 1: Write the failing tests.**

`internal/port49d/brokerd_test.go`:
```go
// A paged load that meets a compaction between pages reads again, as the
// ledger's did; anything but an outage or a compaction ends the start
// (11a final review N1).
func TestAPagedLoadRetriesACompaction(t *testing.T) {
	was := startRetryWait
	startRetryWait = time.Millisecond
	t.Cleanup(func() { startRetryWait = was })
	var out bytes.Buffer
	n := 0
	err := pagedLoad(context.Background(), &out, "marks", func() error {
		if n++; n == 1 {
			return fmt.Errorf("store: reading the revocations in force: %w", store.ErrCompacted)
		}
		return nil
	})
	if err != nil || n != 2 || !strings.Contains(out.String(), "trying again") {
		t.Fatalf("%v after %d tries\n%s", err, n, out.String())
	}
	boom := errors.New("a fault")
	if err := pagedLoad(context.Background(), &out, "marks", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
}

// The broker start's marks and logouts loads go through pagedLoad: a
// compaction in front of each is read again and the broker starts
// (pre-flight I11).
func TestTheBrokerStartRetriesACompactionInItsMarksAndLogouts(t *testing.T) {
	was, wasWait := pagedLoadFault, startRetryWait
	t.Cleanup(func() { pagedLoadFault, startRetryWait = was, wasWait })
	startRetryWait = time.Millisecond
	var mu sync.Mutex
	hit := map[string]int{}
	pagedLoadFault = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		if hit[name]++; hit[name] == 1 && (name == "marks" || name == "logouts") {
			return fmt.Errorf("store: reading the %s: %w", name, store.ErrCompacted)
		}
		return nil
	}
	f := splitFleet(t)
	var out syncBuffer
	startBroker(t, f.broker, &out, 1) // brokerd_test.go:295: waits for the broker to serve
	mu.Lock()
	defer mu.Unlock()
	if hit["marks"] != 2 || hit["logouts"] != 2 {
		t.Fatalf("marks %d, logouts %d tries; want 2 each\n%s", hit["marks"], hit["logouts"], out.String())
	}
}
```

`internal/port49d/runner_test.go`: extend `TestAFailedLogoutReachIsTriedAgain`'s fake to fail `alice` three times in a row, then succeed. Assert that `port49 revoke --principal user:alice@example.com` appears exactly once in the output, and that the second and third failures say "still not reached". Add:

```go
// A logout that lapses while its reach keeps failing leaves no entry behind
// in the failure count.
func TestALapsedLogoutLeavesNoFailureCount(t *testing.T)
```
It queues a logout whose `Until` is 30 ms away, makes every reach fail, waits past `Until`, and then sends a second, unrelated logout whose reach succeeds. It sets `reachFailuresSeen` to send each size on a buffered channel (restored in `t.Cleanup`), and asserts the size it reports after the second logout is 0: the lapsed key was pruned. The hook is called from `reachFollowed`'s own goroutine, so the test reads the channel, never the map.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/port49d/ -run 'PagedLoad|RetriesACompaction|FailedLogoutReach|LapsedLogout' -count=1`
Expected: FAIL: `pagedLoad` undefined; the remedy is said on every retry.

- [ ] **Step 3: Implement.** In `internal/port49d/brokerd.go`, lift the `retry` closure out of `openBroker`:

```go
// startRetryWait is how long a broker start waits before reading again.
var startRetryWait = 5 * time.Second

// startRetry runs f until it succeeds, ctx ends, or it fails with an error
// that is neither an outage nor one of also: each wait is said, since
// nothing is served meanwhile.
func startRetry(ctx context.Context, out io.Writer, f func() error, also ...error) error {
	for {
		err := f()
		if err == nil || ctx.Err() != nil {
			return err
		}
		wait := errors.Is(err, store.ErrUnavailable)
		for _, a := range also {
			wait = wait || errors.Is(err, a)
		}
		if !wait {
			return err
		}
		fmt.Fprintf(out, "port49-broker: %v; nothing is served yet; trying again in %v\n", err, startRetryWait)
		if !sleepCtx(ctx, startRetryWait) {
			return ctx.Err()
		}
	}
}

// pagedLoadFault, set by a test, is asked before each try of the load name
// and its error returned in place of the load's: how a test puts a
// compaction between pages without racing etcd's compactor. Nil in
// production.
var pagedLoadFault func(name string) error

// pagedLoad is startRetry for a load that reads pages at one revision: the
// ledger's contexts, the marks, the logouts. A compaction between pages
// reads the whole load again (11a final review N1).
func pagedLoad(ctx context.Context, out io.Writer, name string, f func() error) error {
	return startRetry(ctx, out, func() error {
		if pagedLoadFault != nil {
			if err := pagedLoadFault(name); err != nil {
				return err
			}
		}
		return f()
	}, store.ErrCompacted)
}
```
- Inside `openBroker`, `retry := func(f func() error, also ...error) error { return startRetry(ctx, out, f, also...) }` keeps the other call sites unchanged.
- The ledger, marks and logouts loads call `pagedLoad(ctx, out, "ledger", func() error { … })`, `"marks"` and `"logouts"`. Delete the ledger's explicit `store.ErrCompacted` argument.
- The ledger message changes from "trying again in 5s" to the variable's value; update any test asserting "5s".

In `internal/port49d/runner.go` `reachFollowed`, `failed` becomes `map[string]failedReach` with `type failedReach struct { n int; until time.Time }`. At each `followedLogouts` event, first prune:

```go
			now := time.Now()
			for k, f := range failed {
				if !f.until.IsZero() && now.After(f.until) {
					delete(failed, k) // the logout lapsed: nothing is left to reach
				}
			}
```
After each event, `if reachFailuresSeen != nil { reachFailuresSeen(len(failed)) }`, with `var reachFailuresSeen func(n int)` declared beside `reachFollowed` ("set by a test to see the failure count's size; nil in production"). In the default case, `f := failed[l.Key]; f.n++; f.until = l.Until; failed[l.Key] = f`, and the line:

```go
				wait := logoutRetryFirst << min(f.n-1, 6)
				if f.n == 1 {
					line += fmt.Sprintf("; not every step finished (%s): it is tried again in %v while this replica "+
						"runs the keyspace, and its mints and refreshes are refused meanwhile; to end its live "+
						"sessions here at once, %s", printsafe.Line(err.Error(), 300), wait,
						r.brk.FollowedLogoutByHand(l.Logout, rep))
				} else {
					line += fmt.Sprintf("; still not reached after %d tries (%s); tried again in %v", f.n,
						printsafe.Line(err.Error(), 300), wait)
				}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/port49d/ -count=1`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/port49d
git commit -m "fix: the broker start's paged loads retry a compaction; a logout reach's remedy is said once

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 14: One issuing CA per store

**Files:**
- Create: `internal/store/etcd/issuer.go`, `internal/store/etcd/issuer_test.go`, `internal/port49d/issuerrecord.go`, `internal/port49d/issuerrecord_test.go`
- Modify: `internal/issuer/issuer.go` (`CA.Previous`), `internal/port49d/brokerd.go` (`BrokerMain`'s subcommands, `openBroker`'s `startChecks`, the shared-store branch, `openDirectoryLater`'s check at :702)

**Interfaces:**
- Produces:
  - `type etcd.IssuerRecord struct { Current, Previous, WrittenBy string; WrittenAt time.Time }` with JSON keys `current`, `previous`, `written_by`, `written_at`;
  - `func (s *Store) IssuerRecord(ctx context.Context) (IssuerRecord, uint64, error)`: revision 0 when absent;
  - `func (s *Store) PutIssuerRecord(ctx context.Context, r IssuerRecord, over uint64) (bool, error)`: false when another write got there first;
  - `func (s *Store) DeleteIssuerRecord(ctx context.Context) (IssuerRecord, bool, error)`;
  - `issuer.CA.Previous *x509.Certificate`;
  - `type heldCA struct { current, previous string }` and `func heldIssuer(cfg config.Config, now time.Time) (heldCA, bool)`;
  - `type issuerRecorder interface { IssuerRecord(context.Context) (etcdstore.IssuerRecord, uint64, error); PutIssuerRecord(context.Context, etcdstore.IssuerRecord, uint64) (bool, error) }`;
  - `func checkIssuerRecord(ctx context.Context, rec issuerRecorder, held heldCA, who string, out io.Writer) error`;
  - `func forgetIssuer(args []string, stdout, stderr io.Writer) int`.

- [ ] **Step 1: Write the failing tests.**

`internal/store/etcd/issuer_test.go`:
```go
// meta/issuer is written only over the revision read: two brokers recording
// at once never write one over the other.
func TestTheIssuerRecordIsCompareAndSwap(t *testing.T) {
	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if _, rev, err := s.IssuerRecord(ctx); err != nil || rev != 0 {
		t.Fatalf("an absent record: %d %v", rev, err)
	}
	if ok, err := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:a"}, 0); !ok || err != nil {
		t.Fatalf("create: %v %v", ok, err)
	}
	if ok, _ := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:b"}, 0); ok {
		t.Fatal("a second create over the first")
	}
	r, rev, _ := s.IssuerRecord(ctx)
	if ok, _ := s.PutIssuerRecord(ctx, IssuerRecord{Current: "sha256:c", Previous: r.Current}, rev); !ok {
		t.Fatal("an update at its revision")
	}
	if old, ok, err := s.DeleteIssuerRecord(ctx); !ok || err != nil || old.Current != "sha256:c" {
		t.Fatalf("delete: %+v %v %v", old, ok, err)
	}
}
```

`internal/port49d/issuerrecord_test.go`, with an in-memory `issuerRecorder` (a struct with `rec`, `rev` and a `racer func()` called inside `PutIssuerRecord` before the compare):
```go
// The record follows a rotation: a broker promoted here starts and updates it,
// one restarted before its files were copied is refused with the copy, and a
// broker with another CA is refused with both fingerprints (Review Focus 6;
// decision 53 ruling 10).
func TestTheIssuerRecordFollowsARotation(t *testing.T) {
	ctx := context.Background()
	rec := &memRecorder{}
	var out bytes.Buffer
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@a", &out); err != nil ||
		rec.rec.Current != "sha256:f1" {
		t.Fatalf("first: %v %+v", err, rec.rec)
	}
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@b", &out); err != nil {
		t.Fatalf("same: %v", err)
	}
	if err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f2", previous: "sha256:f1"}, "port49-broker@a", &out); err != nil ||
		rec.rec.Current != "sha256:f2" || rec.rec.Previous != "sha256:f1" {
		t.Fatalf("promoted: %v %+v", err, rec.rec)
	}
	err := checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f1"}, "port49-broker@b", &out)
	if err == nil || !strings.Contains(err.Error(), "behind a promotion") || !strings.Contains(err.Error(), "issuing-ca-previous.pem") {
		t.Fatalf("behind: %v", err)
	}
	err = checkIssuerRecord(ctx, rec, heldCA{current: "sha256:f9"}, "port49-broker@c", &out)
	if err == nil || !strings.Contains(err.Error(), "sha256:f9") || !strings.Contains(err.Error(), "sha256:f2") ||
		!strings.Contains(err.Error(), "forget-issuer") {
		t.Fatalf("other: %v", err)
	}
}

// Two brokers recording at once: the loser reads the winner's record and is
// judged against it.
func TestALostRaceToRecordIsJudgedAgain(t *testing.T)
```
In the second test, `memRecorder.racer` writes `sha256:other` first, and the broker holding `sha256:mine` is refused.

The wiring, end to end on etcd (Review Focus 6; pre-flight I11), in `internal/port49d/issuerrecord_test.go`:
```go
// Two port49-brokers on one store, each with its own init-issuer: the first
// records its CA and starts, the second is refused naming both
// fingerprints, at each of the three places the directory first answers.
func TestASecondBrokerOnAnotherCAIsRefused(t *testing.T)
```
Three subtests, each on a fresh fleet:
- **split, at start** (`startChecks`): `f := splitFleet(t)`; give `f.broker` and a second broker from `f.brokerVia(t, f.proxy.Addr(), "port49-broker", "")` each `broker.identity.issuance` (as `issuer_test.go:207` enables it) and run `initIssuer` in each one's `broker.state_dir`, so the two CAs differ. Start the first with `startBroker` and wait for "recorded the issuing CA"; run the second with `runBrokerUntil(t, cfg2, &out2, "is not the one the store records", 1)`, and assert the line names both fingerprints and `forget-issuer`.
- **shared stores** (the shared-store branch after `bs.dir.set(b)`): the same with `stores.shared: true` in both broker configurations, as the existing shared-store broker test writes them (`git grep -n 'shared: true' -- 'internal/port49d/*_test.go'`).
- **a late directory** (`openDirectoryLater`): cut the directory's proxy (`f.ddproxy`, `brokerd_test.go:55`) before the second broker starts, so its directory opens late; restore it, and assert the run ends with the same refusal.

Then, in the split subtest, copy the first broker's `issuing-ca.pem` and `issuing-ca.key` into the second's state directory and assert the second starts: the copy instruction works.

`internal/issuer/issuer_test.go`: `Load` sets `CA.Previous` when `issuing-ca-previous.pem` is present and valid.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/store/etcd/ ./internal/port49d/ ./internal/issuer/ -run 'Issuer|Rotation|LostRace|Previous|AnotherCA' -count=1`
Expected: FAIL to build.

- [ ] **Step 3: Implement.**

`internal/store/etcd/issuer.go`. Copy `PutWitness`'s compare-and-swap shape (`internal/store/etcd/meta.go:503`):
```go
package etcd

// IssuerRecord is meta/issuer (decision 53 ruling 10): the issuing CA every
// broker on this store issues from, by fingerprint. Never key material.
type IssuerRecord struct {
	Current   string    `json:"current"`
	Previous  string    `json:"previous,omitempty"`
	WrittenBy string    `json:"written_by"`
	WrittenAt time.Time `json:"written_at"`
}

// IssuerRecord reads meta/issuer and the revision it was written at; 0 when
// there is none.
func (s *Store) IssuerRecord(ctx context.Context) (IssuerRecord, uint64, error) {
	resp, err := s.ctxKV.Get(ctx, s.k.meta("issuer"))
	if err != nil {
		return IssuerRecord{}, 0, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return IssuerRecord{}, 0, nil
	}
	var r IssuerRecord
	if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
		return IssuerRecord{}, 0, fmt.Errorf("etcd: %s does not decode; port49-broker forget-issuer removes it",
			s.k.meta("issuer"))
	}
	return r, uint64(resp.Kvs[0].ModRevision), nil
}

// PutIssuerRecord writes r if meta/issuer is still at over (0: absent), and
// reports false when another write got there first.
func (s *Store) PutIssuerRecord(ctx context.Context, r IssuerRecord, over uint64) (bool, error) {
	key := s.k.meta("issuer")
	r.WrittenAt = s.now().UTC()
	body, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	resp, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(over))).
		Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return false, unavailable(err)
	}
	return resp.Succeeded, nil
}

// DeleteIssuerRecord removes meta/issuer, returning what it held.
func (s *Store) DeleteIssuerRecord(ctx context.Context) (IssuerRecord, bool, error) {
	r, rev, err := s.IssuerRecord(ctx)
	if err != nil || rev == 0 {
		return r, false, err
	}
	if _, err := s.ctxKV.Delete(ctx, s.k.meta("issuer")); err != nil {
		return r, false, unavailable(err)
	}
	return r, true, nil
}
```
The broker's role already holds write on the whole prefix (`roles.go:80`); the daemon's never reads this key, so the roles need no change. Confirm that `checkGrantsWith` raises nothing for the new key: `go test ./internal/store/etcd/ -run Roles`.

`internal/issuer/issuer.go`: `CA` gains `Previous *x509.Certificate // the previous CA, from PreviousCertFile, when present and valid`. In `Load`'s loop, set it in the `cert != nil` case when `o.name == PreviousCertFile`.

`internal/port49d/issuerrecord.go`:
```go
package port49d

// heldCA is the issuing CA this broker's files hold, by fingerprint.
type heldCA struct{ current, previous string }

// heldIssuer reads cfg's broker's issuing CA for the record (decision 53
// ruling 10): ok is false with no issuance or no usable CA, which the start
// says already and which issues nothing to check.
func heldIssuer(cfg config.Config, now time.Time) (heldCA, bool) {
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.Issuance == nil {
		return heldCA{}, false
	}
	ca, _ := issuer.Load(issuerFiles(brokerStateDir(cfg)), now)
	if ca.Unavailable != nil || ca.Cert == nil {
		return heldCA{}, false
	}
	h := heldCA{current: issuer.Fingerprint(ca.Cert)}
	if ca.Previous != nil {
		h.previous = issuer.Fingerprint(ca.Previous)
	}
	return h, true
}

type issuerRecorder interface {
	IssuerRecord(context.Context) (etcdstore.IssuerRecord, uint64, error)
	PutIssuerRecord(context.Context, etcdstore.IssuerRecord, uint64) (bool, error)
}

// checkIssuerRecord holds this broker's CA to the store's record (decision 53
// ruling 10): it records one where there is none, follows a promotion its
// own files show, and refuses any other difference, saying what to copy.
func checkIssuerRecord(ctx context.Context, rec issuerRecorder, held heldCA, who string, out io.Writer) error {
	for range 3 {
		r, rev, err := rec.IssuerRecord(ctx)
		if err != nil {
			return err
		}
		next := etcdstore.IssuerRecord{Current: held.current, Previous: held.previous, WrittenBy: who}
		switch {
		case rev == 0:
			ok, err := rec.PutIssuerRecord(ctx, next, 0)
			if err != nil {
				return err
			}
			if !ok {
				continue // another broker recorded first: judge against it
			}
			fmt.Fprintf(out, "port49-broker: issuance: recorded the issuing CA %s in the store; every broker on it "+
				"must issue from it\n", held.current)
			return nil
		case r.Current == held.current:
			return nil
		case held.previous != "" && held.previous == r.Current:
			ok, err := rec.PutIssuerRecord(ctx, next, rev)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			fmt.Fprintf(out, "port49-broker: issuance: the store's issuing CA is now %s, promoted from %s on this "+
				"broker; copy the files rotate-issuer named to every other broker, then restart each\n",
				held.current, held.previous)
			return nil
		case r.Previous != "" && held.current == r.Previous:
			return fmt.Errorf("issuance: this broker's issuing CA (%s) is behind a promotion: the store records %s, "+
				"promoted from it by %s at %s. Copy %s, %s and %s from that broker into broker.state_dir, then "+
				"start", held.current, r.Current, printsafe.Line(r.WrittenBy, 120), r.WrittenAt.Format(time.RFC3339),
				issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile)
		default:
			return fmt.Errorf("issuance: this broker's issuing CA (%s) is not the one the store records (%s, by %s "+
				"at %s): every broker on one store issues from one CA. Copy %s and %s from a broker that holds it; "+
				"if every broker lost it, run `port49-broker forget-issuer` once, then init-issuer on one broker "+
				"and copy its files to the others", held.current, r.Current, printsafe.Line(r.WrittenBy, 120),
				r.WrittenAt.Format(time.RFC3339), issuer.CertFile, issuer.KeyFile)
		}
	}
	return errors.New("issuance: the store's issuing CA record kept changing under this start; start again")
}
```

Wiring in `internal/port49d/brokerd.go` `openBroker`:
- Compute `held, issues := heldIssuer(cfg, time.Now())` and `who := "port49-broker@" + hostname`. Use `os.Hostname()`, as the runner's `who` is built: `grep -n 'who :=\|who =' internal/port49d/runner.go internal/port49d/brokerd.go`.
- Define `issuerCheck := func(s *etcdstore.Store) error { if !issues { return nil }; c, cancel := context.WithTimeout(ctx, 4*de.CallTimeout); defer cancel(); return checkIssuerRecord(c, s, held, who, out) }`.
- Call it:
  - at the end of `startChecks` (a split's directory at start);
  - after `bs.dir.set(b)` in the shared branch (wrapped in `retry`, so an outage waits as the other start reads do);
  - at the end of `openDirectoryLater`'s check callback (:702), where a fault already ends the run.

`forget-issuer`: in `BrokerMain`, before the flag parsing:
```go
	if len(args) > 0 && args[0] == "forget-issuer" {
		return forgetIssuer(args[1:], os.Stdout, os.Stderr)
	}
```
`forgetIssuer` parses `--config`, loads with `config.LoadBroker`, and opens the record's store as `offlineBroker` opens its own: `m := metrics.New(prometheus.NewRegistry()); s, err := attempt(ctx, cfg, ref, m, stderr, false)` (no floor check: Task 12). Here `ref` is `directoryRef(cfg)` unless `cfg.Stores.Shared`, else `sessionRef(cfg)`. It then calls `s.DeleteIssuerRecord` and prints "port49-broker: removed the issuing CA record (sha256:…, by … at …); the next broker start records its own" or "no issuing CA record to remove". Add `forget-issuer` to the usage line.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/store/etcd/ ./internal/issuer/ ./internal/port49d/ -count=1`
Expected: PASS. Every existing split-broker test with issuance now records and checks: a fixture copying one CA to two brokers passes, and one giving each broker its own `init-issuer` is refused. Fix such a fixture to share one CA (`grep -n 'init-issuer\|initIssuer(' internal/port49d/*_test.go`).

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/store/etcd internal/issuer internal/port49d
git commit -m "feat: every port49-broker on a store issues from the CA the store records

The key stays on each broker's disk; the store holds fingerprints alone
(decision 53 ruling 10).

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 15: The write fence walks every ancestor directory

**Files:**
- Modify: `internal/fence/fence_linux.go` (`Read`'s doc comment, `resolvePolicyPath`, a new `ancestorWritableByUsAlone`)
- Test: `internal/fence/fence_linux_test.go`

**Interfaces:**
- Produces: `func ancestorWritableByUsAlone(dir string) error` (unexported).

- [ ] **Step 1: Write the failing tests** in `internal/fence/fence_linux_test.go`:

```go
// A directory above the file that others can write could rename the file's
// directory and put another in its place: refused, unless its sticky bit
// keeps others from renaming what is below it (decision 53 ruling 11).
func TestAnAncestorOthersCanWriteIsRefused(t *testing.T) {
	top := t.TempDir()
	mid := filepath.Join(top, "shared")
	dir := filepath.Join(mid, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("x: 1\n"), 0o600)
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, 1<<20, "policy file"); err == nil || !strings.Contains(err.Error(), mid) {
		t.Fatalf("an others-writable ancestor: %v", err)
	}
	if err := os.Chmod(mid, 0o1777); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, 1<<20, "policy file"); err != nil {
		t.Fatalf("a sticky ancestor, as /tmp is: %v", err)
	}
}

// An ancestor on a read-only mount is excused, as a link's directory is.
func TestAWritableAncestorOnAReadOnlyMountIsAccepted(t *testing.T)
```
Model the second test on `TestAWritableDirectoryOnAReadOnlyMountIsAccepted` (`fence_linux_test.go:198`), which swaps `ReadOnlyFS`.

```go
// A POSIX ACL granting another user write shows in the mode's group bits
// (the ACL mask), so the mode check already refuses it.
func TestAnACLGrantingWriteIsRefused(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is not installed")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("x: 1\n"), 0o600)
	if out, err := exec.Command(setfacl, "-m", "u:nobody:rw", p).CombinedOutput(); err != nil {
		t.Skipf("this filesystem takes no ACL: %v %s", err, out)
	}
	if _, err := Read(p, 1<<20, "policy file"); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("an ACL granting write: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/fence/ -run 'Ancestor|ACL' -count=1 -v`
Expected: the ancestor test FAILS (the file is read); the ACL test PASSES (or skips), which records that ACLs need no new code.

- [ ] **Step 3: Implement.** In `resolvePolicyPath`, check each directory before looking up a component in it:

```go
	ancestors := map[string]bool{}
	for len(pending) > 0 {
		comp := pending[0]
		…
		next := filepath.Join(resolved, comp)
		if !ancestors[resolved] {
			if err := ancestorWritableByUsAlone(resolved); err != nil {
				return "", err
			}
			ancestors[resolved] = true
		}
		fi, err := os.Lstat(next)
		…
```
and:
```go
// ancestorWritableByUsAlone holds a directory the path passes through to
// the fence's rule (decision 53 ruling 11): owned by this process's user or
// root, and writable by nobody else, unless its sticky bit is set — others
// can then rename nothing below it that they do not own, and the next
// directory down is checked in turn — or it is on a read-only mount, as a
// link's directory is excused.
func ancestorWritableByUsAlone(dir string) error {
	d, di, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	what := "the directory " + dir + ", above the file"
	if di.Mode()&fs.ModeSticky != 0 {
		return ownedByUsOrRoot(what, di)
	}
	return dirWritableByUsAlone(what, d, di)
}
```
Replace `Read`'s doc sentence "Directories above those are not walked; keep the file where only root can rename its directory." with "Every directory above them is held to the same rule, a sticky one (`/tmp`) and one on a read-only mount excused (decision 53 ruling 11); POSIX ACLs show in the mode's group bits, NFSv4 ACLs are not read."

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/fence/ ./internal/port49d/ ./internal/inventory/ -count=1`
Expected: PASS. `t.TempDir()` sits under `/tmp` (sticky, root's) or `$TMPDIR`. If a test environment's `TMPDIR` has an others-writable, non-sticky parent, the failure names it. Say so in the report rather than excusing it in code.

- [ ] **Step 5: Verify and commit**

Run `make test && make vet`, then:
```bash
git add internal/fence
git commit -m "fix: the write fence holds every ancestor directory to its rule

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 16: Docs — the roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 12a — As built", the status line, the hand-offs)

- [ ] **Step 1: Write "Plan 12a — As built"** in 11b's style: the task commits, the rulings as recorded, what changed in review, and what was carried forward.

- [ ] **Step 2: Write the hand-offs.**
  - **12b:**
    - the deployment shapes write `secret_ref`, and each shape's device keys live under `key_secret_refs.file_dir` (`/run/port49/keys` by default) or in `PORT49_KEY_*` variables;
    - **`file:` secrets per shape** (`fence.ReadSecret`: links followed inside the directory, owner root or port49d's user, no world bit, group-read allowed):
      - **Kubernetes Secret volume:** mount the whole volume at `file_dir`, never by `subPath`: kubelet updates `..data` in a whole-volume mount, so a key version added to the Secret reaches port49d's next retry with no pod restart, and a `subPath` mount never sees it. Set `defaultMode: 0440` (or `0400`) and `securityContext.fsGroup` to port49d's group, so the root-owned files are group-readable by port49d and by nobody else;
      - **Secrets Store CSI driver:** the same whole-volume mount; the driver's default file mode is 0644, which is refused, so set the provider's file permission (where it has one) and `fsGroup`; measure the mode each provider writes;
      - **Vault Agent:** the template's `perms = "0440"` (or `"0400"`), and the agent running as root or as port49d's user (the injector's default uid 100 is refused: set `vault.hashicorp.com/agent-run-as-same-user` or the equivalent for the shape); render into `file_dir`;
      - **Docker and systemd credentials:** Docker's `secrets:` long syntax with `mode: 0440` and the gid (the default is documented as 0444, world-readable: measure it in the shape's smoke); systemd's `LoadCredential=` files under `$CREDENTIALS_DIRECTORY`, which `key_secret_refs.file_dir` names (their owner, mode and ACL as port49d's user sees them are unmeasured: measure in the shape's smoke before the shape documents them);
      - each shape's smoke test adds a key version by writing a new file and asserts it is in force without a restart (the 30 s retry);
    - a secret store's secrets as `file:` references rendered by its own agent (above), shown in at least one shape: port49 has no `vault:` scheme (decision 53 ruling 5);
    - `limits.max_connections` and `LimitNOFILE=`;
    - the issuing CA's files on each broker's state volume, with `init-issuer` once and copies to every other broker;
    - `forget-issuer` in the runbook;
    - the etcd floor line asserted in each shape's smoke test;
    - the policy file's `keys:` in every shape's example;
    - no NFS for the policy (NFSv4 ACLs are not read).
  - **12c:**
    - an alarm on `port49_connections_shed_total{reason="global_cap"}` increasing: the cap is shedding now;
    - a warning on `port49_connections` near `port49_connections_max`, sustained: it is about to.
  - **Plan 13:** the `secret_ref` reference page with `key_secret_refs`; key rotation as policy edits, and the 30 s retry while a file is rendered; the issuer record's three refusals at 3am; the shedding lines.
  - **12b runbook, the issuer record:** a broker refused "behind a promotion" on Kubernetes crash-loops, so `kubectl cp` into it cannot work: the runbook copies the files with a debug pod that mounts the broker's state PVC (pre-flight M19).

- [ ] **Step 3: Write the operator-facing notes for the PR body.**
  - Every `*_env` secret key is replaced by a `secret_ref` key (the table in "Design notes"), with no alias. A config written for an earlier build is refused, naming each removed key and what replaces it.
  - `keys:` moves from port49d.yaml into the policy file; port49-broker.yaml's `key_refs` goes. port49d and port49-broker refuse a policy with no `keys:`.
  - A policy names only the secrets `key_secret_refs` allows (`PORT49_KEY_*`, `/run/port49/keys` by default); port49d.yaml's own secrets may not sit inside it.
  - Key rotation no longer restarts port49d; a version whose file is not rendered yet is retried every 30 s.
  - A reload that retires a version resets its open connections with no strike.
  - `limits.max_connections`, its start line, `port49_connections_max`, and shedding at Accept with `port49_connections_shed_total` and its lines.
  - The etcd floor line, and its refusal.
  - The issuing CA record, its refusals, and `port49-broker forget-issuer`.
  - A second YAML document is refused in every file.
  - `HTTPS_PROXY` for the inventory service's sources, and its start line.
  - The fence's ancestor walk: a policy under a group-writable directory, or under one owned by another non-root user (a `/home/<someone>` path), is now refused.
  - **Upgrade notes** (pre-flight M14):
    - **Brokers on different CAs.** Brokers that each ran their own `init-issuer` will refuse after the first records its CA. Before upgrading, compare `port49-broker`'s start line fingerprint on every broker, and copy one CA's files to the others.
    - **etcd below the floor.** The first replica of a rollout refuses to start against a member below 3.4.24, 3.5.8 or 3.6. Upgrade etcd first.
    - **The start guard's first start.** The bundle last judged predates the policy's `keys:` block. The first start after the upgrade is still judged against it: a new policy whose `keys:` block omits a key_ref a key group names takes those devices out of service, and past `max_removed_percent` the start is refused. Run `port49 policy diff` between the old and new policy in CI before the upgrade, so the refusal is found there and not at the rollout.
    - **Order of edits.** Move `keys:` into the policy and remove it from port49d.yaml in the same rollout: the new build refuses either alone.
    - **Old replicas and the new policy.** A pre-12a replica decodes the policy strictly, so it refuses a policy with `keys:` at reload (`port49_policy_file_refused` at 1, its policy in force kept) and cannot restart on it. Roll the binary in the same change, and expect that alarm on old replicas until each is replaced.
- [ ] **Step 4: Run** `make test && make vet` and report the output.
- [ ] **Step 5: Commit**: `docs: plan 12a as built`.

---

## Leaves for later

**12b, deployment artifacts, release and publishing** (inventory theme A, theme E):
- **The shapes.** systemd units for port49d and port49-broker, with a CI smoke under a systemd container; Kubernetes manifests or a Helm chart, with a kind smoke. The broker is a StatefulSet with a volume per replica, no `fsGroup`, and an initContainer for the 0700 subdirectory (A3, A4, A6).
- **The four requirements every shape states:** the source address unrewritten, two processes on etcd, `broker.state_dir` surviving, and port49's own etcd (A5). Also:
  - the per-shape admin socket and surge replacement (A7);
  - `port49 revoke` per shape, and whether revocation is also reachable over the API (A8, still undecided);
  - D §13's SHOULDs (A31).
- **The issuing CA's files** in each shape's state volume, with `init-issuer` in each shape's setup (A17's artifact half, which this plan's record makes safe).
- **etcd artifacts:** members, compaction, quota, `store-roles`. Also:
  - single-site and multi-region examples;
  - one encryption secret per region, with the R27 rotation;
  - backups: snapshot, export cron, Velero (A18–A21);
  - `tls_listener` 300 exposed (A22);
  - the keytab and `PORT49_SITE` (A23);
  - the CronJob test in and out of the cluster, and `issuer-discovery` (A24);
  - the workload anchor's CRL (A25);
  - `fsGroup` notes (A26);
  - the policy and inventory path protection (A27, now with the ancestor walk);
  - compose's secrets as `file:` references in place of env files (A29).
- **Release and packaging.** A release pipeline for both `port49` builds, with `check-static` and the macOS `hwkey_dlopen` build (A10, E4). Client packages: `/etc/port49/config.yaml`, the broker CA, the `tss` group, the Python library and the Ansible collection (A11–A16). The 0755 install (A9). PyPI trusted publishing and the Galaxy token (E2, E3).
- **CI:** Ryan lifted the 2026-10-19 hold on workflow changes on 2026-10-24 (E9): GitHub-hosted runners, release jobs on tags only.
  - `make test` and `make vet` in CI (E5);
  - `TestAnotherUIDIsRefused` as root (E6);
  - the etcd floor in each shape's smoke test, which now reads port49's own start line (E7, B9's CI half).
- **Install pages (G1).** 12b ships each artifact's README; plan 13 writes the docs-site pages (ruled 2026-10-24).
- **`file:` secrets per shape**, as Task 16's hand-off lists them: whole-volume mounts, `defaultMode`/`fsGroup`, Vault Agent's `perms`, Docker's secret `mode`.
- **Anycast through MetalLB (A28)** goes to 12b, offered only after a lab row measures `externalTrafficPolicy: Local` (ruled 2026-10-24); the NX-OS per-request concern is moot because port49 offers single-connect.

**12c, reference configurations, alarms and lab rows** (themes C, D, F):
- Per-platform reference AAA configurations, the TLS ones from L73 (C1–C13).
- L39 (b) and (c).
- The SR Linux ERROR row, which gates `exit-on-reject true` (D2, C12).
- The failure matrix, including the cut region (D4).
- Oxidized's host keys (D6).
- **Alert rules (F1–F15).** They include the global cap's alarm on `port49_connections_shed_total{reason="global_cap"}` and its warning on `port49_connections` near `port49_connections_max`, and the `key_ref` cardinality bound (B7, F11, F14).
- **The Junos and NX-OS ERROR disagreement (inventory Q2)**, settled in the lab before a reference configuration relies on either reading.
- The 12 s dark member beside the store alarms (B19).
- **The Junos `idle-timeout` per role (B12), unresolved.** Spec §8 and decision 21 render every class from `session.max_session_age_default`. Rendering it per role needs a ruling: which role's ceiling governs a class that several roles reach. It goes with the Junos reference configuration.
- **Load validation at the §5 rate with `make qual-fleet` (D3)**, and the items sized from its numbers: the accounting group commit (B6), `call_timeout`/`bulk_timeout`/`packet_deadline` (B11), the matcher and quarantine scale (B13), the inventory-only refresh's cost (B14), TLS session tickets (B15), concurrent mints (B16), and per-source admission sizing (B17). It is assigned here unless Ryan places it elsewhere.

**Plan 13:** the operator and admin pages this plan's notes feed (G1–G8): `secret_ref` and `key_secret_refs`, key rotation in the policy, the issuer record, the connection cap and its shedding lines.

**Unassigned:** the cross-region policy-bundle check (B18), "if a deployment shows the need".

---

## Self-review notes

### Coverage of the inventory's theme B and theme A's code items

| Item | Task |
|---|---|
| B1 `secret_ref` resolvers (`env:`, `file:`; no store client, ruling 5); key sets into the policy | 3, 4, 5, 6, 7, 8 |
| B2 `token_secret_ref`, `webhook_secret_ref` | 9 |
| B3 second YAML document (port49d.yaml, `InventoryServiceOf`, and every single-document loader) | 2 |
| B4, B20 egress proxy and its start line | 10 |
| B5 global connection cap (its alarm: 12c) | 11 |
| B6 accounting group commit | 12c, needs load numbers |
| B7 `key_ref` cardinality | 12c, with the alarms (roadmap: "bound it when the alarms are written") |
| B8 write fence ancestors and ACLs | 15 |
| B9 etcd floor (start check; CI half 12b) | 12 |
| B10 paged loads and `ErrCompacted`; the remedy once; lapsed entries | 13 |
| B11, B13–B17 sizing from load | 12c (load validation) |
| B12 Junos `idle-timeout` per role | 12c, needs a ruling |
| B18 cross-region bundle check | unassigned, optional |
| B19 dark member 12 s | 12c |
| B21 decision 48's budget | ruled; nothing to do |
| A17 the cross-broker same-CA check (code) | 14 |
| A29 compose `secret_file` | the code is `file:` (Task 3); the compose change is 12b |

### Security rules

- **No secret printed:** `Secret` redacts (Task 3); Parse quotes nothing (3); `ErrBadProxy`, and a misread proxy never dialled (10); `secretFrom` (9); test failure messages print lengths, never values (3, 4, 6).
- **A policy cannot aim port49d at the host's secrets:** `key_secret_refs` bounds every reference before anything is read, and a link out of `file_dir` is refused at the read (3, 6, 8).
- **`file:` allows group-read, which `keyfile.ReadSecret` never did.** That is ruled (team lead, pre-flight I12) for Kubernetes Secret and CSI volumes and agents' `perms`; the file stays writable by its owner alone, with no world bit, and every directory on the way is fenced. `keyfile.ReadSecret` keeps its owner-only rule for TLS keys and the keytab.
- **The CA key never leaves the broker's disk:** the record is fingerprints alone (14).
- **The fence is stricter, never looser:** a sticky or read-only ancestor is excused only where a rename by others is already impossible (15).
- **A version's secret never changes under a device:** refused at reload (6) and in `policy diff` (8).

### Pre-flight findings (`.superpowers/sdd/preflight-12a.md`), where each is applied

| Finding | Where |
|---|---|
| C1, I2 the cap sheds, counted and said at once | Design notes; Task 1 ruling 8 and §12 lines; Task 11 |
| I1 listeners hold no slot | Task 11 (`TestIdleListenersHoldNoSlot`) |
| I3 no strike for a reload's withdrawal | Task 1 ruling 4; Task 7 |
| I4 a reload waiting on a secret is retried | Task 1 ruling 2; Task 6 (`keyretry.go`) |
| I5 `key_secret_refs` | Task 1 ruling 12; Task 3 (`Allowance`); Task 6; Task 8 |
| I6 spec S:7783, S:5163, Step 8's grep | Task 1 Steps 3, 5, 8 |
| I7 `policy test` fails every policy port49d refuses | Task 8 |
| I8 key notices and the swap's key line | Task 6 |
| I9 the qualification policy | Task 6 item 9 |
| I10 a misread proxy refused by the transport | Task 10 |
| I11 wiring tests | Task 11 (start line and gauge), 12 (floor), 13 (marks and logouts), 14 (three call sites) |
| I12 `file:` through the fence, links inside the directory, group-read | Design notes; Task 3; Task 16 hand-off |
| M1 Task 6's file list | Task 6 Files |
| M2 `key_refs` comments | Task 6 Step 5 |
| M3 `config.KeySets` deleted | Task 8 |
| M4 no canonical text | Tasks 4, 5, 6 |
| M5 `ResolveSecret` on a hand-built Config | Task 4 |
| M6 when the bind password is read | Design notes table |
| M7 test messages print no secret | Tasks 3, 4, 6, 9 |
| M8 a bare `keys:` | Task 5 |
| M9 a re-keyed version in `policy diff` | Task 8 |
| M10 `keys: {}` beside a policy | Task 6 |
| M11 removed keys named | Tasks 4, 6, 9 (`yamlfault.Replaced`) |
| M12 a pasted secret: rotate it | Task 5 |
| M13 the floor at server starts only | Task 12 |
| M14 the start guard's first start after the upgrade (`compileBundle`); upgrade notes | Task 6 (item 6, `TestTheFirstStartAfterTheUpgradeIsJudgedAgainstAPolicyWithNoKeysBlock`); Task 16 Step 3 |
| M15 Task 10's stray `internal/secretref` | Task 10 |
| M16 `keys status` with no policy | Design notes; Task 8 |
| M17 `inventory diff`'s unchecked verdict | Task 8 |
| M18 roadmap gaps (A28, E9, Q2, G1) | Leaves for later; README |
| M19 the failure-count hook; the crash-loop runbook | Task 13 (`reachFailuresSeen`); Task 16 hand-off |
| Re-review N1 the overlap check by resolved path, key files, keytab and state directory | Design notes; Task 1 ruling 12; Task 6 (`secretsApart`, `TestAConfigSecretInsideTheAllowanceIsRefused`) |
| N2 `liveKeys` reads inside `file_dir` | Task 6 (`TestAPolicyKeyLinkingOutOfTheDirectoryIsRefused`) |
| N3 the keys in force before the policy | Task 6 item 7 (`swap`) |
| N4 the notices after every reload | Task 6 item 7; `TestASwapSaysItsKeyChanges` |
| N5 the key-line test's `r.keys` | Task 6 Step 1 |
| N6 `secret_env` in the policy named | Task 5 (`policy.Parse`, `TestAKeySetThePolicyCannotUseIsRefused`) |
| N7 old replicas; the ancestor walk's other owner | Task 16 operator and upgrade notes |
| N8 a shed counted as single-connect | Task 11 (`Serve`) |
| N9 the floor at a late directory open | Design notes; Task 1 ruling 9 |
| N10 no fixture secret in a test message | Global Constraints; Tasks 3, 5, 6, 10 |
| N11 the world-readable refusal's remedies | Design notes; Task 3 (`fence.ReadSecret`) |
| N12 Docker and systemd modes unmeasured | Task 16 hand-off |
| N13 nits | Task 1 Step 7; README |
