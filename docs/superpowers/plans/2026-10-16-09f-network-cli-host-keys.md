# network_cli host keys under the port49 name: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the `network_cli` address-keying gap (spec §13 decision 46 ruling 15, L66 (e)) in the
`port49.client.token` lookup. Before it mints, the lookup checks the device's address entry against
the key filed under the port49 name. If the address has no key, it copies the name's key to the
address. If the address has a different key, it refuses, naming both, and mints nothing.

**Architecture:** The check and the copy run on the controller, in the lookup, before any mint. It
needs a new helper in the Python library (`port49.hostkeys`) that reads what is filed under a name
and under an address, and appends lines. The lookup takes the address and port from the inventory
(`hostvars[device].ansible_host`/`ansible_port`), because that is what `network_cli` keys by, not
from the broker. It writes nothing when the connection is not `network_cli`.

**Tech Stack:** Python 3.10+ stdlib, OpenSSH `ssh -G` and `ssh-keygen -F` (already used by
`port49.hostkeys`), ansible-core 2.16+, containerlab for the lab cell.

**Spec:** docs/design/2026-08-23-policy-engine-spec.md: §13 decision 46 ruling 15 (amended by
Task 3), ruling 13 (the Python client's host keys), and §15 L66. Owner's ruling 2026-10-15
(roadmap, docs/superpowers/plans/README.md, "small plan closes the `network_cli` address-keying gap").

## Global Constraints

- No token, password, challenge or response in any output, log, exception or test message.
- Error codes are the client's existing `HostKeyError` codes (clients/python/README.md code table):
  `host_key_changed`, `host_key_revoked`, `host_key_uncheckable`, `host_keys_not_kept`,
  `known_hosts_unread`, `device_name`, `address`. Add none. These are client codes, not §5.7 reasons.
- Writes are one O_APPEND, flock'd write of whole lines, as `hostkeys.remember` does. Hashed names
  when `HashKnownHosts yes` (`hostkeys.hashed`). Nothing is ever deleted or rewritten.
- Never touch the real `~/.ssh` or `~/.ansible` in tests: every test runs with `HOME` set to a temp dir.
- snake_case for every option name. Python stdlib only in the library.
- Commits: Conventional Commits, ending only with the implementer's `Co-Authored-By` line.

## Rulings (controller, 2026-10-16)

- **R1. Which file.** `network_cli`'s two ssh types, paramiko and libssh, both read and file the
  address under `~/.ssh/known_hosts` (L66 (c), (e)). The lookup reads and writes the address's
  entry there, with a lookup option `known_hosts_file` (default `~/.ssh/known_hosts`) for an
  operator who points Ansible elsewhere. The name's keys are read from every file `ssh -G <name>`
  names (`userknownhostsfile`, `globalknownhostsfile`), the same files `port49 ssh` uses.
- **R2. The four cases**, per key type: the name's unrevoked keys N against the address's keys A
  in `known_hosts_file`. The address is filed as `addr`, or as `[addr]:port` when the port is not 22.
  1. N has keys and A has none: append each of N's keys under the address, then mint.
  2. N and A both have keys: every key type present in both must match, or the lookup refuses
     `host_key_changed`. The message names the device, the address, both keys' types and SHA256
     fingerprints (as `ssh-keygen -lf` prints them), and the command that clears the stale address
     entry (`ssh-keygen -R <addr-entry> -f <file>`). Nothing is minted. A key type N has and A lacks
     is appended; a type A has and N lacks is left alone.
  3. N has none and A has keys: copy A's keys under the name, in the first `userknownhostsfile`
     (as `remember` chooses), then mint. Without that, the next address change would be a first
     contact again. This copies the key the address already holds, and Ansible trusts that key
     anyway, so it narrows the gap and widens nothing. This goes beyond the owner's ruling, which
     names only cases 1 and 2.
  4. Neither has a key: a first contact, the same as today. Mint, and change nothing.
  - Any key of A that a `@revoked` line or `RevokedHostKeys` revokes: refuse `host_key_revoked`.
- **R3. When it runs.** Only when the device's `ansible_connection` (from hostvars, else the
  play's) is `network_cli` or `ansible.netcommon.network_cli`. Otherwise the lookup does exactly
  what it does today. There is no option to switch the check off.
- **R4. Workload mode** checks every device in `terms` before the one `wl.tokens` call. Any refusal
  fails the lookup before the mint.
- **R5. A device that has no `ansible_host`** uses its inventory name as the address, as Ansible does.

## Review Focus

1. A hashed known_hosts (`HashKnownHosts yes`): both the name and the address are found through
   `ssh-keygen -F`, and copies are written hashed.
2. A non-22 `ansible_port`: the entry is `[addr]:port` on both read and write.
3. Two lookups at once on the same file: no duplicated or interleaved line.
4. A `known_hosts_file` holding `@cert-authority` lines: they are not counted as keys, and nothing
   is copied from them.
5. The lookup runs for a different device than the current host: use that device's hostvars.

---

### Task 1: `port49.hostkeys` address helpers

**Files:**
- Modify: `clients/python/src/port49/hostkeys.py`
- Test: `clients/python/tests/test_hostkeys.py`

**Interfaces:**
- Produces:
  - `filed(name, paths, *, ssh_keygen="ssh-keygen") -> tuple[list[str], list[str]]`: the
    `(keys, revoked)` filed under `name` across `paths`, each key `"<type> <b64>"`, deduplicated in order.
  - `address_entry(address, port) -> str`: `addr` for port 22, else `[addr]:port`. Raises
    `HostKeyError("address", …)` on a `"`, newline, space or empty address.
  - `known_files(name, *, ssh="ssh", ssh_config=None) -> tuple[list[str], str, bool]`: the paths
    `ssh -G name` names (user then global, `~` expanded), the first user file as the write target,
    and `hash_names`.
  - `append(path, host, keys, *, hash_names, ssh_keygen="ssh-keygen")`: the O_APPEND, flock'd
    write of one line per key under `host` (hashed if `hash_names`). It re-reads under the lock and
    skips a key already filed. Under the lock, a different key of the same type now filed under
    `host` raises `host_key_changed`, as `remember` does.
  - `fingerprint(key) -> str`: `SHA256:<b64>` as `ssh-keygen -lf` prints it, computed in Python
    (base64-decode, SHA-256, unpadded base64).

- [ ] Step 1: Write failing tests:
  - `filed` across two files, one hashed;
  - `@cert-authority` lines excluded and `@revoked` lines returned as revoked;
  - `address_entry` for port 22, port 830 and an IPv6 address with a port (`[2001:db8::1]:830`),
    plus the refusals;
  - `append` writes hashed and plain, adds a missing final newline, skips a duplicate, and refuses
    a different key of the same type filed under the lock;
  - `fingerprint` checked against `ssh-keygen -lf` on a generated key (skip if `ssh-keygen` is
    missing).
- [ ] Step 2: Run `make test-python` and see them fail.
- [ ] Step 3: Implement. Refactor `remember` to call `append`, so there is one writer.
- [ ] Step 4: Run `make test-python` and see it pass. Prove each new test with a mutation.
- [ ] Step 5: Commit `feat: hostkeys reads and files keys under an address`.

### Task 2: the lookup checks and copies before it mints

**Files:**
- Modify: `clients/ansible/ansible_collections/port49/client/plugins/lookup/token.py`
- Test: `clients/ansible/ansible_collections/port49/client/tests/unit/test_token.py`

**Interfaces:**
- Consumes: Task 1's `filed`, `address_entry`, `known_files`, `append`, `fingerprint`, and the
  existing `is_revoked`/RevokedHostKeys handling in `hostkeys`.
- Produces: the lookup option `known_hosts_file` (str, default `~/.ssh/known_hosts`, documented
  in DOCUMENTATION), and `_check_host_keys(device, hostvars, known_hosts_file)`, called for each
  term before any mint when R3 holds.

- [ ] Step 1: Write failing tests (temp `HOME`, real `ssh-keygen`, fake library as today), one per
  R2 case:
  - case 1 writes the address line, and the mint follows;
  - case 2 with a mismatch raises through `_fail` with `[host_key_changed]`, both fingerprints,
    the address and the `ssh-keygen -R` hint, and the fake library records **no mint call**;
  - case 2 with a match mints and writes nothing;
  - case 2 with a type missing on the address appends that type only;
  - case 3 writes the name line;
  - case 4 writes nothing and mints;
  - a revoked address key gives `[host_key_revoked]` with no mint;
  - a non-network_cli connection does nothing to the file;
  - workload mode with one conflicting device of two mints nothing;
  - a non-22 port uses `[addr]:port`;
  - another device's hostvars are used;
  - no output contains the fake token.
- [ ] Step 2: Run `make test-python` and see them fail.
- [ ] Step 3: Implement, keeping `_fail`'s control-byte stripping and the `from None` discipline.
- [ ] Step 4: Run `make test-python` and see it pass. Prove each test with a mutation.
- [ ] Step 5: Commit `feat: the port49 lookup files network_cli host keys under the port49 name`.

### Task 3: docs and spec

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (decision 46 ruling 15, near "**15. The
  Ansible lookup**"; the ruling 13 cross-reference "It does not hold for Ansible's `network_cli`")
- Modify: `clients/ansible/ansible_collections/port49/client/README.md` ("## Host keys")
- Modify: the lookup's DOCUMENTATION text (`token.py` lines 11–13), and
  `test_token.py::test_the_doc_names_libssh_for_host_key_auto_add` if its asserted wording moves
  (the libssh warning stays: the check runs before the connection, and libssh still accepts a key
  that changes later in a run).

- [ ] Step 1: Amend ruling 15. Say that the lookup closes the gap before minting, and describe the
  four cases and the owner's ruling of 2026-10-15. Mark the claim *provisional on L66* until Task 4
  measures it. Keep every measured sentence.
- [ ] Step 2: Rewrite the README's first bullet to cover:
  - what the lookup now does;
  - the refusal's message and how to clear a stale address (`ssh-keygen -R`);
  - `known_hosts_file`;
  - that paramiko still refuses a file holding `@revoked`/`@cert-authority` lines.
- [ ] Step 3: Run `make test-python`. Commit `docs: the port49 lookup closes network_cli's address-keying gap`.

### Task 4: lab cell (L66 (e) rerun with the lookup)

**Files:**
- Modify: the L66 harness (`tests/lab/` – find `TestL66`; `make lab-ansible`)
- Create: `tests/lab/results/L66-<platform>.md` addenda (one dated section per platform run)

- [ ] Step 1: Add an (e3) cell to the harness:
  - file the device's key under its name, as `port49 ssh` does;
  - move the inventory `ansible_host` to the stand-in host (the (e) cell's), and run the play
    through the lookup, with `host_key_auto_add` on, once for each ssh type;
  - pass when the lookup refuses `host_key_changed` naming both keys, the broker log shows no
    mint for that run, and the stand-in saw no TACACS+ exchange.
- [ ] Step 2: Add a control: the same play at the device's own new address with no address entry.
  The lookup copies the key, and the play logs in.
- [ ] Step 3: Run it on one platform under the lab rules: single occupant, STOP sentinel,
  watchdog, a disk floor of 67584M, and a detached worktree pinned at the commit. Write the
  results addendum, then commit `test: L66 (e3) the lookup refuses a moved address before minting`.
- [ ] Step 4: Change ruling 15's *provisional* to measured, citing the note. Commit with Step 3's work.
