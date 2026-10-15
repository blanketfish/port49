# L62 — ser8

**Closed.** Every clause of spec §15 L62 was measured on 2026-10-15 in one session with Ryan,
run by `tests/lab/runbooks/L62-ser8.md`. The second host is a container with its own swtpm and
machine id (see "The second host"). Every clause that depends on TPM firmware ran on the SER8's
real TPM.

- **Date measured:** 2026-10-15, 03:59–05:19Z
- **Platform:** beehive, the SER8 lab machine: Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic
  before the reboot and 7.0.0-38-generic after it (the reboot installed a pending kernel)
- **TPM:** `/dev/tpmrm0` (`crw-rw---- tss tss`), ACPI `MSFT0101`; family "2.0", revision 1.38,
  manufacturer `MSFT`, vendor string "Pluton.TPM.A", firmware 0x60004 / 0x1017F (AMD Pluton)
- **Keycloak:** 26.4 (`quay.io/keycloak/keycloak:26.4@sha256:9409c59b…`, `tests/lab/oidc/compose.yaml`)
- **Build:** `port49-l62`, the static binary built from `8b3dc921` and installed at
  `/usr/local/bin/port49-l62`; the broker and Keycloak came from the `tests/lab/l62` harness
  (`PORT49_L62_UP=1`) at the same commit
- **Users:** `p49lab` (uid 1001, in `tss`), `p49notss` (uid 1002, not in `tss`). Neither is
  root. The harness pins nothing about the key store; each step names its config
  (`issued_key_store: tpm`, `file` or `pkcs11`).
- **Second host:** container `l62host2` (ubuntu:24.04.5) on the SER8, swtpm 0.10.1 through
  `tpm_vtpm_proxy` (its own `/dev/tpmrm1`, mapped to the container's `/dev/tpmrm0`), its own
  `/etc/machine-id`, and `p49lab`'s `~/.port49` mounted over NFS 4.2 from the SER8
- **Token (step 6):** the YubiKey 5C Nano FIPS of L60, slot 9e (CKA_ID 0x04) through
  libykcs11 (serial recorded locally, not here)
- **Capture:** the observation logs (`obs-p49lab-beehive.log`, `obs-rwendt-beehive.log`,
  written by the runbook's `o` helper, which drops any line naming a password, token, secret,
  code, state or challenge; the YubiKey serial masked) and `L62-ser8-tls.pcap` (loopback,
  tcp 8449, steps 0–3a), kept locally under `tests/lab/captures/L62-ser8-2026-10-15/` (the pcap's
  sha256 begins `355aab0c`). The PIN was typed by Ryan only at port49's own prompt and was never
  in the session or a file.

## Claim

Spec §15 L62: a real TPM 2.0 through `/dev/tpmrm0` on the SER8 for a non-root user in `tss`.
Whether `issued_key_store: tpm` creates a key under the ECC SRK, signs a TLS 1.3 handshake and
a refresh, survives an agent restart and a reboot, and is refused on another machine given the
same key file. With a shared home, whether each host keeps its own `.tpmkey`, reads the other's
as no held pair and overwrites neither. Whether a token host and a file host on the same home
each sign in once, log in again with no sign-in, and overwrite neither certificate. And the
control: a user outside `tss` is refused, naming the group.

## Observation

Machine ids are the first 8 hex digits of the sha256 of `/etc/machine-id`: the SER8 is
`f89db056`, host2 is `9939ac4d`. `$B` is `127.0.0.1_8449`.

### Step 0: the platform

As listed above. The persistent handles before anything ran: `0x81000001`, `0x81000009`,
`0x81010001`.

### Step 1: the key is created under the ECC SRK

`port49 login --oidc --no-browser`, exit 0: `no TPM key for this machine yet`, one sign-in,
`logged in to https://127.0.0.1:8449`. No `the key is a file`.

- `issued/` held `$B.f89db056.tpmkey` (398 bytes) and `$B.f89db056.pem` (1604 bytes), both
  0600 and owned by `p49lab`. There was no `$B.pem` or `$B.key`.
- The key file's header is `-----BEGIN TSS2 PRIVATE KEY-----`. asn1parse gives
  `OBJECT :2.23.133.10.1.3` (a loadable key), `BOOLEAN :255` (emptyAuth true) and
  `INTEGER :40000001` (the parent is the owner hierarchy).
- The persistent handles are unchanged. port49 makes the SRK at each open and never persists it.
- sha256: `.tpmkey` `a9d1d155…`, `.pem` `8afabc9a…`.

The agent started, so the real TPM loaded the key under port49's ECC SRK template.

### Step 2: TLS 1.3 and a refresh

`refresh` exit 0, `identity` exit 0 naming `user:alice@corp.example.com` (subject `oidc_alice`).
The agent log shows `connected`, then two `refreshed`, and no TPM error. The pcap holds four
ServerHellos from the broker, every one with `supported_versions` 0x0304 (TLS 1.3; legacy
version 0x0303), parsed from the raw capture because tshark is not installed on beehive. The
agent's connection is mTLS with the issued key (`internal/agent/agent.go`), so the TPM signed
the TLS 1.3 handshake itself, and the refresh signs that session's TLS exporter.

### Step 3: an agent restart and a reboot

- **3a, the restart:** after `kill`, `login` printed `using your certificate … (signed in at …
  at 2026-10-15T04:01:43Z)` and `logged in to …`, with no sign-in address, exit 0. Both hashes
  were unchanged.
- **3b, the reboot** (and a kernel update, 7.0.0-31 to 7.0.0-38): the harness came back with
  `issuing CA: reused`. `login` printed `using your certificate` with no sign-in address, exit 0,
  and `refreshed at 04:19:17Z`. That refresh was signed by the real TPM after the reboot. Both
  hashes were unchanged, and the persistent handles were still step 0's three.

In both 3a and 3b a separate `refresh` run straight after `login` got `refresh_too_soon`
(exit 1, `retry in 10s`). `login` already refreshes as it connects, so this is the broker's
refresh spacing, not the TPM. A rerun 3 minutes later in 3a exited 0. The runbook now says so.

### Step 4: shared home, each host keeps its own `.tpmkey`

On host2, `login --oidc --no-browser` printed `no TPM key for this machine yet` (the SER8's
pair was not taken as held), one sign-in, exit 0, and no `your held certificate is not used`.
`issued/` then held both pairs: `$B.f89db056.{pem,tpmkey}` (hashes as in step 1) and
`$B.9939ac4d.{pem,tpmkey}` (`ee6a4759…`, `b186be07…`).

The second login on each host printed `using your certificate`, with no sign-in address, exit 0.
All four hashes were unchanged.

### Step 5: the key file is refused on another machine

Each `login --key "tpm:file=…" --cert …` exited 2 with `loading the client certificate: tpm:
this key file was made by another TPM, or this machine's TPM was cleared since it was made;
make a key here`. No agent started, and all four hashes were unchanged.
- The SER8's key offered to host2 (swtpm) was refused.
- host2's swtpm key offered to the SER8 was refused by **the real TPM's firmware**, at
  `TPM2_Load`.

### Step 6: shared home, a token host and a file host

The YubiKey before: PIN tries 3/3; slots 9A (one fingerprint), 9C and 9E listed.

- **Token host (the SER8, `pkcs11`, slot 9e):** PIN asked once, one sign-in, exit 0. A new
  `$B.8d8d2d7b.pem` (`f1bd1cda…`, written 05:13) appeared, with no new key file.
- **File host (host2, `file`):** one sign-in, exit 0. `$B.pem` (`0047e50b…`) and `$B.key`
  (`80564891…`) appeared, both 0600, written 05:14.
- **Second logins, after stopping both agents:** each printed `using your certificate`, with no
  sign-in address, exit 0, at 05:16 and 05:18. The token host asked the PIN once.

Afterwards:
- the token certificate, `$B.pem` and `$B.key` kept their first-login times and their hashes;
- both TPM pairs kept step 5's hashes;
- `ykman piv info` showed the same slots, the same fingerprint and PIN tries 3/3. Nothing was
  written to the token.

### Step 7: the control, a user outside `tss`

`id p49notss`: `groups=1002(p49notss)`. `login --oidc --no-browser` exited 1 with
`issued_key_store is tpm, and port49 cannot open the TPM (/dev/tpmrm0): add this user to the
tss group, then log in again`. There was no sign-in address, so the refusal cost no password.
(It printed `no TPM key for this machine yet` first.) The control is valid because step 0
showed `/dev/tpmrm0` as `tss` 0660.

## The second host

There is no second machine with a real TPM in the lab. host2 is a container on the SER8 with its
own swtpm, resource manager, machine id and network-mounted home. port49 tells hosts apart only
by `/etc/machine-id` and by which TPM answers `/dev/tpmrm0`, and both differ. What it lacks is
its own kernel and its own box.

The clauses that depend on firmware all ran on the real TPM:
- key creation under the SRK;
- TLS 1.3 and refresh signing;
- surviving a reboot;
- refusing a foreign key file.

The shared-home clauses test port49's naming and its held-pair logic, which work the same over
any TPM. One direction of step 5 (a real-TPM key offered to another real TPM) is the only cell
that a second real-TPM machine would add.

**Ruling (Ryan, 2026-10-15):** this container stand-in, together with the real firmware's refusal
of a foreign key in step 5, measures the row as written. L62 closes on it.

## Runbook corrections found in the session

- swtpm's AppArmor profile lets it write only under `/var/lib/swtpm/`, so its state, pid and
  log moved to `/var/lib/swtpm/port49-l62`.
- `/etc/exports.d` does not exist on a fresh Ubuntu 26.04 install; the runbook now creates it.
- 3a and 3b: `login` refreshes as it connects, so the separate `refresh` that follows it may
  get `refresh_too_soon`. Wait 10s.

## Side observation, not part of L62

Agent pid 13345, started in 3b, had exited (`signal received; exiting`) by the time step 4's
`kill` reached it, near when that `p49lab` shell closed (04:21:45Z). This was checked afterwards
and is not the terminal. The agent runs in its own session with no tty (`Setsid`; for example
`pid 37488 sid 37488 tty ?`). Agents survived both `script` closing their pty and a
`sudo -iu p49lab` session ending, so the signal was an explicit one, not a hangup.
