# L90 — arista_eos

- **Date measured:** 2026-11-04
- **Run:** commit `1c211e6c499372109072cd7279448bf986fd406a`, `PORT49_LAB_PLATFORMS=eos`, `-run ^TestL90$`
- **Platform:** arista_eos
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`), Oxidized 0.37.0-101-g65125713 (image `oxidized/oxidized:latest@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc`, oxidized/oxidized@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc)
- **Capture:** `tests/lab/evidence/L90-oxidized-arista_eos.json`
- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are never written; certificates are public.

## Claim

Oxidized's SSH host-key handling against accept-new, on one EOS device. (a) `secure: true` with no `known_hosts` entry: what Oxidized does. (b) `secure: true` with a changed key: PASS iff refused. (c) `secure: true` after ruling 9's `ssh … accept-new … PreferredAuthentications=none … exit` line wrote the entry: PASS iff the backup runs. (d) Any Oxidized input or `vars` setting that maps to net-ssh's `verify_host_key: :accept_new`: PASS iff an unknown key is saved and a changed key refused.

## Observation

- **Device capture:** `tests/lab/evidence/L90-oxidized-arista_eos.pcap` — 2539 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L90-oxidized-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Oxidized** `oxidized --version`: 0.37.0-101-g65125713 (image `oxidized/oxidized:latest@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc`, oxidized/oxidized@sha256:b58a2db261be348990a2345ad3cec8dba03b373ac817865ef1080bd7db7d2ccc); `examples/oxidized/config` with `secure: true`. `known_hosts` is the run's temp home's, mounted read-only at Oxidized's `~/.ssh/known_hosts`; nothing of the operator's `~/.ssh` is read or written.
- **(a) `secure: true`, no `known_hosts` entry:**
  - the run ended with status `no_connection`; 0 authentications reached port49d (0 port49d records in all); `known_hosts` held 0 key line(s) before and 0 after.
  - Oxidized's log for that run (class and message lines only):
    - `oxidized-1 | 2026-11-04 15:18:25.331149 W [7:Job 'leaf1'] Oxidized::Node -- 172.100.100.11 raised Net::SSH::HostKeyUnknown with msg "fingerprint SHA256:FT2fWz/ty61LH3FE1SiOhgI8vH95gF4gwy0whbJu/EQ is unknown for "172.100....`
  - Refused at the host key (no token sent): yes.
- **(b) `secure: true`, a changed key** (the device's address with a fresh public key of each type it offers):
  - the run ended with status `no_connection`; 0 authentications reached port49d (0 port49d records in all); `known_hosts` held 3 key line(s) before and 3 after.
  - Oxidized's log for that run (class and message lines only):
    - `oxidized-1 | 2026-11-04 15:18:33.333827 W [7:Job 'leaf1'] Oxidized::Node -- 172.100.100.11 raised Net::SSH::HostKeyMismatch (rescued RuntimeError) with msg "fingerprint SHA256:6oavtCXsBu0LfSnpotRaqoHAKcY1jMfQCSSH0NvqxE0 ...`
  - **(b) PASS**: PASS iff refused; refused: yes.
- **(c) `secure: true`, after ruling 9's line wrote the entry:**
  - The line: `ssh -F /dev/null -o UserKnownHostsFile=<known_hosts> -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o PreferredAuthentications=none -o PubkeyAuthentication=no -o IdentityAgent=none -o IdentitiesOnly=yes -o ConnectTimeout=15 -- <address> exit`. It exited 255 (a refusal of `none` is expected: methods listed `publickey,keyboard-interactive`); it wrote 1 key line(s) to `known_hosts` (hostnames hashed: no); 0 port49d records arrived during it (no credential sent).
  - the run ended with status `success`; 1 authentications reached port49d (9 port49d records in all); `known_hosts` held 1 key line(s) before and 1 after.
  - **(c) PASS**: PASS iff the backup runs; status `success`.
- **(c2) the same line with `-o HashKnownHosts=yes`:**
  - The entry's host field is hashed (`|1|`): yes.
  - the run ended with status `success`; 1 authentications reached port49d (9 port49d records in all); `known_hosts` held 1 key line(s) before and 1 after.
  - **(c2) PASS**: the backup runs with a hashed entry; status `success`.
- **(c3) the wrapper itself sweeps an empty `known_hosts`** (`port49-oxidized-run` with `OXIDIZED_KNOWN_HOSTS` the file Oxidized reads):
  - the run ended with status `success`; 1 authentications reached port49d (9 port49d records in all); `known_hosts` held 0 key line(s) before and 1 after.
  - **(c3) PASS**: PASS iff the wrapper saved the key (lines after: 1) and the backup runs; status `success`.
- **(d) A setting that maps to net-ssh's `verify_host_key: :accept_new`:**
  - Oxidized's source (`0.37.0 gem in the image`, `lib/oxidized/input/sshbase.rb`) sets `verify_host_key` once, from the one boolean `secure`: `must_secure? ? :always : :never`. Lines naming `verify_host_key` or `must_secure` under `lib`:
    - `oxidized/input/sshbase.rb:34: verify_host_key: must_secure? ? :always : :never,`
    - `oxidized/input/sshbase.rb:49: vars(:ssh_proxy), vars(:ssh_proxy_port), must_secure?`
    - `oxidized/input/sshbase.rb:72: def must_secure?`
  - Lines naming `accept_new` or `accept-new` anywhere under Oxidized's `lib`: no line.
  - net-ssh's own `ssh.rb` (documentation of `verify_host_key`): `214: # * :never (very insecure) ::Net::SSH::Verifiers::Never | 215: # * :accept_new_or_local_tunnel (insecure) ::Net::SSH::Verifiers::AcceptNewOrLocalTunnel | 216: # * :accept_new (insecure) ::Net::SSH::Verifiers::AcceptNew | 217: # * :always (secure) ::Net::SSH::Verifiers::Always`.
  - Tried: `input: ssh: secure: accept_new` in `config` (Oxidized restarted).
  - Unknown key (empty `known_hosts`):
  - the run ended with status `success`; 1 authentications reached port49d (9 port49d records in all); `known_hosts` held 0 key line(s) before and 0 after.
  - Changed key:
  - the run ended with status `success`; 1 authentications reached port49d (9 port49d records in all); `known_hosts` held 3 key line(s) before and 3 after.
  - **(d) FAIL**: PASS iff an unknown key is saved (saved: no) and a changed key refused (refused: no).
- **Logs:** L90: Oxidized's log (4162 bytes, default level) holds none of the 12 tokens minted so far and no compact JWS.

