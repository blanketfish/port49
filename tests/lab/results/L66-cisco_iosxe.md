# L66 — cisco_iosxe

- **Date measured:** 2026-10-14
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L66-cisco_iosxe.pcap` — 8069 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L66-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `cb9ebac73c823b8f13275d77fdbc9f9d1a06b83b`, `PORT49_LAB_PLATFORMS=iosxe`, `-run TestL66`
- **tty:** this run's `ansible.builtin.ssh` plays (L66e-ssh, L66e2-names) ran with the ssh plugin's default `use_tty: true`. Host-key checking and authentication happen before any channel or pty request, so these readings stand under 28207cc6's `ansible_ssh_use_tty: false`. That setting was added because `raw` over a tty never ends on the Junos CLI (see the Junos notes).

## Claim

The Ansible lookup `port49.client.token` over `ansible.netcommon.network_cli` against cisco_iosxe (policy engine spec §15, L66): (a) mints per host for a ten-task play with the lookup in `ansible_password`; (b) the same play minting once, and (b2) an idle gap or `meta: reset_connection` after it; (c) host keys under `host_key_checking` and `host_key_auto_add` for `libssh` and `paramiko`, and a changed key; (d) a denied device, and no token in `-vvv` output, in `-vvvv` output or in the persistent connection's log; (e) an address moved in the inventory, for `libssh`, `paramiko`, `libssh` with a `HostKeyAlias`, and `ansible.builtin.ssh`, and (e2) two inventory names at one address over `ansible.builtin.ssh`.

## Observation

Versions in this run: python 3.14.4 ansible-core 2.21.4 ansible-pylibssh 1.4.0 (libssh 0.12.0) paramiko 5.0.0 port49 0.1.0; ansible-playbook [core 2.21.4]; collections: ansible.netcommon 8.7.1, arista.eos 12.3.0, cisco.ios 11.6.0, cisco.nxos 13.0.0, junipernetworks.junos 11.1.1, port49.client 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 27 Jan 2026; nss_wrapper /usr/lib/x86_64-linux-gnu/libnss_wrapper.so; ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass; tree commit cb9ebac73c823b8f13275d77fdbc9f9d1a06b83b.

The 10s before the first cell: 1 decision records and 20 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L66a | PASS | 16s |
| L66b | OBSERVED | 21.8s |
| L66b2-idle | OBSERVED | 39.5s |
| L66b2-reset | OBSERVED | 19s |
| L66d | PASS | 54.3s |
| L66d2 | FAIL | 17.2s |
| L66c1-libssh | PASS | 15.9s |
| L66c2-libssh | FAIL | 36.2s |
| L66c1-paramiko | OBSERVED | 37.9s |
| L66c1b-paramiko | PASS | 15.9s |
| L66c2-paramiko | PASS | 34.2s |
| L66e-libssh | OBSERVED | 35.7s |
| L66e-paramiko | OBSERVED | 34.2s |
| L66e-libssh-alias | OBSERVED | 34.3s |
| L66e-ssh | OBSERVED | 29.6s |
| L66e2-names | OBSERVED | 13.3s |

### L66a: PASS

A ten-task play (each task a `cisco.ios.ios_command` of `show version`) with `ansible_password: "{{ lookup('port49.client.token', ...) }}"` and `ansible_user` from a second lookup with `field='username'`. **With the default token.candidate_cap of 8, the play fails at task 2 with candidate_cap_reached. 10 mint records (1 denied), 1 redeem records and 1 TACACS+ authentication starts for 2 tasks attempted (1 ok, 1 failed, 0 unreachable in the recap) on one host: 5.00 mint records per task attempted, with 2 lookups of port49.client.token in the connection variables.** ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 10 mint records (1 denied; reasons map[candidate_cap_reached:1 grants_matched:9]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "Task failed: The lookup plugin 'port49.client.token' failed: port49: xe1: deny candidate_cap_reached"}`; ansible: `[ERROR]: Task failed: The lookup plugin 'port49.client.token' failed: port49: xe1: deny candidate_cap_reached`; warning: `[WARNING]: WorkerProcess for [xe1/TASK: show version 2] errantly sent data directly to stderr instead of using Display:`; warning: `[WARNING]: port49: xe1: deny candidate_cap_reached`. Candidate cap: port49's default of 8 unspent tokens per device and username (this cell measures it), on a port49d restarted with an empty token store.

### L66b: OBSERVED

The same play minting once in `pre_tasks` (`set_fact`, `field='all'`, `no_log`): **1 mint records, 1 redeem records, 1 TACACS+ authentication starts** in the capture for ten tasks on one host. ansible-playbook exit 0, `xe1` recap {OK:11 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 714 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. This run is a good login, so its window is its own positive control: true. Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66b2-idle: OBSERVED

The minted-once play with an idle gap of 20s between two tasks (persistent_connect_timeout 10s in the inventory and the environment). **The next task logged in again: true** (2 TACACS+ authentication starts, 2 redeem records with reasons map[receipt_replayed:1 token_redeemed:1], for 1 mint records). ansible-playbook exit 0, `xe1` recap {OK:5 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 2 redeem records (reasons map[receipt_replayed:1 token_redeemed:1]); 714 TACACS+ packets and 2 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66b2-reset: OBSERVED

The minted-once play with `meta: reset_connection` between two tasks (persistent_connect_timeout 10s in the inventory and the environment). **The next task logged in again: true** (2 TACACS+ authentication starts, 2 redeem records with reasons map[receipt_replayed:1 token_redeemed:1], for 1 mint records). ansible-playbook exit 0, `xe1` recap {OK:4 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 2 redeem records (reasons map[receipt_replayed:1 token_redeemed:1]); 714 TACACS+ packets and 2 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66d: PASS

The positive control, a good login through the lookup just before: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] (control true).

A device with no grant (`srx1`, which the policy grants nothing on), `-vvv`: the output names `no_grants_matched`: true; ansible-playbook exit 2, `srx1` recap {OK:0 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (1 denied; reasons map[no_grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [srx1]: FAILED! => { "censored": "the output has been hidden due to the fact that 'no_log: true' was specified for this result", "changed": false }`; ansible: `[ERROR]: Task failed: Finalization of task args for 'ansible.builtin.set_fact' failed: Error while resolving value for 'p49': The lookup plugin 'port49.client.token' failed: port49: srx1: deny no_grants_matched`; warning: `[WARNING]: WorkerProcess for [srx1/TASK: mint once] errantly sent data directly to stderr instead of using Display:`; warning: `[WARNING]: port49: srx1: deny no_grants_matched`. The token was searched for in clear text, by hash: words of its output that hash to a minted token's `credential_sha256`: 0 (lines []); the harness knows 14 token hashes from this run.

A good login (`xe1`), a 3-task play, `-vvv`, searched the same way: 0 words hash to a minted token (lines []); 1 token hashes in its own window. a window of 10s with no decision record and no TACACS+ packet preceded it a window of 10s with no decision record and no TACACS+ packet preceded it ansible-playbook exit 0, `xe1` recap {OK:4 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 420 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66d2: FAIL

A good login, a 3-task play, with `-vvvv`, `ANSIBLE_PERSISTENT_LOG_MESSAGES=True` and `ANSIBLE_LOG_PATH` a private file (428275 bytes, 2604 lines, holding 16 `jsonrpc request:` lines, one of them a set_options: true; the persistent socket carries the connection's options, password included, to the process on every task after the first, so a log that holds those lines is one a token could be in). The token was searched for in clear text: each word of stdout (325 lines), stderr (1 lines) and the log was hashed and compared with the 15 token hashes the decision log names (`credential_sha256` and the mint's `token_sha256`). Words that match: stdout 0 (lines []), stderr 0 (lines []), log 4 (lines [1871 1873 2243 2245]). **Not as claimed:** words that hash to a minted token are in log lines [1871 1873 2243 2245]. Never enable `persistent_log_messages` with the lookup. ansible-playbook exit 0, `xe1` recap {OK:4 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 420 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]; warning: `[WARNING]: Persistent connection logging is enabled for 172.100.100.41. This will log ALL interactions to /tmp/p49l663488039241/ansible-d2.log and WILL NOT redact sensitive configuration like passwords. USE WITH CAUTION!` Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66c1-libssh: PASS

`ansible_network_cli_ssh_type: libssh`, `ANSIBLE_HOST_KEY_CHECKING=True`, `ANSIBLE_HOST_KEY_AUTO_ADD=True`, from a known_hosts holding a comment line, an `@revoked` line and an `@cert-authority` line for unrelated patterns. The play passed: true. The file changed in: the private known_hosts (`~/.ssh/known_hosts` of the run's home), which libssh reads because the harness gives the user that home in the passwd entry (nss_wrapper); libssh takes its home from there, not from $HOME. Mode: **appended**. Lines added: `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`; lines gone: none; comment lines lost: []; marker lines lost: []. ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]

Before (keys shortened to their first 16 characters):

```
# L66 baseline: a comment line a client that rewrites this file may drop
@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
@cert-authority *.unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
```

After:

```
# L66 baseline: a comment line a client that rewrites this file may drop
@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
@cert-authority *.unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...
``` Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66c2-libssh: FAIL

The positive control, a good login through the lookup just before: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] (control true).

`libssh`: the key of each line the first contact filed (172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...) replaced by a fresh key of its type, the other lines left. a window of 10s with no decision record and no TACACS+ packet preceded it. The play was refused (did not pass): false; **336 TACACS+ packets**, **1 TACACS+ authentication starts**, records other than mint and blob: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] (the token was never presented if there are none). **Not as claimed:** the play did not fail; 336 TACACS+ packets reached port49d; 1 redeem record(s): the token was presented; records other than mint and blob: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]; the error does not name a changed host key in libssh's wording (it was ""). **libssh accepted the changed key and logged in.** The token was presented to the device: true (1 redeem records in the window, each with the `credential_sha256` of a token this run minted; 1 such hashes known). The file after the refused run: appended, added `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`, gone none. ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66c1-paramiko: OBSERVED

The positive control, a good login through the lookup just before: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] (control true).

**Paramiko refused to read the known_hosts file it was given** (`InvalidHostKey`): it holds an `@revoked` line and an `@cert-authority` line for unrelated patterns, which paramiko's loader takes for a key line of the type `unrelated.l66.invalid`. The play failed before any TACACS+ traffic (0 packets in its window). ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "('@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOavd7GATlOJXzhGXSEda4zA6ZT0NNSOmOjApAu+W/sT', Error('Incorrect padding'))"}`; ansible: `[ERROR]: Task failed: Action failed: ('@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOavd7GATlOJXzhGXSEda4zA6ZT0NNSOmOjApAu+W/sT', Error('Incorrect padding'))`

The file, keys shortened:

```
# L66 baseline: a comment line a client that rewrites this file may drop
@revoked unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
@cert-authority *.unrelated.l66.invalid ssh-ed25519 AAAAC3NzaC1lZDI1...
``` Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66c1b-paramiko: PASS

`ansible_network_cli_ssh_type: paramiko`, `ANSIBLE_HOST_KEY_CHECKING=True`, `ANSIBLE_HOST_KEY_AUTO_ADD=True`, from a known_hosts holding a comment line alone. The play passed: true. The file changed in: the private known_hosts (`~/.ssh/known_hosts` of the run's home). Mode: **rewritten**. **The file was rewritten** **without 1 comment line(s) and 0 marker line(s) it held**. Lines added: `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`; lines gone: none; comment lines lost: ["# L66 baseline: a comment line a client that rewrites this file may drop"]; marker lines lost: []. ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]

Before (keys shortened to their first 16 characters):

```
# L66 baseline: a comment line a client that rewrites this file may drop
```

After:

```
172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...
``` Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66c2-paramiko: PASS

The positive control, a good login through the lookup just before: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account] (control true).

`paramiko`: the key of each line the first contact filed (172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...) replaced by a fresh key of its type, the other lines left. a window of 10s with no decision record and no TACACS+ packet preceded it. The play was refused (did not pass): true; **0 TACACS+ packets**, **0 TACACS+ authentication starts**, records other than mint and blob: [] (the token was never presented if there are none). The file after the refused run: unchanged, added none, gone none. ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "host key mismatch for 172.100.100.41"}`; ansible: `[ERROR]: Task failed: Action failed: host key mismatch for 172.100.100.41` Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66e-libssh: OBSERVED

**libssh.** Step 1, at the device's address `172.100.100.41`: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. File after step 1: mode appended, added `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`.

Step 2, `ansible_host` changed to the stand-in (`172.100.100.250`, a throwaway sshd container on the lab bridge with its own host keys ssh-ed25519 SHA256:geoV4rJ0rNJ8x2e7A34X4w1qIqKpMBdxEwD680UOiic, ecdsa-sha2-nistp256 SHA256:VlYlnYye+oPBzs9fPgPvKjC6txM8mRpZyu9aJWm4xuU, ssh-rsa SHA256:aJczMfjyj27rDTkM2EDLZtN66QKbk9UYRpMbxd7q7hk; it refuses every login and logs a password's length and hash only). a window of 10s with no decision record and no TACACS+ packet preceded it ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "ssh connection failed: Failed to authenticate with keyboard-interactive: Access denied for 'keyboard interactive'. Authentication that can continue: password,publickey,keyboard-interactive"}`; ansible: `[ERROR]: Task failed: Action failed: ssh connection failed: Failed to authenticate with keyboard-interactive: Access denied for 'keyboard interactive'. Authentication that can continue: password,publickey,keyboard-interactive`. **The stand-in's key was auto-added: true** (mode appended, added `172.100.100.250 ssh-ed25519 AAAAC3NzaC1lZDI1...`, gone none). The stand-in saw 1 connection(s), 1 password attempt(s) and 1 keyboard-interactive answer(s); **the minted token was presented to it: true** (an attempt's hash is one of the token hashes the run's mint and redeem records name). Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66e-paramiko: OBSERVED

**paramiko.** Step 1, at the device's address `172.100.100.41`: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. File after step 1: mode rewritten, added `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`.

Step 2, `ansible_host` changed to the stand-in (`172.100.100.250`, a throwaway sshd container on the lab bridge with its own host keys ssh-ed25519 SHA256:geoV4rJ0rNJ8x2e7A34X4w1qIqKpMBdxEwD680UOiic, ecdsa-sha2-nistp256 SHA256:VlYlnYye+oPBzs9fPgPvKjC6txM8mRpZyu9aJWm4xuU, ssh-rsa SHA256:aJczMfjyj27rDTkM2EDLZtN66QKbk9UYRpMbxd7q7hk; it refuses every login and logs a password's length and hash only). a window of 10s with no decision record and no TACACS+ packet preceded it ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "Failed to authenticate: Failed to authenticate: Authentication failed."}`; ansible: `[ERROR]: Task failed: Action failed: Failed to authenticate: Failed to authenticate: Authentication failed.`. **The stand-in's key was auto-added: false** (mode unchanged, added none, gone none). The stand-in saw 1 connection(s), 1 password attempt(s) and 0 keyboard-interactive answer(s); **the minted token was presented to it: true** (an attempt's hash is one of the token hashes the run's mint and redeem records name). Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66e-libssh-alias: OBSERVED

**libssh with `ansible_libssh_config_file` naming an ssh_config with `HostKeyAlias` (is that file honoured at all?).** **`ansible_libssh_config_file` naming `HostKeyAlias xe1` was honoured (step 1 filed the key under that name): false.** Step 1, at the device's address `172.100.100.41`: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:0 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 336 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account authorize_command account account]. File after step 1: mode appended, added `172.100.100.41 ssh-rsa AAAAB3NzaC1yc2EA...`.

Step 2, `ansible_host` changed to the stand-in (`172.100.100.250`, a throwaway sshd container on the lab bridge with its own host keys ssh-ed25519 SHA256:geoV4rJ0rNJ8x2e7A34X4w1qIqKpMBdxEwD680UOiic, ecdsa-sha2-nistp256 SHA256:VlYlnYye+oPBzs9fPgPvKjC6txM8mRpZyu9aJWm4xuU, ssh-rsa SHA256:aJczMfjyj27rDTkM2EDLZtN66QKbk9UYRpMbxd7q7hk; it refuses every login and logs a password's length and hash only). a window of 10s with no decision record and no TACACS+ packet preceded it ansible-playbook exit 2, `xe1` recap {OK:1 Changed:0 Unreachable:0 Failed:1 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: FAILED! => {"changed": false, "msg": "ssh connection failed: Failed to authenticate with keyboard-interactive: Access denied for 'keyboard interactive'. Authentication that can continue: password,publickey,keyboard-interactive"}`; ansible: `[ERROR]: Task failed: Action failed: ssh connection failed: Failed to authenticate with keyboard-interactive: Access denied for 'keyboard interactive'. Authentication that can continue: password,publickey,keyboard-interactive`. **The stand-in's key was auto-added: true** (mode appended, added `172.100.100.250 ssh-ed25519 AAAAC3NzaC1lZDI1...`, gone none). The stand-in saw 1 connection(s), 1 password attempt(s) and 1 keyboard-interactive answer(s); **the minted token was presented to it: true** (an attempt's hash is one of the token hashes the run's mint and redeem records name). Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66e-ssh: OBSERVED

**ansible.builtin.ssh with `-o HostKeyAlias={{ inventory_hostname }}` (the `raw` module).** Step 2's own ssh log: a connection of its own true, looked the alias up true, filed a key under it false.:

```
debug1: using hostkeyalias: xe1
debug1: using hostkeyalias: xe1
```
 Step 1, at the device's address `172.100.100.41`: ansible-playbook exit 0, `xe1` recap {OK:2 Changed:1 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 1 redeem records (reasons map[token_redeemed:1]); 126 TACACS+ packets and 1 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account account]. File after step 1: mode appended, added `xe1 ssh-rsa AAAAB3NzaC1yc2EA...`.

Step 2, `ansible_host` changed to the stand-in (`172.100.100.250`, a throwaway sshd container on the lab bridge with its own host keys ssh-ed25519 SHA256:geoV4rJ0rNJ8x2e7A34X4w1qIqKpMBdxEwD680UOiic, ecdsa-sha2-nistp256 SHA256:VlYlnYye+oPBzs9fPgPvKjC6txM8mRpZyu9aJWm4xuU, ssh-rsa SHA256:aJczMfjyj27rDTkM2EDLZtN66QKbk9UYRpMbxd7q7hk; it refuses every login and logs a password's length and hash only). a window of 10s with no decision record and no TACACS+ packet preceded it ansible-playbook exit 4, `xe1` recap {OK:1 Changed:0 Unreachable:1 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 1 mint records (0 denied; reasons map[grants_matched:1]), 0 redeem records (reasons map[]); 0 TACACS+ packets and 0 TACACS+ authentication starts in the window; records other than mint, blob and redeem: []; the error: `fatal: [xe1]: UNREACHABLE! => {"changed": false, "msg": "Task failed: Failed to connect to the host via ssh:", "unreachable": true}`; ansible: `[ERROR]: Task failed: Failed to connect to the host via ssh:`. **The stand-in's key was auto-added: false** (mode unchanged, added none, gone none). The stand-in saw 1 connection(s), 0 password attempt(s) and 0 keyboard-interactive answer(s); **the minted token was presented to it: false** (an attempt's hash is one of the token hashes the run's mint and redeem records name). Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

### L66e2-names: OBSERVED

Two inventory names (`l66a`, `l66b`) at one address (172.100.100.41), `ansible.builtin.ssh` with `-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new -o LogLevel=DEBUG3 -E <a file per host>`, one fork, from a known_hosts holding a comment only. Per host, from its own ssh log: `l66a`: recap {OK:2 Changed:1 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; opened a connection of its own: true; authenticated on it: true; reused an open master: true; ssh looked its alias up in known_hosts: true; ssh filed a key under its alias: true:

```
debug1: using hostkeyalias: l66a
debug1: using hostkeyalias: l66a
Warning: Permanently added 'l66a' (RSA) to the list of known hosts.
```
; `l66b`: recap {OK:2 Changed:1 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; opened a connection of its own: true; authenticated on it: true; reused an open master: true; ssh looked its alias up in known_hosts: true; ssh filed a key under its alias: true:

```
debug1: using hostkeyalias: l66b
debug1: using hostkeyalias: l66b
Warning: Permanently added 'l66b' (RSA) to the list of known hosts.
```
. The known_hosts file after the run holds key lines for: [l66a l66b] (filed by the run: `l66a ssh-rsa AAAAB3NzaC1yc2EA...`, `l66b ssh-rsa AAAAB3NzaC1yc2EA...`). ansible-playbook exit 0, `l66a` recap {OK:2 Changed:1 Unreachable:0 Failed:0 Skipped:0 Rescued:0 Ignored:0}; 2 mint records (0 denied; reasons map[grants_matched:2]), 2 redeem records (reasons map[token_redeemed:2]); 252 TACACS+ packets and 2 TACACS+ authentication starts in the window; records other than mint, blob and redeem: [authorize_session account authorize_command account account authorize_session account authorize_command account account] Candidate cap: raised to 64 with `token.candidate_cap` (this cell does not measure the cap; port49's default is 8), on a port49d restarted with an empty token store.

