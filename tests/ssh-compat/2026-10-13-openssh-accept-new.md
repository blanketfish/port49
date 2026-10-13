# OpenSSH under accept-new, and `ssh -G`'s forms — 2026-10-13

- **Date measured:** 2026-10-13
- **For:** plan 9d (`docs/superpowers/plans/2026-10-13-09d-openssh-host-keys-and-python-clients.md`),
  Task 2: decision 46 rulings 2 and 6. Host-key trust is OpenSSH's job; `port49 ssh` passes
  `StrictHostKeyChecking=accept-new` and a `HostKeyAlias`. Is an `accept-new` client safe when a
  server presents a key of a type the known_hosts line does not hold (gate G1), and can
  `port49 ssh` tell a ProxyJump hop's password prompt from the device's (gate G1c)?
- **What this is:** a note about the operator's ssh client, not a device. It is not a lab register
  entry (policy engine spec §15 is for device behaviour).
- **Where:** Docker on the plan 9d workstation (Ubuntu; OpenSSH 10.2p1 on the host). Each container
  ran two `sshd`s on 127.0.0.1: port 22 with every host key `ssh-keygen -A` makes, and port 2222
  with the Ed25519 key alone (the impostor of G1), and the client under test against them. The host's
  10.2p1 client ran against a 24.04 container's two ports, published on 127.0.0.1.
- **Scripts:** `tests/ssh-compat/2026-10-13-openssh-accept-new/`. `run.sh` sets a container up and
  runs `keys.sh`, the cells. Standalone: nothing of plan 9a's harness is used.

## Clients

| Client | Where it came from |
|---|---|
| OpenSSH_8.5p1, OpenSSL 1.1.1f | upstream `openssh-8.5p1.tar.gz` built in `ubuntu:20.04` (the floor, `minSSH`) |
| OpenSSH_8.9p1 Ubuntu-3ubuntu0.17, OpenSSL 3.0.2 | `ubuntu:22.04` |
| OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 | `ubuntu:24.04` |
| OpenSSH_10.2p1 Ubuntu-2ubuntu3.6, OpenSSL 3.5.5 | the host, against `ubuntu:24.04`'s servers |

**The 8.5p1 tarball.** `openssh-8.5p1.tar.gz` from cdn.openbsd.org, SHA-256
`f52f3f41d429aa9918e38cf200af225ccdd8e66f052da572870c89737646ec25`, pinned in `run.sh`.
Checked before pinning: its `.asc` from the same directory, against the OpenSSH release key
`RELEASE_KEY.asc` fetched from `ftp.openbsd.org/pub/OpenBSD/OpenSSH/`:

```
gpg: Signature made Tue 02 Mar 2021 12:05:43 PM UTC
gpg:                using RSA key 7168B983815A5EEF59A4ADFD2A3F414E736060BA
gpg: Good signature from "Damien Miller <djm@mindrot.org>" [unknown]
Primary key fingerprint: 7168 B983 815A 5EEF 59A4  ADFD 2A3F 414E 7360 60BA
```

(The "not certified" warning is only that the measuring machine's keyring has no trust path to the
key; the fingerprint is the release key's.) Each run re-checks the pinned sum (`openssh-8.5p1.tar.gz: OK`).

**The impostor's positive control.** Every run first asks `ssh-keyscan -p 2222` what port 2222
offers and refuses to go on unless the answer is exactly `ssh-ed25519`. Port 22 offers ECDSA,
Ed25519 and RSA. Cell `g1-control` shows the 2222 server is reachable and that `accept-new` files its
key when `kh` is empty (exit 0, `leaf1` filed). Without it G1 would be INVALID; with it, G1's refusal
is the ECDSA line's doing and not a dead server's.

## The cells

Each cell writes a known_hosts `kh`, connects with `BatchMode=yes` and no terminal, as `tuser` by the
control key, with `StrictHostKeyChecking=accept-new HostKeyAlias=leaf1`, and the client on its default
algorithms (except `g1b`). Key bodies are elided as `<key>`; the files were never changed
by a refusal.

| Cell | `kh` before; server | 8.5p1 | 8.9p1 | 9.6p1 | 10.2p1 |
|---|---|---|---|---|---|
| **g1** | `leaf1 <ECDSA>`; 2222 (Ed25519 only) | exit 255 | exit 255 | exit 255 | exit 255 |
| g1-control | empty; 2222 | exit 0, `leaf1` filed | exit 0, filed | exit 0, filed | exit 0, filed |
| g1b | `leaf1 <ECDSA>`; 22, `HostKeyAlgorithms=ssh-ed25519` | exit 255 | exit 255 | exit 255 | exit 255 |
| changed-same-type | `leaf1 <other Ed25519>`; 22 | exit 255 | exit 255 | exit 255 | exit 255 |
| hashed | empty; 22, `HashKnownHosts=yes` | exit 0 | exit 0 | exit 0 | exit 0 |

For every refused cell `kh` was identical after (g1, g1b and changed-same-type each ended with the
single line it started with). stderr, last lines:

| Client | g1 / g1b / changed-same-type |
|---|---|
| 8.5p1 | `Offending ECDSA key in <kh>:1` (`ED25519` for changed-same-type); `Host key for leaf1 has changed and you have requested strict checking.`; `Host key verification failed.` |
| 8.9p1 | `  ssh-keygen -f "<kh>" -R "leaf1"`; the same two lines (double quotes) |
| 9.6p1 | `  ssh-keygen -f '<kh>' -R 'leaf1'`; the same two lines (single quotes) |
| 10.2p1 | as 9.6p1 |

g1-control's stderr, every version: `Warning: Permanently added 'leaf1' (ED25519) to the list of
known hosts.` The `hashed` cell wrote `|1|<salt>|<hash> ssh-ed25519 <key>` on every version and
`ssh-keygen -F leaf1 -f kh` found it (`hashed found: 1`).

### G1c: whose child is the askpass at a ProxyJump hop

A `-J jumpuser@127.0.0.1:22` hop that asks for a password; `SSH_ASKPASS` is a script that appends its
own `$PPID` to a file and exits 1, `SSH_ASKPASS_REQUIRE=force`. The top ssh is the shell's background
job, so `$top` is its pid.

| Client | top ssh pid | askpass parent pid(s) | G1c |
|---|---|---|---|
| 8.5p1 | 15695 | 15696 | PASS |
| 8.9p1 | 3689 | 3690 | PASS |
| 9.6p1 | 3843 | 3844 | PASS |
| 10.2p1 | 3129737 | 3129738 | PASS |

The askpass ran on every version, and its parent was never the top ssh: the hop's ssh is a child
of the top ssh (the ProxyCommand's), so the pid of the asker's parent tells a hop from the device.

## `ssh -G`: the forms

`ssh -G -F <cfg> -o 'HostName="fe80::1%%eth0"' -l alice -- <dest>` for `cfg` holding in turn each
line below, destinations `leaf1` and `Leaf1`. The first column is `cfg`; "—" means the line is absent.
All four versions agree except where a row says otherwise.

| `cfg` | `stricthostkeychecking` | `hostkeyalias` | `userknownhostsfile` | other |
|---|---|---|---|---|
| (empty) | `ask` | — | the default, below | `hashknownhosts no` |
| `StrictHostKeyChecking yes` | `true` | — | default | |
| `StrictHostKeyChecking no` | `false` | — | default | |
| `StrictHostKeyChecking ask` | `ask` | — | default | |
| `StrictHostKeyChecking accept-new` | `accept-new` | — | default | |
| `StrictHostKeyChecking off` | `false` | — | default | |
| `Host leaf1` / `HostKeyAlias Corp-Leaf1` | `ask` | `corp-leaf1` for `leaf1`; **absent for `Leaf1`** | default | |
| `UserKnownHostsFile /dev/null` | `ask` | — | `/dev/null` | |
| `UserKnownHostsFile none` | `ask` | — | **8.5p1: line absent. 8.9p1, 9.6p1, 10.2p1: `none`** | |
| `RevokedHostKeys <krl>` | `ask` | — | default | `revokedhostkeys <krl>` as written |
| `KnownHostsCommand /bin/true %H` | `ask` | — | default | `knownhostscommand /bin/true %H` as written |
| `Match user alice` / `HostKeyAlias alice-leaf1` | `ask` | `alice-leaf1` (both destinations) | default | |
| `HashKnownHosts yes` | `ask` | — | default | `hashknownhosts yes` |

Unset, `hostkeyalias`, `revokedhostkeys` and `knownhostscommand` are absent. A set alias is
lowercased. `Host leaf1` does not match `Leaf1`. `Match user alice` matches under `-l alice`.
`StrictHostKeyChecking yes|no|off` print as `true`|`false`|`false`; `ask` and `accept-new` as written.
Nothing in the output differs between `leaf1` and `Leaf1` apart from the `Host leaf1` row.
(`ssh -G` also writes `Pseudo-terminal will not be allocated because stdin is not a terminal.` to
stderr when stdin is not a terminal; it is not on stdout.)

### The known-hosts file defaults (K6)

Both settings print as **space-separated absolute paths, `~` already expanded, never `%d`**, and each
lists its `...2` companion:

| Client | `globalknownhostsfile` | `userknownhostsfile` (run as root; the host's was run as `rwendt`) |
|---|---|---|
| 8.5p1 (upstream build) | `/usr/local/etc/ssh_known_hosts /usr/local/etc/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 8.9p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 9.6p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 10.2p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `/home/rwendt/.ssh/known_hosts /home/rwendt/.ssh/known_hosts2` |

(8.5p1's global path is its own build's `--sysconfdir`; a distro build prints `/etc/ssh/...`.)

Set explicitly, with `UserKnownHostsFile ~/kh1 %d/kh2 /etc/kh3` and `GlobalKnownHostsFile ~/g1 %d/g2`:

| Client | `userknownhostsfile` | `globalknownhostsfile` |
|---|---|---|
| 8.5p1, 8.9p1, 9.6p1 | `/root/kh1 /root/kh2 /etc/kh3` (`~` and `%d` both expanded to the home directory) | `~/g1 %d/g2` **verbatim, not expanded** |
| 10.2p1 | `/home/rwendt/kh1 /home/rwendt/kh2 /etc/kh3` | `~/g1 %d/g2` verbatim |

So a parser of `ssh -G` may take `userknownhostsfile` as absolute paths (or `none`, or absent on
8.5p1, or `/dev/null`) and must treat `globalknownhostsfile` as possibly unexpanded when the operator
set it.

## Gates

| Gate | Result |
|---|---|
| **G1** (a known ECDSA line, an Ed25519-only server, default algorithms: ssh refuses, `kh` unchanged) | **PASS** on 8.5p1, 8.9p1, 9.6p1 and 10.2p1 |
| G1b (ECDSA line, `HostKeyAlgorithms=ssh-ed25519`) | PASS on all four |
| changed-same-type | PASS (refused) on all four |
| **G1c** (the hop's askpass is not a child of the top ssh) | **PASS** on all four, including the 8.5p1 floor |
| g1-control (validity of G1) | exit 0, key filed, on all four: G1 is valid |

**The floor stays.** 8.5p1 refuses what 8.9p1, 9.6p1 and 10.2p1 refuse, so `minSSH` in
`cmd/port49/ssh.go` is unchanged, as are decision 42 ruling 10's "Why 8.5" and decision 46
ruling 6. Task 3's `sshPolicy` and Task 9's `port49.hostkeys.lookup` follow the `ssh -G` forms above.

## Harness fixes found while measuring

- `sshd_g1` (port 2222) needs `UsePAM yes`: its `-f` config replaces the distro's, and without PAM
  sshd refuses the new, locked `tuser`, so g1-control exited 255 although it had filed the key.
- In serve mode (the host's client) `sshd_g1` listens on 0.0.0.0 in the container: a 127.0.0.1
  listener there is unreachable through docker's published port, and every connection to 2222 was
  reset.
