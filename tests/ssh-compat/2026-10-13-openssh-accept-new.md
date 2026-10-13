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
key.) The fingerprint was also checked against sources other than the ftp server the key and tarball
came from: openssh.com/portable.html states `7168B983815A5EEF59A4ADFD2A3F414E736060BA`, and
keys.openpgp.org serves a key with that fingerprint. Each run re-checks the pinned sum (`openssh-8.5p1.tar.gz: OK`).

**The impostor's positive control.** Every run first asks `ssh-keyscan -p 2222` what port 2222
offers and refuses to go on unless the answer is exactly `ssh-ed25519`. Port 22's own scan, logged
as `port 22 offers:` on every in-container run, was `ecdsa-sha2-nistp256 ssh-ed25519 ssh-rsa`. Cell `g1-control` shows the 2222 server is reachable and that `accept-new` files its
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

`SSH_ASKPASS` is `askpass.sh`, with `SSH_ASKPASS_REQUIRE=force`: it logs its parent's pid, that
parent's command line (`/proc/$PPID/cmdline`) and the prompt it was given, and exits 1. It never has
a password. The top ssh runs as the shell's background job, so `$top` is its pid. A ProxyJump hop's
ssh gets only the top ssh's `-F`, not its `-o` options, so the hop's trust is seeded through a `-F`
cfg (`Host 127.0.0.1`: its own known_hosts holding the server's Ed25519 key, `StrictHostKeyChecking
yes`), which is what lets the hop reach its password prompt. (The first run of this cell did not do
that and measured the hop's host-key question only; the table below replaces it.) Three runs per client:

- **g1c-hostkey:** the hop's host key unknown (empty file, `StrictHostKeyChecking ask`): the hop asks
  the host-key question. Recorded, not a gate; it is a hop prompt port49's askpass must also refuse.
- **g1c (the gate):** the hop's key known, so the hop asks `jumpuser@127.0.0.1's password: ` (three
  times; `NumberOfPasswordPrompts=1` applies to the top ssh). PASS needs a password prompt logged and
  no logged parent equal to `$top`.
- **g1c-control:** no `-J`; the top ssh itself asks the same password prompt (the device's own
  prompt). PASS needs the parent to be `$top`. G1c is valid only if the control passes.

The asker in every row is `ssh -l jumpuser -p 22 -F <cfg> -W [127.0.0.1]:2222 127.0.0.1` (the hop's
ssh, ProxyJump's `-W` form) except in the control, where it is the top ssh itself
(`ssh -F <cfg> ... -p 22 jumpuser@127.0.0.1 true`). The host's run used the published port for 22 in place
of 22 (`-p <P22>`, `[127.0.0.1]:<P22>` in the known_hosts line) and an explicit `UserKnownHostsFile`,
so the operator's own `~/.ssh/known_hosts` was never consulted.

| Client | Run | top ssh pid | asker pid (parent of the askpass) | Prompt | Result |
|---|---|---|---|---|---|
| 8.5p1 | g1c-hostkey | 15714 | 15715 | `The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established. ...` | recorded |
| 8.5p1 | **g1c** | 15728 | 15729 | `jumpuser@127.0.0.1's password: ` | **PASS** |
| 8.5p1 | g1c-control | 15751 | 15751 | `jumpuser@127.0.0.1's password: ` | PASS |
| 8.9p1 | g1c-hostkey | 3708 | 3709 | host-key question | recorded |
| 8.9p1 | **g1c** | 3722 | 3723 | `jumpuser@127.0.0.1's password: ` | **PASS** |
| 8.9p1 | g1c-control | 3745 | 3745 | `jumpuser@127.0.0.1's password: ` | PASS |
| 9.6p1 | g1c-hostkey | 3862 | 3863 | host-key question | recorded |
| 9.6p1 | **g1c** | 3876 | 3877 | `jumpuser@127.0.0.1's password: ` | **PASS** |
| 9.6p1 | g1c-control | 3899 | 3899 | `jumpuser@127.0.0.1's password: ` | PASS |
| 10.2p1 | g1c-hostkey | 3275305 | 3275306 | `The authenticity of host '[127.0.0.1]:<P22> ...` | recorded |
| 10.2p1 | **g1c** | 3275320 | 3275321 | `jumpuser@127.0.0.1's password: ` | **PASS** |
| 10.2p1 | g1c-control | 3275343 | 3275343 | `jumpuser@127.0.0.1's password: ` | PASS |

On every version the hop's password prompt has the hop's ssh (top + 1, a child of the top ssh, its
`-W` command line shown) as parent, never the top ssh; the device's own prompt has the top ssh as
parent. The pid of the asker's parent therefore tells a hop's prompt from the device's, password and
host-key question alike.

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

| Client | `globalknownhostsfile` | `userknownhostsfile` (run as root; the host's was run as the operator, `<home>`) |
|---|---|---|
| 8.5p1 (upstream build) | `/usr/local/etc/ssh_known_hosts /usr/local/etc/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 8.9p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 9.6p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `/root/.ssh/known_hosts /root/.ssh/known_hosts2` |
| 10.2p1 | `/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2` | `<home>/.ssh/known_hosts <home>/.ssh/known_hosts2` |

(8.5p1's global path is its own build's `--sysconfdir`; a distro build prints `/etc/ssh/...`.)

Set explicitly, with `UserKnownHostsFile ~/kh1 %d/kh2 /etc/kh3` and `GlobalKnownHostsFile ~/g1 %d/g2`:

| Client | `userknownhostsfile` | `globalknownhostsfile` |
|---|---|---|
| 8.5p1, 8.9p1, 9.6p1 | `/root/kh1 /root/kh2 /etc/kh3` (`~` and `%d` both expanded to the home directory) | `~/g1 %d/g2` **verbatim, not expanded** |
| 10.2p1 | `<home>/kh1 <home>/kh2 /etc/kh3` | `~/g1 %d/g2` verbatim |

A path holding a space (`UserKnownHostsFile "/a b/kh" /c/kh`) prints **unquoted**, `userknownhostsfile
/a b/kh /c/kh`, on 8.5p1, 8.9p1 and 9.6p1 (the host's 10.2p1 was not run on this cfg): the value cannot
be split unambiguously.

So a parser of `ssh -G` may take `userknownhostsfile` as absolute paths (or `none`, or `/dev/null`) and
must treat `globalknownhostsfile` as possibly unexpanded when the operator set it. **An absent
`userknownhostsfile` line on 8.5p1 means `none`**: no user file (an unset setting prints the defaults
above, so absence is only `UserKnownHostsFile none`). **Task 9 must refuse a value it cannot split
unambiguously**, a path with a space in it.

## Gates

| Gate | Result |
|---|---|
| **G1** (a known ECDSA line, an Ed25519-only server, default algorithms: ssh refuses, `kh` unchanged) | **PASS** on 8.5p1, 8.9p1, 9.6p1 and 10.2p1 |
| G1b (ECDSA line, `HostKeyAlgorithms=ssh-ed25519`) | PASS on all four |
| changed-same-type | PASS (refused) on all four |
| **G1c** (the askpass of a ProxyJump hop's *password* prompt is not a child of the top ssh) | **PASS** on all four, including the 8.5p1 floor |
| g1c-control (validity of G1c: the device's own password prompt has the top ssh as parent) | PASS on all four: G1c is valid |
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
