# OpenSSH clients and `port49 ssh`'s askpass — 2026-10-09

- **Date measured:** 2026-10-09
- **For:** plan 9a (`docs/superpowers/plans/2026-10-09-09a-sweeps-and-ssh.md`), pre-flight I-5:
  is refusing OpenSSH below 8.4 a tested technical reason, and can older clients be served by
  running ssh with no controlling terminal?
- **What this is:** a note about the operator's ssh client, not a device. It is not a lab register
  entry (policy engine spec §15 is for device behaviour).
- **Where:** Docker on the plan 9a workstation (Ubuntu, OpenSSH 10.2p1 on the host). Each
  container ran its own `sshd` on 127.0.0.1 and the client under test against it.
- **Scripts:** `tests/ssh-compat/2026-10-09-openssh-askpass/`. `setup.sh` installs sshd and expect
  and makes a throwaway user. Its throwaway password is generated in the container into
  `/root/pw` (mode 0600), and is never printed. `askpass.sh` logs how ssh ran it (the prompt
  argument, `SSH_ASKPASS_PROMPT`, whether `/dev/tty` opens), never the password, and answers with
  the password.

## Clients

| Client | Where it came from |
|---|---|
| OpenSSH_8.0p1, OpenSSL 1.1.1k FIPS | `rockylinux:8` (`openssh-clients`), util-linux 2.32.1 |
| OpenSSH_8.2p1 Ubuntu-4ubuntu0.13, OpenSSL 1.1.1f | `ubuntu:20.04`, util-linux 2.34 |
| OpenSSH_8.4p1 Debian-5+deb11u3, OpenSSL 1.1.1w | `debian:11` (the security archive removed from `sources.list`: its pool answered 404) |
| OpenSSH_8.4p1 (upstream) | `openssh-8.4p1.tar.gz` from cdn.openbsd.org, built in `ubuntu:20.04` (`build-and-measure.sh 8.4p1`) |
| OpenSSH_8.5p1 (upstream) | `openssh-8.5p1.tar.gz`, built the same way |
| OpenSSH_8.9p1 Ubuntu-3ubuntu0.17, OpenSSL 3.0.2 | `ubuntu:22.04` |

Each was run with `sg docker -c "docker run --rm -v <scripts>:/work:ro <image> sh /work/run.sh"`,
or with `sh /work/t3.sh` after `setup.sh` for test 3, or with `build-and-measure.sh`.
`rockylinux:9` now ships OpenSSH_9.9p1; its keyboard-interactive case did not apply (its
`sshd_config.d` overrides the edit), so it is not cited.

## Test 1: `SSH_ASKPASS_REQUIRE=force` with a terminal

`t1.exp` gives ssh a pty (expect's `spawn`) and runs
`ssh -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password tuser@127.0.0.1 echo LOGGED_IN_OK`
with `SSH_ASKPASS` set to the logging askpass, and the environment named.

| Client | No `REQUIRE`, `DISPLAY` set | `force`, no `DISPLAY` | `force`, `DISPLAY` set |
|---|---|---|---|
| 8.0p1 | terminal prompt `password:` | terminal prompt | terminal prompt |
| 8.2p1 | terminal prompt | terminal prompt | terminal prompt |
| 8.4p1 Debian, 8.4p1 upstream, 8.5p1, 8.9p1 | — | askpass ran, logged in | askpass ran, logged in (Debian 8.4p1) |

On 8.0p1 and 8.2p1 the askpass never ran: `force` is ignored and ssh takes the terminal.

## Test 2: the no-terminal route on 8.0p1 and 8.2p1

**Without a pty** (`run.sh`, T2a): `printf 'line-one\nline-two\n' | DISPLAY=:0 SSH_ASKPASS=… setsid -w ssh … 'cat; exit 3'`
logged in through the askpass, echoed both lines, and exited 3. With `DISPLAY` unset the askpass
was not used and authentication failed (`Permission denied`).

**From an interactive shell** (`t2.exp`). Expect drives `bash -i` on a pty with job control. In it:
- **control:** `ssh` run as usual, logged in by a key, since what is compared is terminal handling;
- **setsid:** `DISPLAY=:0 SSH_ASKPASS=… setsid -w ssh …`. `setsid -w` stays in the shell's foreground
  job, as `port49 ssh` would. ssh runs in a new session with no controlling terminal.

| Behaviour | control | setsid route (8.0p1 and 8.2p1 alike) |
|---|---|---|
| Login, and typed input reaching the remote shell | yes | yes, through the askpass |
| Askpass able to open `/dev/tty` | — | no (`dev_tty=fails`): a jump host's prompt could not be asked of the terminal by the askpass itself |
| Local resize to 40x120, then the remote's `stty size` | `40 120` | `24 80`: ssh is not in the terminal's foreground process group, so it gets no `SIGWINCH` |
| The same with `SIGWINCH` sent to ssh by hand (`t4.exp`) | — | `40 120`: a parent that forwards it would fix this |
| ^C during a remote `sleep 20` | interrupted | interrupted (raw mode passes it to the remote) |
| `~?` escape | works | works |
| `~^Z` | the shell reports `Stopped`, ssh state `T` | ignored: ssh stays `Ss`, the shell gets no prompt back (a stop signal to an orphaned process group is discarded) |
| `exit 7` in the remote shell | — | the local shell sees status 7 |

## Test 3: the prompt the askpass is given, `HostKeyAlias=dev1`

`t3.sh` runs `setsid -w ssh` with `DISPLAY` set and
`-o HostKeyAlias=dev1 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password`.
It runs once with sshd offering `password` only, then once with sshd offering
`keyboard-interactive` only, through PAM.

| Client | `password` prompt | `keyboard-interactive` prompt |
|---|---|---|
| 8.0p1 | `tuser@dev1's password: ` | `Password: ` |
| 8.2p1 | `tuser@dev1's password: ` | `Password: ` |
| 8.4p1 Debian | `tuser@dev1's password: ` | `Password: ` |
| 8.4p1 upstream | `tuser@dev1's password: ` | `Password: ` |
| 8.5p1 upstream | `tuser@dev1's password: ` | `(tuser@dev1) Password: ` |
| 8.9p1 | `tuser@dev1's password: ` | `(tuser@dev1) Password: ` |

The source agrees. Upstream `sshconnect2.c`'s `input_userauth_info_req` builds
`"(%s@%s) %s"` from `server_user` and `host_key_alias` in 8.5p1, 8.6p1, 8.7p1, 8.8p1 and 8.9p1.
8.4p1 has no such line. Every one of them, 8.4p1 included, reads `SSH_ASKPASS_REQUIRE` in
`readpass.c`.

## Test 4: the option values `port49 ssh` writes, on 8.5p1

`ssh -G -F /dev/null -o KnownHostsCommand=none -o HostName="fe80::1%%eth0" -o UserKnownHostsFile="/tmp/a b/%%d/k" -o HostKeyAlias=leaf1 x`
printed `hostname fe80::1%eth0`, `userknownhostsfile /tmp/a b/%d/k` and `hostkeyalias leaf1`,
with no error. The quotes keep the space, `%%` is a literal `%`, and `KnownHostsCommand=none` is
accepted. 10.2p1 on the host printed the same, and given `HostName=fe80::1%eth0` unescaped it
refused it (`unknown key %e`).

## What follows for `port49 ssh`

- **8.0 to 8.3 cannot be served by `force`.** They ignore it.
- **The no-terminal route serves a session tolerably**, with `SIGWINCH` forwarded and `~^Z` lost.
- **It cannot keep the token's one rule** (decision 42 ruling 10: answered once, to the prompt
  naming `<username>@<device>`). On 8.0p1, 8.2p1 and 8.4p1 a keyboard-interactive prompt reaches
  the askpass as the server's own text, `Password: `, naming no host. A jump host's ssh, which
  `ProxyJump` runs with the same environment, is the same client, so its keyboard-interactive
  prompt would come bare too (not run here: no jump host was set up). The askpass then has two
  choices, and neither is acceptable:
  - answer it, and possibly hand the token to a host that is not the device;
  - refuse it, and lose every device that takes keyboard-interactive. Which devices those are is
    L54's (open).
- **8.4p1 fails on the same point**, though it honours `force`.
- **8.5p1 is the first client whose prompts all name the host,** and it honours `force` and
  takes the option values above.

**Ruling (plan 9a, decision 42 ruling 10):** `port49 ssh` needs OpenSSH 8.5 or later, and refuses
an older one by name before minting. RHEL 8 (8.0), Ubuntu 20.04 (8.2) and Debian 11 (8.4) are
served by `port49 token` and the operator's own ssh.
