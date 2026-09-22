# Lab harness

Runs `port49d` against real network OS images in containerlab and closes lab register
entries (policy engine spec §15). Nothing here runs under `go test ./...`; it needs the
`lab` build tag: `make lab`.

## Setup

1. containerlab: `bash -c "$(curl -sL https://get.containerlab.dev)"`, and Docker running.
   You must be in the `docker` and `clab_admins` groups, and `sudo -n` must work without a
   password: the harness runs `containerlab`, `tcpdump`, and `setcap` under `sudo -n`.
2. **Check the management subnet is free on *this* machine before deploying.** These topologies
   use `172.100.100.0/24` rather than containerlab's `172.20.20.0/24` default, because that
   default collided with an existing Docker network on the machine they were written on. The
   collision is per-machine, so re-check on any new one: list the taken subnets with
   `docker network ls --format '{{.Name}}'` piped through
   `docker network inspect <n> --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`, and check
   `ip -4 route` too. A clash fails the deploy with `Requested subnet(s) ... overlap an existing
   Docker network`. To move the lab, change the address in all eight files that carry it —
   `grep -rn '172\.100\.100\.' .` finds them — keeping `port49d`'s `listen` and the device
   configs' server address on the subnet's `.1` gateway.
3. Images: the source is Google Drive `My Drive/Network Images` (on WSL:
   `sudo mount -t drvfs G: /mnt/g`); build from a local copy, not the mount (on the main PC:
   `/mnt/c/Users/rhwen/Network Images/`). All are VM disks built with vrnetlab
   (`git clone https://github.com/srl-labs/vrnetlab`; KVM required). First build the base
   image once: `sudo ./build-base-image.sh 0.3.0` in the repo root (it is not pullable). Any
   subset works and an absent image skips its platform:
   - vEOS 4.32.2F: `qemu-img convert -f qcow2 -O vmdk veos-4.32.2F/hda.qcow2 vrnetlab/arista/veos/vEOS-lab-4.32.2F.vmdk`
     (needs `qemu-utils`; the launcher wants a vmdk and ignores the Aboot ISO), then
     `script -qec make /dev/null` in `vrnetlab/arista/veos` (the ZTP step needs a TTY).
     (A cEOS tarball, which needs an arista.com account, would instead be `docker import`ed
     as `ceos:4.32.2F` with the `kind:`/`image:` in `topologies/eos.clab.yml` changed per its
     comment.)
   - vJunos-router 23.4R2-S2.1: copy the qcow2 into `vrnetlab/juniper/vjunosrouter`. On an
     AMD host, patch the CPU check by hand and use `make docker-image` — see the plan's
     Task 15 prerequisites for the exact guestfish lines. On Intel, `make`.
   - vSRX 21.4R3.15: copy the qcow2 into `vrnetlab/juniper/vsrx`, `make` there.
   - Nexus 9300v 10.4(2)F: copy the qcow2 into `vrnetlab/cisco/n9kv` **renamed to
     `n9kv-<version>.qcow2`** — the Makefile derives the image tag from that name with a `sed`,
     and a name it cannot parse fails the build with a version-string error. The lab uses
     `n9kv-9300v64-10.4.2.F.qcow2`, which gives `vrnetlab/cisco_n9kv:9300v64-10.4.2.F`. Then
     `make docker-image` there. This build only packages the qcow2; it never boots the VM.
   - Catalyst 8000V 17.13.01a: copy the qcow2 into `vrnetlab/cisco/c8000v` and build the
     **autonomous** variant:
     ```sh
     cp /mnt/images/c8000v-universalk9_8G_serial.17.13.01a.qcow2 ~/git/vrnetlab/cisco/c8000v/
     cd ~/git/vrnetlab/cisco/c8000v && sg docker -c \
       "make IMAGE=c8000v-universalk9_8G_serial.17.13.01a.qcow2 MODE=autonomous docker-build"
     ```
     Unlike every other build here, this one **boots the VM**: after the docker build it runs
     the image with `--install`, which sets the serial console and the license level and then
     commits the result. It took 1m24s on this host. The tag is
     `vrnetlab/cisco_c8000v:17.13.01a`, derived from the version in the filename.

     There is also a `controller-17.13.01a` tag, which `MODE=controller` produces without
     booting anything, and it is the **wrong image for this lab**: controller (SD-WAN) mode has
     a different AAA model, puts management in VRF 513, and expects vManage to provision it.
     `configs/iosxe-startup.cfg` is written against the autonomous build and nothing else.
   Check `docker images` for the tag each build produced and match the `image:` lines in
   `topologies/`. Expected: `vrnetlab/arista_veos:4.32.2F`,
   `vrnetlab/juniper_vjunos-router:23.4R2-S2.1`, `vrnetlab/juniper_vsrx:21.4R3.15`,
   `vrnetlab/cisco_n9kv:9300v64-10.4.2.F`, `vrnetlab/cisco_c8000v:17.13.01a`.

   The N9Kv asks the host for more than the others: the launcher gives the VM **10 GB of RAM
   and 4 vCPUs**. Do not deploy it beside another VM platform on a machine that cannot spare
   both.
4. `export PORT49_LAB_KEY=labsecret`
5. `make build && make lab`

`PORT49_LAB_ENC_KEY` is the encryption-at-rest key (design §8). port49d refuses to start
without one and it must be exactly 32 bytes; the harness supplies a default, so export it
only to override. The lab store is in memory, so it seals nothing that outlives a run.

## Why this needs bare metal

The Junos platforms need a host where KVM is not itself inside a VM. This is not a
performance preference; on a nested host they do not boot at all.

The lab was first run on a Windows machine with Docker under WSL2, which puts the vrnetlab
VM at the bottom of four levels of virtualisation. vEOS was fine there — it answered a
breakglass login 57 seconds after `containerlab deploy`. `vrnetlab/juniper_vjunos-router`
was not. Measured from the container console on that host: the FreeBSD kernel came up about
4 minutes in, Junos userland started about 10 minutes in, package mounting finished
(`mount done`) at 35 minutes and 2 seconds, and SSH never served a handshake at all. Two runs
with budgets of 20 and 35 minutes measured nothing, and `vrnetlab/juniper_vsrx` behaved the
same way: the gate gave up at 35m10s with no handshake, an empty decision log, and captures
holding nothing but the harness's own loopback probes.

The symptom is a trap worth naming, because it looks like a device fault rather than a host
one. vrnetlab forwards port 22 into the VM from the moment the container starts, so TCP to
port 22 succeeds immediately and stays up for the whole boot. The tests fail with
`ssh: handshake failed: ... i/o timeout`, which reads like an SSH problem on a device that is
plainly listening. It is not; the VM inside has not finished booting.

On bare metal with nested KVM enabled (the current lab host: Ubuntu 26.04, `/dev/kvm`
present, no outer hypervisor) the same image answers a breakglass login **1 minute 31
seconds** after deploy, reproducibly. The boot budgets in `harness_test.go` are set from
these figures.

## What runs

`make lab` is `go test -tags lab ./tests/lab/... -timeout 120m`. One `go test` run does this:

- `TestMain` resolves the repository root, `setcap cap_net_bind_service=+ep` on `bin/port49d`
  so it can bind port 49 unprivileged, and then, **one platform at a time**, deploys that
  platform's topology, waits for the device to serve SSH authentication, and starts a
  `port49d` for it.
- The wait has a per-platform budget, set from boots measured on this host and listed in the
  `platforms` table in `harness_test.go`: **6 minutes for vEOS and vSRX, 8 for vJunos-router**.
  A budget is there to end a run that is not going to finish, not to race the device — the
  measured boots are 57s, about 3 minutes, and 1m31s respectively.
- The device counts as ready when it either lets `breakglass` log in or runs SSH
  authentication through to a rejection. The second is deliberate: on vSRX the `breakglass`
  account has no password at all — the startup config's `plain-text-password-value` never
  becomes an `encrypted-password` on that image — so requiring the login meant that platform
  could never pass. See `waitDeviceReady` and
  `results/juniper_vsrx-config-verified.md`.
- Every register test then runs against that already-deployed device. The topologies are
  **deployed once per run**, not once per test: these are VMs and each boot costs minutes.
- At the end of the run every topology is destroyed with `containerlab destroy --cleanup`.

Select platforms with `PORT49_LAB_PLATFORMS`, a comma-separated list of `eos`, `vjunos`,
`vsrx`, `nxos`, `iosxe` (default: all five). One at a time is the normal way to run it:

```sh
PORT49_LAB_PLATFORMS=eos make lab
PORT49_LAB_PLATFORMS=nxos make lab
PORT49_LAB_PLATFORMS=iosxe make lab
```

## IOS-XE keeps its console on a method list of its own

`configs/iosxe-startup.cfg` carries two lines no other startup config here needs:

```
aaa authentication login CONSOLE local
line con 0
 login authentication CONSOLE
```

They are there because of what L4 does. Its second cell sets `aaa authentication login default
group port49` — a method list with no `local` method — and measures a login against it with
port49d stopped. NX-OS survives that because it keeps a separate `aaa authentication login
console` list which defaults to `local`; Junos survives it because the console is a root shell.
IOS-XE runs `line con 0` through the same `default` list as every vty, so without the named
list above, that cell would lock out SSH and the console at the same moment and the device
could not be put back without a redeploy.

It does not weaken L4: every login L4 attempts is over SSH, on a vty using the `default` list
under test.

`register_test.go` has one test per open register entry this plan closes: L1, L2, L5, L6, L8,
L10. Each writes `results/L<N>-<platform>.md` with the observation. **A register test passes
when the measurement was made and fails when it is inconclusive** — whichever way the device
behaved is the result, but "the login never happened" or "no matching record reached the log"
is a failure, because nothing was measured.

## Transports other than SSH

`transport_test.go` measures eAPI, NX-API and NETCONF. Everything else here measures a person
typing at an SSH session, and every register row closed so far is a claim about that one
transport; these tests are the first that are not.

The question they exist for is the third one in the file's own header: **does a second request
with the same credential re-authenticate?** port49 tokens are single-use, so a transport that
authenticates per HTTP request spends a token per request — an operator who pastes a token
into a script that makes forty calls gets one success and thirty-nine denials. Spec §13
decision 15 is provisional on that measurement and register entry L7 is the row it names.

The eAPI and NX-API tests write `results/L7-<platform>.md`. The NETCONF test writes
`results/netconf-<platform>.md` and not an `L<N>` name, because §15 has **no row** for NETCONF
AAA behaviour and adding one is not a test's to do. Propose the row, then rename the note.

These tests have not been run. The `<edit-config>` payloads in `netconfEdit` were written from
model documentation, which is not a measurement: expect the first run to collect an
`<rpc-error>` or two, and rewrite the payload from what the device said rather than from more
documentation.

The device-side switches they need are in the startup configs and nowhere else: `management
api http-commands` and `management api netconf` in `configs/eos-startup.cfg`, `system services
netconf ssh` in `configs/vjunos-startup.conf`, and `feature nxapi` / `feature netconf` /
`nxapi use-vrf management` in `configs/nxos-startup.cfg`. EOS serves NETCONF on **port 22** as
an SSH subsystem; Junos and NX-OS serve it on **830**. `netconfPort` in `transport_test.go`
carries that difference, so change the two together.

## Tokens

`port49d-lab.yaml` seeds single-use tokens, because redemption deletes the token: every login
in a run consumes one. The pool is deliberately larger than the run needs. `lab.nextToken()`
hands them out in order, so a test never reuses a spent one.

A seed no longer carries its secret. It names who gets a token pair, and port49d mints the
pair at start and writes it to `lab.seed_token_file` (`/tmp/port49-lab-tokens.jsonl`), one
JSON object per line at mode 0600, truncated on every start. So the credentials of a run
exist only on the machine that ran it, and only until the next run: **redact the captures
before running the lab again**, or `make evidence` has nothing to verify them against. That
file is also why `labcreds.Secrets` reads it rather than this config.

`longpw<N>` users are kept, but L8 cannot be measured through them any more. A seed cannot ask
for a secret of a chosen length now that the daemon mints it — every token is 30 characters
(design §8) — so the password-length question needs a mechanism that does not exist yet. The
register entry stays open; see spec §15, L8.

## Captures

`tcpdump --immediate-mode -i any -U -n -s 0 -w captures/<test>-<platform>.pcap 'tcp port 49'`
runs around each test. Captures are git-ignored; the results note quotes the fields that
matter, names the **evidence** file (see below), and reports how many packets in it are
device traffic.

`--immediate-mode` is not decoration. Without it libpcap hands tcpdump the kernel ring on a
one-second read timeout, so a capture stopped within a second of its last packet loses that
packet — which is how the first vEOS run produced a 24-byte L10 capture beside a results note
that claimed a measurement.

The harness brackets each capture with a TCP connection to `127.0.0.1:49`, where nothing
listens. Those two loopback packets are its proof that the file is really capturing: the test
does not start until one has reached the file, and tcpdump is not stopped until another has,
which by ordering means everything the test produced is already on disk. They are on the
loopback, so they are excluded from the device-packet count a results note quotes.

## Evidence: what a results note actually points at

**`tests/lab/evidence/` is committed. `tests/lab/captures/` is not.**

A capture holds the lab tokens and the breakglass password. They are obfuscated, but under
`labcreds.Key`, which this repository publishes — so in a capture they are in the clear for
anyone who opens it. That is why `captures/` is git-ignored. But a results note that pointed
into it would point at nothing for everyone except the machine that took it, and spec §15
rule 3 requires a capture pointer that closes a register row.

So every capture gets a redacted copy in `tests/lab/evidence/`, and that is what the notes
name. In an evidence file:

- **Credential bytes are overwritten with `x`, byte for byte.** The fields are the ones RFC
  8907 puts a secret in: an authentication START's `data` (a PAP password, a CHAP challenge
  and response), a CONTINUE's `user_msg` and `data` (an ASCII password), and a REPLY's `data`
  (a server challenge). A scan of every variable-length field of all 1803 packets in the
  captures on this machine found lab credentials in exactly two of them —
  `authen_continue.user_msg` and `authen_start.data` — and in no AV pair, username, port,
  `rem_addr` or server message. `go run ./tests/lab/cmd/redact-pcap -scan` re-runs that scan
  and fails if a credential turns up in a field the redactor does not overwrite.
- **Everything else is byte-identical.** Same packets, same order, same timestamps, same
  lengths, same TCP sequence numbers, same TACACS+ headers. The one exception is the TCP
  checksum of a rewritten packet, and only when it was correct in the capture to begin with;
  these captures come off a veth with checksum offload, so almost every checksum in them is
  already wrong, and those are left exactly as they were found rather than "fixed" into
  looking more correct than the device sent them.
- **It still decodes with the lab key.** The body is de-obfuscated, the credential bytes
  replaced, and the result re-obfuscated under the same header, so the MD5 pad is unchanged.
  In Wireshark: **Edit → Preferences → Protocols → TACACS+ → key**, set to the value of
  `labcreds.Key`. Nothing about reading an evidence file differs from reading the capture.

`make evidence` rewrites `evidence/` from whatever is in `captures/`, and `make lab` does it
automatically at the end of a run — so a note written by a run always points at a file that
exists. A run whose evidence cannot be produced fails, because the alternative is notes
citing files that are not there.

Nothing is written unverified. For each file the redactor re-reads its own output from disk,
de-obfuscates every body again, and refuses to leave the file in place unless every
credential field is entirely `x`, no field and no body holds any seeded token or the
breakglass password, no value that a credential field of the input carried appears anywhere
in the output, and every other byte matches the input. `tests/lab/labpcap` holds the code and
its tests, including one that deliberately misses a field to prove the verifier fails.

## Startup configs must be pure ASCII

Every file in `configs/` is ASCII only, comments included, and `checkStartupConfigASCII` in
`harness_test.go` refuses to deploy one that is not.

The N9Kv launcher applies its config by typing it into the serial console one line at a time.
The first NX-OS deploy stopped dead on line 8 of `nxos-startup.cfg`, which held an em dash in
a comment. Every line after it — the break-glass account, `feature tacacs+`, the server, the
group, all four method lists — was never sent. The device then came up looking perfect: SSH
serving, authentication answering, `containerlab inspect` healthy, and no AAA configuration at
all. Nothing in the launcher log said anything was wrong; it simply stopped.

Write `--` for an em dash and `'` for a curly quote. The check costs nothing and the failure
it prevents costs a ten-minute boot and a results note about a device that was never
configured.
