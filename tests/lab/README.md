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
   - **L73 images** (opt-in selectors; one per run). Built just before each run, from
     `/mnt/images/` (the Cisco ones from CML refplat 20260409, signature verified):
     - vJunos-router 26.2R1.7 (`vjunos26`) and vJunos-switch 26.2R1.7 (`vjunosswitch26`): copy
       the qcow2 into `vrnetlab/juniper/vjunosrouter` (or `vjunosswitch`), patch
       `/home/pfe/junos/start-junos.sh` on `/dev/sda2` for AMD exactly as for 23.4 (the
       `CPU_FLAG` line), `make IMAGE=<qcow2> docker-build`, then delete the copy.
     - Catalyst 8000V 17.18.02 (`iosxe1718`): as 17.13.01a above, with
       `c8000v-universalk9_8G_serial.17.18.02.qcow2`.
     - Nexus 9300v 10.6.2.F (`nxos106`): copy `nexus9300v64.10.6.2.F.qcow2` into
       `vrnetlab/cisco/n9kv` as `n9kv-9300v64-10.6.2.F.qcow2`, then
       `make IMAGE=n9kv-9300v64-10.6.2.F.qcow2 docker-build`.
     - IOL-XE 17.18.02 (`iolxe1718`, L71 help cell only): copy `iol-xe-17-18-02.tar.gz` into
       `vrnetlab/cisco/iol` first (an `IMAGE=/mnt/images/...` path fails the Makefile's version
       regex), then `make IMAGE=iol-xe-17-18-02.tar.gz docker-build` there.
     - XRd control plane 26.1.1 (`xrd261`, a full L73 row): `docker load -i
       ios-xrd-control-plane-26-1-1.tar.gz`, tagged `port49lab/xrd-control-plane:26.1.1`. XRd
       needs `fs.inotify.max_user_instances` >= 4000 (`sudo sysctl -w`, not persisted).

     - cEOS-lab 4.36.3M (`ceos436`): imported as `ceos:4.36.3M` (containerlab kind `arista_ceos`);
       no build.

     The lab's disk floor is 67584M. If a build would cross it, free space in this order:
     `go clean -cache`, then the `controller-17.13.01a` image, then an earlier L73 image (its
     results are committed, and this recipe rebuilds it). Built 2026-10-17:
     - `vrnetlab/juniper_vjunos-router:26.2R1.7`, ID
       `sha256:64a17c7eb9eb5c4cc36b5398347e6edaf0f82ff5d30a5b740ef08ea07585ff8c`, 3170396026 bytes,
       source sha256 `500e0a67549f663a3201ab839d40b6be9082263b14cd5e2b669d27b9bc9125be`,
       Δ of `/` 11000M (81908M to 70908M avail).
     - `ceos:4.36.3M` (imported, not built), ID
       `sha256:0da07c2edcea0e2969c66941771f7af2e2c5e0008008fb2882d3e0d16ff2be63`, 1073813169 bytes.
     - `vrnetlab/cisco_n9kv:9300v64-10.6.2.F` (built 2026-10-18; the 10.4.2.F leftover qcow2 in the
       build directory was removed after `cmp` proved it identical to `/mnt/images`), ID
       `sha256:3ddc45448d436dcd592654f84f9ddda5aa95fcf11b0a23d3de5367a2a2ece5bd`, 3485174928 bytes,
       source sha256 `f0ceb78ebb1cb0e6e82599fd9140364d77b0aa21e28bb3118191090b043a395e`,
       Δ of `/` 8744M (80052M to 71308M avail).
       Removed 2026-10-18 (lead's ruling, to pass the C8000V disk gate; its L73 results are committed in
       b4d12cbf and this recipe rebuilds it).
     - `vrnetlab/cisco_c8000v:17.18.02` (built 2026-10-18, recipe `MODE=autonomous`, the 17.18.02 qcow2
       copied in and removed again), ID
       `sha256:d41d1a5bd9e7f092ca0fcae636ab9c808fe6d2f3a3bdca25d72c55f49f8d175c`, 2913613093 bytes,
       source sha256 `6443ee46b0e2a437812a4d96a05e8f8135ee5d929c12468e3cae5fe0142cd2dd`,
       Δ of `/` 8328M (79094M to 70766M avail, after the N9Kv removal above).
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
   `vrnetlab/cisco_n9kv:9300v64-10.4.2.F`, `vrnetlab/cisco_c8000v:17.13.01a`, and for L73
   `vrnetlab/juniper_vjunos-router:26.2R1.7`.

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

`register_test.go` has one test per open register entry this plan closes: L1, L2, L5, L6,
L10; L8 moved to `l8_test.go` when its method changed (below). Each writes `results/L<N>-<platform>.md` with the observation. **A register test passes
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

## The vertical slice

Plan 3's broker runs inside `port49d` when the config carries a `broker:` block
(`tests/lab/slice/broker.yaml`), against the policy in `tests/lab/slice/policy.yaml` and
certificates from `go run ./tests/lab/cmd/slice-pki` (written to the git-ignored
`tests/lab/logs/slice-pki/`). `make build` builds `bin/port49` beside `bin/port49d`.

**Automated:** `TestSliceEndToEnd`, vEOS only. It restarts the daemon with the broker block, runs
`port49 login` and `port49 token leaf1`, logs in as `slice01` with the minted token, and writes
`results/slice-arista_eos.md`.

**By hand**, for the two measurements plan 3 does not automate. The daemon and topology are then
yours to start and stop, one platform at a time, destroyed afterwards.

**Wait for `breakglass`, and configure the device, before port49d starts.** Once port49d is
running, a `breakglass` login reaches it as a TACACS+ login, is refused `token_not_found`, and
neither vEOS nor IOS-XE falls through to `local` on that FAIL under `aaa authentication login
default group port49 local` — the ssh client ends `Permission denied
(publickey,keyboard-interactive)` however long you wait (111 such refusals in
`results/L7-login-arista_eos.md`; `results/L1-restconf-cisco_iosxe.md`, "Order"). So an
interactive `breakglass` session exists only while port49d is down. Once port49d is up, the only
readiness signal is the one the harness uses: the device has sent port49d a packet.

```sh
make build
sudo -n setcap cap_net_bind_service=+ep bin/port49d
sudo -n containerlab deploy -t tests/lab/topologies/<eos|iosxe>.clab.yml
# port49d is not running yet, so breakglass gets in once the device is up (1-2 minutes);
# its password is labcreds.BreakglassPassword. Address: leaf1 172.100.100.11, xe1 172.100.100.41
until ssh -o StrictHostKeyChecking=no breakglass@<address> 'show version | include Software'
do sleep 10; done
# any device configuration the run needs (plan 3 Task 17's RESTCONF AAA) goes here, as breakglass
# the daemon config: the lab file, plus the broker block where the run needs a broker
cat tests/lab/port49d-lab.yaml tests/lab/slice/broker.yaml > tests/lab/logs/port49d-byhand.yaml
# a broker run only: port49d refuses a policy file, or a directory holding one, that others could
# write (spec §5.1.3), and the same of broker.revocations_file's directory (tests/lab/logs, in
# slice/broker.yaml); a checkout under a umask of 002 is group-writable
chmod go-w tests/lab/slice tests/lab/slice/policy.yaml tests/lab/quarantine tests/lab/quarantine/policy.yaml tests/lab/logs
# a broker run only: its certificates, written before the daemon that loads them at start
go run ./tests/lab/cmd/slice-pki
# a broker run only: port49d never creates broker.revocations_file; init creates it once, run as the
# user port49d runs as (a later run over a file that loads writes nothing); init refuses a relative
# path, so the derived config names the file absolutely
sed -i "s|^  revocations_file: tests/|  revocations_file: $PWD/tests/|" tests/lab/logs/port49d-byhand.yaml
bin/port49d init-revocations --config tests/lab/logs/port49d-byhand.yaml
PORT49_LAB_KEY=labsecret PORT49_LAB_ENC_KEY=port49-lab-encryption-key-32byte \
  bin/port49d -config tests/lab/logs/port49d-byhand.yaml \
  > tests/lab/logs/decisions-byhand.jsonl 2> tests/lab/logs/port49d-byhand.log &
sudo -n tcpdump --immediate-mode -i any -U -n -s 0 -w tests/lab/captures/<note-name>.pcap 'tcp port 49' &
# a broker run only: open the session, then mint one token per device login
bin/port49 login --broker https://127.0.0.1:8449 \
  --cert tests/lab/logs/slice-pki/client.pem --key tests/lab/logs/slice-pki/client-key.pem \
  --broker-ca tests/lab/logs/slice-pki/broker-ca.pem
TOKEN=$(bin/port49 token leaf1)
# ... the run ...
sudo -n pkill -INT -f 'tcpdump.*<note-name>'; kill -INT %1
make evidence
sudo -n containerlab destroy -t tests/lab/topologies/<eos|iosxe>.clab.yml --cleanup
```

A token never goes on a command line: `port49 token` writes it to stdout, a shell variable holds
it, and `printf` (a builtin, so no process of its own) feeds it to `curl` on stdin. **Never run
these steps under `set -x` (`xtrace`)**: the shell then prints every expanded command, so the
minted `$TOKEN` lands in your terminal, your scrollback and any log you tee it to. That happened
once in plan 3's lab run. The seed-token
file `/tmp/port49-lab-tokens.jsonl` is truncated at every daemon start; `make evidence` reads it,
so run `make evidence` before the next daemon start.

`port49 login` needs all four of `--broker`, `--cert`, `--key` and `--broker-ca`; there is no
fallback to the system roots. It refuses a key file that is a symlink, has group or other bits
set, or is owned by anyone but you or root: `slice-pki` writes 0600 files in a 0700 directory,
so run it as the user who runs `port49` and `port49d`. The agent's socket directory (`$XDG_RUNTIME_DIR/port49`,
else `/tmp/port49-<uid>`) must be a real 0700 directory you own. If the agent will not start,
`port49 login` prints the end of `agent.log` in that directory; if `port49d` will not start with
the broker block, its stderr says why: a bad certificate, key or anchor at start is
`port49d: broker TLS files (…): …`, naming the three files. An expired or not-yet-valid
server certificate does not stop the start; it is one line, `port49d: broker: server
certificate expired at …; logins will fail`. Once running, a failed handshake (a login with an
untrusted or expired certificate) is logged as `port49d: broker: http: TLS handshake error …`.

### The fault switch

A by-hand run that needs port49 to answer ERROR adds `fault_file: <path>` to the `lab:` block of
its derived config (never to `port49d-lab.yaml`, so a file left behind cannot fault a later
run). port49d re-reads the file on every request; its trimmed contents name the fault:
`store_unavailable` fails the store reads each handler starts with (authentication answers ERROR,
authorization FAIL, accounting is spooled unattributed), `command_error` / `command_fail` answer
every per-command authorization ERROR / FAIL, and anything else is no fault. It is what
`tests/lab/results/L4-error-*.md` measured with; `author.LabFault` holds the code.

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

`longpw<N>` users are kept but unused. A seed cannot ask for a secret of a chosen length now
that the daemon mints it — every token is 30 characters (design §8) — so `l8_test.go` measures
password length without one: it types a probe of length N under a username that holds no token,
and compares `auth.credential_sha256` on port49's refusal against the hash of every prefix of
the probe. A match on all N characters means the password arrived intact; a shorter match is a
truncation; no record means the device refused the password itself and never asked. The 30-character
answer is not left to a probe: the test also logs in once with a real minted token.

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

## The compose mode (plan 7f)

`l.startCompose(t)` (tests/lab/compose_test.go) runs the lab on `deploy/compose` instead of
host processes: port49d, port49-broker and a three-member etcd as the compose project
`port49lab`, with `tests/lab/compose/lab.yaml` as the overlay. It stops the standing host
port49d first and puts it back at cleanup, and it needs Docker Compose v2.24.4 or later (the
overlay's `!override`).

It publishes port49d's TACACS+ port on `172.100.100.1:49`, the clab management bridge's
gateway, where every topology's devices already send it; port49d's metrics on
`127.0.0.1:9049`; the broker on `127.0.0.1:8449` (the slice's `sliceBrokerURL`, mapped to the
container's `:8443`) and its metrics on `127.0.0.1:9050`. The topology must be deployed first,
as the host harness needs it for the bridge address.

Its files are under `tests/lab/logs/compose-<platform>/` (git-ignored): `config/` and `local/`
(the YAML files and the PKI and env files the stack reads, written by `composeLabFiles` and
`testpki.WriteCompose`), `compose.log` (every command the harness ran, with its output),
`decisions-<platform>.jsonl` and `port49d-<platform>.log` (port49d's stdout and stderr, followed
with `docker logs -f` into `l.logPath` and `l.errPath`, so the host harness's `mark`,
`waitForRecords` and `errLinesSince` read them unchanged), and `broker.log` and `broker.err`.

`composeStack` carries what a test does to the stack: `HangStore()` is `docker compose pause`
on the three etcd members (the store stops answering without a reset) and `ReleaseStore()`
unpauses them; `StopDaemon()` and `StartDaemon()` stop and start port49d's container, the
follower resuming from the stop's time; `Revoke(args...)` runs `port49-broker revoke --offline` inside
its container; `ProxyMode()` says whether Docker's userland proxy serves
the published port.

New register rows run on it. Rows already closed keep their re-checks on the host harness
(`startSplit` and the standing daemon), so a closed row's note stays comparable.

What a published port does to a device's source address is L39 (a)
(`results/L39-docker-proxy-*-arista_eos.md`). The overlay's inventory lists the compose gateway
as the device `l39_gateway`, so a rewritten source is recorded rather than refused.

`startCompose` also inserts, with `sudo -n`, `iptables -t nat -I POSTROUTING 1 -s
172.100.100.0/24 -d 172.30.49.0/24 -j RETURN`, and deletes it at cleanup (both are in
`compose.log`, with the POSTROUTING rules in force once the stack is up). Stale copies of the rule
from a killed run are purged before the insert; after a run, `iptables -t nat -S POSTROUTING` must
show no `172.30.49.0/24 -j RETURN`. The clab management network is itself a
Docker bridge network, so Docker masquerades everything from 172.100.100.0/24 that leaves by
another interface: without the rule a device's packet DNAT'd to the compose bridge reaches
port49d from the compose gateway, which is the lab's own rule at work and not what a device
off the host would meet. The rule models an off-host device. A first L39 run without it
(5ee1137) saw only the gateway and is recorded as invalid in the notes.

## Directories (plan 7g)

`make lab-directory` runs L42 and L43 on two containers, OpenLDAP (Debian's slapd 2.5, the
`memberof` overlay) and Samba AD (Debian's samba 4.17 as a DC), with no network device and no
containerlab. It needs Docker, Compose v2.24.4 or later, and the base image
`debian:bookworm-slim`; the first run builds both images (a few minutes of `apt`). In a shell
that is not in the `docker` group the test runs docker as `sg docker -c`.

`tests/lab/directory_test.go` writes the PKI with `internal/testpki`, brings the compose
project `port49labdir` up (`tests/lab/directory/compose.yaml`, network `172.30.42.0/24`,
published on `127.0.0.1`: OpenLDAP 10389 and 10636, Samba 20389, 20636 and 20088 for the KDC),
waits for each directory's fixture and for LDAPS to answer, and takes the project down with its
volumes at the end of the test. Both tests read the fixture of the plan's Task 17 (`alice`,
`carol`, `dave`, `bob`, `eve`, `eve2`, the groups `g-leaf`, `g-mid`, `netops-oncall`,
`g-loop-a`, `g-loop-b`, a second `netops-oncall` under `OU=Users-Can-Create`, and the broker's
account `port49` under `OU=Svc`) and drive it through `internal/directory`, the broker's own
dialer, pool and resolver.

Files, under `tests/lab/logs/directory/` (git-ignored; a run starts from an empty directory):
`pki/` (the lab CA, the directories' server certificate for `localhost`, the broker's
certificate `CN=port49-broker,O=port49 lab`), `out/` (the keytab Samba exports, chowned to the
test's user, and the `krb5.conf` the test writes), `lab.env` (the passwords the containers read,
mode 0600, generated for the run; the test never prints one and refuses to write a note or
evidence file that holds the bind password) and `openldap.log`, `samba.log`.

The users CA that signs alice's and eve's certificates has the subject
`CN=lab-users-CA,DC=corp,DC=example,DC=com`, written in DER with its `DC=` RDNs, so
`issuer_serial` and the issuer pin meet them on real directories.

What each directory is configured to do, and where the lab departs from the plan's text:

- **OpenLDAP** loads its seed through `ldapadd` on the `ldapi:///` socket, not `slapadd -n1`:
  the `memberof` overlay writes `memberOf` only for an operation that runs through it. The
  broker's certificate maps to `cn=port49,ou=Svc,...` by `olcAuthzRegexp`. `olcSecurity` is
  `ssf=1` while the seed loads (`tls=1` would refuse the seed's own `ldapi:///` connection), then
  the entrypoint sets `olcSecurity: tls=1` with `ldapmodify` on `cn=config`, so every operation the tests make is under TLS.
- **Samba AD** is provisioned at first start, with the sysvol ACLs kept in `user.NTACL` (a
  container cannot write `security.NTACL`; the lab reads nothing from sysvol). It sets
  `ldap server require strong auth = yes`; L43 measures GSSAPI and the plain-LDAP bind under it and again after
  switching `smb.conf` to `allow_sasl_over_tls` and restarting the DC. The DC's account has the extra SPN `ldap/localhost`,
  because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`,
  which the test certificate carries. `bob`'s `mail` is edited with `ldbmodify` on the DC's own
  database (`/lab/set-attr.sh`), the non-interactive form of `samba-tool user edit`.

Two environment variables are for debugging the harness: `PORT49_LAB_DIRECTORY_OUT=<dir>`
writes the notes and evidence under `<dir>/tests/lab/` instead of the repository, so a dry run
leaves nothing to commit; `PORT49_LAB_DIRECTORY_KEEP=1` leaves the containers up afterwards
(take them down with `docker compose -p port49labdir -f tests/lab/directory/compose.yaml down -v`; `lab.env` is optional there).

A recorded run is made from a detached worktree pinned at the commit under test, as every
lab run is.

**L50 (plan 8b).** `make lab-l50` (`PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run
'^TestL50WorkloadAttributeWriters$' -count=1 -v -timeout 240m`) measures who can write the
attribute a workload mapping reads, on Samba AD first and then on the Windows Server DC (it
needs L44's KVM, ISO and 66 GiB). Four writers (the target entry itself, `svc-oxidized-01`; an
Account Operators member, `l50-acctop`; a delegated OU administrator, `l50-ouadmin`; an ordinary
user, `l50-user`) each try to replace each of `uid`, `description`, `wWWHomePage` and `url` on
`CN=svc-oxidized-01,OU=Workloads` with a SPIFFE ID, under two ACL states: `default`, and
`prescribed`, an inherited deny of write on that attribute on the OU for SELF, Account Operators
and `l50-ouadmin`. Under the prescribed deny on `uid` it then tries to get round the deny as
`l50-ouadmin`: write an entry it created, add an allow ACE for itself to the target and write,
take ownership of the target and do both (each undone, and the target's descriptor checked
against the one before). The audit is read in two modes, as installed and with auditing turned on:
Samba's `dsdbChange` records in the container's log (before and after `smbcontrol ... debug
dsdb_json_audit:5 dsdb_audit:5`, with a positive control) and the Windows Security log's 5136
and 4662 events (before and after `audit.ps1 on`; the settings as found are recorded first). The
actors' `actor_password` is generated per run, reaches the VM on stdin and the Samba container
as an argument, and is never printed; the notes and evidence refuse to hold it. A run from a
pinned worktree sets `PORT49_LAB_DIRECTORY_OUT` to the branch's worktree so the notes land where
they are committed.

**L67 (plan 9e).** `make lab-l67` (`go test -tags lab ./tests/lab/ -run '^TestL67$' -count=1 -v
-timeout 45m`; run `make build` first) measures a person's simple bind and the
directory-password sign-in on OpenLDAP and Samba AD, the two containers in parallel;
`make lab-l67-windows` (`PORT49_LAB_L67_WINDOWS=1 ... -run '^TestL67Windows$'`, L44's KVM and
ISO) runs the same cells on the Windows DC. Cells: (a) `CheckPassword` right and wrong over
LDAPS and StartTLS; (b) an unauthenticated bind, and an empty password that opens no connection;
(c) an expired, must-change, disabled and locked account, each with the right and a wrong
password; (d) six wrong sign-ins at port49's default limits, then nine across a 2m window
boundary against a lockout threshold of ten; (e) a wrong code leaves the directory's count
alone; (f) `SignInEntry`'s creation time; (g) `login --directory`, `token` and a stopped
directory, on port49d with the memory store and (OpenLDAP only) on the compose stack's broker
on etcd, which also needs the containerlab platform that stack uses. Every cell runs its
positive control first, and the evidence keeps each state's LDAP result and diagnostic data
(AD's `data 52e`, ppolicy's error). The people's `person_password` is generated per run, held
in memory, reaches the containers and the DC through their environment and stdin, and is
written to the evidence as `<alice's password>`; no TOTP secret, code or token is printed.
OpenLDAP gets the ppolicy overlay only when `LAB_L67` is set (so L42, L43 and the end-to-end lab
keep their fixture), started with `olcPPolicyUseLockout: TRUE`; cell (c) then flips it to
FALSE (the stock default) over ldapi, re-records the locked and disabled people, signs the
locked person in through the broker six times to see the limiter count the refusals, and sets
TRUE back. Each state's row keeps both what `CheckPassword` returned and the raw bind's result
code, any AD `data` code (no allow-list) and the ppolicy control (absent, present with no
error, or its error number). Under FALSE a locked or disabled account's bind is a plain result
49 with a control that carries no error, which port49 cannot tell from a wrong password. L67
runs OpenLDAP with `olcSecurity: ssf=56` instead of `tls=1`, so ldapi stays open for the flip.

## Identity provider (plan 7h)

`make lab-oidc` runs L45 and L46 on one container, Keycloak, with no network device and no
containerlab. It needs Docker and Compose v2.24.4 or later; in a shell that is not in the
`docker` group the test runs docker as `sg docker -c`. The image is pinned by digest
(`tests/lab/oidc/compose.yaml`, and `kcImage` in `oidc_test.go`, which a unit test holds equal);
a note records `kc.sh --version` and the image ID it ran.

`tests/lab/oidc_test.go` writes a PKI with `internal/testpki` under `tests/lab/logs/oidc/`
(git-ignored), generates the admin password for the run (`admin.env`, mode 0600, never printed;
a note that holds it is refused), brings the compose project `port49laboidc` up on
`127.0.0.1:18443`, imports `tests/lab/oidc/keycloak/realm.json` and waits for the realm's
discovery document (the import takes up to 90s). It takes the project down with its volumes at
the end, keeping `keycloak.log`.

- The issuer is `https://keycloak.port49.lab:18443/realms/port49-lab`. The test's client resolves
  that name to the published port and trusts the run's own CA; the receiver's and the broker's
  certificates come from the same CA.
- Keycloak posts back-channel logouts to the receiver the test starts on the host's port 18750.
  `host.port49.lab` must reach it from the container: compose maps it to `host-gateway`.
- Evidence (`tests/lab/evidence/L45-keycloak.json`, `L46-keycloak.json`) holds decoded JWS
  headers and claims, never a signature: the writer (and the note writer) refuse any value that holds a
  compact JWS or a value the run registered as secret (the admin password, each code, state, token and
  cookie value the flow handled). Failure messages carry no URL, Location query or page body.
  The wire is TLS, so there is no pcap.
- `realm.json` fixes `port49-svc`'s service-account user id, so its client-credentials tokens'
  `sub` is known before Keycloak starts and the broker config can pin it (Ruling 21). L46 fails
  if Keycloak did not keep that id, after writing its note.
- L45 stops as INVALID, writing no note, if the receiver gets nothing within 20s of the first
  end-session logout, or gets a request whose `iss`/`aud` are not this realm's and `port49-cli`'s.
  The end-session request is a POST form, so the ID token is never in a URL.
- L46 stops without writing its note if its SSO control (step 1b, a plain second login that must
  reuse the session) fails: without it, "prompt=login asked for the password" proves nothing.
- `PORT49_LAB_DIRECTORY_OUT=<dir>` redirects notes and evidence here too, for a dry run.

## OIDC sign-in and issued certificates (plan 9b): L55 and L56

- `make lab-oidc-l55` measures L55 on the standalone Keycloak. It changes `port49-cli`'s redirect
  URIs for the run and puts them back. Cell 4b keeps one browser's SSO session across three
  sign-ins, 15s apart, to see whether `prompt=login` authenticates again.
- `make build && make lab-oidc-agent` measures L56: `bin/port49 login --oidc --no-browser` on the
  compose stack, a scripted browser signing in from the address port49 prints.
- L56 starts the broker with `broker.identity.issuance` and no issuing CA, checks what it says, then
  runs `docker compose run --rm --no-deps port49-broker init-issuer` and restarts the broker.
- The CLI reaches `keycloak.port49.lab` through a CONNECT proxy the test runs on loopback
  (`HTTPS_PROXY`), since the host does not resolve that name. port49 never sends the broker through
  a proxy.
- L56 step 4b runs `port49 login --sign-in` with a pty for stdin and types the address Keycloak sent
  the browser to, as a person on a jump host pastes it.
- Every CLI command's raw output is checked for a compact JWS or a registered secret (the issued
  key's PEM included, read once the command has ended, so a run is checked against the key it
  wrote) before it is scrubbed for the note, and a leak fails the run. Only what port49 prints by
  design is exempt. The PKCE verifier port49 draws is never seen by the lab; the unit tests check
  it.
- Each L56 cell asserts, and each assertion has a control that shows it can fail. A control that
  does not hold is INVALID, and no note is written.
- Keycloak is stopped and started by `docker compose stop|start keycloak`.
- The CLI runs with `HOME` set to a temporary directory and `PORT49_CONFIG` and `XDG_CONFIG_HOME`
  removed, so the issued key and certificate (`~/.port49/issued/`) are the run's own and the real
  `~/.port49` is never touched. The CLI does read `/etc/port49/config.yaml` when it exists, so L56
  stops as INVALID, writing no note, if that file exists on the lab host.
- A device token must be `port49 token`'s whole stdout and is looked for everywhere else (its
  stderr, every other command's output, the agent's log, and the broker's and port49d's logs at
  the end); it is never exempt. Only the authorization URL's state, nonce and `code_challenge` are.
- L55 cell 3's right-verifier exchange must return an `id_token`, or the run is INVALID: the
  wrong-verifier and no-verifier refusals mean something only beside it.

## Workload CA and Oxidized (plan 8)

Two targets measure the workload-certificate path. Build first: both need `bin/port49d` and
`bin/port49` (`make build`).

- `make lab-workload` runs L48 on one container, step-ca, and a local `bin/port49d` with a broker
  and the workload verifier. No device, no containerlab. It needs Docker with Compose v2.24.4 or
  later; docker runs as `sg docker -c` outside the `docker` group.
- `PORT49_LAB_PLATFORMS=<one> make lab-oxidized` runs L49 on the compose stack with Oxidized added
  (`tests/lab/compose/oxidized.yaml`): containerlab, the platform's image, one platform per
  invocation, as `make lab` runs them. With no selector it loops over every platform and stops at
  the first that fails.

Both images are pinned by digest, in the compose file and in the Go constant that names the same
reference (`tests/lab/workload/compose.yaml` and `stepCAImage` in `stepca_test.go`;
`tests/lab/compose/oxidized.yaml` and `oxidizedImage` in `oxidized_test.go`).
`TestTheWorkloadImagesArePinnedOnce` holds each pair equal. A note records `step-ca version`,
`oxidized --version` and the image ID it ran. The Oxidized image is a build after its 0.37.0
tag (`0.37.0-101-g65125713`), so no tag names it and the digest is the pin.

- step-ca's state is `tests/lab/logs/workload/step` (git-ignored), emptied at the start of a run.
  The directory is emptied and chowned through a root container (`docker run --user root`), as the
  Keycloak harness does, so no sudo is needed. The provisioner `lab` is a JWK. The harness
  generates a random password for the run into `tests/lab/logs/workload/pw/password` (mode 0600,
  never printed, never read back) and mounts it as `DOCKER_STEPCA_INIT_PASSWORD_FILE`, so the CA
  key's and the provisioner's passwords are that one value, which the harness refuses anywhere it
  would be written. (Left to itself the image generates two passwords and prints the provisioner's
  once in its log.) A step command's output that holds key material, a compact JWS or that password
  is withheld, and `step-ca.log` is kept with its password lines dropped and any JWS- or
  JWE-shaped string redacted to `<jws redacted>`, or not at all (a registered secret or key material
  in what is left refuses it).
- L48's local broker trusts step-ca's root for the CRL fetch through `SSL_CERT_FILE`: step-ca serves
  its CRL over https under its own private root, and the broker fetches with the system roots. A
  CRL fetch that fails TLS is INVALID, never a measured "no".
- Oxidized runs as the host user, not as the image's `oxidized` (uid 30000), and `oxidized` is
  started directly instead of the image's runit services. The image's run script chowns its whole
  config directory to uid 30000 at every start, which would lock out `port49-oxidized-run` (a host
  process here, as cron is on a real host) from replacing `router.db`. Starting `oxidized` directly
  also skips the image's auto-reload service, which reloads in a loop when `CONFIG_RELOAD_INTERVAL`
  is set at all. The directory is `tests/lab/logs/compose-<platform>-<phase>/local/oxidized`; `known_hosts`
  is mounted at `~/.ssh/known_hosts` (that is where Oxidized's SSH client reads it), filled by
  `ssh-keyscan` of the device.
- Oxidized exits with `NoNodesFound` on an empty `router.db`, and the wrapper never writes an
  empty one. So `startOxidized` brings the stack up without Oxidized (its service is under the
  compose profile `oxidized`), runs the wrapper once (it writes `router.db`, then exits 75 at
  `/reload` because Oxidized is not up: a setup step, not a cell, and it mints one token for the
  node), then starts Oxidized with `--profile oxidized up -d oxidized`. After the wrapper's reload,
  `awaitNode` fails the test (INVALID) if Oxidized never lists the node.
- After a run, `router.db` and the wrapper's lock file stay in
  `tests/lab/logs/compose-<platform>-<phase>/local/oxidized`, and `router.db` holds live tokens (mode 0600)
  until they expire. The directory is git-ignored; never copy it into evidence. Task 14's cleanup
  removes it.
- Each L49 phase has its own stack directory, `compose-<platform>-a` (phase A) and
  `compose-<platform>-bc` (phases B and C), because `startComposeWith` removes the directory it is
  about to use. Phase A's logs survive phase B's start.
- The host harness's `port49d` (not the stack's) mints its labcreds at every start, about 152
  `mint` records per start, and the breakglass redeem `token_not_found` in its log is the lab's
  readiness probe. Both are expected, and neither is in the stack's `broker.log` or decision log.
- The example's `config` sets `auth_methods` with `keyboard-interactive` for the `eos` model alone.
  vEOS offers only `publickey,keyboard-interactive` (`results/L4-error-arista_eos.md`), and
  Oxidized's default list does not name the second, so without it Oxidized never sends the token to
  EOS (measured in the L49 debug). It is not global because a global setting made one stale token
  cost two authentications on NX-OS and IOS-XE (run set 2) instead of one. Phase A's note says what
  the example sets.
- Phase B records, from Oxidized's own log, the class-and-message lines of the stale run (leak
  checked, never the whole log) and whether a node crashfile was created (`crashes/` under
  Oxidized's root, `/oxhome/.config/oxidized`, the mounted `local/oxidized`; a unit test derives the
  path from the overlay) and whether the process-crash file `crash` exists. Oxidized logs the refusal as
  `Errno::ENOTTY ... creating crashfile`: net-ssh's keyboard-interactive asks a tty for a second
  password.
- Oxidized's log (`oxidized.out`, `oxidized.err` beside the stack's other logs) stays on disk. A
  note quotes only phase B's excerpt of the stale run (class-and-message lines, each checked whole
  against every minted token and for a compact JWS before it is cut to 220 characters, and the
  whole excerpt is withheld on a hit). The username (`svc-oxidized`) is an account name, not a
  secret; the password column of `router.db` is.
- Phase A also asks the device's sshd which methods it lists (`ssh` with `PreferredAuthentications=none`,
  refused locally, no TACACS+ attempt) and the note records the answer; the EOS finding is cited
  only in the EOS note. Phase B counts the redeem records of the one stale run (from a mark just
  before the `PUT`). If Oxidized is down after the stale run (REST dead, with or without the
  process-crash file), that is phase B's finding: the wrapper-again run and phase C are skipped and
  the note says so. A crashfile counts as written by the stale run when its mtime is at or after the
  `PUT`, because Oxidized names it by the device address and overwrites it.
- A fault in the setup (an image that will not pull, step-ca that never answers, Oxidized that never
  answers its REST API) is `t.Fatal` before any note: the run is INVALID. A step that ran and did
  not do what the claim says is a failed cell, and the note records it.
- `TestL48StepCA` runs six cells (issue, renew, daemon timing, the CA down, the CRL, the name
  policy) and writes `results/L48-step_ca.md` and `evidence/L48-step_ca.json`. `TestL49Oxidized`
  runs, per platform, phase A (what Oxidized sends, role `**`) on one stack and phases B and C (a
  stale token, with `receipt_idle_ttl: 2m` in that stack's `port49d.yaml`; then the example's
  role) on a second, and writes `results/L49-oxidized-<platform>.md` and
  `evidence/L49-oxidized-<platform>.json`. Phase D (no token in Oxidized's log) checks each
  stack's log. A note is written only if neither it nor the evidence holds a token, a key or a
  compact JWS; `router.db` is removed when each stack goes down.

## SSH host-key scan (L53)

`make build && make lab-ssh` measures the SSH host key each platform presents to a scan (L53; the
scan is `labScan` in `hostkeyscan_test.go`, moved from `internal/hostkeys` by plan 9d, which
removed `port49 devices trust` and with it L54's half). Each device is reloaded once, so it is
gated by `PORT49_LAB_SSH=1`. `PORT49_LAB_REMEASURE` passes through from the caller's environment,
so a plain `make lab-ssh` refuses to overwrite closed entries; `PORT49_LAB_REMEASURE=L53 make
lab-ssh` re-measures it. The note goes to `tests/lab/results/L53-*.md`. The run's capture is
`tests/lab/captures/L53L54-<platform>.pcap` and goes through `make evidence` like every other. On
IOS-XE and NX-OS the run sets a login-attempt limit for about three minutes (a 70 s wait, three
scans, the control's logins, which may each wait up to 30 s, and a 75 s wait) and removes it; a run
stopped in that window leaves it set (`no login block-for`, `no aaa authentication rejected 2 in 60
ban 60`). Each run also makes a refused login as `l53-control` and requires the device's log to show
it: a log that does not is no evidence about what the scan wrote, and the note says the log clause is
unmeasured. The Junos images log to `messages` through the `system syslog` stanza in
`configs/vjunos-startup.conf`.

## Kubernetes (L69)

`make lab-k8s` runs L69 (plan 10, spec §15): a Kubernetes cluster's service account tokens as
port49's `k8s` verifier meets them, on two kind clusters and a local `bin/port49d` with a broker.
It touches no device. It needs Docker, kind v0.29.0 (`go install sigs.k8s.io/kind@v0.29.0`; the run
looks on `PATH`, then in `~/go/bin`, and refuses any other version), `kubectl` and `make build`.
The node image is `kindest/node:v1.33.1`, pulled by tag and recorded by digest. `make lab-unit`
runs its pure tests (`l69_unit_test.go`) without any of that.

- Two clusters, `port49-l69-a` and `port49-l69-b` (API servers on 127.0.0.1:16443 and :16444), each
  with its own `--service-account-issuer` (`tests/lab/k8s/kind-a.yaml`, `kind-b.yaml`; B also sets a
  `--service-account-jwks-uri` that differs from where its keys are read). `tests/lab/k8s/workload.yaml`
  is the workload: namespaces `netops` and `backup`, service account `netops:oxidized`, a pod with the
  projected token of `examples/kubernetes/backup-cronjob.yaml` (audience `port49-lab`,
  `expirationSeconds: 600`, the API server's minimum) and a pod with the default token.
- The cells, in order: (a) the projected token's claims; (c) issuer discovery and the JWKS read
  anonymously before and after `examples/kubernetes/issuer-discovery.yaml`, then a broker on each
  cluster's verifier; (b) when the kubelet rewrites the file (about ten minutes: the poll reads the
  file's hash, never the token); (d) a signing key added at A's API server and whether the running
  broker mints with the new key's token; (e) a token after its pod, then its service account, is
  deleted (TokenReview and port49), then after `port49 revoke`; (f) B's token at a broker that lists
  A alone, at one that lists a namespace only A lists, and at one where both list it; (g) the
  shapes port49 refuses (another audience, unbound, Secret-bound, Node-bound, a legacy Secret
  token); (h) the default `kube-api-access` token. A "no" in a cell is a measurement; a fault in the
  setup is `t.Fatal`, INVALID, and writes no note.
- Tokens are read into memory only (`kubectl exec ... cat`, `kubectl create token`), written to a
  0600 file under `t.TempDir()` for `port49 workload token --token-file`, and registered as secrets.
  The evidence (`tests/lab/evidence/L69-kind.json`) keeps a token's decoded header and claims and its
  sha256, never the compact token; the note (`tests/lab/results/L69-kind.md`) and the evidence are
  checked against every token read, and against any compact JWS, before they are written.
- The sentinel `/tmp/port49-STOP-LAB` and the disk floor (67584M free on `/`) are checked before each
  cell and before each cluster is made.
- Both clusters are deleted when the run ends, however it ends (a signal included). After a run killed
  hard (`go test`'s timeout skips cleanup), delete them by hand: `kind delete cluster --name
  port49-l69-a` and `--name port49-l69-b`. A run refuses to start while either exists. The run never
  touches another kind cluster or any other container.

## L72: the RFC 9887 listener against reference clients

`go test -tags lab ./tests/lab/ -run TestL72 -v -timeout 20m` on the lab host. It needs no
containerlab and no device: it builds port49d and `tests/lab/cmd/tacacs-tls-client`, makes a PKI in
a temporary directory, and starts port49d with both listeners on 127.0.0.1 (a `tls` device at
127.0.0.1, a `tcp` device at 127.0.0.2, nothing at 127.0.0.3). It needs `openssl` 3.x on `PATH`.
Every key, secret and token is random, held in memory or in a 0600 file under the test's
temporary directory, and checked out of the note and the evidence before either is written.
The note is `results/L72-reference.md`, and the evidence (decision log lines and openssl
transcripts) is `evidence/L72-reference/`. Besides the decision log, cells h, l and n read
port49d's `port49_connection_events_total` (`declined_refused` against `held_refused`) to tell a
decline, which opens a window and is no strike, from a strike. No device's RFC 9887 behaviour is
measured here; that is L73 (closed 2026-10-18; see the L73 section below).

**Running L72 and L71 (recorded).** Make the run worktree under the repository, not `/tmp`:
`git worktree add --detach ~/git/port49/.worktrees/run-l7x <sha>`. `/tmp` is a nosuid tmpfs, and
port49d cannot bind :49 with file capabilities there. Run `make build` in the worktree first. L71
is `PORT49_LAB_PLATFORMS=eos,iosxe,nxos,vjunos,vsrx go test -tags lab ./tests/lab/ -run
TestL71TLSClientSupport -v -timeout 3h`. It sends no TACACS+, so its capture is the masked CLI probe
transcript (`evidence/L71-<platform>/probe.txt`), not a pcap. vJunosEvolved and vSRX 23.4 are not
in the harness platform list and are not probed.

## L74 and L75: three regions

`make lab-regions` (`go test -tags lab ./tests/lab/ -run '^TestRegions$' -timeout 120m`) on the lab
host. It builds three network namespaces, `p49r1..3`, each joined by a veth to the host bridge
`p49rbr0` (10.149.0.1/24). Region i is 10.149.0.(10+i). `tc netem delay 20ms` sits on each
region's side, so region to region is 40ms round trip and host to region 20ms. The cut is iptables
in region 3's namespace dropping its traffic with the other two regions; the host still reaches it,
so the harness keeps driving it. The directory etcd has one member per namespace; each region also
runs a one-member session etcd on its own loopback, a port49-broker and a port49d. The TACACS+
client is the harness, on the host, as the device `l74-client` at 10.149.0.1.

- **Needs:** `sudo -n` for `ip`, `tc` and `iptables` (and `sudo -n -u <you>` inside the namespace);
  `PORT49_LAB_ETCD_BIN` naming a directory with etcd and etcdctl v3.6.15; and L67's directory
  images. Stopping a process needs no sudo. The lab is single-occupant: the run takes the
  shared lock `/tmp/port49-lab.lock` (as L73 and L76 do) before its pre-clean, which deletes
  `p49r1..3` and `p49rbr0`, and refuses to start while another run holds it.
- **L75's brokers run on the host**, not in a namespace: directory membership needs the directory
  (OpenLDAP, L67's containers), which the namespaces cannot reach.
- **10.149.0.0/24 must be free** (`ip -4 route`).
- **Stopping is by recorded PID, and the keys are not on argv.** Each member and process is
  started as `sh -c 'echo $$ > <name>.pid; . <run.env>; exec <argv>'` with its pidfile and `run.env`
  (the TACACS+ and encryption keys, 0600) in the run's 0700 temporary directory, so the PID is the
  program's and sudo's log holds no key. A stop reads the pidfile, checks that `/proc/<pid>/cmdline`
  still holds the member's `--data-dir` or the process's `--config` argument, and sends SIGTERM; past
  15s it checks again and sends SIGKILL; a wait on a process that will not end is bounded at 10s and
  reported. A mismatch is logged and skipped. Nothing is ever ended by a `pkill` or `pgrep -f`
  pattern.
- **Removing a left-over network** (a run killed hard skips its cleanup): `sudo ip netns del p49r1`
  (and `p49r2`, `p49r3`), then `sudo ip link del p49r1h` (and `p49r2h`, `p49r3h`, which a namespace
  that still held a process leaves behind) and `sudo ip link del p49rbr0`. A left-over etcd member or
  port49 process is ended by the PID in its `*.pid` file under `/tmp/p49l74*/`, after checking
  `/proc/<pid>/cmdline` by hand: `kill <pid>`.

## L73: device RFC 9887 clients against port49

`PORT49_LAB_PLATFORMS=<selector> go test -tags lab ./tests/lab/ -run '^TestL73$' -count=1 -v -timeout 3h`,
one selector per run (`vjunos26`, `iosxe1718`, `nxos106`, `ceos436`, `xrd261`; help cell `iolxe1718`;
`vjunosswitch26`), from a pinned worktree under `.worktrees/`, after `make build`.

- **Opt-in selectors.** A run that names no platform never deploys them.
- **Occupancy.** The test takes the lab's single-occupant lock (`/tmp/port49-lab.lock`,
  `labOccupyForRun`), holds it until `TestMain` has torn the topology down, and refuses to start
  beside another containerlab topology.
- **Order of a run.** It first asks the image's help about every statement it types (an addendum
  to L71). It then enrols the device: the key pair stays on the device, a Junos request is read
  from a file, and an IOS XE, NX-OS or EOS request is read off the terminal. Last, it runs cells
  (a)-(j) against port49d, restarted per cell with a `tls_listener:`.
- **Dialects.** Per-platform lines, asks and enrolment prompts live in `l73_dialect.go`
  (`l73Dialects`). An unknown prompt is INVALID, with the scrubbed screen in
  `PORT49_L73_INVALID_DIR`.
- **Evidence.** Raw captures stay git-ignored in `captures/L73-<platform>/`, outside
  `make evidence`'s glob: TLS is not `labpcap`'s. The committed evidence is
  `evidence/L73-<platform>/<cell>.tls.json`, a per-connection summary whose types hold no session
  bytes. Beside it are the redacted decision log, the device's masked configuration and TLS log
  lines, and the help exchange.
- **PKI.** `PORT49_L73_ALG=rsa` switches the lab PKI from ECDSA P-256 to RSA 2048.

## L76: Nokia SR Linux over TACACS+

`PORT49_LAB_PLATFORMS=srlinux go test -tags lab ./tests/lab/ -run '^TestL76$' -count=1 -v -timeout 90m`,
from a pinned worktree under `.worktrees/`, after `make build`. Run L76 only with `-run '^TestL76$'`: the
`srlinux` row is opt-in, and with no `-run`, `TestL73` would deploy the node too.

- **The image's terms.** The public SR Linux image is for learning, demo, test and CI use only. It is pulled
  anonymously from ghcr.io: no `docker login`, no token, no employer account.
- **The node.** `srl1` (172.100.100.71), `kind: nokia_srlinux`, image `ghcr.io/nokia/srlinux:26.7.2-519`
  (digest `sha256:0096fe3e...b48be8`). It is a container, not a vrnetlab VM. The row is opt-in.
- **Sources.** Every SR Linux command and statement the test uses is checked against Nokia's 26.7
  documentation, containerlab's srl kind page, or the image's own YANG and `sr_cli --help`. The results
  note's "Sources" section lists each one with its page (`l76Sources`).
- **The config.** `configs/srlinux-startup.cli`, in containerlab's hierarchical `.cli` form, is applied
  after SR Linux's default config. It follows Nokia's *Configuration Basics Guide 26.7*, "Securing access",
  except where the image's YANG overrules it: the local server group must be named `local`, the
  accounting event is `command`, and each local role must list `services [ cli ]` or no login on it succeeds. The file has no comments because containerlab's `.cli` comment syntax is
  not documented. Its secret and break-glass password are `labcreds`' published values.
- **Device commands.** The test reads and changes the device with `docker exec clab-port49-srlinux-srl1
  sr_cli -d`, which runs as the container's root, outside TACACS+. Cells (i), (j) and (l) restore what they change, and cell (k) clears the checkpoint it tries to make. A run of the closed entry needs `PORT49_LAB_REMEASURE=L76`.
- **Occupancy.** The test takes `/tmp/port49-lab.lock` (`labOccupyForRun`) and holds it through `TestMain`'s teardown.
- **Evidence.** `evidence/L76-nokia_srlinux/` holds the masked running config, the model excerpts, each
  login's outputs, the AAA log lines (filtered), and the redacted decision log. `evidence/L76-nokia_srlinux.pcap`
  is the redacted capture (`make evidence`).
- **An INVALID run** writes no note. It keeps the device's own view, filtered and leak-checked, in the
  git-ignored `logs/L76-invalid-<stamp>/` (masked running config, AAA log tail, session table).

## Qualification (plan 11b)

`make lab-qualify P=<selector>` runs `TestQualify`, the conformance run a firmware is vetted by. It
is opt-in (`PORT49_LAB_QUALIFY=1`, which the target sets), runs one platform at a time, and holds the
lab lock like every other lab run.

It plays the cells in `qualCells` (`tests/lab/qual_evidence.go`) under `tests/qual/qual-policy.yaml`
and `tests/qual/qual-daemon.yaml`, with tokens the broker mints: no seed and no lab instrument can
answer. Each cell cites the register rows it re-measures and closes none. The denied command is per
platform (`qualDeniedCommand`): Junos sends no command authorization (L18), so its `command_denied`
and `command_permitted` cells are recorded `not_applicable`.

Output, with `<slug>` the firmware's `devicemock.Slug` and `<lp>` the lab platform name:

- `tests/lab/evidence/QUAL-<slug>-<lp>/`: `run.json`, `decisions.jsonl` (only whitelisted fields, see
  `qualRecord`), `<cell>.conns.json` (plain 49) and `<cell>.tls.json`;
- `tests/lab/evidence/QUAL-<slug>-<lp>.pcap`, beside the directory, redacted like every capture;
- `tests/lab/results/QUAL-<slug>-<lp>.md`, the note.

To vet a firmware and add its mock in one command, use `make qual-vet P=<selector>`; the
procedures are in `tests/qual/README.md`.

`run.json` holds `cells` (the start time of each cell that ran) and `results` (every cell's verdict: `pass`,
`fail`, `not_applicable` or `not_run`). `command_authorization` says, for each TLS login cell, what its
commands did at port49 (`sent`, `not_sent` or `not_applicable`), graded from port49's records alone;
`denied_command_ran` is L80's cell.

The TLS login cells grade what the operator configured. `tls_token_login` runs per-request, the
device default; `tls_single_connection` runs last with single-connection on the TLS server, then
puts the device back. Each verdict line starts with its mode. A per-request login whose commands
reached port49 as no `authorize_command` (NX-OS 10.6(2)F, L73 cell a) passes as a login and says
"command authorization not sent", with each command's first output line: a device fact, never a pass
for command authorization over TLS. Only then does `tls_denied_command` run: one login typing the
denied command alone, graded from its first output line and port49's records, which writes
`tests/lab/results/L80-<lp>.md` beside the QUAL note (spec §15 L80). It is a measurement, not a
qualification check: its verdict is `observed` ("denied command ran; port49 never asked (the device's
local method, presumed)" or "denied command refused", with the first line and the record counts), never `pass`,
and `fail` only when port49 permitted the command, the device ran it after port49 denied it, or
there was no output to read.

Every evidence file passes a leak gate before any is written; a failure names the file and the kind
of content, never the content.

## Regressions (plan 11b)

`make lab-regress` reruns every closed entry in `tests/lab/regress.yaml` and rewrites its results
notes. Each entry's `measured_minutes` is its wall time in a full run (the first, commit `2c680dbf`,
2026-10-19/20, then the L35, L37, L66, L79 and L80 entries): the manifest sums to 733.6 minutes. A clean
full run is about 12 h plus NX-OS boot hangs (below), so routine use needs a subset:
`make lab-regress LAB_REGRESS_ARGS=-only=L35,L37`. The slowest are L34 (103 min), L36 (67) and
L22 (44).

Runs before the 2026-10-20 rebase name the rebased twin of the commit they ran (`2c680dbf` for the
first full run); the tree differs by PR #29's client and spec changes only. The vJunos 23.4R2-S2.1
QUAL run names `73f7a5df`, the commit its amended-away original became: the code is identical, and
only two stray pcaps were dropped.

The first run passed 58 of 66 entries. Of the 8 that failed, all are resolved:

- **L35, L37**: the test expected plan 7e's circuit-open line; port49d now goes dark on decision 37's
  health checks (about 5 s). The verdict was fixed and both passed on the rerun.
- **L66 (five entries)**: the lookup failed for a name outside the inventory; fixed by PR #29, and L66
  passed on the rerun.
- **L29-reload on vjunos**: no connection open across the change was reset in the refused/rekeyed
  phase. Junos sends nothing on a held connection, so the phase can fail its premise; a device
  flake, so retry the entry.

**L80** (`L80-nxos106`) is a regress entry: it re-measures a security fact (a command port49 denies runs
over NX-OS 10.6's per-request TLS), and a run that observes nothing is INVALID. A flipped outcome shows as
changed lines in the note diff, and a run that observes nothing writes no L80 note. `lab-regress` reports
note changes and does not fail on them. It does fail an entry whose listed note the run did not rewrite
(its mtime is before the entry started): notediff masks the header lines a rerun changes, so an untouched
note would otherwise read "unchanged".

**NX-OS boot hang.** 11 of 39 NX-OS deployments never booted: the container log stops after
`feature netconf` and port49d sees no packet within 8 min. The cause is not yet known; the device
appears to hang while the launcher applies its startup config. Retry the entry.

**What a run needs beyond the base setup:**

- `PORT49_LAB_ETCD_BIN` names a directory holding `etcd`, `etcdctl` and `etcdutl`, all v3.6.15
  (on beehive, `/mnt/images/etcd-v3.6.15`). L35-restore needs `etcdutl`.
- L66 needs `tests/lab/l66/.collections`, which is git-ignored, so a fresh worktree lacks it. Create it
  with `/home/rwendt/lab-venv/bin/ansible-galaxy collection install -p tests/lab/l66/.collections <collections>`;
  the L66 preflight prints the exact command with the collection names.
- Building `vrnetlab/cisco_iol` needs the image file copied into the build directory first (step 3's
  IOL-XE recipe); an `IMAGE=/mnt/images/...` path fails the Makefile's version regex.
- cEOS 4.36.3M must be docker-imported from its tarball (`docker import ... ceos:4.36.3M`).
