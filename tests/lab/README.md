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
   Check `docker images` for the tag each build produced and match the `image:` lines in
   `topologies/`. Expected: `vrnetlab/arista_veos:4.32.2F`,
   `vrnetlab/juniper_vjunos-router:23.4R2-S2.1`, `vrnetlab/juniper_vsrx:21.4R3.15`.
4. `export PORT49_LAB_KEY=labsecret`
5. `make build && make lab`

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
  authentication through to a rejection. The second is deliberate: vSRX will not fall through
  `authentication-order` to a local password while port49d is not listening yet, so requiring
  the login meant that platform could never pass. See `waitDeviceReady`.
- Every register test then runs against that already-deployed device. The topologies are
  **deployed once per run**, not once per test: these are VMs and each boot costs minutes.
- At the end of the run every topology is destroyed with `containerlab destroy --cleanup`.

Select platforms with `PORT49_LAB_PLATFORMS`, a comma-separated list of `eos`, `vjunos`,
`vsrx` (default: all three). One at a time is the normal way to run it:

```sh
PORT49_LAB_PLATFORMS=eos make lab
```

`register_test.go` has one test per open register entry this plan closes: L1, L2, L5, L6, L8,
L10. Each writes `results/L<N>-<platform>.md` with the observation. **A register test passes
when the measurement was made and fails when it is inconclusive** — whichever way the device
behaved is the result, but "the login never happened" or "no matching record reached the log"
is a failure, because nothing was measured.

## Tokens

`port49d-lab.yaml` seeds single-use tokens, because redemption deletes the token: every login
in a run consumes one. The pool is deliberately larger than the run needs. `lab.nextToken()`
hands them out in order, so a test never reuses a spent one.

`longpw<N>` users each hold one token whose secret is exactly `N` characters. L8 logs in as
each and reads the outcome, so a device that truncates the password produces
`credential_mismatch` against that user rather than a silent pass against a shorter token.

## Captures

`tcpdump --immediate-mode -i any -U -n -s 0 -w captures/<test>-<platform>.pcap 'tcp port 49'`
runs around each test. Captures are git-ignored; the results note quotes the fields that
matter, names the file, and reports how many packets in it are device traffic.

`--immediate-mode` is not decoration. Without it libpcap hands tcpdump the kernel ring on a
one-second read timeout, so a capture stopped within a second of its last packet loses that
packet — which is how the first vEOS run produced a 24-byte L10 capture beside a results note
that claimed a measurement.

The harness brackets each capture with a TCP connection to `127.0.0.1:49`, where nothing
listens. Those two loopback packets are its proof that the file is really capturing: the test
does not start until one has reached the file, and tcpdump is not stopped until another has,
which by ordering means everything the test produced is already on disk. They are on the
loopback, so they are excluded from the device-packet count a results note quotes.
