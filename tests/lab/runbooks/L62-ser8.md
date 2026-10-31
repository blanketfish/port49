# L62 session runbook: the SER8's TPM

Spec §15 L62 on beehive, the SER8. `issued_key_store: tpm` on a real TPM 2.0 through
`/dev/tpmrm0`, for a non-root user in `tss`. Eight steps: one session-start step (0), then one
per clause. Steps 1 to 3 need only the SER8. Steps 4 to 7 also need the second host (Part B).
L62 closed on 2026-10-15 (`tests/lab/results/L62-ser8.md`); this runbook is kept to re-run it,
for example on new TPM firmware or a second machine with a real TPM.

**Who runs what.** You type every command that reaches a TPM, as `p49lab` on the SER8 or
through `docker exec` into the second host. No agent runs anything as `p49lab`. `rwendt` is
not in `tss`, so a Claude session running as `rwendt` cannot open `/dev/tpmrm0`. The controller
only reads the filtered logs in `/var/tmp/port49-l62/` afterwards.

**Secrets.** The YubiKey PIN goes only to port49's own `PIN for …:` prompt. alice's lab password
goes only into Keycloak's form in the browser. Nothing in this runbook asks you to paste a
token, a PIN, a key file's contents or a sign-in address into a chat. The `o` helper (Part A,
A9) filters every line it logs.

## Blocking prerequisite P0 (controller, before the session)

**Done:** the harness is `tests/lab/l62/up_test.go` (`make lab-l62-up`), on branch
`test/l62-session`. L62 needs `port49 login --oidc`, so it needs an identity provider and a
broker that issues certificates; the L60 and L56 harnesses don't fit (no OIDC; vEOS and a
torn-down stack). Gated by `PORT49_L62_UP=1`, it:

- brings up compose project `port49labl62`: the lab Keycloak (`tests/lab/oidc`, realm
  `port49-lab`, `port49-cli` redirect `http://127.0.0.1:18749/callback`) on `127.0.0.1:18443`,
  and `port49-broker` on `127.0.0.1:8449` (its certificate names IP `127.0.0.1`) with
  `broker.identity.issuance: {certificate_lifetime: 24h}`, the realm as its provider, and its
  CA made by `init-issuer`;
- keeps the PKI and the broker's state in `~rwendt/.cache/port49-l62/` and reuses them on the
  next run. A certificate issued before the reboot then stays valid after it.
  `PORT49_L62_FRESH=1` starts over. The lab PKI lasts 24h: a kept state is reused only with at
  least 6h of validity left, otherwise it starts over with a new issuing CA;
- writes `broker-ca.pem` and `oidc-ca.pem` (public certificates) there, and the broker log,
  filtered, as `broker.log`;
- prints `L62 UP` and the issuing CA's status (`reused (already there)`, or `NEW: certificates
  issued before are no longer valid`), holds until Enter, then stops the stack (keeping its
  volumes);
- refuses to start if 8449 or 18443 is held by anything else;
- never opens a TPM and never runs `port49 login`.

It was run once with no one present (2026-10-15): broker and Keycloak answered, and a second
start reused the kept CA.

## Part A: SER8 prerequisites (about 20 min)

A1. **Tools:** `sudo apt install -y tpm2-tools nfs-kernel-server`. swtpm, tcpdump, ykman and
Docker are already installed.

A2. **The lab user, in `tss`.** Use a dedicated user, so that adding someone to `tss` does not
give your own account (and any agent running as you) access to the TPM:

```
sudo useradd -m -s /bin/bash -G tss p49lab
sudo install -d -o p49lab -g p49lab -m 700 /home/p49lab/.port49
```

A3. **The control user, not in `tss`:** `sudo useradd -m -s /bin/bash p49notss`

A4. **pcscd for `p49lab`** (step 6 only). Find the polkit rule that lets `rwendt` reach pcscd
(`sudo grep -rl pcsc /etc/polkit-1/rules.d`; the directory is unreadable to `rwendt`, so a
`*` glob would expand before `sudo` and find nothing) and add `p49lab` to it the same way. Check it:
`sudo -iu p49lab ykman piv info | grep 'PIN tries'`.

A5. **Build.** As `rwendt`, in the session worktree (`cd ~/git/port49/.worktrees/l62-session`,
branch `test/l62-session`; every later `go test` and `make` runs here too):

```
make build-client && sudo install -m 755 bin/port49-client /usr/local/bin/port49-l62
git rev-parse --short HEAD     # note it for the results
```

A6. **Keycloak's name:** `echo '127.0.0.1 keycloak.port49.lab' | sudo tee -a /etc/hosts`

A7. **Your browser.** On your workstation, add `127.0.0.1 keycloak.port49.lab` to its hosts
file. Then keep this running for the whole session:

```
ssh -N -L 18443:127.0.0.1:18443 -L 18749:127.0.0.1:18749 rwendt@beehive
```

Keycloak's redirect then lands on whichever `port49 login` is waiting on beehive's
`127.0.0.1:18749`. The second host uses the host network, so this covers it too. Accept the lab
CA's certificate warning once. If a redirect page fails to load, copy its address into port49's
paste prompt (input is hidden). Sign in as `alice`. The password is in
`tests/lab/oidc/keycloak/realm.json` (lab-only); type it only into the browser.

A8. **Start the stack** (as `rwendt`, in its own tmux pane, which must be a real terminal; it
stays up). This first start of the session is fresh, so step 1's certificate can't be
invalidated by a CA remade at the reboot:

```
PORT49_L62_FRESH=1 PORT49_L62_UP=1 go test -tags lab ./tests/lab/l62/ -run '^TestL62Up$' -count=1 -v -timeout 10h
```

It reads Enter from `/dev/tty`. Run in the background, Enter does nothing, and only Ctrl-C
(SIGINT/SIGTERM) stops it. Check that its output says `issuing CA: NEW` this time.

Then set up `p49lab`'s local config. It is per host and lives outside the shared home:

```
sudo install -d -m 755 /var/lib/port49-l62
sudo install -d -o p49lab -g p49lab -m 700 /var/lib/port49-l62/ser8 /var/lib/port49-l62/host2
for d in ser8 host2; do sudo install -o p49lab -g p49lab -m 600 \
  ~rwendt/.cache/port49-l62/broker-ca.pem ~rwendt/.cache/port49-l62/oidc-ca.pem /var/lib/port49-l62/$d/; done
sudo install -d -m 1777 /var/tmp/port49-l62
```

Write three configs into each of `/var/lib/port49-l62/{ser8,host2}/`, owned by `p49lab` and
mode 0600. Relative paths resolve against the file's own directory:

```
# config-tpm.yaml
broker: https://127.0.0.1:8449
broker_ca: broker-ca.pem
method: oidc
oidc_ca: oidc-ca.pem
oidc_redirect_port: 18749
issued_key_store: tpm
```

`config-file.yaml` is the same with `issued_key_store: file`. `config-pkcs11.yaml` (ser8 only)
is the same with:

```
issued_key_store: pkcs11
issued_key: "pkcs11:id=%04?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"
```

That is slot 9e's key (CKA_ID 0x04, per `L60-ser8.md` (c)). port49 writes nothing to the token.

A9. **The helpers.** Paste these into every shell you use (`p49lab`'s, and `rwendt`'s for the
second host). `o` runs a command, shows you everything, and appends a filtered copy to
`/var/tmp/port49-l62/obs-<user>-<host>.log`:

```
o() { local log=/var/tmp/port49-l62/obs-$(id -un)-$(hostname -s).log
  echo "## $(date -u +%FT%TZ) \$ $*" >>"$log"
  ( set -o pipefail; "$@" 2>&1 | tee >(grep --line-buffered -v -i \
      'password\|token\|secret\|eyJ\|code=\|state=\|code_challenge' >>"$log") )
  local rc=$?; echo "## exit $rc" | tee -a "$log"; }
P=/usr/local/bin/port49-l62; B=127.0.0.1_8449; I=/home/p49lab/.port49/issued
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
```

In `p49lab`'s shell (`sudo -iu p49lab`) also set:

```
export PORT49_CONFIG=/var/lib/port49-l62/ser8/config-tpm.yaml
M=$(sha256sum /etc/machine-id | cut -c1-8)
```

Each login prints `(agent pid N, log PATH)`. Note N; "stop the agent" below means `kill N`.

## Step 0: record the platform (5 min)

As `p49lab`. In a second terminal, as `rwendt`, start the capture and leave it running until
step 3a ends. The controller reads the TLS version from it:

```
sudo tcpdump -i lo -U -w /var/tmp/port49-l62/L62-ser8-tls.pcap 'tcp port 8449'
```

(If AppArmor refuses that path, write to `/tmp/L62-ser8-tls.pcap` and say so.)

```
o id
o ls -l /dev/tpmrm0
o uname -r
o sh -c "tpm2_getcap properties-fixed | grep -A3 -E 'TPM2_PT_(FAMILY_INDICATOR|REVISION|MANUFACTURER|VENDOR_STRING_[1-4]|FIRMWARE_VERSION_[12])'"
o cat /sys/class/tpm/tpm0/tpm_version_major /sys/class/tpm/tpm0/device/description /sys/class/tpm/tpm0/device/hid
o tpm2_getcap handles-persistent
o echo "machine $M"
```

**Pass:** `id` lists `tss`. `/dev/tpmrm0` is `crw-rw---- tss tss`. `tpm2_getcap` answers. The
manufacturer, vendor strings and firmware version are in the log. Keep the persistent-handle
list; steps 1 and 3 compare against it.

## Step 1: the key is created under the ECC SRK (5 min)

```
o $P login --oidc --no-browser
```

Sign in once in the browser.

**Pass:**
- exit 0;
- `no TPM key for this machine yet`, then exactly one `open this address … sign in at`;
- `signed in at … as …`, then `logged in to https://127.0.0.1:8449 …(agent pid N, …)`;
- no `the key is a file`.

```
o ls -ln $I
o head -1 $I/$B.$M.tpmkey
o sh -c "openssl asn1parse -in $I/$B.$M.tpmkey | grep -E 'OBJECT|BOOLEAN|INTEGER'"
o sh -c "openssl x509 -in $I/$B.$M.pem -noout -subject -enddate; openssl x509 -in $I/$B.$M.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum"
o tpm2_getcap handles-persistent
o sha256sum $I/$B.$M.tpmkey $I/$B.$M.pem
```

**Pass:**
- `$B.$M.tpmkey` and `$B.$M.pem` exist, mode 0600, owned by `p49lab`. There is no `$B.pem` or
  `$B.key`.
- The header reads `-----BEGIN TSS2 PRIVATE KEY-----`.
- asn1parse gives `OBJECT :2.23.133.10.1.3` (a loadable key), `BOOLEAN` true (emptyAuth) and
  `INTEGER :40000001` (the parent is the owner hierarchy's SRK).
- The persistent handles are unchanged: the SRK is made at each open and never persisted.

That the agent started at all shows the real TPM loaded the key under port49's
`ECCSRKTemplate` SRK. A key under any other parent fails `TPM2_Load`. No tpm2-tools command
rebuilds that exact SRK reliably (its `unique` field is not tpm2-tools' default), so this step
does not try. The `grep` prints no octet string, so no key blob reaches the log.

## Step 2: it signs a TLS 1.3 handshake and a refresh (3 min)

```
o $P refresh
o $P identity
o sh -c "grep -v -i 'password\|token\|secret\|eyJ' LOG | tail -20"
```

`LOG` is the `log PATH` that step 1's login printed.

**Pass:** `refresh` exits 0 with `refreshed at …`, and `identity` exits 0 naming alice. The agent
log shows no TPM error. The agent and the broker both require TLS 1.3 at minimum, and the refresh
signs the TLS exporter of that session, so a refresh that succeeds was signed by the TPM key
inside a TLS 1.3 session. The pcap from step 0 lets the controller confirm the ServerHello's
`supported_versions` is 0x0304.

## Step 3: it survives an agent restart and a reboot (15 min, including the reboot)

**3a, the agent restart:**

```
kill N
o $P login --oidc --no-browser
o $P refresh
o sha256sum $I/$B.$M.tpmkey $I/$B.$M.pem
```

**Pass:**
- `using your certificate for … (signed in at … at …), valid until …`, then `logged in to …`;
- no `open this address` line, and no browser;
- the refresh exits 0;
- both hashes equal step 1's.

Now stop the tcpdump (Ctrl-C).

**3b, the reboot:** `sudo reboot`. Once the SER8 is back up:
1. As `rwendt`, re-run A8's harness command. It reuses its state; wait for `L62 UP`.
2. Restart A7's ssh tunnel.
3. In a new `p49lab` shell, re-paste A9.

```
o $P login --oidc --no-browser
o $P refresh
o sha256sum $I/$B.$M.tpmkey $I/$B.$M.pem
o tpm2_getcap handles-persistent
```

**Pass:** the same as 3a, and the persistent handles are still step 0's list.

`login` refreshes as it connects, so a `refresh` straight after it (3a and 3b) may get
`refresh_too_soon` (`retry in 10s`). That is the broker's spacing, not the TPM: wait 10s and rerun.

## Part B: the second host (about 20 min, after the reboot)

There is **no second machine with a real TPM**. The nearest honest stand-in is a container on
the SER8 with its own swtpm (through the kernel's `tpm_vtpm_proxy`, so it gets its own
resource manager), its own `/etc/machine-id`, and `p49lab`'s `~/.port49` mounted over NFS.
port49 tells hosts apart only by `/etc/machine-id` and by which TPM answers `/dev/tpmrm0`, and
both differ here. What the stand-in does not have is its own kernel or a separate box.

As `rwendt`:

```
sudo modprobe tpm_vtpm_proxy
sudo install -d -m 700 /var/lib/swtpm/port49-l62      # swtpm's AppArmor profile allows only /var/lib/swtpm/
ls /dev/tpmrm*                                     # before
S=/var/lib/swtpm/port49-l62
sudo swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir=$S --daemon --pid file=$S/pid --log file=$S/log
ls -l /dev/tpmrm*                                  # a new /dev/tpmrm1, group tss
# if it is not tss 0660: sudo chgrp tss /dev/tpmrm1 && sudo chmod 660 /dev/tpmrm1
systemd-id128 new | sudo install -o p49lab -m 444 /dev/stdin /var/lib/port49-l62/host2/machine-id

sudo install -d -m 755 /etc/exports.d                # absent on a fresh Ubuntu 26.04
echo '/home/p49lab/.port49 127.0.0.1(rw,sync,no_subtree_check)' | sudo tee /etc/exports.d/port49-l62.exports
sudo exportfs -ra
sudo install -d /mnt/l62-port49 && sudo mount -t nfs -o vers=4.2 127.0.0.1:/home/p49lab/.port49 /mnt/l62-port49
ls -lnd /mnt/l62-port49                            # p49lab's uid, drwx------

U=$(id -u p49lab); G=$(id -g p49lab); T=$(getent group tss | cut -d: -f3)
docker run -d --init --name l62host2 --network host --user $U:$G --group-add $T \
  --device /dev/tpmrm1:/dev/tpmrm0 --add-host keycloak.port49.lab:127.0.0.1 \
  --tmpfs /home/p49lab:uid=$U,gid=$G,mode=0700 \
  -v /mnt/l62-port49:/home/p49lab/.port49 -v /var/lib/port49-l62/host2:/cfg \
  -v /var/lib/port49-l62/host2/machine-id:/etc/machine-id:ro \
  -v /usr/local/bin/port49-l62:/usr/local/bin/port49-l62:ro \
  -e HOME=/home/p49lab -e PORT49_CONFIG=/cfg/config-tpm.yaml ubuntu:24.04 sleep infinity

h2x() { docker exec -it l62host2 "$@"; }; h2() { h2x /usr/local/bin/port49-l62 "$@"; }
M=$(sha256sum /etc/machine-id | cut -c1-8)
M2=$(sha256sum /var/lib/port49-l62/host2/machine-id | cut -c1-8)
o echo "ser8 $M host2 $M2 swtpm $(swtpm --version | head -1)"
```

**Gate:** `$M` and `$M2` differ. If they are equal, stop: the shared-home steps would prove
nothing.

## Step 4: shared home: each host keeps its own `.tpmkey` (10 min)

Clause: each host's `port49 login --oidc` keeps its own `<host>_<port>.<machine>.tpmkey`, reads
the other's as no held pair, and overwrites neither.

As `rwendt`:

```
o h2 login --oidc --no-browser
```

Sign in once. **Pass:**
- `no TPM key for this machine yet` (the SER8's pair was not taken as held);
- one sign-in, then `logged in to …`, exit 0;
- no `your held certificate is not used`.

As `p49lab`:

```
o ls -ln $I
o sha256sum $I/$B.*
```

**Pass:** `$B.$M.{pem,tpmkey}` and `$B.$M2.{pem,tpmkey}` are both there, and the `$M` pair's
hashes equal step 3's.

Log in again on each host, with no sign-in. On the SER8: `kill N`, then
`o $P login --oidc --no-browser`. On host2: `o h2x kill N2`, then
`o h2 login --oidc --no-browser`. N2 is the pid host2's login printed (the container's pid
namespace). Then, as `p49lab`, `o sha256sum $I/$B.*`.

**Pass:** each login prints `using your certificate`, with no `open this address`. All four
hashes are unchanged.

## Step 5: the key file is refused on another machine (5 min)

The SER8's real-TPM key, offered to host2's TPM. As `rwendt`:

```
PORT49_TEST_AGENT_SOCKET=/tmp/l62-foreign.sock o h2 login --key "tpm:file=/home/p49lab/.port49/issued/$B.$M.tpmkey" --cert /home/p49lab/.port49/issued/$B.$M.pem
```

host2's swtpm key, offered to the SER8's real TPM. As `p49lab`:

```
PORT49_TEST_AGENT_SOCKET=/tmp/l62-foreign.sock o $P login --key "tpm:file=$I/$B.$M2.tpmkey" --cert $I/$B.$M2.pem
o sha256sum $I/$B.*
```

**Pass:** both exit non-zero with `this key file was made by another TPM, or this machine's TPM
was cleared since it was made`. No agent starts, and every hash is unchanged.

The second command is the measurement on real firmware: the SER8's TPM refusing a foreign key
file at `TPM2_Load`. The first shows the SER8's file is no use to a different TPM, but that TPM
is swtpm. If any other Linux machine of yours has a real TPM, copy those two files to it
(`install -m 600`) and run the same command there. That closes this clause on real firmware in
both directions.

## Step 6: shared home: a token host and a file host (15 min)

The SER8 is the token host (YubiKey, slot 9e) and host2 is the file host. First stop both TPM
agents: `kill N` on the SER8 and `h2x kill N2`. Then, as `p49lab`:

```
o sh -c "ykman piv info | grep -E 'Slot|Fingerprint|PIN tries'"
o env PORT49_CONFIG=/var/lib/port49-l62/ser8/config-pkcs11.yaml $P login --oidc --no-browser
```

Type the PIN at port49's prompt, then sign in once. **Pass:** the PIN is asked once, there is
one sign-in, exit 0, and a new `$B.<8 hex>.pem` appears with no new key file.

As `rwendt`:

```
o h2x env PORT49_CONFIG=/cfg/config-file.yaml /usr/local/bin/port49-l62 login --oidc --no-browser
```

Sign in once. **Pass:** one sign-in, exit 0, and `$B.pem` and `$B.key` appear (0600).

Log in again on each host, with no sign-in. Stop both agents, then run the same two logins
again. As `p49lab`:

```
o sha256sum $I/$B.*
o sh -c "ykman piv info | grep -E 'Slot|Fingerprint|PIN tries'"
```

**Pass:**
- Both second logins print `using your certificate`, with no `open this address`. The token
  host asks the PIN once.
- The token certificate's hash is unchanged since its first login, and so are `$B.pem` and
  `$B.key`, and both TPM pairs since step 5.
- The `ykman` slot list and fingerprints match the first run. Nothing was written to the token,
  which is also L60 cell (g)'s claim.

## Step 7: the control: a user outside `tss` is refused, naming the group (3 min)

As `rwendt`:

```
sudo install -d -o p49notss -g p49notss -m 700 /var/lib/port49-l62/notss
sudo install -o p49notss -g p49notss -m 600 /var/lib/port49-l62/ser8/config-tpm.yaml \
  /var/lib/port49-l62/ser8/broker-ca.pem /var/lib/port49-l62/ser8/oidc-ca.pem /var/lib/port49-l62/notss/
o id p49notss
o sudo -iu p49notss env PORT49_CONFIG=/var/lib/port49-l62/notss/config-tpm.yaml /usr/local/bin/port49-l62 login --oidc --no-browser
```

**Pass:**
- `id` shows no `tss`;
- exit 1 with `issued_key_store is tpm, and port49 cannot open the TPM (/dev/tpmrm0): add this
  user to the tss group, then log in again`;
- no `open this address` line. The refusal comes before any sign-in, so it costs no password.

The control is valid only because step 0 showed `/dev/tpmrm0` at `tss` 0660.

## What to paste back

The controller runs on beehive and reads `/var/tmp/port49-l62/obs-*.log` and
`L62-ser8-tls.pcap` itself, so you do not paste the logs. Paste only:

1. One line per step: `step N: pass` or `fail`. For a fail, add what you saw.
2. For each login, whether the browser was used (`signed in` / `no browser`). This is
   a cross-check on the log's `open this address` lines.
3. The port49 commit from A5.
4. Anything the logs cannot show: a prompt you didn't expect, a browser error, the pcap path if
   it changed.

If the controller cannot read the logs, paste `tail -60` of each `obs-*.log`. They are already
filtered.

From those the controller writes `tests/lab/results/L62-ser8.md`, with:
- the platform (beehive, Ubuntu 26.04.1, the kernel);
- the TPM's manufacturer, vendor strings and firmware version, from step 0;
- swtpm's version for the stand-in;
- Keycloak's version and the commit;
- the observation per clause;
- the capture pointer: the obs logs and the pcap.

**Closing (CLAUDE.md rule 3).** Step 5's forward direction and steps 4 and 6 ran against a
container with swtpm, not against a second box with real firmware. The note must say so. If
Ryan rules that the reverse direction on real firmware plus the container stand-in measures
the row as written, it closes. Otherwise the row stays open for step 5's forward direction on a
second real TPM. (Ryan ruled on 2026-10-15 that it closes.)

## Cleanup (5 min, after the controller confirms the note)

As `rwendt`:
- `docker rm -f l62host2`, `sudo umount /mnt/l62-port49`,
  `sudo rm /etc/exports.d/port49-l62.exports && sudo exportfs -ra`;
- `sudo kill $(sudo cat /var/lib/swtpm/port49-l62/pid)`, `sudo rm -rf /var/lib/swtpm/port49-l62`, `sudo modprobe -r tpm_vtpm_proxy`;
- press Enter in the harness pane, then remove what it kept:
  `docker compose -p port49labl62 down -v`, `rm -rf ~/.cache/port49-l62`,
  `docker rmi port49-l62:dev port49-l62-setup:dev`;
- remove the `keycloak.port49.lab` line from `/etc/hosts` and from the workstation's hosts file.

Then, as `p49lab`, stop the agent (`kill N`), and delete the users and files:

```
sudo userdel -r p49lab
sudo userdel -r p49notss
sudo rm -rf /var/lib/port49-l62 /usr/local/bin/port49-l62
```

Deleting `p49lab` deletes its TPM key files with it.

## Your time

About **2 hours**:

| Part | Time |
|---|---|
| Part A | 20 min |
| Steps 0–3, including the reboot | 30 min |
| Part B | 20 min |
| Steps 4–7 | 35 min |
| Paste-back and cleanup | 10 min |

You sign in in the browser 4 times. You type the PIN twice.
