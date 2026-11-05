# L86 runbook: an admin call's touch on a real YubiKey

Spec §15 L86, on the SER8 with the YubiKey 5 plugged in. About 15 to 20 minutes (cell (c) also starts
the lab's Keycloak, a minute or three the first time), run from your own terminal at the repo root. Each cell prints numbered steps, says when to type, touch or pull, and fails by a
deadline rather than hanging. The harness is `tests/lab/l60/l86_test.go`; it drives only `port49`.

Your PIN goes only to port49's own `PIN for ...:` prompt. It is never typed into a chat, on a command
line or into an environment variable. ykman asks for its own management key at its own prompt. The lab
user's password goes only into Keycloak's form in your browser. Nothing below prints a PIN, a password,
a serial or a token.

**Agents never run any command marked "Ryan types this".** Agents run no `ykman`, `pkcs11-tool` or `tpm2_*`.

## What the cells check

| Cell | Check | PASS iff |
|---|---|---|
| (a) | Two admin calls 5 s apart, touch policy `always` | each call needs its own touch; the untouched second fails with the timeout words |
| (b) | No touch at all | the CLI prints the timeout line, exits 1, and `port49 revoke --list` shows no mark |
| (c) | The real OIDC path: `port49 login --oidc` against the lab's Keycloak with `issued_key_store: pkcs11` (the session key is the one in slot 9e), then an admin call with the touch key (9c) | the certificate was issued for the sign-in, and the admin call succeeds with one touch |
| (d) | The key unplugged with the agent running | the CLI says to insert the key, nothing is sent, and the broker's log has no `admin_touch_refused` |

Cell (c) is the row's own cell: an OIDC-issued session key in the token's slot, L60's open issued-key cell
(g) (plan 9e). A lab-CA certificate imported into 9e is only a proxy: `TestL86C9eFallback` runs it (see
"If Keycloak cannot be had"), and its result is recorded as "proxy, does not close (c)".

The firmware in the results is "operator-reported from ykman": you type it (step 3) because port49 does not
read it, and the observation line says so.

## Setup

1. **Already provisioned from L60?** If `ls ~/.cache/port49-l60/` shows `client-ca.pem`,
   `slot9a.pem` and `yubico-piv-ca-1.pem`, and slot 9a holds that certificate, skip to step 3.
   Otherwise do `tests/lab/l60/RUNBOOK.md` steps 0a, 1 and 2 first. (Slots 9a PIN once and touch
   never, 9c PIN once and touch **always**, 9e PIN once, were made for L60 with `ykman piv keys
   generate`.)

2. **Slot 9c is the key L60 provisioned (touch always); this runbook never makes, resets or overwrites a
   slot.** Each cell checks that 9c's key is on the token before it starts and stops with `INVALID: slot
   9c ... is not on the token` if it is not. If you see that, stop and tell the lead: do not generate a
   key to get past it. Nothing here runs `ykman piv keys generate` or `reset`; the one `ykman` write is
   the certificate import the proxy below prints for you to type.

3. **The firmware, operator-reported from ykman.** port49 does not report it. **Ryan types this**
   (read the version line; do not paste the serial anywhere):

   ```
   ykman info
   export PORT49_L86_FIRMWARE=5.4.3      # the version it printed, three numbers
   ```

4. **Build this branch.** One command, about 40 s:

   ```
   git rev-parse --short HEAD            # note it: the results cite this commit
   make l86-build
   ```

5. **The shell setup**, once per terminal:

   ```
   export PORT49_L86=1 PORT49_L86_BIN=$PWD/bin/l86/port49
   export L86_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)     # step 12 collects only what this run wrote
   l86() { bin/l86/l60.test -test.v -test.timeout 20m -test.run "^$1\$"; }
   ```

   Each cell serves its own broker in-process, with Yubico's PIV root (`yubico-piv-ca-1.pem` in the L60
   lab directory) as the attestation roots a touch is checked against, and takes the lab lock
   `/tmp/port49-lab.lock` itself. If a cell says `INVALID: the lab is occupied`, stop: someone else
   holds it. Never kill them.

6. **Cell (c)'s identity provider** (5 minutes, once). The cell brings up and takes down the lab's
   Keycloak itself, with the files the lab's own OIDC tests use: `tests/lab/oidc/compose.yaml`, compose
   project `port49laboidc`, the realm `tests/lab/oidc/keycloak/realm.json` (`make lab-oidc` and `make
   lab-oidc-l55` bring up the same project; there is no separate command). It needs Docker as those do
   (the cell runs it under `sg docker`), port 18443 free (stop any other lab's Keycloak; the cell stops
   with `INVALID` if one answers), and the image pulled the first time: **pull it yourself now**, so the cell's `up` is quick (the cell
   gives `up` 8 minutes and stops with `INVALID` past that). **Ryan types this**:

   ```
   docker compose -p port49laboidc -f tests/lab/oidc/compose.yaml pull
   ```

   The cell makes a fresh lab CA each run
   and keeps the generated admin password in a 0600 file compose reads; it never prints it.

   Slot 9e must hold a key you made with `ykman piv keys generate` (L60's step 1 made it; the id is `04`
   unless you set `PORT49_L86_SLOT_9E_ID`). port49 writes nothing to the token. Run cell (c) **before** the
   fallback below, so 9e holds no certificate from it.

   **Ryan types this** (once per boot; Keycloak's name must resolve to this host, for port49 and for your
   browser). The line carries a marker comment so the clean-up removes only this line and never the L62
   runbook's A6 line for the same name (if A6's line is there already, the name resolves: skip this):

   ```
   echo '127.0.0.1 keycloak.port49.lab # port49-l86' | sudo tee -a /etc/hosts
   ```

   Your browser must reach `https://keycloak.port49.lab:18443` and the redirect to `http://127.0.0.1:18749`.
   On the SER8's own browser nothing more is needed. From your workstation, put the same hosts line in its
   hosts file and keep this running for the whole cell:

   ```
   ssh -N -L 18443:127.0.0.1:18443 -L 18749:127.0.0.1:18749 <user>@<lab-host>
   ```

   Each run makes a new lab CA, so your browser warns once about the certificate: accept it.

   Sign in as `alice`. Her password is in `tests/lab/oidc/keycloak/realm.json` (lab-only): read it
   there and type it only into the browser's form, never into a chat or onto a command line. The
   broker takes her verified email, `alice@corp.example.com`, as the principal.

## The cells

Cells (a), (b) and (d) start with `[... 1] port49 login`: type your PIN at port49's prompt, then answer
"How many times did port49 ask for the PIN?" with `1`. Cell (c) starts with the browser sign-in (step 9). Each ends with a line `L86 <cell> verdict: PASS: ...` or
`FAIL: ...`.

7. **(a)** about 3 minutes:

   ```
   l86 TestL86A
   ```

   - Call 1: **touch** the key when it blinks.
   - The harness waits 5 s. Call 2: **do not touch**. Watch the key. It fails after about 15 s. Answer
     "Did the key blink again?" with `1` (it did) or `0` (it did not).
   - Call 3: **touch** the key when it blinks.

8. **(b)** about 2 minutes:

   ```
   l86 TestL86B
   ```

   - **Do not touch.** It fails after about 15 s with the timeout line, exit 1. The harness then runs
     `port49 revoke --list` and checks it shows no mark.

9. **(c)** about 6 minutes (the first Keycloak start imports the realm, up to 90 s more):

   ```
   l86 TestL86C
   ```

   - It starts Keycloak and the broker, then runs `port49 login --oidc --no-browser`. port49 prints an
     address on its own line: open it in your browser, sign in as `alice`, and wait for the page that
     says the sign-in is done.
   - port49 then asks for your PIN (the key in slot 9e signs the certificate request): type it at its
     prompt. Answer "How many times did port49 ask for the PIN?" with the true number.
   - **Touch once** when the key blinks for the admin call. Answer "How many times did you touch the
     key?" with the true number (a second touch makes it FAIL on purpose).
   - PASS needs the login to say a certificate was issued for the sign-in, the broker's log to hold a
     permitted `issue` record (the cell reads the event and verdict only), and the call to succeed with
     one touch. At the end it takes Keycloak down (`docker compose down -v`).

10. **(d)** about 3 minutes:

    ```
    l86 TestL86D
    ```

    - After login it says to pull the key. **Pull it out**, press Enter. The call fails at once with
      "agent: insert your key".
    - **Put it back**, press Enter.

## If Keycloak cannot be had

The proxy for (c), a lab-CA certificate in slot 9e with no OIDC and no issuance, measures only the admin
path's half. It does not close (c), and its result says "proxy, does not close (c)". It writes nothing to
the key and asks for no PIN; it makes the certificate for slot 9e's public key and prints the import command:

```
PORT49_L86_PREP=1 l86 TestL86Prep9e
```

**Ryan types this** (the command it prints, with its path):

```
ykman piv certificates import 9e ~/.cache/port49-l60/slot9e.pem
```

If it says it cannot open slot 9e, the slot's PKCS#11 id on this libykcs11 is not `04`: set
`export PORT49_L86_SLOT_9E_ID=<id>` (the id libykcs11 lists for 9e) and run it again. Then:

```
l86 TestL86C9eFallback
```

**Touch once** when it blinks and answer the count. If you ran this, tell the lead before cell (c)
is run: 9e then holds that certificate.

## Clean-up and handing back

11. When a cell ends normally or fails on an assertion, it stops every agent it started by its pid,
    restores the terminal and takes its Keycloak down. When it is **killed** (Ctrl-C, a `kill`, or the
    `-test.timeout` 45 s before it fires), the harness catches SIGINT, SIGTERM and that deadline and
    does the same, then releases the lab lock and exits 2 with `L86 cell ...: ... cleaning up`. A
    `kill -9`, a power loss or a lost terminal skips it: do the next block.

    **If a cell was killed** (**Ryan types this**; nothing here is guessed for you):

    ```
    stty sane                                              # the terminal, if it is raw or echo is off
    pgrep -u "$USER" -af 'port49 agent'                    # the PIN-unlocked agents; read the pids
    kill <pid>                                             # each one, by pid, never by pattern
    docker compose -p port49laboidc -f tests/lab/oidc/compose.yaml down -v
    ```

    The lab lock (`/tmp/port49-lab.lock`) lets go when the process dies; if the next cell says the lab
    is occupied, `cat /tmp/port49-lab.lock` names the holder, and a holder that is not alive is stale.

    Then remove this runbook's hosts line (the marker keeps it away from any other line), confirm the key
    is back in, and:

    ```
    sudo sed -i '/ # port49-l86$/d' /etc/hosts
    unset PORT49_L86 PORT49_L86_BIN PORT49_L86_PREP PORT49_L86_FIRMWARE PORT49_L86_SLOT_9E_ID L86_START
    rm -rf bin/l86
    ```

12. **Hand the results back.** The lead writes `tests/lab/results/L86-ser8.md` from these lines. They
    hold no PIN, no token and no serial (a serial is masked). Collect them and tell the lead the path:

    ```
    awk -v s="$L86_START" '$1 >= s && / L86 /' ~/.cache/port49-l60/observations.log > ~/.cache/port49-l60/L86-observations.txt
    grep -c verdict ~/.cache/port49-l60/L86-observations.txt   # one per cell run since L86_START: a, b, c, d (5 with the proxy)
    ```

    Only lines since `L86_START` (step 5) are taken, so an earlier attempt's or a killed cell's old lines
    are left out. A cell you ran twice in this run has two verdicts: the later one is the cell's, and
    the lead reads them in order. A killed cell writes `L86 <cell> killed: ...` and no verdict.

    The firmware line reads `firmware_operator_reported_from_ykman`: it is yours, not the harness's.
    The broker's decision log for each cell stays in `~/.cache/port49-l60/decisions-<cell>.jsonl`
    (event names, never a token or a challenge). If a cell stopped early, what it saw before stopping is
    already in `observations.log`.
