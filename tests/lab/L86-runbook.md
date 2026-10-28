# L86 runbook: an admin call's touch on a real YubiKey

Spec §15 L86, on the SER8 with the YubiKey 5 plugged in. About 15 minutes, run from your own terminal
at the repo root. Each cell prints numbered steps, says when to type, touch or pull, and fails by a
deadline rather than hanging. The harness is `tests/lab/l60/l86_test.go`; it drives only `port49`.

Your PIN goes only to port49's own `PIN for ...:` prompt. It is never typed into a chat, on a command
line or into an environment variable. ykman asks for its own management key at its own prompt. Nothing
below prints a PIN, a serial or a token.

**Agents never run any command marked "Ryan types this".** Agents run no `ykman`, `pkcs11-tool` or `tpm2_*`.

## What the cells check

| Cell | Check | PASS iff |
|---|---|---|
| (a) | Two admin calls 5 s apart, touch policy `always` | each call needs its own touch; the untouched second fails with the timeout words |
| (b) | No touch at all | the CLI prints the timeout line, exits 1, and `port49 revoke --list` shows no mark |
| (c) | A session key in slot 9e beside the touch key (9c) | the admin call succeeds with one touch |
| (d) | The key unplugged with the agent running | the CLI says to insert the key, nothing is sent, and the broker's log has no `admin_touch_refused` |

Cell (c) measures the admin path's half of the register row: a session key that is not 9a, on the same
token as the touch key. The OIDC sign-in that would issue that key is L60 cell (g) and plan 9e, and is
not exercised here. The note will say so.

## Setup

1. **Already provisioned from L60?** If `ls ~/.cache/port49-l60/` shows `client-ca.pem`,
   `slot9a.pem` and `yubico-piv-ca-1.pem`, and slot 9a holds that certificate, skip to step 3.
   Otherwise do `tests/lab/l60/RUNBOOK.md` steps 0a, 1 and 2 first. (Slots 9a PIN once and touch
   never, 9c PIN once and touch **always**, 9e PIN once, were made for L60 with `ykman piv keys
   generate`.)

2. **Only if slot 9c is not touch-always** (check: L60's note says it is; skip otherwise).
   **Ryan types this; agents never run it.** ykman asks for the management key at its own prompt:

   ```
   ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy ALWAYS 9c ~/.cache/port49-l60/pub-9c.pem
   ```

3. **The firmware, in your own words.** port49 does not report it. **Ryan types this**
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
   l86() { bin/l86/l60.test -test.v -test.timeout 20m -test.run "^$1\$"; }
   ```

   Each cell serves its own broker in-process, with Yubico's PIV root (`yubico-piv-ca-1.pem` in the L60
   lab directory) as the attestation roots a touch is checked against, and takes the lab lock
   `/tmp/port49-lab.lock` itself. If a cell says `INVALID: the lab is occupied`, stop: someone else
   holds it. Never kill them.

6. **Cell (c)'s certificate** (1 minute). It writes nothing to the key and asks for no PIN; it makes the
   certificate for slot 9e's public key and prints the import command:

   ```
   PORT49_L86_PREP=1 l86 TestL86Prep9e
   ```

   **Ryan types this** (the command it prints, with its path):

   ```
   ykman piv certificates import 9e ~/.cache/port49-l60/slot9e.pem
   ```

   If it says it cannot open slot 9e, the slot's PKCS#11 id on this libykcs11 is not `04`: set
   `export PORT49_L86_SLOT_9E_ID=<id>` (the id libykcs11 lists for 9e) and run it again.

## The cells

Every cell starts with `[... 1] port49 login`: type your PIN at port49's prompt, then answer "How many
times did port49 ask for the PIN?" with `1`. Each ends with a line `L86 <cell> verdict: PASS: ...` or
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

9. **(c)** about 2 minutes:

   ```
   l86 TestL86C
   ```

   - **Touch once** when it blinks. Answer "How many times did you touch the key?" with `1` (type the true
     number: a second touch makes it FAIL on purpose).

10. **(d)** about 3 minutes:

    ```
    l86 TestL86D
    ```

    - After login it says to pull the key. **Pull it out**, press Enter. The call fails at once with
      "agent: insert your key".
    - **Put it back**, press Enter.

## Clean-up and handing back

11. Every agent a cell started is stopped by its pid when the cell ends. Confirm the key is back in and:

    ```
    unset PORT49_L86 PORT49_L86_BIN PORT49_L86_PREP PORT49_L86_FIRMWARE PORT49_L86_SLOT_9E_ID
    rm -rf bin/l86
    ```

12. **Hand the results back.** The lead writes `tests/lab/results/L86-ser8.md` from these lines. They
    hold no PIN, no token and no serial (a serial is masked). Collect them and tell the lead the path:

    ```
    grep ' L86 ' ~/.cache/port49-l60/observations.log > ~/.cache/port49-l60/L86-observations.txt
    grep -c verdict ~/.cache/port49-l60/L86-observations.txt     # 4 verdicts: a, b, c, d
    ```

    The broker's decision log for each cell stays in `~/.cache/port49-l60/decisions-<cell>.jsonl`
    (event names, never a token or a challenge). If a cell stopped early, what it saw before stopping is
    already in `observations.log`.
