# L91 runbook: `port49 hwkey status` and `setup` on a real YubiKey

Spec §15 L91, on the SER8 with the YubiKey 5 plugged in, slots 9a and 9c made as the L86 runbook made them (9a
PIN once and touch never, 9c PIN once and touch **always**). About 10 minutes, from your own terminal at the repo
root. The harness is `tests/lab/l60/l91_test.go`; it drives only `port49`. **Row L91 stays open until this has
run and the lead has read the note and edited spec §15** (TODO(L91)).

`port49 hwkey` is read-only on the token: it asks for no PIN, signs nothing and writes no object. The one
write in the run is to the config in the run's own temporary HOME. Nothing below prints a PIN or a serial (a
serial is masked).

**Agents never run any command marked "Ryan types this".** Agents run no `ykman`, `pkcs11-tool` or `tpm2_*`.

## What the cells check

| Cell | Check | PASS iff |
|---|---|---|
| (a) | `status` before setup, with no `issued_key` or `touch_key` in the config | exit 1; the config checks FAIL and the slot checks pass; no PIN asked; no serial printed |
| (b) | `setup` | exit 0; only `issued_key` and `touch_key` change in the config; `ykman piv info` (you type it) reads the same before and after |
| (c) | whether libykcs11 lists a slot's key with no certificate in it | an observation; "no such slot" if your token has none |
| (d) | `status` after setup, with an agent logged in | exit 0 and the agent check reads `touch_key: true` |
| (e) | `status --json` | the keys are snake_case; neither the serial nor a PIN appears |

## Setup

1. **Provisioned from L60/L86?** Slots 9a and 9c must hold the keys and certificates those runbooks made
   (`ls ~/.cache/port49-l60/` shows `client-ca.pem`, `slot9a.pem` and `yubico-piv-ca-1.pem`). If not, do
   `tests/lab/l60/RUNBOOK.md` first. This runbook never makes, resets or overwrites a slot.

2. **The firmware, operator-reported from ykman.** **Ryan types this** (read the version line; do not paste the
   serial anywhere):

   ```
   ykman info
   export PORT49_L91_FIRMWARE=5.4.3      # the version it printed, three numbers
   ```

3. **Build this branch** (about 40 s):

   ```
   git rev-parse --short HEAD            # note it: the results cite this commit
   make l86-build
   ```

4. **The shell setup**, once per terminal:

   ```
   export PORT49_L91=1 PORT49_L86_BIN=$PWD/bin/l86/port49
   ```

   The run serves its own broker in-process, with Yubico's PIV root as the attestation roots, and takes the lab
   lock `/tmp/port49-lab.lock` itself. If it says `INVALID: the lab is occupied`, stop: someone else holds it.
   Never kill them. Before each cell it looks for `/tmp/port49-STOP-LAB`; if that file is there it ends the run
   cleanly.

## The run

5. Run all five cells in order (about 10 minutes):

   ```
   bin/l86/l60.test -test.run '^TestL91$' -test.count=1 -test.v -test.timeout 20m
   ```

   - **(a)** nothing to do; it prints the status output.
   - **(b)** it stops twice and asks you to run `ykman piv info` in **another terminal**. **Ryan types this**
     (before `setup`, then after it):

     ```
     ykman piv info > /tmp/l91-before.txt
     ykman piv info > /tmp/l91-after.txt && cmp /tmp/l91-before.txt /tmp/l91-after.txt && echo SAME
     rm /tmp/l91-before.txt /tmp/l91-after.txt
     ```

     Answer "Did cmp print nothing and your terminal say SAME?" with `1` or `0`. The harness records only that
     number, never the listings.
   - **(c)** it asks whether slot 9e holds a key but no certificate. Answer `0` if you do not know.
   - **(d)** it logs in with the token's keys: type your PIN at port49's own `PIN for ...:` prompt, then answer
     "How many times did port49 ask for the PIN?" with the true number. `status` then reads the agent.
   - **(e)** nothing to do.

   Each cell ends with a line `L91 all cell_<x>_verdict: PASS: ...` or `FAIL: ...`, and the run writes
   `tests/lab/results/L91-ser8.md` (masked) when it reaches the end.

## Clean-up and handing back

6. The run stops the agents it started by pid and restores the terminal, also when killed (Ctrl-C, or the
   `-test.timeout` 45 s before it fires). After a `kill -9` or a lost terminal, **Ryan types this**:

   ```
   stty sane
   pgrep -u "$USER" -af 'port49 agent'      # read the pids
   kill <pid>                               # each one, by pid, never by pattern
   ```

   Then:

   ```
   unset PORT49_L91 PORT49_L86_BIN PORT49_L91_FIRMWARE
   rm -rf bin/l86
   ```

7. **Hand the note back:** tell the lead the path `tests/lab/results/L91-ser8.md` (it holds observations and
   verdicts only: no PIN, no token, no serial). The lead edits spec §15's row; cell (b)'s `ykman` answer is your
   own yes or no.
