# L60 session runbook

The rest of spec §15 L60 on the SER8, YubiKey 5C Nano FIPS plugged in. One command per
step, run in order from your own terminal, at the repo root on branch `test/l60-session`.
Each cell prints numbered steps and tells you when to type, touch or pull. Each step has a
deadline, so nothing hangs. The observations go to the test log and to
`~/.cache/port49-l60/observations.log`.

Your PIN goes only to port49's `PIN for …:` prompt or into the pin-source file you make in
step 0. ykman asks for the PUK and the management key at its own prompts. None of them is ever
typed into a chat.

Every cell runs through this zsh function. Define it once per shell:

```
l60() { CGO_ENABLED=0 go test -tags hwkey_dlopen ./tests/lab/l60/ -count=1 -v -timeout 30m -run "^$1\$"; }
```

| # | Step | Command | Takes | You |
|---|---|---|---|---|
| 0a | Lab dir and Yubico's PIV root | `mkdir -p -m 700 ~/.cache/port49-l60 && curl -fsSo ~/.cache/port49-l60/yubico-piv-ca-1.pem https://developers.yubico.com/PKI/yubico-piv-ca-1.pem` | 5s | — |
| 0b | Your pin-source file (0600, read by port49 only) | `install -m 600 /dev/null ~/.cache/port49-l60/pin && read -rs 'p?PIN: ' && printf '%s\n' "$p" >> ~/.cache/port49-l60/pin; unset p` | 10s | type your PIN (no echo) |
| 0c | Point the cells at it | `export PORT49_L60_PIN_SOURCE=~/.cache/port49-l60/pin` | — | — |
| 1 | Lab CA and the slot 9a certificate (no PIN, writes nothing to the key) | `PORT49_L60_IMPORT=1 l60 TestL60Import9a` | 1 min | — |
| 2 | Import it into 9a (default management key, no prompt expected) | `ykman piv certificates import 9a ~/.cache/port49-l60/slot9a.pem` | 10s | — |
| 3 | **(b)** login on 9a, refresh, mint; file-key control | `PORT49_L60_B=1 l60 TestL60B` | 2 min | type your PIN once; answer "1" |
| 4 | **(d)** token under `hardware_key_touch` (9c) | `PORT49_L60_D=1 l60 TestL60D` | 3 min | PIN once; **touch**, then **don't touch** (about 15s), then **touch** |
| 5 | **(e2)** a second process's login and token | `PORT49_L60_E2=1 l60 TestL60E2` | 3 min | PIN twice (agents A and B); Enter on any unexpected prompt |
| 6 | **(e)** the unplug | `PORT49_L60_E=1 l60 TestL60E` | 4 min | PIN; **pull**; **re-insert**; PIN; **pull** and **re-insert** again |
| 7 | GET /status cost | `PORT49_L60_STATUS=1 l60 TestL60StatusCost` | 2 min | PIN twice |
| 8 | **(f)** ONE wrong PIN (refuses under 3 tries) | `PORT49_L60_F=1 l60 TestL60F` | 3 min | a **wrong** PIN once, then your PIN once if asked |
| 9 | **(f-lock)** three wrong PINs, then unblock. **Last.** Starts only from exactly 3 tries | `PORT49_L60_FLOCK=1 l60 TestL60FLock` | 8 min | PIN; **wrong** PIN ×3; your PIN at the blocked prompts; in a 2nd terminal `ykman piv access unblock-pin` (the PUK, then your PIN as the new PIN); PIN once more |
| 10 | Remove the pin-source file | `rm ~/.cache/port49-l60/pin` | — | — |

Notes:

- The first cell builds `port49` with `-tags hwkey_dlopen` (under a minute). Later cells rebuild
  from the cache in seconds.
- After each prompt, the cell asks "How many times did port49 ask for the PIN?". Type the number.
- The cells run `ykman piv info` only while none of their agents is up, and keep only its
  PIN-tries line. A cell that sees fewer tries than it needs stops before typing starts.
- A wrong PIN means one you know is wrong. Never use the default PIN as the wrong one.
- If a cell stops early, it says why. What it saw before stopping is already in
  `observations.log`. Every agent it started is stopped by pid.
- Cell (g) (`TestL60G`) skips until plan 9e is built. The cert-import-order sub-cell of (c) is
  not built.
