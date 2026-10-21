# L75 — three simulated regions

- **Date measured:** 2026-10-21
- **Platform:** port49 on the lab host, three simulated regions (network namespaces, tc netem 20ms each way)
- **Image version:** etcd Version: 3.6.15
- **Capture:** tests/lab/evidence/L75-regions/
- **Run:** commit `9111f962678475eb7917d59eec50b51f9b12cadd`, `-run TestRegions`

## Claim

spec §15 L75, cell by cell (decision 51: unlocks, TOTP fail-closed, membership's pin, back-channel logouts across brokers; decision 47 ruling 5).

## Observation

| cell | claim | observed | agrees with decision 51 |
|---|---|---|---|
| a | a code signed in at broker 1 is refused at broker 2 within its step (broker 2 takes a fresh code) | broker 1: 200; broker 2, the same code: 401 sign_in_refused; broker 2, a fresh code: 200; brokers 2 and 3 read the enrollment store as ok 25.1s after init-enrollments (D7: within 30s) | yes |
| b | one code sent to brokers 1 and 2 at once, twenty steps: pairs with exactly one 200 (the other refused for the code); broker 1 is unlocked after each pair, so no pair runs on a locked-out broker | 20 of 20: 401/200 401/200 200/401 401/200 401/200 401/200 401/200 200/401 200/401 200/401 200/401 200/401 200/401 401/200 401/200 200/401 200/401 401/200 401/200 200/401 | yes |
| c | locked out at broker 2, unlocked at broker 1: broker 2's next sign-in is judged | broker 2 refused after 6 wrong code(s); a valid code while locked: 429; unlock at broker 1 exit 0; broker 2's next sign-in 200 | yes |
| d | the attempt counts are per broker: failures each takes before it refuses, and the total across three | broker 1: refused at try 6, broker 2: refused at try 6, broker 3: refused at try 6; 15 failures in all (threshold 5 each) | yes |
| e | broker 3 cut from the directory: a password sign-in 503 store_unavailable; unlock and reset-second-factor refused; how long each took | store status exit 3 under the cut; sign-in 503 store_unavailable in 507ms; unlock exit 1 in 516ms: port49 directory unlock: broker: unlocking user:carol@corp.example.com failed: the directory store did not answer, so nothing changed: run it again; reset exit 1 in 515ms: port49 directory reset-second-factor: broker: resetting user:bob@corp.example.com failed: the store did not answer, so nothing changed: run it again; healed true | yes |
| f | membership's pin: written once in the directory; a forget at broker 1 re-pins at broker 2's next mint; with broker 3 cut, a forget there refused, a pinned member served from the cached pin and said, a first bind refused (and served after the heal) | mint at b2 200, pin revision 80; forget at b1 exit 0; next mint at b2 200, pin revision 83; cut: forget at b3 exit 1 in 515ms; carol's mint at b3 200 (said true); bob's first mint at b3 503 store_unavailable; bob's mint at b3 after the heal 200 | yes |
| g | a logout received at broker 1 refuses broker 2's mint for that session | mint at b2 200; logout at b1 200; b2 refused after 0s (credential_revoked); b2's runner line after 100ms (true): followed (a logout made elsewhere) | yes |
| g2 | with broker 3 cut, a logout there is answered 200, refused there at once and pending; broker 1 mints for it until the heal, then refuses | mint at b1 200; logout at b3 200; b3's mint 401 credential_revoked; status (after 3.5s) exit 3: directory  etcd    ?/? members  unreachable  cache 5.1s  1 logouts pending /            timed out / session    etcd    1/1 members  reachable; b1's mint during the cut 200; forwarded line true; b1 refused 5.11s after the heal (credential_revoked) | yes |

**Not measured here:**

- the brokers run on the host, not in the namespaces: OpenLDAP's ports are published on the host's loopback alone
- Keycloak's own sending of a logout, and that it does not retry a 503: L45's; (g) signs its logout tokens with an in-process provider
