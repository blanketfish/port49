# Plan 2 revision notes — read before executing plan 2

**Date:** 2026-09-20. **Status:** input to a rewrite of
`2026-09-06-02-token-model.md`; that plan is NOT executable as written.

Plan 2 was written from plan 1's text and assumes the `(nas, port)` login-context key. The
lab showed that key breaks every measured vendor, and the owner ruled the key is
`(nas, username)`, the receipt `(nas, username, credential_sha256)`, `port` and `rem_addr`
recorded only (spec §13 decision 15; `docs/design/2026-09-20-login-context-key-options.md`).
The code on `feature/lab-l4-fallthrough` implements the ruling. What follows is the
implementer's list of what plan 2 must be rewritten against, line numbers as of commit
`8160276`. One item (plan line 1305) is a security decision for the owner, not a rename.

**The key types themselves**

- **377** — `type ReceiptKey struct{ NAS, Port, Username string }`. Must become
  `{NAS, Username string; CredentialSHA256 [32]byte}`.
- **387** — `type ContextKey struct{ NAS, Port string }`. Must become `{NAS, Username string}`,
  and plan 2's `Context` needs the `Port` field this change added.
- **459, 480, 981, 994** — store test literals carrying `Port:` in a key.
- **586–587, 609–610, 649, 675, 686, 693, 704** — the sealed store's map declarations and
  method signatures. Signatures survive; the literals in the tests around them do not.
- **1204, 1215, 1228, 1237, 1250** — the `wrapped` encryption shim. Unaffected in shape, but
  note that the receipt's sealed blob now duplicates a hash that is also in the plaintext key:
  plan 2 should say whether that is acceptable (it leaks that two redemptions presented the
  same credential, which the old plaintext `(nas, port, username)` key already leaked in a
  coarser form).

**The reasoning, which is where the real work is**

- **20** — "the context key stays `(nas, port)` until measured". Measured; it did not stay.
- **1662** — Task: "**Row 5 first.** A START on `(nas, port)` under a different username than
  the live context invalidates that context, even when this authentication is then rejected."
  Teardown row 5 is withdrawn (spec §5.6). This whole step should be deleted, not ported.
- **1664** — "**Enable resolves the username from context.** … Read the context at
  `(nas, port)`". The `$enab{level}$` lookup must become the `(nas, rem_addr)` secondary
  index, **with an explicit ambiguity refusal** — `rem_addr` is measured identical for two
  concurrent sessions behind one bastion — and that refusal needs a reason code, which means
  spec §5.7's table first. Note also that on the one platform where an enable has been
  measured (vEOS), the START carries the operator's own username, so the common path is the
  wire username and the index is the exception.
- **1850** — `ctxKey := store.ContextKey{NAS: s.peer.NAS, Port: port}` in the plan's rewritten
  `redeem`.
- **1866–1871** — the row-5 block inside that `redeem`, including its `UnindexContext` call.
- **1876–1897** — the enable block reading `incumbent` from the `(nas, port)` context.
- **1898** — `rk := store.ReceiptKey{NAS: ..., Port: port, Username: lookupUser}`, and the
  comment two lines below it, "a different credential on the same line fails", which is no
  longer the behavior.
- **1723, 1727, 1741, 1760, 1766–1807, 2009–2082** — handler tests written around
  `(nas, port)`, several of which (the `$enab15$` ones) test the path that has to be
  redesigned rather than re-keyed.
- **1305** — "the ref is `(nas, port)` and is itself plaintext; design §12 accepts this because
  the ref carries no identity on its own". **The ref now carries the username.** That sentence
  is the whole argument for leaving `contexts_by_principal` entries unencrypted, and it stops
  being true: a store dump would reveal principal → device → username. This is the one item on
  this list that is a security decision rather than a rename, and it should be settled before
  plan 2 is executed.
- **2371, 2384, 2399, 2404, 2419, 2449, 2499** — `store.ContextRef{NAS, Port}` through the
  index tests and the revocation path; the ref shape changes with the key.
- **2151–2164, 2181–2238, 2261, 2294–2299, 2871** — Task 7, accounting annotation. Two
  problems, not one: the lookup key, and the fact that the `task_id` binding it specifies is
  measured wrong on Junos (`task_id` restarts at `1` per session, so two concurrent logins
  both sent `task_id=1`). Spec §5.8 now specifies a per-platform session discriminator
  (`session_pid` on Junos, `task_id` on EOS) and defers the choice to the plan-5 adapters;
  plan 2's Task 7 inherits the old text verbatim and must not.
- **2864** — the coverage table row for enable, "username resolved through context on
  `$enab{level}$`", follows 1664.

**Not a contradiction, but worth plan 2 knowing:** `Receipt.CredentialSHA256` is now redundant
with the key and is kept deliberately, for the post-lookup constant-time compare. Plan 2's
sealed-receipt code should not "simplify" it away.
## One thing the change made visible, which plan 2 owns

An `enable` START is a second authentication under the same username on the same device. Under
`(nas, username)` it therefore lands on the login context and **overwrites it**, taking the
`ctx_id` with it. Measured on vEOS this run, the whole of `alice04`:

```
18:00:37.499  redeem            permit token_redeemed   port=ssh   priv=1   ctx=QOZ6DYFB
18:00:37.705  authorize_session permit context_matched  port=vty4  priv=1   ctx=QOZ6DYFB
18:00:38.673  redeem            permit token_redeemed   port=vty4  priv=15  ctx=TVGMSVTY  replaced_ctx_id=QOZ6DYFB
```

Spec §5.6 teardown row 1 and §7 both say the opposite: "an `enable` redemption is not this: it
updates `privilege` in place and keeps `ctx_id`". **This is not a regression the re-key
introduced.** Plan 1 has no escalate path at all — its `redeem` treats an enable START as an
ordinary redemption of a `kind: enable` token, and did so before. Under `(nas, port)` the
enable's port (`vty4`) differed from the login's (`ssh`), so it wrote a *second, separate*
context and left the login one intact; that was equally wrong and simply invisible, and in any
case the session was being killed before it got that far.

What is new is that it is now *visible*: `session.replaced_ctx_id` is what surfaced it, on the
first lab run that carried the field. I did not fix it — the escalate path is plan 2's
(`docs/superpowers/plans/2026-09-06-02-token-model.md`, the enable step at line 1664), and
building it here would mean inventing the `(nas, rem_addr)` index and its reason code outside a
plan. Plan 2 must make `enable` update in place rather than re-`PutContext`.
