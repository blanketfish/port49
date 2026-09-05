# port49 — Deep review findings

**Date:** 2026-09-05
**Reviews:** [`2026-08-21-port49-design.md`](2026-08-21-port49-design.md),
[`2026-08-23-policy-engine-spec.md`](2026-08-23-policy-engine-spec.md),
[`2026-08-26-spec-review-findings.md`](2026-08-26-spec-review-findings.md), and the commit history.
**Brief:** `~/vaulty/ideas/port49-deep-review-prompt.md` — second pass, security and usability
weighted heaviest, findings that would change the implementation plan separated from polish.

Nothing here re-derives the first review. Every item below is either an interaction between
pieces that were each specified correctly on their own, a claim that is almost true, or a
resolution that did not go far enough. Where a decision looked questionable and turned out to
be right, that is said in §C so silence is not mistaken for oversight.

Confidence is stated per finding. **Verified** means the finding is textual — the documents
contradict themselves or each other. **Reasoned** means it follows from the design plus
protocol behavior I am confident of. **Unverified** means it rests on device behavior that the
lab, not this review, should settle.

## Status

| Cluster | Items | State |
|---|---|---|
| A — would change the implementation plan | A1–A14 | **resolved** — all fourteen, 2026-09-05 |
| B — polish, stale text, small gaps | B1–B20 | **resolved** — one editing pass, 2026-09-05 |
| C — challenged and upheld | — | recorded |

Cluster A closed in one session. Five needed Ryan's call (A1, A2, A9, A12, A13) and are noted
under each item; the other nine took their stated recommendation. Spec §13 gained decisions
15–21. The lab register (spec §15) came out of A9 and A14 and now gates decisions 15 and the
L4 fall-through claim.

---

## Cluster A — findings that would change the implementation plan

Ordered by severity. A1–A4 are security; A5–A8 are correctness of stated guarantees; A9–A14
are operational and adoption risks that need a design answer before the plan is written.

### A1. The broker API has no authorization model of its own

**What breaks.** `POST /v1/tokens/revoke` accepts "handle, principal, or OIDC sid". Nothing
says which callers may revoke *another* principal. With OIDC, every employee who can complete
an SSO login is an authenticated principal — they need no grant to reach the API, only to
mint. So as specified, anyone in the identity provider can:

```
POST /v1/tokens/revoke   { "principal": "alice@example.com" }
```

and Alice's live router sessions are torn down (teardown row 2, "authoritative, from the
identity layer") in the middle of a change. That is precisely the outcome §5.6 was rewritten
to prevent, delivered through the front door. The same gap covers `/v1/explain` for a subject
other than the caller (a permission oracle: who may do what, where), `POST /v1/sync` ("operator
or CI identity" — nothing defines what makes an identity an operator), `port49 keys show`
rendering a group secret ("a separately-authorized operation" — authorized by what?), and
`port49 policy replay` over records that name other people.

**Evidence.** Design §17 lists eight endpoints and seven requirements; none is an
authorization requirement. Spec §12: "rendering the secret itself is a separately-authorized
operation". The policy schema has no construct for API-level rights — roles carry command
rules, grants carry device scope, and neither describes a broker operation.

**Confidence.** Verified: the authority is simply absent from every document.

**Recommendation.** Add API authority to the policy schema so it is reviewed like everything
else, and keep it tiny: an `api:` list on a subject — `revoke_others`, `explain_others`,
`sync`, `keys_show`, `replay` — with the default being *self only*. No subject needs the line;
every principal may revoke, refresh, explain, and read identity for themselves and nobody else,
and only a subject that crosses to another principal declares it. CI reports every subject that
does. `/v1/logout` is exempt because the IdP authenticates by `logout_token` signature, not as a
principal. Then the prohibition on API keys stays intact and the "who can log the network team
out of its routers" question has a one-line answer in the policy file.

**Resolution (2026-09-05).** Agreed by Ryan: default self-only, overridden per subject. To be
written into design §17 and spec §2 with the cluster A edits.

### A2. What makes a principal human or machine is never defined

**What breaks.** Design §7 requires the two trust domains to be "unforgeably distinct" and
calls it "a small amount of code carrying a large share of the security value". That code
has no specification. Three concrete holes:

- **OIDC client-credentials tokens.** A corporate IdP (Entra ID, Okta) issues tokens for
  *applications* from the same `iss` as human logins, with a valid signature and
  `aud=port49` if an admin consents to it. The design maps "OIDC" to "human". Such a token
  has no `preferred_username` and its `sub` resolves to no directory user, so it would fail
  the username step — but by accident, not by rule, and only for the directory-backed case.
- **Literal identities.** A subject may list `identity: ["alice@example.com"]`. Is that human
  or machine? "Listing a human and a machine identity under one subject is a policy load
  error" — CI cannot enforce that without a classification rule for strings.
- **Certificates.** Humans and workloads are separated by "a separate trust anchor". That is
  the right mechanism, and it is the only place a rule is stated.

**Evidence.** Design §7, "Trust domain separation"; spec §2, "Identities from different trust
domains MUST remain distinguishable"; spec §5.5 table defining `all_humans` as "every human
principal" with no definition of human.

**Confidence.** Verified that the rule is absent; reasoned that IdP-issued application tokens
are indistinguishable from human tokens by issuer alone.

**Recommendation.** Make trust domain a property of the *authentication path*, stamped on the
principal by the broker and never inferred from a string: a human is a principal validated by
the human trust anchor or by an OIDC assertion that resolves to a directory user; a machine is
a principal validated by the workload trust anchor, a Kubernetes JWKS, or an OIDC assertion
whose `sub` is an application. Anything that resolves to neither is refused at mint with its
own reason code. Then require identity strings in policy to carry the domain in their form —
`user:` / `spiffe://` / `system:serviceaccount:` — so CI can classify at load, and `all_humans`
has a definition an auditor can read.

**Resolution (2026-09-05).** Agreed by Ryan; separate trust anchors, and verifier-tagged
classification generally. Recorded as spec §13 decision 16 and design §7. LDAP-authenticated
service accounts have no path into port49 and move to a workload certificate or one OIDC
application per service, which Ryan judged better than LDAP alone.

### A3. `all_humans` is the whole identity provider, and the `everyone` resolution overshoots there

**What breaks.** The resolution replaced `everyone` with `all_humans`, `all_machines`, and
`all_principals`, and deliberately allowed permits on them: "a baseline `show version` permit
is a legitimate thing to want". Under OIDC, "every human principal" is every person who can
log in to SSO — the whole company, not the network team. So:

```yaml
grants:
  - {subject: all_humans, scope: all_devices, roles: [baseline_show]}
```

gives every employee a device login. CI reports permit-carrying grants to `all_principals` but
not to `all_humans`, so this one passes review quietly. The first review's concern was a permit
crossing the *trust-domain* boundary; the reversal fixed that and opened a *population*
boundary in the same move.

**Evidence.** Spec §5.5: "`all_humans` — every human principal"; "CI MUST additionally report
every permit-carrying grant to `all_principals`" — `all_humans` is not mentioned. Design §7:
OIDC "requires no PKI, which removes an adoption barrier" — the population is anyone the IdP
knows.

**Confidence.** Verified.

**Recommendation.** Define universal subjects over principals that match **at least one
non-universal subject**. This costs nothing for denies — a principal matched by no subject
cannot mint, so a deny that fails to reach them changes nothing — and it turns the permit case
back into what an author means by "everyone": everyone who has access already. Extend the CI
report to permit-carrying grants on any universal subject. This is a two-line change to §5.5
and removes the sharpest footgun in the schema.

**Resolution (2026-09-05).** Applied as recommended: spec §5.5, decision 18, §14.

### A4. `TAC_PLUS_UNENCRYPTED_FLAG` is never mentioned, and honoring it voids the boundary

**What breaks.** RFC 8907 §4.1 defines a header flag (`0x01`) marking the body as not
obfuscated. The design's admission argument rests on the key: "the address list is not the
security boundary — the shared key is, since a device connecting without the right key sends
unreadable data". A server that honors the flag reads the body without any key. An attacker
able to complete a TCP handshake from an admitted address — a compromised device, or anyone on
a segment where source addresses are not filtered — could then, with no key material:

- send an authentication START on Alice's `(nas, port)` under another username and tear her
  context down (teardown row 5, "including one port49 rejects");
- inject accounting records, which are recorded and annotate contexts as `foreign_session`;
- drive the per-`(nas, username)` failure counters and backoff for a real operator.

None of that mints authority — a token is still required — but every one of them is a
denial-of-service against a live operator that the key is supposed to make impossible.

**Evidence.** No document mentions the flag (checked: `unencrypted`, `FLAG` appear nowhere).
Spec §10 header validation lists "version major MUST be `0xc`, type in {1, 2, 3}, a client
`seq_no` odd, and the body within the 4096-byte bound" — the flags octet is not validated.

**Confidence.** Reasoned; the flag's existence and the RFC's "MUST NOT be used in production"
language are certain. Whether any NOS sets it without a key configured is a lab question and
does not change the recommendation.

**Recommendation.** Header validation MUST reject the unencrypted flag, with its own bucket in
the `keys status` report (`unencrypted — refused`) so a device misconfigured with no key is
diagnosable rather than counted as noise. One line of code; it keeps a stated security claim
true. While there, state the daemon's handling of `TAC_PLUS_SINGLE_CONNECT_FLAG`, since the
per-connection key cache and the per-NAS connection cap both interact with it.

**Resolution (2026-09-05).** Applied: spec §10 refuses the flag with its own report bucket
and states single-connect handling; design §11; §14 assertion.

### A5. Revocation, the session ceiling, and username binding never reach a session-only platform

**What breaks.** Every post-login control in §5.6 acts at the *next authorization request*:
the ceiling denies commands, revocation deletes context so the next command is denied, a
username mismatch denies and invalidates, the ceiling warning rides on an authorization REPLY.
On Junos — the flagship session-only platform — the device asks port49 exactly once, at login.
`allow-commands` and `deny-commands` are handed over and the device never calls again. So on
an SRX: a back-channel logout at 09:00 for a stolen laptop reaches a context nobody will ever
read; `session_expires` passes and nothing changes; the `server_msg` warning has no REPLY to
ride on. The same is true on any platform for the privilege tiers it does not authorize
(`aaa authorization commands 15` with a priv-1 session, spec §9).

The test assertion "Revocation reaches live sessions: a back-channel logout naming `sid` … each
invalidate the matching contexts" would pass on Junos while the operator keeps typing.

**Evidence.** Spec §1: Junos has "no meaningful per-command path". Design §9, "The decision
log": revocation "reaches live device sessions". Spec §14, "Session lifetime and revocation".
Nowhere is the reach of these controls qualified by `supports`.

**Confidence.** Verified from the design's own description of session-only platforms.

**Recommendation.** State it plainly in §5.6 and design §9: on a `supports: [session]`
platform, and on unauthorized tiers elsewhere, post-login controls are bounded by the device's
own session and port49 can neither warn nor revoke. `port49 explain` MUST say so for any
question about revocation or ceilings on such a platform, the same way it already must for
`pipe_authorized: false`. Then give operators the two levers that do exist: render the Junos
class `idle-timeout` from `max_session_age` (an approximation, but an enforced one), and make
the revocation record name every live context it could *not* reach so an incident responder
knows which boxes still need a manual kick. Do not remove the assertion — narrow it to
command-authorizing platforms and add the negative assertion for Junos.

**Resolution (2026-09-05).** Applied: spec §5.6 "Where these controls do not reach", decision
21, design §9 "Reach", and the §14 assertion split into a positive and a negative.

### A6. Blob lifetime is specified three incompatible ways, and the shortest one causes denials

**What breaks.** Spec §5.1.1: "A blob carries a TTL slightly exceeding the maximum token TTL,
so it expires on its own." Token TTLs are 30–600 seconds. A login context created at
redemption holds `blob_hash` for the session — hours, or `never`. At hour three, Alice's
command lands on a replica that has restarted since her login, the replica reads the context,
fetches the blob, and finds it expired: `blob_unavailable`, denied mid-session. Spec §5.7 then
separately requires "blobs MUST be retained at least as long as the decision records that
reference them" — years, for a compliance artifact. Three lifetimes: minutes, the session, and
the retention period.

**Evidence.** Spec §5.1.1 "Lifetime"; §5.1.3 (refresh writes a new hash into each context, so
the *old* blob is what every earlier record names); §5.7 "Replay"; the reason code table
already contains `blob_unavailable`, which suggests the collision was felt but not resolved.

**Confidence.** Verified.

**Recommendation.** Two mechanisms, one per consumer. For live contexts: the store keeps a blob
while any context references it — simplest is for redemption and refresh to bump the blob's TTL
to the context's remaining lifetime, and for `blob_unavailable` on the command path to be
treated as a store fault (serve the replica's cache, alarm) rather than a policy verdict. For
replay: **emit the blob itself into the decision log once, when it is first created**, as a
`blob` event. Replay then needs only the log, the store owes nothing to the auditor, and the
integrity property in §5.7 gets stronger — the blob a record names is in the same tamper-evident
stream as the record.

**Resolution (2026-09-05).** Applied: spec §5.1.1 lifetime rewritten, `blob` event added to
§5.7, `blob_unavailable` redefined as a store fault, decision 19, §14 assertion.

### A7. The store interface in design §12 no longer describes the store

**What breaks.** The narrow interface is what gets implemented first and what makes the store
pluggable. As written it has four operations: set-with-TTL into a keyed set, atomic
match-and-delete, receipt write/read, context read/write. The design now also requires:

- blob write and read by hash, with the retention semantics of A6;
- the `contexts_by_principal` index (spec §5.1.3), and an index by OIDC `sid` and by
  `(issuer, serial)`, or revocation by those keys is a keyspace scan;
- the idempotency record for `(principal, Idempotency-Key)` (design §17) — which **contains
  the minted tokens in the clear**, must be encrypted like a token, and should expire with the
  tokens it holds, or it extends the exposure window §8 is careful about;
- the per-`(nas, username)` failure counters of §11 if they are to survive a replica change.

Two further consequences hide in the same section. First, **"its own key prefixes"** (design
§17, internal interfaces) cannot separate broker from daemon: both write login context — the
daemon creates it, the broker refreshes and revokes it. Second, the design says the token
encryption key is "held in the daemon's secret mount", but the broker writes tokens, so the
broker holds it too, and "an attacker needs the store *and* a daemon's key" should say *or the
broker's*.

**Evidence.** Design §12 "Store interface"; §17 "Internal interfaces" table; §8 "Tokens and
login context are encrypted at rest"; spec §5.1.3.

**Confidence.** Verified.

**Recommendation.** Rewrite §12's interface as the actual record set — token set, receipt,
context, blob, three indexes, idempotency record, counters — each with who writes it, who
reads it, its TTL rule, and whether it is encrypted. That table is the store plan. State the
encryption key as shared by broker and daemon. The index entries need their own TTL or a
sweep: contexts expire by store TTL and nothing removes their index entries, so a
170-login-per-second poller grows its `contexts_by_principal` set without bound.

**Resolution (2026-09-05).** Applied: design §12's interface is now a record table (eight
records with writer, reader, expiry, encryption), the encryption key is stated as shared by
broker and daemon in §8, the idempotency record is named as token-bearing and encrypted, and
§17's "own key prefixes" is replaced by per-operation separation.

### A8. Two replica races the receipt does not close

**What breaks.** The receipt exists for the retry that reaches a second replica. Under the
two-step CHAP-compatible design, replica A fetches candidates, verifies, removes the winning
token, *then* writes a receipt. Replica B, serving the device's retry, fetches, verifies, tries
to remove, fails — and if that happens before A's receipt write lands, B reads no receipt and
replies FAIL. The device got FAIL from B after timing out on A: the login is refused even though
A redeemed the token, which is exactly the flaky-login outcome the receipt was introduced to
prevent. The window is small and real.

Second race: when B *does* find the receipt and replays PASS, B creates login context — with a
fresh `ctx_id`. A already created one. Two `ctx_id`s for one login; A's `redeem` record names
one and every later command names the other. The correlation chain, which §5.7 makes a
compliance property, breaks on the very retry it was designed to survive.

**Evidence.** Design §8 "Single-use means single-session"; §12 "The match cannot be a single
server-side primitive … the daemon fetches the candidate set, decrypts and verifies locally,
then performs an atomic remove-if-present". The receipt write is a separate step in the
interface list.

**Confidence.** Reasoned; it follows from the two-step shape the first review correctly
insisted on.

**Recommendation.** Make removal and receipt one atomic store operation — remove-if-present
*and* write receipt in a single transaction (a Lua script, a DynamoDB transaction, a
`SELECT … FOR UPDATE`). On removal failure, the loser reads the receipt and, if absent, waits up
to the store timeout before answering FAIL. Put `ctx_id` in the receipt and have replay *adopt*
the existing context rather than create one. Add both to §14's CHAP race assertion.

**Resolution (2026-09-05).** Applied: design §8 and §12 make removal-and-receipt one atomic
operation, the loser reads the receipt and waits to the store timeout before FAIL, the receipt
carries `ctx_id` and replay adopts it; spec §14 CHAP assertion extended.

### A9. A login is assumed to be an SSH session; HTTP-API transports break single-use and the context key

**What breaks.** The originating consumers are automation — Oxidized, Netmiko, Ansible — and a
large share of Arista and Cisco automation authenticates over **eAPI and NX-API**, not SSH.
With basic authentication, every HTTP request carries the credential and the device
authenticates it through AAA per request. A single-use token then serves exactly one API call:
the first `show version` succeeds and the second fails with `token_not_found`. Ansible's
`httpapi` plugin logs in once per play, which helps, but `eapi` with per-request credentials
does not. Separately, the context key `(nas, port)` assumes `port` is a stable, unique line;
what a device puts there for an HTTP session is unknown and may be identical for every request,
so concurrent API logins from two principals would overwrite each other's context (row 1) and
then deny each other (row 4).

**Evidence.** Design §6 taxonomy: "login — one shell session on one device". Design §17's
integration examples are all SSH. No document mentions eAPI, NX-API, NETCONF, RESTCONF, or
gNMI (checked). Spec §5.6 lists the Junos `port` format as a lab item but not the API case.

**Confidence.** Reasoned for eAPI/NX-API basic auth; unverified for what `port` contains.

**Recommendation.** Decide it before the plan, because both answers are large. Either declare
HTTP-API transports out of scope for v1, or support them with a **reusable token**: a subject
property, valid until TTL rather than for one redemption, still device- and username-bound,
with match-without-delete in the store and no receipt. No use counter — TTL already bounds
exposure and a counter is a second knob for the same thing. Add `port` uniqueness and stability
per platform and per transport to the lab list as the assumption the entire context model rests
on, not only the Junos format.

**Resolution (2026-09-05).** Ryan chose support: eAPI and NX-API carry the automation at work.
Recorded as spec §13 decision 15, **provisional** pending lab register entries L1 and L7
(spec §15, new). The context-key question is deliberately left open until `port` has been
measured for API sessions.

### A10. Source-of-truth write access discloses tokens through a rogue address

**What breaks.** Mint returns the device's *address* from inventory and the operator's SSH
client connects to it. Whoever can add an address to `core-sw01`'s record in NetBox — write
access the design already calls privileged — can list a host they control. `port49 ssh
core-sw01` connects to it, its SSH server prompts for a password, the agent supplies the
token, and the attacker replays it against the real `core-sw01` within the TTL from the real
device's address. Device binding holds — the token is presented from the right NAS — and
single-use holds, because the legitimate login never happened. The attacker has an
authenticated, fully authorized session as Alice, and the decision log records Alice.

**Evidence.** Design §17: "The response carries the address back, since the caller usually
needs it to connect." Design §10: "Source-of-truth write access is privilege-granting" — listed
consequences are scope movement, not credential disclosure. No document mentions SSH host-key
verification (checked: `known_hosts`, `host key`).

**Confidence.** Reasoned; every step uses a specified behavior.

**Recommendation.** The agent's SSH integration MUST verify host keys and MUST NOT accept a
first-seen key silently for a device inventory already knows. Inventory can carry the host
key fingerprint (NetBox custom field, or learned and pinned on first verified connection with
an explicit `port49 devices trust` step). Add "an address added to a device record" to the
sync diff's security events alongside scope-membership changes. This is agent-plan work and a
line in §10.

**Resolution (2026-09-05).** Applied: design §17 requires host-key verification with an
inventory fingerprint or an explicit `port49 devices trust` pin; spec §10 makes an added
address a security event in the sync diff.

### A11. An inventory sync can make a valid policy invalid, and nothing says what happens then

**What breaks.** Several load-time checks are joint over policy *and* inventory: "a level with
no mapping and no resolvable `parent:` chain, on a platform present in inventory, is a policy
load error"; `enable: auto` is a load error on a platform with a non-principal
`enable_username`. Both are true today, and a sync adds a device with a new platform tomorrow.
The bundle now fails validation. The inventory service either publishes a bundle the consumers
will reject, or refuses to publish — in which case **every** inventory change is blocked until
someone edits policy, including the leaf racked in another site that has nothing to do with the
offending platform. A ticket-queue bottleneck of exactly the kind design §2 exists to remove,
created by the safety mechanism.

**Evidence.** Spec §6 "A level with no mapping … is a policy load error"; §5.6 "Granting it
there is a policy load error"; §10 "One versioned bundle" — the bundle is validated as a whole
and consumers "reject a snapshot that fails to parse, that is empty, or that drops more than
the configured share". Joint validity is not a listed failure.

**Confidence.** Verified.

**Recommendation.** Quarantine at device granularity. A device whose platform fails joint
validation is published in the bundle with `admission: quarantined` and a reason; the daemon
refuses it with `device_quarantined`, the alarm names it, and the rest of the fleet moves.
Policy load in CI reports the same list so the fix is visible in the pull request. Add a
`quarantined` column to `port49 devices capabilities`.

**Resolution (2026-09-05).** Applied: spec §10 quarantine paragraph, `device_quarantined`
reason code, decision 20, §14 assertion.

### A12. Drift and capability verification need something that logs into devices, and no component may

**What breaks.** The Junos class baseline "lives outside port49's control, so drift MUST be
detected, not merely documented", and detection is by `show cli authorization` or `?`
completion — both require an interactive session on the device. The broker "never sees a
network device"; the daemon "speaks TACACS+" and nothing else; the inventory service reads
sources of truth. The only thing that can log into a device is an operator, or a machine
identity port49 would have to mint for itself. As designed, the MUST has no owner, and the
Junos deny baseline silently rots on the box.

**Evidence.** Spec §8 "Verification"; design §6 components table, "Never" column.

**Confidence.** Verified.

**Recommendation.** Either a fourth process — a *prober* that holds a workload identity, mints
for itself under a `port49_prober` subject with a `verify_only` role, and runs the completion
probe on a schedule — or an explicit statement that drift detection is an operator-run CLI
(`port49 devices verify <device>`) using the operator's own credentials, scheduled by the
deployment's own automation. The prober is the one that satisfies "never require an operator
to assert something the system can observe". Either way the plan needs the line item, and the
`VERIFIED` column in `platform list` needs to say which one produced it.

**Resolution (2026-09-05) — resolved by deletion, at Ryan's call.** The class is device
configuration, and port49 polices device configuration nowhere else; configuration compliance
is another tool's job. The drift MUST is removed from spec §8. What remains: CI warns when a
role exceeds the wire budget and emits the class snippet as the remedy, `platform export`
publishes the reference class per level for a compliance tool to check, and `explain` states
that on a session-only platform the effective set is class ∩ wire. The `?` completion technique
stays as a lab instrument for the differential test. No prober.

### A13. Session refresh must be a fresh authentication, and the certificate path's session is undefined

**What breaks.** The ceiling is "how long may a session run on the strength of one
authentication event", and refresh "writes `auth_time=T2`". Under OIDC the agent holds a
refresh token for its 8–16 hour session; if `port49 login` silently uses it, no human
re-authenticated, and the IdP's `auth_time` claim — correctly — still says T. If the broker
instead sets `auth_time = now` from its own clock, the compliance clock measures "time since
the CLI was run", not "time since identity was proven". On the certificate path the problem is
earlier: design §7 says the session credential is "a hardware-held key" and design §8 says
"one certificate authentication per day", which cannot both be true unless the agent holds a
long-lived mTLS connection open all day. Otherwise the broker issues the agent *something* after
the challenge, and that something is a bearer in a file — the property §7 says the OIDC path
alone has.

**Evidence.** Spec §5.6 "Session lifetime" trace; design §7 "The paths differ in one security
property"; design §8 table, "Session — 8–16h — agent, local only".

**Confidence.** Verified for the underspecification; reasoned for the OIDC `auth_time`
behavior (an IdP preserves `auth_time` across refresh unless `max_age` or `prompt=login` is
requested).

**Recommendation.** Refresh MUST request a fresh authentication (`prompt=login` or `max_age=0`
on OIDC; a new proof-of-possession challenge on the certificate path) and MUST take `auth_time`
from the assertion, never from the broker's clock. Specify the agent's session credential for
each path: for OIDC, the IdP refresh token bound to a PKCE public client; for certificates,
either per-mint PIN with an OS-cached session (name it) or a broker-issued session token whose
lifetime and storage are stated. Then rewrite §7's "differ in one security property" to
describe what is actually held on disk. State the default for `max_session_age` rather than
"defaulting long" — a compliance parameter with an unstated default is one nobody sets.

**Resolution (2026-09-05).** Agreed by Ryan. Recorded as spec §13 decision 17, spec §5.6
requirements, and design §7 and §8. The cert-path session is a held mTLS connection, so a
300-device Ansible run is one batch mint with no hardware interaction; a reconnect is one
touch. Default `max_session_age` is 12h.

### A14. "Method lists fall through on ERROR, not FAIL" is a configuration property, not a protocol one

**What breaks.** Spec §5.6 leans on it twice: the residual `enable: auto` exposure is bounded
by it, and "Denial at the ceiling is FAIL, not ERROR, so no fall-through to local authorization
opens up". It is true on IOS, IOS-XE, NX-OS, and EOS for the standard method lists. On Junos,
`authentication-order [ tacplus password ]` with `password` listed explicitly tries the local
password when the TACACS+ server *rejects*; only with `password` omitted is local used solely
on unreachability. So the claim is true when the reference AAA configuration makes it true and
false when an operator copies a common Junos snippet.

For port49's controls the consequence is narrow — a rejected START tears down context (row 5)
whether or not the device then admits the user locally, and Junos has no enable — but the
sentence is stated as a fact about method lists, and it will be relied on again.

**Evidence.** Spec §5.6, "Why `enable: auto` is restricted"; spec §5.6 lab list already
includes "Method-list fall-through and `deadtime` behavior per platform".

**Confidence.** Unverified for Junos; this is from documentation memory and Ryan's SRX can
settle it in a minute.

**Recommendation.** Reword as a requirement on the shipped reference configuration —
"fall-through on FAIL MUST be disabled, and the reference configuration per platform is what
disables it" — and add a per-platform assertion to §14. If the SRX confirms the Junos behavior,
record it as the reason `password` is absent from the Junos reference config.

**Resolution (2026-09-05).** Applied: spec §5.6 cites lab register L4 and states the argument
is a requirement on reference configuration until L4 closes; design §12 says the same under
the failure model; §14 asserts fall-through absent per platform.

---

## Cluster B — polish, stale text, and small gaps

> **All twenty resolved, 2026-09-05.** B1–B3 and B14 were textual fixes. B4 closed the
> reason vocabulary with twelve new codes across `redeem`, `escalate`, pipe, service, and
> trust domain. B5, B6, B7, and B19 were folded into spec §7 as a "which field, when" table
> and a token `kind` check. B8 finished the accounting demotion: `closing` now has no effect
> on anything. B9 restricts the unauthorized-tier join to authorized tiers. B10 states the
> context cache TTL as seconds and adds it to the revocation-latency sum in design §9. B11
> adds a context sweep to encryption-key rotation. B12 and B13 are single sentences in design
> §17 and §8. B15 puts the cross-domain username check on the broker at mint. B16 closed with
> A4. B17 gives every denial a `server_msg`. B18 names the offboarding commands and states
> rollback as revert-and-sync. B20 reorders design §19 around a vertical slice at step 3.

Textual unless marked otherwise. None changes the plan's shape; several would mislead an
implementer reading the spec cold.

- **B1. Spec §3 still lower-cases the vector.** Line 156: "`command [cmd, arg1, …] lower-cased,
  <cr> stripped`", contradicting rule 3 four lines later and the resolution of finding 2.1.
- **B2. Spec §14 still lets accounting tear down context.** "an exec accounting START for the
  port invalidates" under *Context teardown* — the exact behavior decision 11 removed. The
  device-accounting assertions three groups later say the opposite.
- **B3. Event count.** §5.7 says "five events"; §14 says "each of the four events"; the
  findings doc says four. It is five plus `account`.
- **B4. Reason vocabulary is not closed for the events it covers.** §5.3 emits `default_deny`
  and the table spells it `no_rule_matched`; `DENY (pipe_stage, …)` has no code; a non-`shell`
  service has none; `redeem` needs `token_not_found`, `device_mismatch`, `receipt_replayed`,
  `credential_mismatch`; `escalate` needs `enable_refused` and `ceiling_exceeded`. Because the
  API reuses the same vocabulary (design §17), this is the API's error set too.
- **B5. Token kind is not checked against `authen_service`.** Both tokens of a pair sit under
  `(nas, username)`; nothing says an enable token is refused at login or a login token at
  enable. Privilege gain is nil today, but the `redeem`/`escalate` records should never be able
  to disagree with the wire. Carry `kind` on the token record and check it.
- **B6. Enable redemption "overwrites unconditionally."** Teardown row 1 must mean *login*
  redemption; escalation updates `privilege` in place (§7). Say so, or an implementer will
  reset `ctx_id` on every `enable`.
- **B7. §7 says command rules "may differ above and below the line."** No syntax expresses a
  rule conditioned on privilege level; the blob has one rule set. The sentence should say what
  is true: the level changes what the device offers, the rules are constant, and the recorded
  level feeds `privilege_exceeded`.
- **B8. The `closing` annotation still has a side effect.** "`closing` stops refresh." Alice
  reconnects to the same line; her old STOP arrives after her new redemption; the new context
  has no `task_id` yet; username matches; `closing`; refresh stops; the staleness ceiling
  eventually denies her. The demotion should finish: `closing` is reported and nothing else,
  or any subsequent START or authorization on the context clears it.
- **B9. Unauthorized-tier report on session-only platforms.** §9 reports every accounted
  command with no authorization request. On Junos that is every command, forever; "once that
  happens nobody reads the report again" is the spec's own warning. Restrict the join to tiers
  the platform's `supports` says it authorizes.
- **B10. Per-replica context cache TTL is unspecified** and it bounds revocation: a context
  deleted by revocation stays valid on a replica's read-through cache until the entry ages out.
  Name the TTL (seconds, not minutes) or use a store notification channel, and fold it into the
  stated revocation latency.
- **B11. Encryption-key rotation for long-lived contexts.** §8 sizes the rotation window by
  `token_ttl`; contexts live for the session, or `never`, and "re-encrypt on next write" never
  reaches an idle Junos context. A rotation needs a sweep over contexts.
- **B12. Idempotency replay should be body-checked.** Same key, different body → refuse, not
  replay.
- **B13. The candidate-set cap ("order of eight")** — say whether it refuses the ninth mint or
  the redemption. Parallel Ansible forks against one device with one service account will find
  out otherwise.
- **B14. Design §17's example `"principal": "svc_oxidized"`** names a subject; the principal is
  `system:serviceaccount:netops:oxidized`, and the username in the example disagrees with the
  spec's `svc-config-backup`. Examples teach the taxonomy.
- **B15. Username uniqueness cannot be checked across trust domains at load.** Machine usernames
  are declared; human usernames come from the directory at mint. A machine subject declaring
  `username: alice` collides only at runtime. The broker must check at mint and refuse with a
  reason; CI cannot.
- **B16. Listener limits lack an idle-connection timeout.** Everything else in design §11 is
  covered; a connection that sends nothing holds a slot under the per-NAS cap indefinitely.
- **B17. Denials should reach the person who typed the command.** `server_msg` is specified
  for the ceiling warning only. A deny reply carrying `port49: denied by no-exfil — try
  'port49 explain'` is the difference between self-service and a ticket, and it leaks nothing
  the operator did not just type.
- **B18. Day-two stories without an instrument.** Decision 2 says offboarding across scattered
  grant rows is "addressed by tooling" — name it (`port49 access review --subject`, `grants
  remove --subject`). Bundle rollback has no command; say it is `git revert` plus `inventory
  sync`, or give it one.
- **B19. `max_privilege` beside `privilege` is the schema's steepest learning step.** The
  reasoning (ceiling on the grant, mechanism on the subject, level on the role) is sound; the
  §11 example's `netops_admins` row carries both `privilege: admin` via the role and
  `max_privilege: admin`, which reads as redundant and invites the question "which one do I
  set?" A one-paragraph "which field when" in §7 would carry it.
- **B20. Sequencing delivers the product's core claim late.** Steps 1–5 are protocol, tokens,
  the full engine, adapters, and the inventory service before any broker exists, so the first
  time a real identity reaches a real device is step 6–8. A thinner vertical slice — protocol,
  in-memory store, a minimal broker with certificate auth and a literal-identity subject, the
  agent's `login`/`token` — would prove the riskiest integration (agent → broker → store →
  daemon → device, including the 255-byte and `server_msg` unknowns) before the engine is
  built out. The full engine and inventory service follow it rather than precede it.

---

## Cluster C — challenged and upheld

Each of these was pushed on and holds. Recorded so the next reviewer does not reopen them.

**Specificity dominance as a partial order.** Tried to construct a real policy where declining
to rank incomparable rules produces a wrong deny; every candidate was a deny the author would
want. The one-sided test is the right asymmetry. The cost — a shadowed deny — is surfaced by
CI, which is a better guarantee than deny-overrides' inability to express an exception.

**Content-addressed blobs.** The dedup, the cache-without-invalidation, the impossibility of
broker/daemon skew, and replayability all follow from one property. A6 is a lifetime bug, not
an argument against the mechanism.

**Accounting demoted to advisory.** Correct, and the first review's original recommendation
(make it load-bearing and specify it carefully) would have been wrong. B8 is the last
remaining side effect.

**Credential expiry bounding the mint, not the session.** Correct. An OIDC `exp` is not a
security event and a certificate's `notAfter` mid-session is not a compromise. A13 is about
making the replacement clock honest, not about reversing the decision.

**Encryption at rest instead of CHAP opt-in.** Correct. One storage path, and it now covers
login context for a second reason. A7 only extends it to the broker and the idempotency record.

**Per-device keys refused.** Correct. A key port49 cannot install is not a feature. The
device-pin tier is the right escape hatch.

**Key rotation as a version set with enforced retirement.** Correct, and the "evidence, not
mechanism" framing is the actual insight. The retired-key-may-identify-never-admit rule is
clean.

**Flat grants.** Correct. The offboarding cost is real and B18 asks only that the tool be named.

**The daemon as executor, the bundle carrying facts.** Correct, and it is what makes A11's
quarantine cheap: the daemon needs only an admission flag per device.

**Multi-tenancy as a non-goal.** Correct, and the reason given — three global namespaces —
is exactly the reason it should not be retrofitted.

---

## What to do with this

Nothing further in this document. Every finding is resolved in the two design documents, the
policy engine spec carries decisions 15–21 and the lab register, and the next artifact is the
implementation plan. The register's open entries — L1 through L10 — are the lab work the plan
schedules, and decision 15 stays provisional until L1 and L7 close.
