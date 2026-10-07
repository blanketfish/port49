# Plan 8: Workload Certificates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an unattended workload on a static host (Oxidized on cron is the day-one consumer)
mint device tokens with a certificate its own CA issued and renews, as a machine principal that
can never present as, or inherit the grants of, a person.

- **The verifier (design §7, machine identity option 2; decision 16).**
  - `x509` under `broker.identity.machines`: one trust anchor, `trust_anchor_file`, and the SPIFFE
    trust domains it may name, `spiffe_trust_domains` (required).
  - It reuses the broker's certificate path (the listener, `certificate_status`, the marks) with a
    separate anchor, as design §7 says.
  - **The domain is the anchor the chain ends at.** TLS verifies against both anchors at once. A
    chain that ends at the workload anchor is a machine's, one that ends at the human anchor a
    person's, and one that ends at both is refused.
- **The principal (spec §2's "workload x509" row).** The leaf's one URI SAN, verbatim, a SPIFFE ID
  with a path, in a listed trust domain. Anything else is `identity_unmapped`, answered over HTTP
  at bind, never as a TLS alert.
- **No directory in plan 8.** A workload principal is never sent to the directory. Its groups are
  none, and its username is its identity subject's declared `username:` (Ruling 5). Decision 16's
  "may still supply groups" is deferred to a named **plan 8b**, not withdrawn, and constrained: a
  machine principal matches only a machine-scoped group subject, never a human `group:` subject.
- **Multi-identity subjects (spec §2).** One subject may list a workload's `spiffe://` ID beside its
  `app:` or `system:serviceaccount:` ID, so a migration is a policy no-op. Built since plan 4;
  this plan pins it with a workload principal.
- **Username collision at mint.** It is built since plan 7g. A directory-derived username that a
  subject declares is refused `username_collision`, and the declared username stands. This plan
  corrects spec §2's "later claimant" to match, and pins it with a workload subject.
- **Enrollment and self-renewal.** port49 is a relying party, never a CA (design §7).
  - The workload enrolls once with the organization's CA, and renews against that CA.
  - port49's part is that a renewal needs nothing from port49. The principal is the SPIFFE ID, not
    the serial.
  - The agentless client reads the certificate and key from their files at every run.
  - A renewal that is running late is said: a broker line, a counter, and a warning from the CLI.
- **The agentless client.** `port49 workload token` and `port49 workload identity` (design §17:
  "machine workloads require no agent: identity is a file and minting is a single request").
  - One request per page of `batch_max`, under an `Idempotency-Key` that a retry reuses.
  - It retries a broker that cannot answer now, within a deadline.
  - Its exit codes tell cron what happened: 0, 1 (some written, some not), 2, 75 (temporary), or
    77 (nothing minted, and a run again will not change that).
- **Oxidized as the day-one consumer.**
  - `examples/oxidized/` holds a wrapper script, an Oxidized config and a policy snippet.
  - The wrapper mints one token per node, writes Oxidized's `router.db` 0600, reloads Oxidized, and
    backs each node up now.
  - The policy snippet is provisional on L49.
- **Lab (on beehive).**
  - **L48:** a real workload CA (step-ca) issues, renews and revokes, and port49 follows each step,
    its CRL included (fetched under step-ca's root), and a provisioner's name policy.
  - **L49:** what Oxidized does with a minted token on each platform, measured end to end on all
    five images. It covers the commands each model sends, when it reads a credential, and what a
    stale token costs.

**Architecture:**
- **`internal/spiffe`**, a new leaf package (stdlib only): `Parse`, `ParseWorkload` and
  `CheckTrustDomain`. The policy's load, the broker's verifier and a revocation's principal read a
  SPIFFE ID through it, so the three agree.
- **`internal/config`**: `x509` under `machines` (`trust_anchor_file`, `spiffe_trust_domains`);
  `oidc.Config.X509Machine`; `BrokerConfig.WorkloadCAFile`. `certificate_status` is required with
  any x509 verifier.
- **`internal/broker`**:
  - `workload.go`: `Workload`, `CertCaller`, `CertCallerOf`, `WorkloadPrincipal`. Every place that
    read a certificate as a person (`Identity`, `CertIdentity`) reads it through `CertCallerOf`
    now: the server's `VerifyConnection`, `authenticate`, `callerOf`, `legacyOf`, and the
    listener (a new `Listener.Caller` hook).
  - `Broker.Wire` sets the listener's hooks, the one way port49d and port49-broker wire it. A
    listener with `Map` and no `Caller` serves nothing, and `BindMap` never maps a machine chain.
  - `Server` puts both anchors in one pool.
  - `normalPrincipal` takes `spiffe://` IDs.
  - A late renewal is said once a day per certificate and counted.
- **`internal/port49d`** (port49d and port49-broker) reads the workload anchor, and refuses the
  start when the two anchors are one certificate or one signs the other. It checks
  `certificate_status` against both anchors and says the start lines.
- **`internal/workload`**, a new package: the agentless client. **`cmd/port49`**: `port49
  workload token` and `port49 workload identity`.
- **`examples/oxidized/`**: the wrapper, Oxidized's config, a policy snippet, and a Go test that runs
  the wrapper against a fake `port49` and a fake Oxidized.
- **`tests/lab`**: a step-ca harness (L48) and an Oxidized harness on the compose stack (L49).

**Tech Stack:**
- Go 1.26, module `github.com/rhwendt/port49`, no cgo, **no new module**. `crypto/x509`, `crypto/tls`
  and `net/http` from the standard library; SPIFFE ID parsing is in-house (about 80 lines against
  the SPIFFE ID specification's §2, not `go-spiffe`).
- etcd v3.6.15 as today.
- Lab:
  - step-ca (`smallstep/step-ca`, pinned by digest at Task 13, with the version recorded in each
    note).
  - Oxidized (`oxidized/oxidized`, pinned the same way).
  - The compose stack (`deploy/compose`, plan 7f) with containerlab for the five device images.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2: the principal table's "workload x509" row, "A subject MAY list several identities", the
    device-facing username and its collision paragraph;
  - §5.1.3: the scheduled refresh's machine principals;
  - §5.1.4: credential identity and revocation;
  - §5.7: the reason codes `identity_unmapped`, `trust_domain_unresolved` and
    `username_collision`;
  - §13: decisions 8, 16, 33, 38 (ruling 3) and 39 (ruling 1) (read and amended), and the new
    40;
  - §14: trust domains and API rights;
  - §15: the register rules, and the new L48 and L49.
- `docs/design/2026-08-21-port49-design.md`:
  - §7: machine identity (option 2), trust domain separation, "port49 is a relying party";
  - §17: "machine workloads require no agent", the integration examples;
  - §18 question 5;
  - §19 step 8.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 8";
  - "Plan 7g — As built", "Carried, for later plans" (8: the workload verifier and
    `Resolver.Map`);
  - "Plan 7h — As built", the operator notes ("`x509` under `machines` … refused until plans 8
    and 10") and "Carried forward" (Plan 8).
- External: the SPIFFE ID specification §2, and the X.509-SVID specification §4 and §5 (one URI
  SAN, the leaf not a CA). Both are on github.com/spiffe/spiffe, `standards/`.
- The merged plan 7h (`2026-10-06-07h-oidc-and-trust-domains.md`), for house style. This plan is
  written against the code at `cee5a6b`.

**Prerequisite:** the 2026-10-07 fix wave merged (PRs #32–#39; `main` at `cee5a6b`).

## The carries: what plan 8 takes, and what it leaves

| Carry | Taken? | Where, or why not |
|---|---|---|
| `x509` under `broker.identity.machines`, refused at load until plan 8 (7h, Ruling 1; roadmap "Plan 7h — As built") | **Taken** | Rulings 1–4; Tasks 3–6, 8 |
| Enrollment and self-renewal (roadmap "Plan 8"; design §7 option 2, §19 step 8) | **Taken, as a relying party's part**: no issuance in port49 (design §7), a renewal that needs nothing from port49, a late renewal said and counted, the CLI reading its files each run | Rulings 8–10; Tasks 5, 9, 10; L48 |
| Multi-identity subjects (roadmap "Plan 8"; spec §2) | **Taken**: built since plan 4, pinned with a workload principal | Ruling 11; Tasks 5, 11 |
| `username` declared on machine subjects (roadmap "Plan 8"; spec §2, decision 8) | **Taken**: built (`checkMinters`), pinned with a workload principal | Ruling 6; Task 5 |
| Cross-domain username collision at mint (roadmap "Plan 8"; spec §2) | **Taken**: built in 7g as "the declared one stands"; spec §2's "later claimant" corrected to it | Ruling 6; Tasks 1, 5 |
| Unattended config backup, Oxidized, as the day-one consumer (roadmap "Plan 8"; design §18 q5, §19 step 8) | **Taken**: `examples/oxidized/`, measured end to end on five images | Ruling 13; Tasks 12–14; L49 |
| "The workload verifier calls `Resolver.Map` for a workload certificate's directory entry, where decision 16 allows one" (7g "Carried"; 7h "Carried forward") | **Deferred to plan 8b, constrained** (controller's ruling on Q1, on recommendation) | Ruling 5. Today's `group:` subject is a human subject, so a machine matching one would take a human subject's grants (design §7 forbids it); plan 8b builds a machine-scoped group subject and a mapping kind keyed on the SPIFFE ID, with its own lab row (L50). Task 1 names plan 8b in the roadmap |
| `system:serviceaccount:` principals and the `k8s` verifier | **Left to plan 10** | Still refused at load, naming plan 10 |
| Mint by `scope` (design §17: "a device name or a `scope`") | **Left to plan 9** (controller's ruling on Q3) | Written into the roadmap's "Plan 9" at pre-flight. The Oxidized wrapper takes a device list |
| L47 (hosted OIDC providers) | **Left unassigned** | 7h's; nothing here depends on it |

## What this plan does not do

- **No certificate is issued, enrolled, renewed or revoked by port49** (design §7: "port49 is a
  relying party, not a certificate authority"). The lab's CA is step-ca. The docs name the
  operator's CA as the one that does each of these.
- **No directory for a workload** (Ruling 5). A `group:` subject never matches a `spiffe://`
  principal, and nothing about a workload asks a DC. The constrained mapping is plan 8b's.
- **No per-verifier certificate status.** One `broker.certificate_status` covers both anchors
  (Ruling 7).
- **No agent for a workload.** `port49 workload` holds no session and writes no socket. Each run is
  one TLS handshake and its requests.
- **No device behaviour changes.** A workload's token logs in as a person's does, and every reply
  port49d sends is one it sends today.
- **No readiness change.** `/readyz` never follows the workload CA or its CRL.
- **No Kubernetes path.** That is plan 10. Nothing here is Kubernetes-only, and the example runs on
  a plain host under cron.

## Rulings where the design and spec are silent or disagree

Each takes the option that denies more, and is written into the tasks named. Spec §13 records them
as decision 40 (Task 1). Each says whether it rests on data (a specification, a measurement) or
on reasoning. Ryan may override any. The plan's three open questions were ruled by the controller
on recommendation at pre-flight (2026-10-07): Rulings 5 and 7, and mint by `scope` (plan 9).

1. **The verifier** (reasoning: design §7, "a separate trust anchor").
   - **The shape.** `x509` under `broker.identity.machines` takes `trust_anchor_file` (one
     certificate, as `LoadTLSAnchor` requires of the human anchor) and `spiffe_trust_domains`
     (required), and nothing else.
   - **At most one.** The handshake verifies a chain against one pool, and one anchor per list keeps
     "which list accepted it" a comparison.
   - **Rotation.** A workload CA is rotated by anchoring at the root that signs both the old and the
     new issuing CA, or by a planned cut-over, as the human anchor is today.
2. **Exactly one anchor accepts** (reasoning; decision 39 ruling 2's "exactly one must accept",
   for certificates).
   - **The handshake.** `crypto/tls` verifies the client chain against one pool holding both
     anchors, and the `CertificateRequest` names both.
   - **The domain.** The domain is the anchor every verified chain ends at.
   - **Both.** Chains ending at both anchors are `trust_domain_unresolved`. That happens when a
     workload sends the human anchor's subordinate as an intermediate, or when the anchors are
     cross-signed.
   - **At start.** Two anchors that are one certificate, or where one signs the other, are refused,
     naming both files. A certificate under the subordinate would otherwise chain to both and be
     refused at every request, or not, depending on which intermediates its client sends.
   - **Only direct signing is checked at start** (pre-flight M-2). An anchor two levels under the
     other passes the start and is refused, fail closed, only when a client sends the middle
     intermediate. The runtime refusal and the README say so: the two anchors belong in
     unrelated hierarchies.
   - **No human x509 verifier.** On a broker with no human x509 verifier (people use OIDC), a chain
     that does not end at the workload anchor is `trust_domain_unresolved`.
3. **The principal** (data: SPIFFE ID §2; X.509-SVID §4.1 and §5.1).
   - **What it is.** The leaf's one URI SAN, verbatim, read through `spiffe.ParseWorkload`. It must
     be a SPIFFE ID with a path, in one of the verifier's `spiffe_trust_domains`.
   - **What is refused.** Each of these is `identity_unmapped`, 401, the reason said in the
     answer's `detail`:
     - zero or several URI SANs;
     - a URI that is not a SPIFFE ID;
     - an ID with no path, which names the trust domain itself, not a workload;
     - a trust domain the verifier does not list;
     - a leaf that is a CA.
   - **Answered at bind, never as a TLS alert.** The handshake completes, so `port49 workload token`
     prints the broker's reason instead of `tls: bad certificate`.
   - **Email SANs are never read on a workload certificate.** Its legacy principal is `""`, so no
     human's mark names it.
4. **The SPIFFE ID form** (data: SPIFFE ID §2.1–§2.3).
   - **The rules.**
     - The scheme is `spiffe://`, in lower case.
     - The trust domain is one or more of `a-z 0-9 . - _`.
     - Each path segment is non-empty, is one or more of `a-z A-Z 0-9 . - _`, and is never `.` or
       `..`.
     - There is no trailing `/`.
     - At most 2048 bytes in all.
   - **Upper case is refused, not folded.** The path is case-sensitive, so folding the whole string
     would make two IDs one.
   - **One parser.** The same parser checks the policy at load (a `spiffe://` identity outside the
     form is a load error), the verifier at bind, and a revocation's principal.
5. **No directory for a workload in plan 8; its directory groups deferred to plan 8b, constrained**
   (reasoning: design §7 trust domain separation. The controller's ruling on recommendation at
   pre-flight, Q1: deferred, not cut, under the follow-the-spec rule).
   - **What plan 8 builds.** A workload never calls `Resolver.Map`, `Verify` or `Current`. Its
     membership is `policy.MemberOf`: identity subjects alone, as `app:` is today. This is the safe
     default, and it stays the default once plan 8b is built.
   - **Why the deferral is constrained.** Today's `group:` subject is a human subject
     (`buildSubjects` sets `Domain = "humans"`, `load.go`). A workload matching one would take
     `attached_roles.humans` and human `api:` rights, which is what design §7 says MUST NOT
     happen. So plan 8b's mapping reaches only a **machine-scoped group subject**, and a machine
     principal never matches a human `group:` subject.
   - **The texts** (pre-flight I-6). Only decisions 8 ("machine subjects declare one, since they
     have no directory entry") and 16 ("its directory entry may still supply groups") conflict, and
     only in the letter. Spec §5.1.3 and decision 38 ruling 13 record 7g's as-built invariant for
     the machine principals of the time (`app:`), and 7g carried the mapping to plan 8 "where
     decision 16 allows one", so they do not withdraw decision 16.
   - **The amendment.**
     - Decision 16 keeps the mapping, constrained to machine-scoped group subjects, and names plan
       8b. Design §7 keeps "may still map", with the same constraint.
     - Spec §2's and §5.1.3's "never sent to the directory" stay true as built, with "until plan
       8b" added.
     - Decision 8 stands for plan 8. Plan 8b amends it if a workload's username comes from its
       entry.
   - **What plan 8b owes** (the roadmap's "Plan 8b", Task 1 Step 9):
     - a mapping kind keyed on the SPIFFE ID, opt-in per verifier. No existing kind serves:
       `issuer_serial` changes at every renewal, `sid` is AD CS's extension, and the weak kinds need
       `allow_weak` and an `issuers:` pin;
     - its own lab row, L50 (Task 1 opens it): who can write the attribute on AD and on Samba;
     - about 6 to 8 tasks. Ryan may cancel it.
   - **What plan 8 buys.** A directory outage never touches a workload: it mints with every DC down
     and no grace held (Task 5 pins it).
6. **The username** (data: decision 38 ruling 3, plan 7g, a95b9fc).
   - **Declared.** A workload's subject declares `username:` (spec §2; `checkMinters` refuses a
     grant without it).
   - **A collision.** A directory-derived username that any subject declares is `username_collision`
     for the directory's claimant, and the declared username stands.
   - **The authority** (pre-flight M-19). Decision 38 ruling 3 ("A derived username a policy subject
     declares is `username_collision`; the declared one stands"; "not provisional") superseded
     §2's "refuses the *later* claimant" sentence (1fc03e4, 2026-09-05), and §2 was never updated.
     Task 1 corrects §2 to the ruling. That is an editorial correction, not the spec bent to fit
     the code. A supporting reason: order of arrival is not a property the store records, and
     recording it would make the store a 3am dependency of every judgement.
   - **Why it is safer.** A directory administrator who renames a person to `svc-oxidized` cannot
     take the workload's contexts.
   - **What it costs.** A policy author who declares a username a directory user holds locks that
     user out at the next refresh, and CI cannot see it in advance. `username_collision` names
     both claimants. The operator notes say so.
7. **Certificate status covers both anchors** (reasoning; decision 33. The controller's ruling on
   recommendation at pre-flight, Q2).
   - **One block.** One `broker.certificate_status`, required with any x509 verifier, with no
     per-verifier opt-out. Decision 33 specifies none, and one would be a security weakening.
   - **Revisited only** if L48, with its CRL fetch trusted (Task 14 cell 5), measures step-ca's
     CRL as unusable with port49. Task 15 then brings the per-verifier question to Ryan with the
     note.
   - **The CRLs.** A CRL's `issuer_file` is either anchor, or a CA certificate either one signed.
   - **An anchor nothing covers.** One with no CRL under it and no OCSP is said at start (as plan
     7b's re-check R3 says an uncovered issuer). One covered by OCSP alone is said as unchecked for
     that anchor (pre-flight M-18).
   - **Why this is said and Ruling 2 refuses** (pre-flight M-16). Both can follow a CA rotation at a
     restart. Crossed anchors are identity ambiguity, a security fault, so they refuse the start.
     An uncovered anchor is an availability fault: a refused port49d start takes device AAA down
     for every person, over a workload CRL's configuration.
   - **The safe paths** for a workload CA with no CRL, which the start line and the notes name:
     turn the CA's CRL on (step-ca's `crl.enabled`, L48); sync the CRL to a `file:` source; stop a
     workload by principal (`port49 revoke --principal`), which a renewal cannot escape. Never
     `on_unavailable: allow` or `disabled: true`, which would weaken it for people too.
   - **A permanent 503 is final at the client** (pre-flight I-2). The broker answers an uncovered
     issuer 503 `certificate_status_unavailable` with `Retry-After`, but nothing changes until the
     operator adds a source. `port49 workload` treats that answer as final (exit 77); a CRL past
     its next update stays temporary.
8. **Enrollment and renewal belong to the operator's CA** (reasoning; design §7).
   - **A renewal.** A renewed certificate gives the same principal, and nothing in port49 changes.
   - **A mark by certificate does not follow a renewal.** It names `(issuer, serial)`, and a renewal
     brings a new serial.
     - **The fix.** To stop a workload, revoke its principal (`port49 revoke --principal
       spiffe://…`), and revoke the certificate at the CA so it cannot be renewed. L48 measures
       that step-ca refuses to renew a revoked certificate.
     - **Said where it is typed.** `port49 revoke` says so when the revoked certificate's issuer is
       the workload anchor's subject, or an issuer this broker has seen on a verified machine
       chain, which covers an intermediate under the workload anchor (pre-flight M-1).
9. **A late renewal is said, never enforced** (reasoning: design §7, "renews its own certificate
   ahead of expiry"; cert-manager renews at two thirds of a lifetime by default, and step's daemon
   is measured in L48).
   - **The threshold.** A workload certificate presented with less than a quarter of its validity
     left is late.
   - **Said.**
     - The broker says one line per certificate per 24h, from a map of its own, so no other
       line's window prunes it (pre-flight M-3).
     - It counts `port49_workload_certificates_renewal_late_total`, which takes no label. Each
       broker replica counts a certificate once, so alert on its increase (pre-flight M-4).
     - `port49 workload` warns on stderr.
   - **Expiry.** An expired certificate is refused as today (`trust_domain_unresolved`, the validity
     named), and the CLI says "renew it against your CA" before it connects.
10. **The agentless client** (reasoning: design §17).
    - **Its files.** `port49 workload token` reads the certificate and key from their files at every
       run (`keyfile.LoadX509KeyPair`, so a key readable by others is refused). A pair that does not
       match, as a renewal writing one file then the other leaves it for a moment, is read again up
       to three times, 500ms apart.
    - **Its requests.**
      - One request per page of `/v1/config`'s `batch_max`, each page under its own
        `Idempotency-Key`.
      - A page is retried under the same key on 503, on 409 `idempotency_in_progress`, on 429, and
        on a connection that failed. A 503 `certificate_status_unavailable` whose detail says no
        source covers the issuer is final, not retried (Ruling 7; pre-flight I-2).
      - A retry waits `Retry-After` (5s when absent, 60s at most), or 1s doubling to 30s after a
        network error, until `--deadline` (2m).
    - **Its output.** Tokens go to stdout, or to `--out` (0600, written to a temporary file and
      renamed over the target), never to stderr. The format is `--format tsv` (the default) or
      `json`.
    - **Its exit codes** (pre-flight I-1: a wrapper must be able to tell "some written" from
      "nothing written").
      - 0: every device permitted, and written.
      - 1: at least one permitted device written, and some device not: denied, or left unminted by
        a final refusal on a later page.
      - 2: usage.
      - 75 (`EX_TEMPFAIL`): the deadline passed with a page unminted. The pages minted before it
        are written.
      - 77 (`EX_NOPERM`): nothing minted, and a run again will not change that until someone acts:
        the certificate expired or not yet valid, a final refusal before any page minted (a
        revoked principal, an uncovered status), or every device denied. Nothing is written, so
        the last output stays as it was.
11. **A workload's sessions follow the human rules** (reasoning; spec §5.6). Two principals of one
    subject logging in to one device at once is a migration's normal window (spec §2: "a workload
    that legitimately runs in two places at once"). They share the username, so the second login
    replaces the first's context, and the replace is logged (§5.6, as built). The answer is the
    same subject's, so no command's verdict changes.
12. **`/v1/config`'s `methods` names how a person authenticates**: `x509` only with a human anchor.
    A workload reads `batch_max` from it, never `methods`.
13. **The lab** (rule 4 of the register).
    - **L48** measures a real workload CA, step-ca.
    - **L49** measures Oxidized, the day-one consumer, on all five images.
    - **L50** opens here for plan 8b, which measures it: who can write the directory attribute a
      workload's mapping would read. Plan 8 neither measures nor relies on it.
    - **Provisional on L49:** the example's role, and the wrapper's REST calls.
14. **What is logged** (CLAUDE.md).
    - **May be logged.** A SPIFFE ID is anchor-vouched identity, not a credential, so it may be
      logged, through `printsafe.Line`.
    - **Never logged.** A token, from `port49 workload` or the wrapper, and an unverified chain's
      URI.
    - **Never in a metric label.** Neither a SPIFFE ID nor a device.
15. **Revocation and explain take `spiffe://` principals** (reasoning).
    - `normalPrincipal` accepts a `spiffe://` ID verbatim, after `spiffe.ParseWorkload`.
    - `system:serviceaccount:` stays refused until plan 10.
    - `port49 directory forget` still takes only `user:`.
16. **A `spiffe://` identity no verifier can give mints for no one, and the start says so** (as
    decision 38 ruling 17 says of group subjects without a directory). That is a policy naming one
    with no machine x509 verifier, or one whose trust domain the verifier does not list. The policy
    still loads.

### Questions for Ryan

None. The plan's three questions were ruled by the controller on recommendation at pre-flight
(2026-10-07), each recorded in decision 40 (Task 1 Step 5), and Ryan may override any:
- **Q1, a workload certificate's directory groups:** deferred to plan 8b, constrained to
  machine-scoped group subjects (Ruling 5). Deferred, not withdrawn.
- **Q2, a per-verifier certificate-status opt-out:** not taken; one block (Ruling 7). Revisited only
  if L48, with its CRL fetch trusted, measures step-ca's CRL unusable.
- **Q3, mint by `scope` (design §17):** plan 9's, written into the roadmap's "Plan 9" at pre-flight.

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 2**: two anchors that are one certificate, or where one signs the other, refuse the
  start. An operator whose users and workloads share one issuing CA must split them first.
- **Ruling 5**: plan 8b, if Ryan keeps it, is about 6 to 8 tasks and a lab row on AD and Samba.
- **Ruling 6** corrects spec §2's collision wording to decision 38 ruling 3, which superseded it.
- **Ruling 8**: a mark by certificate does not survive a workload's renewal. The revoke answer
  says so.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **A broker start with a workload verifier** (Task 8):

  ```
  port49-broker: identity: humans: x509 (trust anchor /etc/port49/broker/users-ca.pem); oidc https://sso.corp.example.com/realms/corp (client_id port49-cli, principal from email in corp.example.com, email_verified required; algorithms RS256)
  port49-broker: identity: machines: x509 (trust anchor /etc/port49/broker/workloads-ca.pem; SPIFFE trust domains corp.example.com; principal: the certificate's one URI SAN)
  port49-broker: identity: workload certificates are issued and renewed by your CA, never by port49; one presented with under a quarter of its validity left is said here and counted in port49_workload_certificates_renewal_late_total
  ```

  A policy naming a SPIFFE ID no verifier can give:

  ```
  port49-broker: policy: 1 workload identities mint for no one: spiffe://lab.example.net/host/x (subject svc_x): no machines x509 verifier lists trust domain lab.example.net
  ```

  An anchor no certificate status source covers:

  ```
  port49-broker: broker: certificate status: every certificate under CN=Workloads Issuing CA (broker.identity.machines' x509 trust_anchor_file) will be refused: no crls entry is that anchor or a CA it signed, and no ocsp is set; turn the CA's CRL on and name it in crls, or sync it to a file: source
  ```

  An anchor covered by OCSP alone (pre-flight M-18):

  ```
  port49-broker: broker: certificate status: certificates under CN=Workloads Issuing CA (broker.identity.machines' x509 trust_anchor_file) are covered by OCSP alone, unchecked for this anchor: one with no OCSP URL, or one its responder does not answer for, is refused
  ```
- **A start refused** (Task 8):

  ```
  port49-broker: broker.identity.machines' x509 trust_anchor_file: CN=Corp Root signs CN=Workloads Issuing CA (broker.identity.humans' x509 trust_anchor_file): a certificate under the one chains to both anchors and is refused at every request; anchor each list at its own issuing CA
  port49-broker: broker.identity.machines' x509 trust_anchor_file: holds the same certificate as broker.identity.humans' x509 trust_anchor_file; a certificate it verifies would be a person's and a workload's at once
  ```
- **New config refusals** (Task 3):
  - `broker.identity.machines: at most one x509 verifier (the broker verifies a workload's chain against one anchor)`;
  - `broker.identity.machines[0]: type x509 takes trust_anchor_file and spiffe_trust_domains alone`;
  - `broker.identity.machines[0].spiffe_trust_domains is required: the SPIFFE trust domains whose workloads this anchor may name (spiffe://<trust domain>/<path>)`;
  - `broker.identity.machines[0].spiffe_trust_domains: "Corp.example.com" is not a SPIFFE trust domain (…)`;
  - `broker.identity.humans[0]: type x509 takes trust_anchor_file alone` (a human x509 verifier
    given `spiffe_trust_domains`);
  - `broker.identity.machines[1].spiffe_trust_domains is an x509 machine verifier's` (on an oidc
    verifier);
  - `broker.identity's humans and machines trust_anchor_file are one file: …`.
- **A workload certificate refused at bind** (Task 6), the answer's body:

  ```
  {"error":"identity_unmapped","detail":"broker: the workload certificate names no principal: spiffe://lab.example.net/host/x is outside broker.identity.machines spiffe_trust_domains (corp.example.com)"}
  ```

  and once per 10s in the process log:

  ```
  port49-broker: broker: answering a connection from 10.20.0.9 identity_unmapped and closing it before it bound: broker: the workload certificate names no principal: it carries 2 URI SANs; exactly one SPIFFE ID names a workload
  ```
- **A late renewal** (Task 5), once per certificate per 24h:

  ```
  port49-broker: identity: workload certificate spiffe://corp.example.com/host/oxidized-01 (serial 4f2a9c) expires 2026-10-08T03:00:00Z with under a quarter of its validity left: its renewal is late; check the workload's renewal against its CA
  ```
- **`port49 revoke` of a workload certificate** (Task 7) adds:

  ```
  this certificate's issuer is the workload trust anchor (broker.identity.machines): the workload renews it under a new serial this mark does not name; revoke its principal too (port49 revoke --principal spiffe://…), and revoke the certificate at your CA so it cannot be renewed
  ```
- **`port49 workload token`** (Task 10), on stderr:

  ```
  port49 workload token: the certificate /etc/oxidized/port49.pem expires 2026-10-08T03:00:00Z (in 2h0m) with under a quarter of its validity left: its renewal is late; renew it against your CA
  port49 workload token: the certificate /etc/oxidized/port49.pem expired at 2026-10-08T03:00:00Z: renew it against your CA (only the first enrollment is manual)
  port49 workload token: core-sw01: deny no_grants_matched
  port49 workload token: the broker did not answer within 2m0s (the last answer: 503 store_unavailable: the broker's store did not answer; the agent retries): 3 of 5 devices were not minted; run again
  port49 workload token: 401 credential_revoked: …: 2 of 5 devices were not minted
  port49 workload token: 503 certificate_status_unavailable: the broker cannot establish this certificate's revocation status (no fresh CRL or OCSP answer covers "CN=Workloads Issuing CA"); try again: 5 of 5 devices were not minted
  ```

  The last is final (exit 77), whatever its "try again" says: no source covers the workload
  anchor until the operator adds one (Ruling 7; pre-flight I-2).
- **The Oxidized wrapper** (Task 12), on stderr:

  ```
  port49-oxidized-run: no tokens minted (port49 workload token exited 77); Oxidized keeps its last router.db and was not reloaded
  port49-oxidized-run: not every node was minted (port49 workload token exited 75: the broker did not answer in time); the minted nodes are queued, the rest wait for the next window
  port49-oxidized-run: fw-07: platform paloalto_panos has no Oxidized model in this script; skipped
  port49-oxidized-run: core/sw#1: a node name outside A-Z a-z 0-9 . _ - is never put in a REST path; skipped
  ```
- **New metric:** `port49_workload_certificates_renewal_late_total` (counter, no labels).

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module**.
- snake_case everywhere it is data: YAML keys (`spiffe_trust_domains`), JSON log keys, config, metric
  names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan adds
  none.** It widens `identity_unmapped`, `trust_domain_unresolved` and `username_collision` in the
  spec table first (Task 1).
- The log never contains a token, password, challenge or response. Credentials appear only as
  `credential_sha256`. **An unvalidated body is never logged.**
  - **A workload's chain.** A chain no anchor verified is never quoted. A verified certificate's
    SPIFFE ID, issuer, serial and fingerprint may be, through `printsafe.Line`.
  - **Tokens.** `port49 workload token` writes tokens to stdout or `--out` alone. Its errors, its
    warnings and the wrapper's lines never carry one.
- No device identity and no principal in metric labels.
- **Fail closed, never widen:**
  - two anchors accepting one chain is a refusal;
  - a workload principal never reaches the directory, and never matches a `group:` subject;
  - a URI SAN that is not exactly one SPIFFE ID in a listed trust domain names no principal;
  - an upper-case SPIFFE ID is refused, never folded.
- The daemon never reads a certificate. Nothing on the TACACS+ path waits on the workload CA.
- Verify with `make test && make vet`, and `make test-race` on every touched package, and report
  the real output. Every test that speaks to a real CA, Oxidized or a device is a lab test
  (`//go:build lab`, Tasks 13 and 14, on beehive), so `go test ./...` needs none.
- **Deployment is not prescriptive.** The workload path runs from cron on a plain host. Nothing
  requires Kubernetes, and nothing requires the workload verifier. Without it, plan 7h's behaviour
  is unchanged.
- **Readiness never follows the workload CA.** No task adds a CA or CRL condition to `/readyz`.
- The lab register rules (CLAUDE.md 1–4).
  - L48 and L49 open in Task 1, and L50 for plan 8b, which plan 8 never cites as measured.
  - Each closes in Task 14 only if its notes exist with platform, image version, observation and a
    capture pointer, for every platform its row names. Rule 5: a row with one platform open stays
    open.
  - The example's role and the wrapper's REST calls are provisional on L49 until it closes.
- Conventional Commits; branch `feature/workload-certificates`. Commit messages end with
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc`.
- Implementers never run `git checkout`, `restore`, `reset`, `stash` or `clean`.

## Review Focus

The six inputs or conditions no task's tests exercise by accident and most likely to bite a person,
with the test that pins each:

1. **A workload certificate that chains to the human anchor too.**
   - **The inputs:**
     - a workload anchor that is a subordinate of the human anchor, with a client that sends the
       subordinate as an intermediate;
     - the same anchor file under both lists;
     - a cross-signed pair.
   - **Expected:** refused at start where the files show it, and `trust_domain_unresolved` at
     every request where only the chains do. Never a person, never a workload by chance.
   - **Pinned by** Task 4's `TestAChainEndingAtBothAnchorsIsRefused` and Task 8's
     `TestAnAnchorSignedByTheOtherRefusesTheStart` and `TestTheSameAnchorTwiceRefusesTheStart`.
2. **A URI SAN that almost names a workload.**
   - **The inputs:**
     - `SPIFFE://corp.example.com/x`;
     - `spiffe://Corp.example.com/x`;
     - `spiffe://corp.example.com`;
     - `spiffe://corp.example.com/x/`;
     - `spiffe://corp.example.com/a/../b`;
     - `spiffe://corp.example.com/a%2fb`;
     - `spiffe://user@corp.example.com/x`;
     - `https://corp.example.com/x`;
     - two URI SANs;
     - a URI SAN beside an email SAN;
     - a CA certificate presented as a leaf.
   - **Expected:** each refused `identity_unmapped`, except the email SAN, which is ignored. None
     becomes a principal by folding or trimming.
   - **Pinned by** Task 2's `TestParseRefuses` and Task 4's `TestTheWorkloadPrincipalTable`,
     `TestAWorkloadsEmailSANIsIgnored` and `TestACACertificateIsNoWorkload`.
3. **A workload under a directory that does not answer.**
   - **Expected:** it mints with every DC down and no grace held, and the resolver is never asked.
     A person on the same broker is answered `directory_unavailable` as before.
   - **And when the wiring is wrong** (pre-flight I-4): a listener given `Map` without `Caller`
     serves nothing, and `BindMap` refuses a machine chain `identity_unmapped` without asking.
   - **Pinned by** Task 5's `TestAWorkloadMintsWhileTheDirectoryIsDown`, and Task 6's
     `TestAWorkloadBindsWithoutAskingTheDirectory` (through `Broker.Wire`, as both daemons wire
     it), `TestAListenerWithMapButNoCallerServesNothing` and `TestBindMapNeverMapsAWorkload`.
4. **A renewal on a bad day.**
   - **The inputs:**
     - the certificate rewritten between the CLI's read of the certificate and its read of the key;
     - the CA down so a renewal never comes;
     - a certificate one second past `NotAfter`;
     - a revoked certificate's renewed successor.
   - **Expected:**
     - the pair read again, never a mismatched handshake;
     - the late-renewal line and counter, then expiry said in plain words, exit 77, and Oxidized's
       last `router.db` left alone (pre-flight I-1);
     - the successor mints;
     - a revocation by principal refuses both.
   - **Pinned by** Task 9's `TestAMismatchedPairIsReadAgain` and `TestAnExpiredCertificateNeverConnects`,
     Task 10's `TestAnExpiredCertificateIsFinal`, Task 12's `TestAnExpiredCertificateLeavesOxidizedAlone`,
     Task 5's `TestALateRenewalIsSaidOncePerDay`, Task 11's `TestARenewedCertificateMintsAsTheSamePrincipal`,
     and Task 7's `TestARevokedPrincipalRefusesEveryCertificateOfTheWorkload`.
5. **A cron run while the broker or its store is down, or answers part of a sweep.**
   - **Expected:**
     - retried under the same `Idempotency-Key` until the deadline, exit 75, no token printed for
       an unminted page;
     - the pages minted before it written, and queued by the wrapper; with none, Oxidized's last
       `router.db` left alone and not reloaded;
     - a final refusal on page two writes page one and exits 1;
     - an uncovered certificate status is final (77), never "run again" every night.
   - **Pinned by** Task 9's `TestARetryReusesTheKeyAndHonoursRetryAfter`,
     `TestTheDeadlineEndsWithTheUnmintedDevices`, `TestAnUncoveredCertificateStatusIsFinal` and
     `TestAStaleCRLIsRetried`; Task 10's `TestExitCodesTellCronWhatHappened` and
     `TestAFinalRefusalOnPageTwoWritesPageOne`; Task 12's `TestATemporaryFailureLeavesOxidizedAlone`
     and `TestAPartialRunQueuesWhatWasMinted`.
6. **Two identities of one subject on one device at once.**
   - **The inputs:** `spiffe://…/oxidized-01` and `app:oxidized`, both in `svc_oxidized`, logged in
     to `leaf1` together during a migration.
   - **Expected:** both mint the same username; the second login replaces the first's context and
     the replace is logged; each command's verdict is the subject's.
   - **Pinned by** Task 5's `TestTwoIdentitiesOfOneSubjectMintOneUsername` and Task 11's
     `TestTwoIdentitiesOfOneSubjectShareTheDevice`.

## Conflict scan: where tasks share a file or an interface

- `internal/broker/broker.go`: Task 5 alone (`authenticate`, `callerOf`, `legacyOf`, `Broker.Workload`).
- `internal/broker/server.go`: Task 5 (`Server`'s pool and `VerifyConnection`) and Task 8
  (`ReadAnchor` factored out of `LoadTLSAnchor`), in that order.
- `internal/broker/listen.go`: Task 6 alone (`Listener.Caller`, `Broker.Wire`, `ErrUnwired`). Its
  `startServerWith` test helper is Task 6's; Task 11 uses port49d's real listener instead.
- `internal/broker/member.go` (`BindMap`) and `member_test.go` (`serveThroughWith`): Task 6 alone.
- `internal/broker/workload.go`: Task 4 creates it; Task 5 (`noteRenewal`, `lateOnce`) and Task 7
  (`noteIssuer`, `Issued`) add to it, in that order.
- `internal/broker/revoke.go`: Task 7 alone.
- `internal/broker/certcheck.go`: Task 5 (`unknownClass` reads `api.UncoveredStatus`).
- `internal/broker/api/api.go`: Task 5 (`LateRenewal`, `UncoveredStatus`). Tasks 9 and 10 read it.
- `internal/daemon/metrics/metrics.go`: Task 5 alone.
- `internal/certstatus/chain_test.go`: Task 5 alone (one test; no certstatus code changes).
- `internal/config/identity.go`, `config.go`: Task 3 alone.
- `internal/oidc/config.go`: Task 3 (`X509Machine`).
- `internal/policy/load.go`, `member.go`: Task 2 alone.
- `internal/port49d/main.go`, `brokerd.go`, `certstatus.go`, `identity.go`: Task 8 alone.
- `internal/testpki/testpki.go`: Task 7 (`CA.IssueCA`) and Task 11 (`WriteWorkloadLab`,
  `RenewWorkload`, `WriteWorkloadLabFrom`), in that order. Tasks 8 and 13 read them.
- `cmd/port49/main.go`: Task 10 alone.
- Spec §2, §5.1.3, §5.1.4, §5.7, §13, §14, §15 and design §7, §17: Task 1 writes them; Task 14
  closes the rows; Task 15 writes "as built".
- `docs/superpowers/plans/README.md`: Task 1 ("Plan 8b") and Task 15 ("Plan 8 — As built"). "Plan
  9"'s scope entry was written at pre-flight, on `main`.

## Running the lab (Tasks 13 and 14)

- On beehive, from a pinned worktree of the branch at the commit under test. Copy any raw captures
  to `main`'s `tests/lab/captures/` before removing the worktree (the labpcap audit).
- Run a background stall watchdog during each run, and re-arm it on wake.
- Before a run: `df -h` and `sg docker -c 'docker compose version'` (≥ v2.24.4).
- Docker is reached as `sg docker -c '…'` on beehive. The lab's Go tests call `docker` through the
  `dockerCmd` helper that prefixes it.
- L48 needs no device: `make lab-workload` (step-ca as a container). L49 needs containerlab and the
  five images: `PORT49_LAB_PLATFORMS=<one> make lab-oxidized`, one platform per invocation, as
  `make lab` does.
- `make build` first: L49 runs the built `bin/port49` as the cron job would.

## File Structure

**Create:**
- `internal/spiffe/spiffe.go` (+ `spiffe_test.go`): `ID`, `Parse`, `ParseWorkload`,
  `CheckTrustDomain`, `Scheme`, `MaxLen`, `ErrNotSPIFFE`.
- `internal/broker/workload.go` (+ `workload_test.go`): `Workload`, `CertCaller`, `CertCallerOf`,
  `machineChain`, `WorkloadPrincipal`, `ErrWorkloadUnmapped`, `DomainHumans`, `DomainMachines`,
  `noteRenewal`.
- `internal/broker/workload_mint_test.go`: the handler path (Task 5).
- `internal/broker/workload_listen_test.go`: the real listener (Task 6).
- `internal/workload/client.go` (+ `client_test.go`): the agentless client.
- `cmd/port49/workload.go` (+ `workload_test.go`): `port49 workload token` and `identity`.
- `internal/port49d/workload_test.go`: the start lines and refusals (Task 8).
- `internal/port49d/workload_e2e_test.go`: through `run` (Task 11).
- `examples/oxidized/port49-oxidized-run`, `examples/oxidized/config`,
  `examples/oxidized/policy.yaml`, `examples/oxidized/README.md`,
  `examples/oxidized/run_test.go`.
- `tests/lab/workload/compose.yaml`: step-ca for L48. `tests/lab/compose/oxidized.yaml`: the
  overlay for L49.
- `tests/lab/l48_test.go`, `tests/lab/l49_test.go`, `tests/lab/workload_unit_test.go`
  (`//go:build lab`).

**Modify:**
- `internal/policy/load.go` (`identityDomain`), `internal/policy/member.go` (`SPIFFEIdentities`).
- `internal/oidc/config.go` (`X509Machine`, `Config.X509Machine`).
- `internal/config/identity.go`, `internal/config/config.go`, `internal/config/identity_test.go`.
- `internal/broker/broker.go`, `server.go`, `listen.go`, `member.go`, `revoke.go`, `certcheck.go`,
  `api/api.go`; `internal/broker/member_test.go` (`serveThroughWith` sets `Caller`).
- `internal/daemon/metrics/metrics.go`.
- `internal/port49d/main.go`, `brokerd.go`, `certstatus.go`, `identity.go`, `certstatus_test.go`.
- `internal/testpki/testpki.go`.
- `cmd/port49/main.go` (usage, dispatch).
- `Makefile` (`lab-workload`, `lab-oxidized`).
- `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`.
- `tests/lab/README.md`.
- `docs/superpowers/plans/README.md` (Task 1: "Plan 8b"; Task 15: "Plan 8 — As built"; the
  status line is the controller's).

---

### Task 1: The spec and the design say what plan 8 builds and what plan 8b owes; L48, L49 and L50 open

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §2, §5.1.3, §5.1.4, §5.7 (three reason
  rows), §13 (decisions 16 and 39 amended, 40 new), §14, §15 (L48, L49, L50)
- Modify: `docs/design/2026-08-21-port49-design.md`: §7, §17
- Modify: `docs/superpowers/plans/README.md`: a "Plan 8b" section after "Plan 8"

**Interfaces:**
- Consumes: Rulings 1–16 above, and the controller's rulings on Q1–Q3.
- Produces: decision 40, which every later task cites; the widened reason rows (Tasks 4–6 cite
  them); register rows L48 and L49 (Task 14 closes them where measured) and L50 (plan 8b's); the
  roadmap's "Plan 8b".

This task is docs only. Each step is an edit with the exact text. Where a step says "replace", the
old text is quoted and appears once; check with `grep -n` before editing.

- [ ] **Step 1: §2, the workload row, the identity forms, the username collision**

In §2's principal table, replace the row

```markdown
| workload x509 | the SAN URI verbatim — `spiffe://…` |
```

with

```markdown
| workload x509 | the leaf's one URI SAN, verbatim: a SPIFFE ID with a path (`spiffe://<trust domain>/<path>`, SPIFFE ID §2), its trust domain one of `broker.identity.machines[].spiffe_trust_domains`; the leaf not a CA. Zero or several URI SANs, another URI, an ID with no path, or an unlisted trust domain is `identity_unmapped` (§13 decision 40 rulings 3 and 4). Its email SANs are never read |
```

In the paragraph beginning "Identities from different trust domains MUST remain distinguishable",
after the sentence that ends, wrapped across two lines as the spec holds it,

```markdown
`user:alice@example.com`, `spiffe://…`, `system:serviceaccount:…`, `app:<client_id>` — and a
string in no recognized form is itself a load error.
```

(find it with `grep -n "string in no recognized form is itself a load error"`), add:

```markdown
A `spiffe://` identity must be a SPIFFE ID with a path, in the form SPIFFE ID §2 gives (lower-case
scheme and trust domain; path segments of `A-Z a-z 0-9 . - _`, never empty, `.` or `..`; no
trailing `/`; at most 2048 bytes): one outside it is a load error, never folded to fit (§13
decision 40 ruling 4).
```

In "The device-facing username", replace

```markdown
**Machine identities have no directory entry**, so the subject declares one:
```

with

```markdown
**Machine identities have no directory entry**, so the subject declares one. A machine principal is
never sent to the directory, at mint or by the scheduled refresh, until plan 8b builds a workload
certificate's opt-in directory mapping, and never matches a human `group:` subject, then or after
(§13 decisions 16 and 40 ruling 5):
```

and replace

```markdown
directory at mint, so a machine subject declaring `username: alice` collides with a human
`alice` only at runtime; the broker checks at mint and refuses the *later* claimant with a
reason naming both.
```

with

```markdown
directory at mint, so a machine subject declaring `username: alice` collides with a human
`alice` only at runtime; the broker checks at bind, at mint and at every refresh, and refuses the
directory's claimant `username_collision` with a reason naming both: the declared username stands,
whichever came first, so a directory administrator who renames a person cannot take a workload's
contexts (§13 decision 38 ruling 3; decision 40 ruling 6).
```

- [ ] **Step 2: §5.1.3, "until plan 8b"; §5.1.4, a workload certificate's revocation and renewal**

In §5.1.3, replace

```markdown
A machine principal (`spiffe://`,
`system:serviceaccount:`, `app:`) is never sent to the directory: it is judged by the policy alone
and stamped with the pass's instant.
```

(it wraps as quoted; find it with `grep -n "is never sent to the directory: it is judged"`) with

```markdown
A machine principal (`spiffe://`,
`system:serviceaccount:`, `app:`) is never sent to the directory, until plan 8b builds a workload
certificate's opt-in directory mapping (§13 decisions 16 and 40 ruling 5): it is judged by the
policy alone and stamped with the pass's instant.
```

In §5.1.4, after the paragraph that ends "an OIDC back-channel logout, by `sid` or `sub`, with plan 7h, as no
mark (below).", add:

```markdown
**A workload certificate, as built (plan 8; §13 decision 40).** A workload certificate is a
certificate credential like a person's: `method: cert`, its fingerprint, issuer, serial and
subject, and the marks, `certificate_status` and the listener's copy apply to it unchanged. Its
principal is its SPIFFE ID, so a renewal, which brings a new serial under the same ID, needs
nothing from port49, and a mark by certificate does not follow it: to stop a workload, revoke its
principal (`port49 revoke --principal spiffe://…`), which refuses every certificate it renews to,
and revoke the certificate at its CA so it cannot be renewed. `port49 revoke` says so when the
certificate's issuer is the workload anchor's subject, or an issuer the broker has seen on a
verified workload chain. A workload certificate presented with less
than a quarter of its validity left is said once a day and counted in
`port49_workload_certificates_renewal_late_total`: its renewal is late, and expiry is refused
`trust_domain_unresolved` as a person's is.
```

- [ ] **Step 3: §5.7, three reason rows widened**

In the `identity_unmapped` row, after "or a weak mapping's issuer is not one its `issuers:` pins
(design §7);", add:

```markdown
or a certificate the workload anchor verified names no workload: zero or several URI SANs, a URI that is not a SPIFFE ID with a path, a trust domain outside `broker.identity.machines[].spiffe_trust_domains`, or a leaf that is a CA (§13 decision 40), answered 401 at bind over HTTP, never as a TLS alert;
```

In the `trust_domain_unresolved` row, after "`mint`: no configured verifier accepted the credential
(design document §7);", add:

```markdown
or the certificate's verified chains end at both the human and the workload trust anchor, or, on a broker with no human x509 verifier, do not end at the workload anchor (§13 decision 40 ruling 2);
```

In the `username_collision` row, replace "or the directory derives a username a policy subject
declares," with "or the directory derives a username a policy subject declares (the declared one
stands, whichever came first; §13 decision 38 ruling 3, decision 40 ruling 6),".

- [ ] **Step 4: §13, decisions 16 and 39 amended**

In decision 16, replace

```markdown
There is no password path for service accounts: an LDAP-authenticated account moves to a
workload certificate, a cluster token, or one OIDC application per service, and its directory
entry may still supply groups through the certificate-to-directory mapping. (§2, design
document §7)
```

with

```markdown
There is no password path for service accounts: an LDAP-authenticated account moves to a
workload certificate, a cluster token, or one OIDC application per service, and its directory
entry may still supply groups through the certificate-to-directory mapping. *Amended by decision
40 ruling 5:* a workload's directory groups, when built, come only through a machine-scoped group
subject, never a `group:` subject, which is a human subject (design document §7: a workload MUST
NOT inherit a human principal's grants), and through a mapping keyed on the workload's SPIFFE ID.
Plan 8 builds none; plan 8b owns it, with its own lab row (L50). (§2, design document §7)
```

In decision 39 ruling 1, replace "`x509` under `machines` and `k8s` are refused, plans 8 and
10." with "`x509` under `machines` is plan 8's (decision 40); `k8s` is refused, plan 10."

- [ ] **Step 5: §13, decision 40**

After decision 39 (and before "## 14."), add:

```markdown
**40. Workload certificates: one more anchor, the chain's end decides the domain, a SPIFFE ID or
no principal, no directory until plan 8b, and a renewal port49 does not need.** *Plan 8,
2026-10-07.* Rulings rest on reasoning unless they say data. Rulings 5 and 7, and mint by `scope`,
were the plan's open questions; the controller ruled each on recommendation at pre-flight, and
Ryan may override any.

- **1. The verifier.** `x509` under `broker.identity.machines`: `trust_anchor_file` (one
  certificate) and `spiffe_trust_domains` (required), nothing else; at most one. Task 3.
- **2. Exactly one anchor accepts.** The handshake verifies against one pool of both anchors; the
  domain is the anchor every verified chain ends at; chains ending at both are
  `trust_domain_unresolved`. Two anchor files holding one certificate, or one anchor signing the
  other directly, refuse the start; an anchor further down the other's hierarchy is refused only
  at a request whose chain shows it, so the two belong in unrelated hierarchies. On a broker with
  no human x509 verifier, a chain not ending at the workload anchor is `trust_domain_unresolved`.
  Tasks 4, 5 and 8.
- **3. The principal** (data: X.509-SVID §4.1, §5.1). The leaf's one URI SAN, verbatim, a SPIFFE
  ID with a path in a listed trust domain; the leaf not a CA; email SANs never read; else
  `identity_unmapped`, 401 at bind, never a TLS alert. Tasks 4 and 6.
- **4. The SPIFFE ID** (data: SPIFFE ID §2.1–§2.3). `spiffe://`, a trust domain of `a-z 0-9 . - _`,
  path segments of `A-Z a-z 0-9 . - _` (none empty, `.` or `..`), no trailing `/`, at most 2048
  bytes; upper case is refused, never folded. One parser for the policy, the verifier and a
  revocation. Task 2.
- **5. No directory for a workload in plan 8; its directory groups are plan 8b's, constrained.**
  Plan 8 builds no directory path for a workload: never `Resolver.Map`, `Verify` or `Current`;
  never a `group:` subject; the username declared. That is the default, and stays the default once
  plan 8b is built. Decision 16's mapping is deferred, not withdrawn: plan 8b builds it opt-in per
  verifier, keyed on the SPIFFE ID (no existing mapping kind survives a renewal or applies off AD
  CS), reaching only a machine-scoped group subject, never a human `group:` subject (design §7),
  with its own lab row, L50. Decisions 8 and 16 conflict only in the letter; §5.1.3 and decision 38
  ruling 13 record 7g's as-built for the machine principals of the time. *The controller's ruling
  on recommendation (plan 8's pre-flight Q1), deferring rather than cutting under the
  follow-the-spec rule; Ryan may cancel plan 8b.* Tasks 1 and 5.
- **6. The declared username stands.** A directory-derived username a subject declares is
  `username_collision` for the directory's claimant, whichever came first. The authority is
  decision 38 ruling 3 (plan 7g, a95b9fc), which superseded §2's "later claimant" sentence; §2 is
  corrected to it, an editorial correction. Declaring a username a directory user holds locks that
  user out at the next refresh, and `username_collision` names both. Tasks 1 and 5.
- **7. One certificate status for both anchors, with no per-verifier opt-out.** Required with any
  x509 verifier; a CRL's issuer is an anchor or a CA one signed; an anchor no CRL covers is said at
  start, never a refused start (crossed anchors, ruling 2, are identity ambiguity, a security
  fault; an uncovered anchor is an availability one, and a refused start takes device AAA down for
  everyone). Decision 33 gives no opt-out, and one would weaken status checking: *the controller's
  ruling on recommendation (plan 8's pre-flight Q2)*, revisited only if L48, its CRL fetch trusted,
  measures step-ca's CRL unusable with port49. A 503 for an issuer no source covers is final at
  `port49 workload`. Tasks 3, 8 and 9.
- **8. The CA enrolls and renews; port49 relies.** A renewal gives the same principal; a mark by
  certificate does not follow it, and `port49 revoke` says so for the workload anchor's issuer and
  any issuer seen on a verified workload chain. Task 7; L48.
- **9. A late renewal is said, never enforced.** Under a quarter of the validity left: one line per
  certificate per 24h and `port49_workload_certificates_renewal_late_total` at each broker replica;
  a warning from `port49 workload`. Tasks 5 and 9.
- **10. The agentless client.** `port49 workload token` and `identity`: the files read each run, a
  mismatched pair read again up to three times; one request per `batch_max` page under its own
  `Idempotency-Key`, retried under it on 503 (but an uncovered status), 409
  `idempotency_in_progress`, 429 and a failed connection, within `--deadline` (2m); tokens to
  stdout or `--out` (0600, renamed into place); exit 0 (all written), 1 (some written, some not),
  2 (usage), 75 (temporary; the pages minted are written) or 77 (nothing minted, final). Tasks 9
  and 10.
- **11. A workload's device sessions follow §5.6.** Two principals of one subject on one device
  replace each other's context, logged; the verdicts are the subject's. Tasks 5 and 11.
- **12. `/v1/config`'s `methods`** names a person's: `x509` only with a human anchor. Task 5.
- **13. The lab.** L48 (step-ca) and L49 (Oxidized on five images); `examples/oxidized` is
  provisional on L49. L50 opens for plan 8b. Tasks 12 to 14.
- **14. What is logged.** A SPIFFE ID, through `printsafe.Line`; never a token; never an unverified
  chain's URI; no SPIFFE ID or device in a metric label. Tasks 5, 6, 9, 10 and 12.
- **15. Revocation and explain take `spiffe://`.** `normalPrincipal` accepts a SPIFFE ID verbatim;
  `system:serviceaccount:` stays plan 10's. Task 7.
- **16. A `spiffe://` identity no verifier can give mints for no one, and the start says so.** Task
  8.

*Ruled by the controller on recommendation (plan 8's pre-flight, 2026-10-07; Ryan may override
any).* **Q1:** a workload certificate's directory groups are deferred to plan 8b, constrained to
machine-scoped group subjects, not withdrawn (ruling 5). **Q2:** no per-verifier certificate-status
opt-out (ruling 7). **Q3:** mint by `scope` (design §17) is plan 9's, which writes its spec text
first.
```

- [ ] **Step 6: §14, the assertions**

In "Session lifetime and revocation", after the API rights bullet, which ends, wrapped as the spec
holds it,

```markdown
  every subject carrying `api:` appears
  in the CI report.
```

(find it with `grep -n "every subject carrying \`api:\` appears"`), add:

```markdown
- **Workload certificates** (§13 decision 40): a certificate under the workload anchor mints as its
  one SPIFFE ID, never as a person, and with every directory server down; one whose chains end at
  both anchors is refused `trust_domain_unresolved`; one with zero or two URI SANs, an upper-case
  or path-less ID, or an unlisted trust domain is refused `identity_unmapped` at bind over HTTP; a
  renewed certificate mints as the same principal; a revocation by principal refuses every
  certificate of the workload, and one by certificate is said not to follow a renewal; a
  `spiffe://` principal and an `app:` principal of one subject mint one username; a directory
  username a subject declares is refused `username_collision` and the declared one mints; a
  scope's `attached_roles.machines` compose into a workload's grant and `attached_roles.humans` do
  not.
```

- [ ] **Step 7: §15, L48, L49 and L50**

After the L47 row, add:

```markdown
| **L48** | A workload CA's behaviour with port49's workload verifier (plan 8). On step-ca: whether a certificate requested for a SPIFFE ID carries it as its one URI SAN, with `clientAuth`, not a CA; whether `step ca renew` keeps the ID and the key and changes the serial, and port49 mints for the renewed certificate with no change; when `step ca renew --daemon` renews, as a fraction of the lifetime; with step-ca stopped, whether port49 mints until `NotAfter` and refuses after, and when the late-renewal line comes; whether step-ca's CRL (`crl.enabled`) is DER, issued by the intermediate, and loaded by port49's `certificate_status` over https with the broker trusting step-ca's root (`SSL_CERT_FILE`), and whether a `step ca revoke` reaches port49 within `refresh_interval` and stops a renewal of the revoked certificate; whether a provisioner's x509 name policy allowing one URI refuses a request for another SPIFFE ID. | §13 decision 40 rulings 7–9 (ruling 7's revisit condition); the workload anchor's recommended placement (the intermediate); the README's advice to restrict the provisioner to the host's own ID | step-ca | open — added 2026-10-07 (plan 8) |
| **L49** | Oxidized as the day-one consumer of minted tokens (plan 8): the commands each model (`eos`, `nxos`, `ios`, `junos`) sends at login and during a backup, as port49 receives them; whether Oxidized reads a node's username and password from its CSV source at each `/reload` and uses them at the node's next run (`/node/next/<node>`); with a token past its TTL, how many authentications one node's run costs and what Oxidized records; that no token appears in Oxidized's log at its default level; and that a backup made with a minted token holds the device's configuration, the decision log naming the workload's principal. | `examples/oxidized` (the role and the wrapper's REST calls; §13 decision 40 ruling 13) | EOS, NX-OS, IOS-XE, Junos (vJunos-router, vSRX) | open — added 2026-10-07 (plan 8) |
| **L50** | Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16 and 40 ruling 5): on Windows AD and on Samba AD, whether an attribute holding a SPIFFE ID on a service account's entry can be written by the entry itself (`SELF`), by an account operator, or by a delegated OU administrator, under the default ACLs and under the ACL plan 8b's docs prescribe; and whether a write is in the directory's audit log. Until it closes, plan 8b's "only directory administrators can write it" is unmeasured. | §13 decision 40 ruling 5 (plan 8b's mapping kind) | Windows Server AD (L44's box), Samba AD | open — added 2026-10-07 (plan 8, for plan 8b) |
```

- [ ] **Step 8: design §7 and §17**

In design §7 "Machine identity", after item 2 ("Issued workload certificate … only initial
enrollment is manual."), add:

```markdown
   As built (plan 8; policy engine spec §13 decision 40): `x509` under `broker.identity.machines`,
   its own `trust_anchor_file` and the `spiffe_trust_domains` it may name. The handshake verifies
   against both anchors, and the anchor the chain ends at is the domain; a chain ending at both is
   refused, and two anchors where one signs the other refuse the start. The principal is the
   leaf's one URI SAN, a SPIFFE ID with a path. The workload enrolls and renews with the
   organization's CA; a renewal needs nothing from port49, and a late one is said
   (`port49_workload_certificates_renewal_late_total`). `port49 workload token` mints with no
   agent, reading the certificate and key each run.
```

In "Trust domain separation", replace "Workload
certificates and `k8s` are refused until plans 8 and 10." with "Workload certificates are plan 8's
(decision 40); `k8s` is refused until plan 10."

Replace

```markdown
Service accounts therefore never authenticate with a directory password; port49 has no
password path at all. One authenticates as a workload certificate, a cluster token, or one
OIDC application per service, and may still map to its directory entry for group membership.
```

with

```markdown
Service accounts therefore never authenticate with a directory password; port49 has no
password path at all. One authenticates as a workload certificate, a cluster token, or one
OIDC application per service, and may still map to its directory entry for group membership.
That membership reaches only a machine-scoped group subject, never a human group subject, so a
workload never inherits a human principal's grants; the mapping is keyed on the workload's
SPIFFE ID. Plan 8 builds no directory path for a workload, so its access is its identity
subject's; plan 8b owns the mapping (policy engine spec §13 decisions 16 and 40 ruling 5).
```

In §17 "Client libraries", replace "Machine workloads require no agent: identity is a file and
minting is a single request." with:

```markdown
Machine workloads require no agent: identity is a file and minting is a single request. As built
(plan 8): `port49 workload token --broker URL --broker-ca FILE --cert FILE --key FILE DEVICE…`
reads the certificate and key at every run, pages by `batch_max` under one `Idempotency-Key` per
page, retries what the broker could not answer now, and exits 75 when it cannot finish and 77
when nothing was minted and a run again will not change that; `examples/oxidized/` drives
Oxidized with it.
```

- [ ] **Step 9: The roadmap names plan 8b**

In `docs/superpowers/plans/README.md`, after the "Plan 8 — Workload certificates (§19 step 8)"
section and before "## Plan 9 — Agent in full (§19 step 9)", which stays as it is, add:

```markdown
## Plan 8b — Workload directory groups (design §7; spec §13 decisions 16 and 40 ruling 5)

Deferred from plan 8 by the controller's ruling on its pre-flight Q1 (2026-10-07), on
recommendation: deferred, not cut. Ryan may cancel it. Plan 8 builds no directory path for a
workload, and that stays the default when this is built: a workload with no mapping mints with
every DC down.

- **The constraint.** A machine principal matches only a machine-scoped group subject, never a
  human `group:` subject. Today's `group:` subject carries `attached_roles.humans` and human
  `api:` rights (`buildSubjects` sets `Domain = "humans"`), which design §7 forbids a workload.
  One subject of both domains is a load error. Decision 38 ruling 15's diff gate and the CI report
  cover the machine form as they cover `group:`.
- **The mapping.** Opt-in per verifier (a `directory:` key on the `x509` machine verifier), a new
  mapping kind keyed on the SPIFFE ID: exactly one entry whose attribute equals it. No existing
  kind serves: `issuer_serial` changes at every renewal, `sid` is AD CS's extension, and the weak
  kinds need `allow_weak` and an `issuers:` pin. It is a weak kind under decision 38 ruling 1,
  pinned to the workload anchor, the entry pinned by `objectGUID` or `entryUUID`.
- **The username.** From the entry's `username_attribute`, under decision 38 ruling 3's collision
  rules (amending decision 8), or declared on the machine group subject. Spec text first.
- **Plumbing.** The `IsUser` gates (`memberFor`, `storedMemberOf`, the scheduled refresh,
  `refresh.go`) become per domain; `forget`, pre-warm and `normalPrincipal` for `forget` widen
  past `user:`; the membership record is keyed by the SPIFFE ID.
- **Lab.** Its own row, L50 (opened by plan 8): who can write the attribute on Windows AD (L44's
  box) and on Samba, since "only directory administrators can write it" is a directory-behaviour
  claim.
- **3am, with the mapping configured.** A DC outage past `broker.directory.grace` stops the
  workload's mints (`directory_unavailable`, `port49 workload` exit 75), and its live device
  sessions deny `context_stale` at `session.staleness_ceiling`. The start line and the operator
  notes say so.
- **Cost.** About 6 to 8 tasks and the lab row.
```

- [ ] **Step 10: Check and commit**

Run: `grep -n "decision 40" docs/design/2026-08-23-policy-engine-spec.md | head -40`,
`grep -n "L48\|L49\|L50" docs/design/2026-08-23-policy-engine-spec.md`,
`grep -n "plan 8b" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md`
and `grep -n "^## Plan 8\|^## Plan 9" docs/superpowers/plans/README.md`.
Expected: decision 40 cited from §2, §5.1.3, §5.1.4, §5.7, §13 (16, 39, 40) and §14; L48, L49 and
L50 one row each; "plan 8b" in §2, §5.1.3, decisions 16 and 40, and design §7; the roadmap's
headings in the order Plan 8, Plan 8b, Plan 9. `make vet` passes (no Go changed).

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md docs/superpowers/plans/README.md
git commit -m "docs: decision 40, workload certificates; open L48, L49 and L50; name plan 8b

§2 corrected to decision 38 ruling 3, which superseded it (a95b9fc).
Decision 16's workload directory groups deferred to plan 8b, constrained to
machine-scoped group subjects (the controller's ruling on pre-flight Q1).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: A SPIFFE ID, parsed once: `internal/spiffe`, and the policy reads through it

**Files:**
- Create: `internal/spiffe/spiffe.go`, `internal/spiffe/spiffe_test.go`
- Modify: `internal/policy/load.go` (`identityDomain`), `internal/policy/member.go`
  (`SPIFFEIdentities`)
- Test: `internal/policy/load_test.go`, `internal/policy/member_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `spiffe.Scheme = "spiffe://"`, `spiffe.MaxLen = 2048`, `spiffe.ErrNotSPIFFE`;
  - `type spiffe.ID struct{ TrustDomain, Path string }` with `String() string`;
  - `spiffe.Parse(s string) (ID, error)`, `spiffe.ParseWorkload(s string) (ID, error)` (a path
    required), `spiffe.CheckTrustDomain(td string) error`;
  - `(*policy.Policy).SPIFFEIdentities() map[string]string` (SPIFFE ID → subject name), which
    Task 8's start line reads.

- [ ] **Step 1: Write the failing tests**

`internal/spiffe/spiffe_test.go`:

```go
package spiffe

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAccepts(t *testing.T) {
	for in, want := range map[string]ID{
		"spiffe://corp.example.com/host/oxidized-01": {TrustDomain: "corp.example.com", Path: "/host/oxidized-01"},
		"spiffe://port49.test/ns/Netops/sa/Oxidized_2": {TrustDomain: "port49.test", Path: "/ns/Netops/sa/Oxidized_2"},
		"spiffe://a-b_c.d":                             {TrustDomain: "a-b_c.d"},
	} {
		got, err := Parse(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

// Each is refused, never folded or trimmed into an ID (decision 40 ruling 4):
// the path is case-sensitive, so folding would make two IDs one.
func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"SPIFFE://corp.example.com/x",
		"spiffe://Corp.example.com/x",
		"spiffe:///x",
		"spiffe://corp.example.com/x/",
		"spiffe://corp.example.com//x",
		"spiffe://corp.example.com/a/../b",
		"spiffe://corp.example.com/./b",
		"spiffe://corp.example.com/a%2fb",
		"spiffe://user@corp.example.com/x",
		"spiffe://corp.example.com:8443/x",
		"spiffe://corp.example.com/x?q=1",
		"spiffe://corp.example.com/x#f",
		"spiffe://corp.example.com/a b",
		"https://corp.example.com/x",
		"spiffe://corp.example.com/" + strings.Repeat("a", MaxLen),
	} {
		if id, err := Parse(in); err == nil || !errors.Is(err, ErrNotSPIFFE) {
			t.Errorf("Parse(%q) = %+v, %v; want ErrNotSPIFFE", in, id, err)
		}
	}
}

// A workload's ID has a path: the bare trust domain names the domain itself,
// not a workload (decision 40 ruling 3).
func TestParseWorkloadNeedsAPath(t *testing.T) {
	if _, err := ParseWorkload("spiffe://corp.example.com"); err == nil ||
		!strings.Contains(err.Error(), "names the trust domain itself, not a workload") {
		t.Fatalf("got %v", err)
	}
	if id, err := ParseWorkload("spiffe://corp.example.com/host/oxidized-01"); err != nil || id.Path != "/host/oxidized-01" {
		t.Fatalf("got %+v %v", id, err)
	}
}

func TestCheckTrustDomain(t *testing.T) {
	for td, ok := range map[string]bool{"corp.example.com": true, "a_b-c": true, "": false, "Corp.example.com": false,
		"corp.example.com/x": false, "corp example": false, strings.Repeat("a", MaxLen): false} {
		if err := CheckTrustDomain(td); (err == nil) != ok {
			t.Errorf("CheckTrustDomain(%q) = %v", td, err)
		}
	}
}
```

In `internal/policy/load_test.go`, add:

```go
// A spiffe:// identity outside SPIFFE ID §2 is a load error, never folded
// (decision 40 ruling 4); one inside it is a machine's.
func TestASpiffeIdentityMustBeAWorkloadID(t *testing.T) {
	const tmpl = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: ["show **"]}]
subjects: [{name: svc, identity: ["%s"], username: svc-backup, token_ttl: 60s}]
grants: [{subject: svc, scope: all_devices, roles: [r]}]
`
	for id, want := range map[string]string{
		"spiffe://Corp.example.com/host/x": "a workload certificate's principal is its SPIFFE ID",
		"spiffe://corp.example.com":        "names the trust domain itself, not a workload",
		"SPIFFE://corp.example.com/host/x": "a workload certificate's principal is its SPIFFE ID",
	} {
		if _, err := loadText(t, fmt.Sprintf(tmpl, id), DirectoryOff); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	p, err := loadText(t, fmt.Sprintf(tmpl, "spiffe://corp.example.com/host/oxidized-01"), DirectoryOff)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SPIFFEIdentities(); len(got) != 1 || got["spiffe://corp.example.com/host/oxidized-01"] != "svc" {
		t.Fatalf("SPIFFEIdentities %v", got)
	}
}
```

`loadText(t, body, mode)` is `member_test.go`'s helper (same package), which loads a policy body
against the test inventory under a directory mode.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/spiffe/ ./internal/policy/ -run 'TestParse|TestCheckTrustDomain|TestASpiffeIdentity' -count=1`
Expected: FAIL: the package `spiffe` does not exist; `SPIFFEIdentities` undefined.

- [ ] **Step 3: Write `internal/spiffe/spiffe.go`**

```go
// Package spiffe reads a SPIFFE ID (the SPIFFE ID specification, §2): the
// form a workload certificate's one URI SAN names its workload in (plan 8;
// policy engine spec §13 decision 40). The policy's load, the broker's
// workload verifier and a revocation's principal each read an ID through
// Parse, so the three agree on what one is. Nothing is folded or trimmed:
// an ID outside the form is refused, since the path is case-sensitive and
// a folded string would make two IDs one.
package spiffe

import (
	"errors"
	"fmt"
	"strings"
)

// Scheme is how every ID begins, in lower case (SPIFFE ID §2).
const Scheme = "spiffe://"

// MaxLen is the longest ID, in bytes (SPIFFE ID §2.3).
const MaxLen = 2048

// ErrNotSPIFFE is a string that is not a SPIFFE ID.
var ErrNotSPIFFE = errors.New("not a SPIFFE ID")

// ID is a parsed SPIFFE ID. Path is "" for the trust domain's own ID, and
// otherwise begins with "/".
type ID struct {
	TrustDomain string
	Path        string
}

// String is the ID as Parse read it.
func (id ID) String() string { return Scheme + id.TrustDomain + id.Path }

// Parse reads s as a SPIFFE ID, or says why it is not one: the lower-case
// scheme, a trust domain of a-z 0-9 . - _ (§2.1), and path segments of
// A-Z a-z 0-9 . - _, none empty, "." or "..", with no trailing "/" (§2.2),
// at most MaxLen bytes. Those sets leave no room for a port, userinfo, a
// query, a fragment or a percent-encoding.
func Parse(s string) (ID, error) {
	if len(s) > MaxLen {
		return ID{}, fmt.Errorf("%w: it is longer than %d bytes", ErrNotSPIFFE, MaxLen)
	}
	rest, ok := strings.CutPrefix(s, Scheme)
	if !ok {
		return ID{}, fmt.Errorf("%w: it does not begin %s, in lower case", ErrNotSPIFFE, Scheme)
	}
	td, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		td, path = rest[:i], rest[i:]
	}
	if err := CheckTrustDomain(td); err != nil {
		return ID{}, err
	}
	if path != "" {
		for _, seg := range strings.Split(path[1:], "/") {
			switch {
			case seg == "":
				return ID{}, fmt.Errorf("%w: an empty path segment (a // or a trailing /)", ErrNotSPIFFE)
			case seg == "." || seg == "..":
				return ID{}, fmt.Errorf("%w: a path segment of . or ..", ErrNotSPIFFE)
			case strings.IndexFunc(seg, func(r rune) bool { return !segmentRune(r) }) >= 0:
				return ID{}, fmt.Errorf("%w: a path segment holds a character outside A-Z a-z 0-9 . - _", ErrNotSPIFFE)
			}
		}
	}
	return ID{TrustDomain: td, Path: path}, nil
}

// ParseWorkload is Parse for a workload's ID, which has a path: the trust
// domain's own ID names the domain, not a workload (decision 40 ruling 3).
func ParseWorkload(s string) (ID, error) {
	id, err := Parse(s)
	if err == nil && id.Path == "" {
		return ID{}, fmt.Errorf("%w: %s names the trust domain itself, not a workload; a workload's ID has a path "+
			"(spiffe://%s/<path>)", ErrNotSPIFFE, s, id.TrustDomain)
	}
	return id, err
}

// CheckTrustDomain checks a trust domain name alone (SPIFFE ID §2.1): one or
// more of a-z 0-9 . - _, as broker.identity.machines[].spiffe_trust_domains
// lists it.
func CheckTrustDomain(td string) error {
	switch {
	case td == "":
		return fmt.Errorf("%w: the trust domain is empty", ErrNotSPIFFE)
	case len(Scheme)+len(td) > MaxLen:
		return fmt.Errorf("%w: the trust domain is longer than an ID may be", ErrNotSPIFFE)
	case strings.IndexFunc(td, func(r rune) bool { return !trustDomainRune(r) }) >= 0:
		return fmt.Errorf("%w: the trust domain holds a character outside a-z 0-9 . - _ (upper case is refused, "+
			"not folded)", ErrNotSPIFFE)
	}
	return nil
}

func trustDomainRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
}

func segmentRune(r rune) bool { return trustDomainRune(r) || r >= 'A' && r <= 'Z' }
```

- [ ] **Step 4: `identityDomain` reads `spiffe://` through `ParseWorkload`, and `SPIFFEIdentities`**

In `internal/policy/load.go`, `identityDomain`, replace the case

```go
	case strings.HasPrefix(id, "spiffe://") && len(id) > len("spiffe://"),
		serviceAccount.MatchString(id),
		strings.HasPrefix(id, "app:") && len(id) > len("app:"):
		return "machines", nil
```

with

```go
	case strings.HasPrefix(strings.ToLower(id), spiffe.Scheme):
		// A workload certificate's principal (plan 8): checked here as the
		// verifier checks it, so a policy naming one it can never give
		// fails CI rather than minting for no one (decision 40 ruling 4).
		if _, err := spiffe.ParseWorkload(id); err != nil {
			return "", fmt.Errorf("identity %q: a workload certificate's principal is its SPIFFE ID, "+
				"spiffe://<trust domain>/<path>, verbatim (spec §2; §13 decision 40): %w", id, err)
		}
		return "machines", nil
	case serviceAccount.MatchString(id),
		strings.HasPrefix(id, "app:") && len(id) > len("app:"):
		return "machines", nil
```

and import `github.com/rhwendt/port49/internal/spiffe`.

In `internal/policy/member.go`, after `DeclaredUsernames`, add:

```go
// SPIFFEIdentities is every spiffe:// identity a subject lists, with the
// subject that lists it: the ones the start checks against the workload
// verifier's trust domains (decision 40 ruling 16).
func (p *Policy) SPIFFEIdentities() map[string]string {
	out := map[string]string{}
	for id, name := range p.byID {
		if strings.HasPrefix(id, spiffe.Scheme) {
			out[id] = name
		}
	}
	return out
}
```

with the same import.

- [ ] **Step 5: Run the tests to verify they pass, and the packages that load policies**

Run: `go test ./internal/spiffe/ ./internal/policy/... ./internal/bundle/... ./internal/broker/... ./internal/inventory/... -count=1`
Expected: PASS. A fixture that named a `spiffe://` identity outside the form (an upper-case trust
domain, no path) now fails to load: change the fixture to a valid ID, and say which in the commit
message. `internal/inventory` reads its own URI SANs and is unchanged; it is run because its
fixtures share IDs.

- [ ] **Step 6: Commit**

```bash
gofmt -l internal/spiffe internal/policy
git add internal/spiffe internal/policy
git commit -m "feat(spiffe): parse a SPIFFE ID once; the policy refuses one outside the form

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: `broker.identity.machines` takes `x509`

**Files:**
- Modify: `internal/oidc/config.go` (`X509Machine`, `Config.X509Machine`)
- Modify: `internal/config/identity.go` (`identityVerifierYAML`, `checkIdentity`,
  `checkOIDCVerifier`, new `spiffeTrustDomains`)
- Modify: `internal/config/config.go` (`BrokerConfig.WorkloadCAFile`, `checkBroker`, the two
  collision lists, the `certificate_status` rule)
- Test: `internal/config/identity_test.go`

**Interfaces:**
- Consumes: Task 2's `spiffe.CheckTrustDomain`.
- Produces:
  - `type oidc.X509Machine struct{ AnchorFile string; TrustDomains []string }` and
    `oidc.Config.X509Machine *X509Machine` (nil without a workload verifier);
  - `config.BrokerConfig.WorkloadCAFile string` (`yaml:"-"`): the machine anchor's file, `""`
    without one. Task 8 reads it;
  - `broker.certificate_status` is required when `ClientCAFile != "" || WorkloadCAFile != ""`.

- [ ] **Step 1: Write the failing tests**

In `internal/config/identity_test.go`, delete the `"workload x509"` entry from
`TestIdentityRefusals`'s map (it now loads), and add:

```go
const workloadLists = `  identity:
    humans:
      - {type: x509, trust_anchor_file: /etc/port49/clients-ca.pem}
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workloads-ca.pem
        spiffe_trust_domains: [corp.example.com, corp.example.com, lab.corp.example.com]
`

func TestAWorkloadVerifierLoads(t *testing.T) {
	c, err := loadWith(t, brokerWithIdentity(workloadLists))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Broker.Identity.X509Machine
	if m == nil || m.AnchorFile != "/etc/port49/workloads-ca.pem" ||
		strings.Join(m.TrustDomains, " ") != "corp.example.com lab.corp.example.com" ||
		c.Broker.WorkloadCAFile != "/etc/port49/workloads-ca.pem" || c.Broker.ClientCAFile != "/etc/port49/clients-ca.pem" {
		t.Fatalf("broker %+v machine %+v: the trust domains once each, in order", c.Broker, m)
	}
}

// People by OIDC, workloads by certificate: an x509 verifier is configured,
// so certificate_status is required (decision 40 ruling 7).
func TestAWorkloadOnlyX509NeedsCertificateStatus(t *testing.T) {
	block := `  identity:
    humans:
      - {type: oidc, issuer: "https://sso.corp.example.com/realms/corp", client_id: port49-cli,
         principal_claim: email, principal_domains: [corp.example.com]}
    machines:
      - {type: x509, trust_anchor_file: /etc/port49/workloads-ca.pem, spiffe_trust_domains: [corp.example.com]}
`
	c, err := loadWith(t, brokerWithIdentity(block))
	if err != nil {
		t.Fatal(err)
	}
	if c.Broker.ClientCAFile != "" || c.Broker.WorkloadCAFile != "/etc/port49/workloads-ca.pem" || c.Broker.CertificateStatus == nil {
		t.Fatalf("broker %+v", c.Broker)
	}
	noStatus := strings.Replace(brokerWithIdentity(block), "  certificate_status: {disabled: true}\n", "", 1)
	if _, err := loadWith(t, noStatus); err == nil || !strings.Contains(err.Error(), "broker.certificate_status is required") {
		t.Fatalf("no certificate_status: %v", err)
	}
}

func TestWorkloadVerifierRefusals(t *testing.T) {
	x := "type: x509, trust_anchor_file: /etc/port49/workloads-ca.pem"
	for name, c := range map[string]struct{ block, want string }{
		"no trust domains": {"  identity:\n    machines: [{" + x + "}]\n",
			"broker.identity.machines[0].spiffe_trust_domains is required: the SPIFFE trust domains whose workloads"},
		"upper case": {"  identity:\n    machines: [{" + x + ", spiffe_trust_domains: [Corp.example.com]}]\n",
			`broker.identity.machines[0].spiffe_trust_domains: "Corp.example.com" is not a SPIFFE trust domain`},
		"a path in a domain": {"  identity:\n    machines: [{" + x + ", spiffe_trust_domains: [corp.example.com/host]}]\n",
			`"corp.example.com/host" is not a SPIFFE trust domain`},
		"two": {"  identity:\n    machines: [{" + x + ", spiffe_trust_domains: [a]}, {type: x509, trust_anchor_file: /b.pem, spiffe_trust_domains: [b]}]\n",
			"broker.identity.machines: at most one x509 verifier (the broker verifies a workload's chain against one anchor)"},
		"no anchor": {"  identity:\n    machines: [{type: x509, spiffe_trust_domains: [a]}]\n",
			"broker.identity.machines[0]: type x509 takes trust_anchor_file and spiffe_trust_domains alone"},
		"an oidc key on it": {"  identity:\n    machines: [{" + x + ", spiffe_trust_domains: [a], audience: x}]\n",
			"broker.identity.machines[0]: type x509 takes trust_anchor_file and spiffe_trust_domains alone"},
		"trust domains on a human x509": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem, spiffe_trust_domains: [a]}]\n",
			"broker.identity.humans[0]: type x509 takes trust_anchor_file alone"},
		"trust domains on an oidc verifier": {"  identity:\n    machines: [{type: oidc, issuer: \"https://sso.corp.example.com/realms/corp\", audience: a, clients: [{client_id: svc, sub: s1}], spiffe_trust_domains: [a]}]\n",
			"broker.identity.machines[0].spiffe_trust_domains is an x509 machine verifier's"},
		"one file for both": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /etc/port49/ca.pem}]\n    machines: [{type: x509, trust_anchor_file: /etc/port49/./ca.pem, spiffe_trust_domains: [a]}]\n",
			"broker.identity's humans and machines trust_anchor_file are one file"},
	} {
		if _, err := loadWith(t, brokerWithIdentity(c.block)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// The workload anchor joins the paths broker.revocations_file and a kept CRL
// may not be (pre-flight M13's list).
func TestTheWorkloadAnchorIsNotTheRevocationsFile(t *testing.T) {
	block := strings.Replace(workloadLists, "/etc/port49/workloads-ca.pem", "/var/lib/port49/revocations.json", 1)
	if _, err := loadWith(t, brokerWithIdentity(block)); err == nil ||
		!strings.Contains(err.Error(), "broker.identity.machines' trust_anchor_file") {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/ -run 'Workload|TestIdentityRefusals' -count=1`
Expected: FAIL: `X509Machine` and `WorkloadCAFile` undefined.

- [ ] **Step 3: `oidc.X509Machine`**

In `internal/oidc/config.go`, before `type Config struct`, add:

```go
// X509Machine is the workload certificate verifier (plan 8; spec §13
// decision 40): x509 under broker.identity.machines, its one trust anchor's
// file and the SPIFFE trust domains a certificate it verifies may name.
type X509Machine struct {
	AnchorFile   string
	TrustDomains []string
}
```

and add to `Config`, after `Shorthand bool`:

```go
	// X509Machine is the workload verifier, nil without one (plan 8).
	X509Machine *X509Machine
```

- [ ] **Step 4: `checkIdentity` takes `x509` under `machines`**

In `internal/config/identity.go`:

- Add to `identityVerifierYAML`, after `TrustAnchorFile`:

  ```go
	SPIFFETrustDomains []string `yaml:"spiffe_trust_domains"`
  ```

- In `checkIdentity`, replace the case

  ```go
			case v.Type == "x509" && list.domain == oidc.Machines:
				return nil, fmt.Errorf("config: %s: type x509 (workload certificates) is plan 8's; remove it", at)
  ```

  with

  ```go
			case v.Type == "x509" && list.domain == oidc.Machines:
				// The workload verifier (plan 8; decision 40 ruling 1).
				if out.X509Machine != nil {
					return nil, errors.New("config: broker.identity.machines: at most one x509 verifier (the broker " +
						"verifies a workload's chain against one anchor)")
				}
				if v.TrustAnchorFile == "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil ||
					v.Algorithms != nil || v.CAFile != "" {
					return nil, fmt.Errorf("config: %s: type x509 takes trust_anchor_file and spiffe_trust_domains alone", at)
				}
				tds, err := spiffeTrustDomains(at, v.SPIFFETrustDomains)
				if err != nil {
					return nil, err
				}
				out.X509Machine = &oidc.X509Machine{AnchorFile: v.TrustAnchorFile, TrustDomains: tds}
  ```

- In the human `x509` case's "takes trust_anchor_file alone" condition, add
  `|| v.SPIFFETrustDomains != nil`.
- In the `default:` refusal, replace `"one of x509 or oidc (k8s is plan 10's)"` unchanged (it is
  still true).
- Replace the "accepts no one" check with:

  ```go
	if out.X509AnchorFile == "" && out.X509Machine == nil && len(out.OIDC) == 0 {
  ```

- After that check, before `distinctVerifiers`, add:

  ```go
	// One file under both lists would make a certificate it verifies a
	// person's and a workload's at once (decision 40 ruling 2); port49d
	// refuses the same certificate in two files, and one signing the other,
	// once it has read them (Task 8).
	if m := out.X509Machine; m != nil && out.X509AnchorFile != "" &&
		filepath.Clean(m.AnchorFile) == filepath.Clean(out.X509AnchorFile) {
		return nil, errors.New("config: broker.identity's humans and machines trust_anchor_file are one file: a " +
			"certificate it verifies would be a person's and a workload's at once; anchor each list at its own " +
			"issuing CA")
	}
  ```

- In `checkOIDCVerifier`, after the `TrustAnchorFile` refusal, add:

  ```go
	if v.SPIFFETrustDomains != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.spiffe_trust_domains is an x509 machine verifier's", at)
	}
  ```

- After `principalDomains`, add:

  ```go
// spiffeTrustDomains is a workload verifier's spiffe_trust_domains, once
// each and in order (decision 40 ruling 1): at least one, each a SPIFFE trust
// domain as it is written, never folded to lower case.
func spiffeTrustDomains(at string, tds []string) ([]string, error) {
	if len(tds) == 0 {
		return nil, fmt.Errorf("config: %s.spiffe_trust_domains is required: the SPIFFE trust domains whose "+
			"workloads this anchor may name (spiffe://<trust domain>/<path>)", at)
	}
	var out []string
	for _, td := range tds {
		if err := spiffe.CheckTrustDomain(td); err != nil {
			return nil, fmt.Errorf("config: %s.spiffe_trust_domains: %q is not a SPIFFE trust domain (%v)", at, td, err)
		}
		if !slices.Contains(out, td) {
			out = append(out, td)
		}
	}
	return out, nil
}
  ```

  and import `github.com/rhwendt/port49/internal/spiffe`.

- [ ] **Step 5: `BrokerConfig.WorkloadCAFile`, the status rule and the collision lists**

In `internal/config/config.go`:

- Add to `BrokerConfig`, after `IdentitySet`:

  ```go
	// WorkloadCAFile is the workload verifier's trust anchor file (plan 8):
	// broker.identity.machines' x509 trust_anchor_file, "" without one.
	WorkloadCAFile string `yaml:"-"`
  ```

- In `checkBroker`, after `b.Identity, b.ClientCAFile = id, id.X509AnchorFile`, add:

  ```go
	if id.X509Machine != nil {
		b.WorkloadCAFile = id.X509Machine.AnchorFile
	}
  ```

- Replace the two `certificate_status` cases' conditions:

  ```go
	x509 := b.ClientCAFile != "" || b.WorkloadCAFile != ""
	switch {
	case b.CertificateStatus == nil && x509:
  ```

  and `case b.CertificateStatus != nil && !x509:`, keeping both messages.
- In `ownRevocationsFile`'s `others` and in `checkCertificateStatus`'s `others`, after
  `{"broker.client_ca_file", b.ClientCAFile}`, add
  `{"broker.identity.machines' trust_anchor_file", b.WorkloadCAFile},`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/config/ ./internal/oidc/ -count=1 && make vet`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/oidc/config.go internal/config
git commit -m "feat(config): x509 under broker.identity.machines with spiffe_trust_domains

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: The broker reads a certificate's trust domain from the anchor its chain ends at

**Files:**
- Create: `internal/broker/workload.go`, `internal/broker/workload_test.go`
- Modify: `internal/broker/broker.go` (the `Workload` field only)

**Interfaces:**
- Consumes: Task 2's `spiffe.ParseWorkload`; `CertIdentity`, `Identity`, `legacyPrincipal`,
  `ErrUntrusted` (identity.go, member.go).
- Produces:
  - `Broker.Workload *Workload` (nil: no workload verifier, and every certificate is read as
    before plan 8);
  - `type Workload struct{ Anchor *x509.Certificate; TrustDomains []string }`;
  - `const DomainHumans = "humans"`, `DomainMachines = "machines"`;
  - `type CertCaller struct{ Domain, Principal, Legacy string; Cred store.Credential; Leaf
    *x509.Certificate }`;
  - `var ErrWorkloadUnmapped` (`identity_unmapped`);
  - `func (b *Broker) CertCallerOf(cs *tls.ConnectionState, now time.Time) (CertCaller, error)`:
    Tasks 5 and 6 call it, and Task 6's `Broker.Wire` sets it as `Listener.Caller`, which both
    daemons call (Task 8);
  - `func (b *Broker) machineChain(cs *tls.ConnectionState) (bool, error)`;
  - `func WorkloadPrincipal(leaf *x509.Certificate, trustDomains []string) (string, error)`.

- [ ] **Step 1: Write the failing tests**

`internal/broker/workload_test.go`:

```go
package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// workloadID is the fixture workload's SPIFFE ID, in workloadPolicy's
// svc_oxidized subject.
const workloadID = "spiffe://corp.example.com/host/oxidized-01"

// withWorkload gives f's broker a workload verifier on its own CA, for
// corp.example.com, and returns that CA.
func (f *fixture) withWorkload(t *testing.T) *testpki.CA {
	t.Helper()
	wca, err := testpki.NewCA("port49 test workloads ca", f.now.Add(-time.Hour), f.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.b.Workload = &Workload{Anchor: wca.Cert, TrustDomains: []string{"corp.example.com"}}
	return wca
}

// workloadCert issues a client certificate from ca naming uris, valid for a
// day from an hour ago.
func (f *fixture) workloadCert(t *testing.T, ca *testpki.CA, uris ...string) tls.Certificate {
	t.Helper()
	l := testpki.Leaf{CommonName: "oxidized-01", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(23 * time.Hour)}
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		l.URIs = append(l.URIs, p)
	}
	c, err := ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// chainState is a connection whose one verified chain is c then ca.
func chainState(c tls.Certificate, ca *testpki.CA) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, ca.Cert}}}
}

func TestAWorkloadCertificateIsAMachine(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	cc, err := f.b.CertCallerOf(chainState(f.workloadCert(t, wca, workloadID), wca), f.now)
	if err != nil || cc.Domain != DomainMachines || cc.Principal != workloadID || cc.Legacy != "" ||
		cc.Cred.Method != "cert" || cc.Leaf == nil {
		t.Fatalf("%+v %v", cc, err)
	}
}

// A person's certificate on the same broker is read exactly as before plan 8.
func TestAHumanCertificateStaysAHuman(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	cc, err := f.b.CertCallerOf(f.state(f.alice), f.now)
	if err != nil || cc.Domain != DomainHumans || cc.Principal != alicePrincipal {
		t.Fatalf("%+v %v", cc, err)
	}
}

// Chains ending at both anchors are no one's (decision 40 ruling 2).
func TestAChainEndingAtBothAnchorsIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	w := f.workloadCert(t, wca, workloadID)
	cs := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{w.Leaf, wca.Cert}, {w.Leaf, f.ca.Cert}}}
	if _, err := f.b.CertCallerOf(cs, f.now); !errors.Is(err, ErrUntrusted) ||
		!strings.Contains(err.Error(), "chains to both the human and the workload trust anchor") {
		t.Fatalf("got %v", err)
	}
}

// People by OIDC, workloads by certificate: a chain that does not end at the
// workload anchor has no verifier (decision 40 ruling 2).
func TestWithNoHumanX509OnlyTheWorkloadAnchorAccepts(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	f.b.NoX509 = true
	if _, err := f.b.CertCallerOf(f.state(f.alice), f.now); !errors.Is(err, ErrUntrusted) ||
		!strings.Contains(err.Error(), "no human x509 verifier") {
		t.Fatalf("got %v", err)
	}
}

func TestTheWorkloadPrincipalTable(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	for name, c := range map[string]struct {
		uris []string
		want string
	}{
		"none":           {nil, "carries 0 URI SANs; exactly one SPIFFE ID names a workload"},
		"two":            {[]string{workloadID, "spiffe://corp.example.com/host/other"}, "carries 2 URI SANs"},
		"https":          {[]string{"https://corp.example.com/host/oxidized-01"}, "not a SPIFFE ID"},
		"upper case":     {[]string{"spiffe://Corp.example.com/host/oxidized-01"}, "not a SPIFFE ID"},
		"no path":        {[]string{"spiffe://corp.example.com"}, "names the trust domain itself, not a workload"},
		"trailing slash": {[]string{"spiffe://corp.example.com/host/"}, "not a SPIFFE ID"},
		"unlisted":       {[]string{"spiffe://lab.example.net/host/x"}, "outside broker.identity.machines spiffe_trust_domains (corp.example.com)"},
	} {
		_, err := f.b.CertCallerOf(chainState(f.workloadCert(t, wca, c.uris...), wca), f.now)
		if !errors.Is(err, ErrWorkloadUnmapped) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// An email SAN on a workload certificate is never read: no human mark names
// it, and it is no principal (decision 40 ruling 3).
func TestAWorkloadsEmailSANIsIgnored(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	u, _ := url.Parse(workloadID)
	c, err := wca.Issue(testpki.Leaf{CommonName: "x", Emails: []string{"alice@example.com"}, URIs: []*url.URL{u},
		Client: true, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := f.b.CertCallerOf(chainState(c, wca), f.now)
	if err != nil || cc.Principal != workloadID || cc.Legacy != "" {
		t.Fatalf("%+v %v", cc, err)
	}
}

// A CA certificate is no workload (X.509-SVID §4.1).
func TestACACertificateIsNoWorkload(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	if _, err := WorkloadPrincipal(f.ca.Cert, []string{"corp.example.com"}); !errors.Is(err, ErrWorkloadUnmapped) ||
		!strings.Contains(err.Error(), "a CA certificate") {
		t.Fatalf("got %v", err)
	}
}

// Expiry is refused as a person's is: trust_domain_unresolved, the validity
// named, and the credential kept for the record.
func TestAnExpiredWorkloadCertificateIsUntrusted(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	w := f.workloadCert(t, wca, workloadID)
	cc, err := f.b.CertCallerOf(chainState(w, wca), f.now.Add(24*time.Hour))
	if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "is valid") || cc.Cred.Fingerprint == "" ||
		cc.Domain != DomainMachines {
		t.Fatalf("%+v %v", cc, err)
	}
}

// With no workload verifier every certificate is read as before plan 8: a
// URI SAN beside the email is not a workload.
func TestNoWorkloadVerifierKeepsTodaysReading(t *testing.T) {
	f := newFixture(t, 8)
	u, _ := url.Parse(workloadID)
	c, err := f.ca.Issue(testpki.Leaf{CommonName: "a", Emails: []string{"alice@example.com"}, URIs: []*url.URL{u},
		Client: true, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := f.b.CertCallerOf(f.state(c), f.now)
	if err != nil || cc.Domain != DomainHumans || cc.Principal != alicePrincipal {
		t.Fatalf("%+v %v", cc, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/broker/ -run 'Workload|AHumanCertificateStays|ChainEndingAtBoth|NoHumanX509|ACACertificate' -count=1`
Expected: FAIL: `Workload`, `CertCallerOf` undefined.

- [ ] **Step 3: Write `internal/broker/workload.go`, and the field**

In `internal/broker/broker.go`, add to `Broker` after `NoX509`:

```go
	// Workload is the workload certificate verifier (plan 8; decision 40):
	// x509 under broker.identity.machines. Nil reads every certificate as a
	// person's, as before plan 8.
	Workload *Workload
```

`internal/broker/workload.go`:

```go
package broker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/store"
)

// Workload is the broker's workload certificate verifier (plan 8; spec §13
// decision 40 ruling 1): its one trust anchor, and the SPIFFE trust domains
// a certificate it verifies may name. It is used through a pointer: Tasks 5
// and 7 add the state it keeps under a mutex.
type Workload struct {
	Anchor       *x509.Certificate
	TrustDomains []string
}

// The trust domains, as broker.identity's lists name them.
const (
	DomainHumans   = "humans"
	DomainMachines = "machines"
)

// ErrWorkloadUnmapped is a certificate the workload anchor verified that names
// no workload: identity_unmapped (spec §5.7; decision 40 ruling 3), answered
// 401 at bind over HTTP, never as a TLS alert.
var ErrWorkloadUnmapped = errors.New("broker: the workload certificate names no principal")

// CertCaller is a connection's verified client certificate as the broker
// reads it (plan 8).
type CertCaller struct {
	// Domain is DomainHumans or DomainMachines: the list whose anchor the
	// chain ends at (decision 40 ruling 2).
	Domain string
	// Principal is a workload's SPIFFE ID; a person's user: and email SAN
	// without a directory; "" for a person under a directory, whom the
	// listener's Map names at bind.
	Principal string
	// Legacy is a person's email-SAN principal under a directory, for the
	// marks made before it (pre-flight I-16); "" otherwise, and always "" for
	// a workload.
	Legacy string
	Cred   store.Credential
	Leaf   *x509.Certificate
}

// CertCallerOf reads cs's verified certificate. With no workload verifier it
// is exactly what the broker read before plan 8: Identity, or, under a
// directory, CertIdentity and the legacy principal. With one, the chain's
// anchor decides the domain first (machineChain); a person's certificate is
// then read as before, and a workload's principal is its SPIFFE ID
// (WorkloadPrincipal). A refusal of a chain an anchor verified keeps the
// credential and the leaf, so the record can say whose certificate it was.
func (b *Broker) CertCallerOf(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
	machine, chainErr := b.machineChain(cs)
	if machine || chainErr != nil {
		cred, leaf, err := CertIdentity(cs, now)
		cc := CertCaller{Domain: DomainMachines, Cred: cred, Leaf: leaf}
		if chainErr != nil {
			cc.Domain = ""
			return cc, chainErr
		}
		if err != nil {
			return cc, err
		}
		p, err := WorkloadPrincipal(leaf, b.Workload.TrustDomains)
		if err != nil {
			return cc, err
		}
		cc.Principal = p
		return cc, nil
	}
	if b.Directory != nil {
		cred, leaf, err := CertIdentity(cs, now)
		cc := CertCaller{Domain: DomainHumans, Cred: cred, Leaf: leaf}
		if leaf != nil {
			cc.Legacy = legacyPrincipal(leaf)
		}
		return cc, err
	}
	p, cred, err := Identity(cs, now)
	cc := CertCaller{Domain: DomainHumans, Principal: p, Cred: cred}
	if cs != nil && len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		cc.Leaf = cs.VerifiedChains[0][0]
	}
	return cc, err
}

// machineChain reports whether cs's verified chains end at the workload
// anchor. crypto/tls verified them against one pool of both anchors (Server),
// so a chain ends at one or the other; chains ending at both are no one's,
// since exactly one verifier must accept (decision 40 ruling 2). On a broker
// with no human x509 verifier, a chain not ending at the workload anchor has
// none. With no workload verifier, or no verified chain (CertIdentity refuses
// that), it is false and nil.
func (b *Broker) machineChain(cs *tls.ConnectionState) (bool, error) {
	if b.Workload == nil || cs == nil || len(cs.VerifiedChains) == 0 {
		return false, nil
	}
	var human, machine bool
	for _, ch := range cs.VerifiedChains {
		if len(ch) == 0 {
			continue
		}
		if bytes.Equal(ch[len(ch)-1].Raw, b.Workload.Anchor.Raw) {
			machine = true
		} else {
			human = true
		}
	}
	switch {
	case human && machine:
		// The start refuses an anchor that signs the other directly; one
		// further down the other's hierarchy is found only here (M-2).
		return false, fmt.Errorf("%w: the certificate chains to both the human and the workload trust anchor, so "+
			"neither verifier may take it; anchor each list at its own issuing CA, in unrelated hierarchies (the "+
			"start refuses only an anchor that signs the other directly)", ErrUntrusted)
	case human && b.NoX509:
		return false, fmt.Errorf("%w: this broker has no human x509 verifier, and the certificate does not chain to "+
			"the workload trust anchor", ErrUntrusted)
	}
	return machine, nil
}

// WorkloadPrincipal is a workload certificate's principal (spec §2; decision
// 40 rulings 3 and 4): its one URI SAN, verbatim, a SPIFFE ID with a path in
// one of trustDomains. A CA certificate, zero or several URI SANs, another
// URI, an ID with no path or an unlisted trust domain is ErrWorkloadUnmapped,
// saying which. Its email SANs are never read.
func WorkloadPrincipal(leaf *x509.Certificate, trustDomains []string) (string, error) {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return "", fmt.Errorf("%w: it is a CA certificate, which no workload presents (X.509-SVID §4.1)",
			ErrWorkloadUnmapped)
	}
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("%w: it carries %d URI SANs; exactly one SPIFFE ID names a workload",
			ErrWorkloadUnmapped, len(leaf.URIs))
	}
	raw := leaf.URIs[0].String()
	id, err := spiffe.ParseWorkload(raw)
	if err != nil {
		return "", fmt.Errorf("%w: its URI SAN is %v", ErrWorkloadUnmapped, err)
	}
	if !slices.Contains(trustDomains, id.TrustDomain) {
		return "", fmt.Errorf("%w: %s is outside broker.identity.machines spiffe_trust_domains (%s)",
			ErrWorkloadUnmapped, raw, strings.Join(trustDomains, ", "))
	}
	return raw, nil
}
```

`leaf.URIs[0].String()` is the URI `crypto/x509` parsed. For anything `ParseWorkload` accepts, it
is byte for byte the SAN, since that character set needs no escaping.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/broker/ -count=1 && go test -race ./internal/broker/ -run 'Workload|ChainEndingAtBoth' -count=1`
Expected: PASS. Nothing yet calls `CertCallerOf` but these tests.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/workload.go internal/broker/workload_test.go internal/broker/broker.go
git commit -m "feat(broker): read a certificate's trust domain from the anchor its chain ends at

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: The broker serves a workload: the server's pool, `authenticate`, a late renewal

**Files:**
- Modify: `internal/broker/server.go` (`Server`)
- Modify: `internal/broker/broker.go` (`authenticate`, `callerOf`, `legacyOf`)
- Modify: `internal/broker/workload.go` (`noteRenewal`, `Workload.lateOnce`)
- Modify: `internal/broker/certcheck.go` (`unknownClass` reads `api.UncoveredStatus`)
- Modify: `internal/broker/api/api.go` (`LateRenewalFraction`, `LateRenewal`, `UncoveredStatus`)
- Modify: `internal/daemon/metrics/metrics.go` (`WorkloadRenewalLate`)
- Create: `internal/broker/workload_mint_test.go`
- Test: `internal/certstatus/chain_test.go` (`TestAnUncoveredIssuerOpensWithTheAPIsWords`)

**Interfaces:**
- Consumes: Task 4's `CertCallerOf`, `CertCaller`, `ErrWorkloadUnmapped`, `machineChain`,
  `Broker.Workload`.
- Produces:
  - `Server` puts the workload anchor beside the human one in `ClientCAs`, and serves a broker
    whose one x509 verifier is the workload's;
  - `authenticate`, `callerOf` and `legacyOf` read through `CertCallerOf`;
  - `api.LateRenewalFraction = 4` and `api.LateRenewal(c *x509.Certificate, now time.Time) bool`
    (Tasks 9 and 10 call it);
  - `api.UncoveredStatus = "no fresh CRL or OCSP answer covers"`: the words that open certstatus's
    detail for an issuer no source covers, which `unknownClass` and Task 9's client both key on;
  - `(*Broker).noteRenewal(cc CertCaller, now time.Time)` and `(*Workload).lateOnce(fp string,
    now time.Time) bool`, with the fields `mu sync.Mutex` and `late map[string]time.Time`;
  - `metrics.Metrics.WorkloadRenewalLate prometheus.Counter`
    (`port49_workload_certificates_renewal_late_total`).

- [ ] **Step 1: Write the failing tests**

`internal/broker/workload_mint_test.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/testpki"
)

// workloadPolicy is testPolicy with svc_oxidized: the workload's SPIFFE ID
// and an app: client, one subject (spec §2's multi-identity subject).
const workloadPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: svc_oxidized, identity: ["spiffe://corp.example.com/host/oxidized-01", "app:Oxidized-01"],
     username: svc-oxidized, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}
`

func newWorkloadFixture(t *testing.T) (*fixture, *testpki.CA, tls.Certificate) {
	t.Helper()
	f := newFixtureWithPolicy(t, 8, workloadPolicy)
	wca := f.withWorkload(t)
	return f, wca, f.workloadCert(t, wca, workloadID)
}

func TestAWorkloadMints(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Principal != workloadID || resp.Subject != "svc_oxidized" || len(resp.Results) != 1 ||
		resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
	var mint map[string]any
	for _, r := range eventsOf(f.records(t), decision.EventMint) {
		mint = r
	}
	if mint["principal"] != workloadID {
		t.Fatalf("the mint record %v", mint)
	}
	if auth, _ := mint["auth"].(map[string]any); auth["method"] != "cert" {
		t.Fatalf("auth %v", mint["auth"])
	}
}

// A workload never reaches the directory (decision 40 ruling 5): it mints
// with every server down and no grace held, and the resolver is never asked.
// A person on the same broker is answered directory_unavailable as before.
func TestAWorkloadMintsWhileTheDirectoryIsDown(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	if res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"); res.Code != http.StatusOK {
		t.Fatalf("the workload: %s", answer(res))
	}
	if n := f.b.Directory.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for a workload", n)
	}
	if res := f.post(context.Background(), f.state(f.alice), mintLeaf1, "k2"); res.Code != http.StatusServiceUnavailable ||
		!strings.Contains(res.Body.String(), "directory_unavailable") {
		t.Fatalf("alice: %s", answer(res))
	}
}

// identity_unmapped over HTTP, recorded with the reason (decision 40 ruling 3).
func TestAnUnmappedWorkloadIsRefusedIdentityUnmapped(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	bad := f.workloadCert(t, wca, "spiffe://lab.example.net/host/x")
	res := f.post(context.Background(), chainState(bad, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"identity_unmapped"`) {
		t.Fatalf("%s", answer(res))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.IdentityUnmapped) {
		t.Fatalf("records %v", recs)
	}
}

// spec §2: one subject, a workload certificate and an OIDC client, one
// username; neither is a person.
func TestTwoIdentitiesOfOneSubjectMintOneUsername(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	iss := f.withOIDC(t)
	byCert := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	byApp := decodeMint(t, f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw))
	if byCert.Subject != "svc_oxidized" || byApp.Subject != "svc_oxidized" || byApp.Principal != "app:Oxidized-01" ||
		byCert.Results[0].Username != byApp.Results[0].Username {
		t.Fatalf("by certificate %+v; by OIDC %+v", byCert, byApp)
	}
}

// The declared username stands (decision 40 ruling 6): a directory person
// whose username a workload subject declares is refused username_collision,
// and the workload mints.
func TestADirectoryUsernameAWorkloadDeclaresIsTheDirectorysCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(workloadPolicy,
		`  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}`,
		`  - {name: netops, group: secret-group, enable: token, token_ttl: 60s}`, 1))
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(alicePrincipal, "svc-oxidized")}, nil)
	res := f.post(context.Background(), f.state(f.alice), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), "username_collision") {
		t.Fatalf("alice: %s", answer(res))
	}
	if res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k2"); res.Code != http.StatusOK {
		t.Fatalf("the workload: %s", answer(res))
	}
}

// /v1/identity answers a workload: its SPIFFE ID, its subject, no groups.
func TestIdentityAnswersAWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	res := f.call(context.Background(), chainState(w, wca), "GET", "/v1/identity", "")
	var id api.Identity
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &id) != nil || id.Principal != workloadID ||
		id.Subject != "svc_oxidized" || id.Method != "cert" || len(id.GroupDNs) != 0 {
		t.Fatalf("%s", answer(res))
	}
}

// A late renewal is said once per certificate per 24h and counted
// (decision 40 ruling 9); a certificate with time left is neither.
func TestALateRenewalIsSaidOncePerDay(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	// logf is the standard logger's, as certcheck_test.go reads it.
	logged := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if testutil.ToFloat64(f.b.Metrics.WorkloadRenewalLate) != 0 {
		t.Fatal("a certificate with 23h of 24h left was counted late")
	}
	f.advance(19 * time.Hour) // 4h of 24h left: under a quarter
	for i := range 3 {
		f.post(context.Background(), chainState(w, wca), mintLeaf1, "k"+string(rune('2'+i)))
	}
	if got := testutil.ToFloat64(f.b.Metrics.WorkloadRenewalLate); got != 1 {
		t.Fatalf("counted %v times, want once", got)
	}
	if n := strings.Count(logged.String(), "its renewal is late"); n != 1 ||
		!strings.Contains(logged.String(), "workload certificate "+workloadID) {
		t.Fatalf("the process log: %q", logged.String())
	}
}

// spec §14: a scope's attached_roles.machines compose into a workload's
// grant, and attached_roles.humans do not (pre-flight M-14). The workload
// explains its own commands, which needs no api: right.
func TestAttachedRolesComposeByTheWorkloadsDomain(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.NewReplacer(
		`  - {name: all_devices, match: {}}`,
		`  - {name: all_devices, match: {}, attached_roles: {humans: [no_version], machines: [no_config]}}`,
		`  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}`,
		`  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
  - {name: no_version, deny: ["show version"]}
  - {name: no_config, deny: ["show running-config"]}`,
	).Replace(workloadPolicy))
	for cmd, want := range map[string]string{"show running-config": "deny", "show version": "permit"} {
		res := f.call(context.Background(), chainState(w, wca), "POST", "/v1/explain",
			`{"device":"leaf1","command":"`+cmd+`"}`)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"verdict":"`+want+`"`) {
			t.Errorf("%s: want %s: %s", cmd, want, answer(res))
		}
	}
}

// methods names how a person authenticates (decision 40 ruling 12): a broker
// whose one x509 verifier is the workloads' offers people oidc alone.
func TestConfigMethodsNameAPersonsMethods(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	f.withOIDC(t)
	f.b.NoX509 = true
	res := f.call(context.Background(), &tls.ConnectionState{}, "GET", "/v1/config", "")
	var c api.Config
	if json.Unmarshal(res.Body.Bytes(), &c) != nil || strings.Join(c.Methods, ",") != "oidc" {
		t.Fatalf("%s", answer(res))
	}
}

// The handshake's pool holds both anchors, and a workload-only broker serves.
func TestTheServersPoolHoldsBothAnchors(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	srv, err := f.b.Server("127.0.0.1:0", tls.Certificate{}, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(f.ca.Cert)
	want.AddCert(wca.Cert)
	if !srv.TLSConfig.ClientCAs.Equal(want) || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatal("ClientCAs is not both anchors")
	}
	f.b.NoX509 = true
	f.withOIDC(t)
	srv, err = f.b.Server("127.0.0.1:0", tls.Certificate{}, nil)
	if err != nil || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("a broker whose one x509 verifier is the workloads': %v", err)
	}
	only := x509.NewCertPool()
	only.AddCert(wca.Cert)
	if !srv.TLSConfig.ClientCAs.Equal(only) {
		t.Fatal("ClientCAs is not the workload anchor alone")
	}
}
```

`lockedBuffer` is `server_test.go`'s. `withDirectory` and `answerFor` are `member_test.go`'s
(pre-flight M-17: `answerFor`'s membership is in `secret-group`, which the test's group subject
names).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/broker/ -run 'Workload|TwoIdentities|ADirectoryUsername|LateRenewal|ConfigMethods|ServersPool|AttachedRolesCompose' -count=1`
Expected: FAIL: a workload's mint is refused `trust_domain_unresolved` (`Identity` finds no email
SAN), and `WorkloadRenewalLate` is undefined.

- [ ] **Step 3: `Server`'s pool**

In `internal/broker/server.go`, replace `Server`'s `clientAuth` switch and its `ClientCAs` with:

```go
	clientAuth := tls.VerifyClientCertIfGiven
	var pool *x509.CertPool
	switch {
	case anchor != nil && b.NoX509:
		return nil, errors.New("broker: an OIDC-only broker (NoX509) takes no anchor: it would still verify " +
			"client certificates")
	case anchor == nil && b.Workload != nil:
		// People by OIDC, workloads by certificate (plan 8): the one anchor
		// is the workloads'.
		pool = x509.NewCertPool()
	case anchor == nil && b.NoX509 && b.Identity != nil:
		// An OIDC-only broker (Ruling 1): no certificate is requested, and
		// every caller authenticates by bearer.
		clientAuth = tls.NoClientCert
	case anchor == nil || anchor.Equal(x509.NewCertPool()):
		return nil, errors.New("broker: the broker trusts exactly one anchor; a nil pool would mean the system " +
			"roots, and an empty one trusts no one (an OIDC-only broker sets NoX509 and Identity)")
	default:
		pool = anchor.Clone()
	}
	// One pool of both anchors (decision 40 ruling 2): the handshake verifies
	// against either, and the anchor a chain ends at is its domain
	// (CertCallerOf).
	if b.Workload != nil {
		pool.AddCert(b.Workload.Anchor)
	}
```

set `ClientCAs: pool,` and replace the `VerifyConnection` body with:

```go
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil // /v1/config only; /v1/tokens refuses it
				}
				// A chain is checked here; a workload naming no principal is
				// answered 401 identity_unmapped at bind, never as a TLS alert
				// the client cannot read (decision 40 ruling 3); a person
				// under a directory is mapped at bind.
				_, err := b.CertCallerOf(&cs, b.Now())
				if errors.Is(err, ErrWorkloadUnmapped) {
					return nil
				}
				return err
			},
```

- [ ] **Step 4: `authenticate`, `callerOf`, `legacyOf`**

In `internal/broker/broker.go`, `authenticate`:

- Replace the case `case b.NoX509:` with

  ```go
	case b.NoX509 && !(hasCert && b.Workload != nil):
  ```

  and its detail with `"this broker accepts an OIDC ID token (Authorization: Bearer), or a workload
  certificate where broker.identity.machines names one; run `port49 login`"` when
  `b.Workload != nil`, and the existing one otherwise.
- Replace the block from `var principal, legacy string` down to the `if err != nil {` refusal's
  `return caller{}, false` with:

  ```go
	cc, err := b.CertCallerOf(r.TLS, now)
	principal, legacy, cred := cc.Principal, cc.Legacy, cc.Cred
	if b.Directory != nil && cc.Domain == DomainHumans {
		if h := heldOf(r); h != nil && h.answer != nil {
			principal = h.answer.Principal // already mapped: it names the refusal's caller
		}
	}
	// named is whose request a refusal records: the principal when known,
	// else the one the certificate's email SAN gave before a directory.
	named := cmp.Or(principal, legacy)
	if err != nil {
		// A chain the anchor verified is named on the refusal (principal when
		// it maps to one, the fingerprint always); no chain names no one. A
		// workload naming no principal is identity_unmapped (decision 40).
		reason := decision.TrustDomainUnresolved
		if errors.Is(err, ErrWorkloadUnmapped) {
			reason = decision.IdentityUnmapped
		}
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: reason, Principal: named,
			Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
		writeError(w, http.StatusUnauthorized, string(reason), err.Error())
		return caller{}, false
	}
	b.noteRenewal(cc, now)
  ```

- Replace `if b.Directory == nil {` (the first of the two returns at the end) with
  `if b.Directory == nil || cc.Domain == DomainMachines {`, and its comment's first line with
  `// Without a directory, and for a workload, which never reaches one (decision 40 ruling 5):`.
- Replace `callerOf`'s body with:

  ```go
	cc, err := b.CertCallerOf(r.TLS, now)
	if err != nil || b.Directory == nil || cc.Domain == DomainMachines {
		return cc.Principal, cc.Legacy, cc.Cred, err
	}
	if h := heldOf(r); h != nil && h.answer != nil {
		return h.answer.Principal, cc.Legacy, cc.Cred, nil
	}
	b.logf("broker: a held connection has no directory principal pinned (the listener has no Map); refusing it")
	return "", cc.Legacy, cc.Cred, errNoPin
  ```

- In `legacyOf`, before `return legacyPrincipal(...)`, add:

  ```go
	if machine, _ := b.machineChain(r.TLS); machine {
		return "" // a workload answers to no person's mark (decision 40 ruling 3)
	}
  ```

- [ ] **Step 5: `noteRenewal` and its own map; the metric; `api.LateRenewal`; `api.UncoveredStatus`**

In `internal/broker/api/api.go`, add:

```go
// UncoveredStatus opens the broker's detail when no certificate status source
// covers a certificate's issuer (certstatus's "uncovered" Unknown). The broker
// answers it 503 certificate_status_unavailable with Retry-After, but nothing
// changes until the operator adds a CRL or OCSP for that issuer, so port49
// workload treats it as final (spec §13 decision 40 ruling 7).
const UncoveredStatus = "no fresh CRL or OCSP answer covers"
```

In `internal/broker/certcheck.go`, `unknownClass`, replace the literal in
`strings.HasPrefix(detail, "no fresh CRL or OCSP answer covers")` with `api.UncoveredStatus`
(importing `internal/broker/api` if the file does not), so the broker's class and the client read
one string. No test runs certstatus's real detail through `unknownClass` today, so pin it at its
source. In `internal/certstatus/chain_test.go`, add (importing `internal/broker/api`, which imports
nothing of certstatus's):

```go
// An issuer no source covers is said in the words port49 workload keys on to
// treat the broker's 503 as final (api.UncoveredStatus; plan 8, pre-flight
// I-2). A rewording here would turn that answer back into "run again".
func TestAnUncoveredIssuerOpensWithTheAPIsWords(t *testing.T) {
	root := newCA(t, "root CA")
	c, _, _ := newChecker(t, Config{}, newClock())
	if r := check(t, c, leaf(t, root, 100), root.Cert); r.Verdict != Unknown ||
		!strings.HasPrefix(r.Detail, api.UncoveredStatus) {
		t.Fatalf("%+v", r)
	}
}
```

`newCA`, `leaf`, `newChecker`, `newClock` and `check` are the package's test helpers.

In `internal/broker/api/api.go`, add also:

```go
// LateRenewalFraction: a workload certificate with less than 1/4 of its
// validity left is late to renew (spec §13 decision 40 ruling 9). The broker
// says it and counts it; port49 workload warns.
const LateRenewalFraction = 4

// LateRenewal reports whether c, presented at now, has under a quarter of its
// validity left.
func LateRenewal(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore)
	return life > 0 && c.NotAfter.Sub(now) < life/LateRenewalFraction
}
```

(import `crypto/x509` and `time` there if they are not).

In `internal/daemon/metrics/metrics.go`, add the field

```go
	// WorkloadRenewalLate is port49_workload_certificates_renewal_late_total:
	// each workload certificate seen with under a quarter of its validity
	// left, once per 24h per certificate on each broker replica (plan 8;
	// decision 40 ruling 9). No label: a certificate is a workload's identity.
	WorkloadRenewalLate prometheus.Counter
```

construct it in `New`

```go
		WorkloadRenewalLate: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_workload_certificates_renewal_late_total",
			Help: "Workload certificates presented with under a quarter of their validity left, once per certificate " +
				"per 24h on this replica; alert on its increase."}),
```

and add `m.WorkloadRenewalLate` to the registration list.

In `internal/broker/workload.go`, add to `Workload`:

```go
	// mu guards late (and, from Task 7, issuers).
	mu sync.Mutex
	// late is when each certificate's late renewal was last said, by
	// fingerprint: a map of its own, since sayOnce prunes its map by each
	// caller's window, which would drop these 24h keys in a large fleet
	// (pre-flight M-3).
	late map[string]time.Time
```

and add:

```go
// lateWindow is how often one certificate's late renewal is said.
const lateWindow = 24 * time.Hour

// lateOnce reports whether fp's late renewal was not said in the last
// lateWindow, and notes it said now. Past 4096 certificates it drops the
// ones said a window ago or more.
func (w *Workload) lateOnce(fp string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if at, ok := w.late[fp]; ok && now.Sub(at) < lateWindow {
		return false
	}
	if w.late == nil {
		w.late = map[string]time.Time{}
	}
	if len(w.late) >= 4096 {
		for k, at := range w.late {
			if now.Sub(at) >= lateWindow {
				delete(w.late, k)
			}
		}
	}
	w.late[fp] = now
	return true
}

// noteRenewal says a workload certificate presented late in its life, once
// per certificate per 24h, and counts it (decision 40 ruling 9). It never
// refuses: expiry does that.
func (b *Broker) noteRenewal(cc CertCaller, now time.Time) {
	if cc.Domain != DomainMachines || cc.Leaf == nil || b.Workload == nil || !api.LateRenewal(cc.Leaf, now) ||
		!b.Workload.lateOnce(cc.Cred.Fingerprint, now) {
		return
	}
	b.logf("identity: workload certificate %s (serial %s) expires %s with under a quarter of its validity left: "+
		"its renewal is late; check the workload's renewal against its CA", printsafe.Line(cc.Principal, 300),
		cc.Cred.Serial, cc.Leaf.NotAfter.UTC().Format(time.RFC3339))
	b.Metrics.WorkloadRenewalLate.Inc()
}
```

importing `sync`, `internal/broker/api` and `internal/printsafe`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/broker/... ./internal/certstatus/ ./internal/daemon/metrics/ -count=1 && go test -race ./internal/broker/ -count=1 && make vet`
Expected: PASS, the existing certificate, directory, OIDC and `unknownClass` tests included. They
pin that a person's path did not move. `go vet`'s copylocks check passes: `Workload` is only ever
used through a pointer.

- [ ] **Step 7: Commit**

```bash
git add internal/broker internal/daemon/metrics/metrics.go internal/certstatus/chain_test.go
git commit -m "feat(broker): a workload certificate mints as its SPIFFE ID; a late renewal is said

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The listener binds a workload as its SPIFFE ID, never through the directory

**Files:**
- Modify: `internal/broker/listen.go` (`Listener.Caller`, `callerOf`, `handshake`, `Accept`,
  `Broker.Wire`, `ErrUnwired`)
- Modify: `internal/broker/member.go` (`BindMap` never maps a machine chain)
- Modify: `internal/broker/member_test.go` (`serveThroughWith`'s `Map` comes with `Caller`)
- Create: `internal/broker/workload_listen_test.go`

**Interfaces:**
- Consumes: Task 4's `CertCaller`, `CertCallerOf`, `ErrWorkloadUnmapped`, `DomainMachines`,
  `machineChain`; Task 5's `Server` pool.
- Produces:
  - `Listener.Caller func(cs *tls.ConnectionState, now time.Time) (CertCaller, error)`. Nil
    without `Map` reads a certificate as before plan 8;
  - `func (b *Broker) Wire(l *Listener)`: `Refused`, `Status` and `Caller` always, `Map` under a
    directory. port49d and port49-broker both call it (Task 8), so the wiring that keeps a
    workload out of `Map` exists once and is tested once (pre-flight I-4);
  - `var ErrUnwired`: `Accept`'s answer on a listener with `Map` and no `Caller`, so it serves
    nothing;
  - `BindMap` answers a machine chain `identity_unmapped` and never asks the directory.

- [ ] **Step 1: Write the failing tests**

`internal/broker/workload_listen_test.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// startServerWith is startServer with the listener wired as both daemons
// wire it (Broker.Wire; Task 8), then set's overrides. It returns the URL and
// what the listener said.
func startServerWith(t *testing.T, f *fixture, set func(l *Listener)) (string, *lockedBuffer) {
	t.Helper()
	said := &lockedBuffer{}
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(Limit(ln, MaxConns), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now,
		func(format string, args ...any) { fmt.Fprintf(said, format+"\n", args...) })
	f.b.Wire(l)
	if set != nil {
		set(l)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String(), said
}

func postMint(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Post(url+"/v1/tokens", "application/json", strings.NewReader(mintLeaf1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Under a directory whose every call would fail, a workload binds and mints
// over a real handshake on a listener wired as both daemons wire it, and the
// resolver is never asked; alice, on the same listener, is mapped through it
// (decision 40 ruling 5; pre-flight I-4).
func TestAWorkloadBindsWithoutAskingTheDirectory(t *testing.T) {
	f, _, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	url, _ := startServerWith(t, f, nil)
	if code, body := postMint(t, clientWith(f, w), url); code != http.StatusOK || !strings.Contains(body, workloadID) {
		t.Fatalf("the workload: %d %s", code, body)
	}
	if n := f.b.Directory.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times", n)
	}
	if code, body := postMint(t, clientWith(f, f.alice), url); code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "directory_unavailable") {
		t.Fatalf("alice: %d %s", code, body)
	}
	if f.b.Directory.Calls.Load() == 0 {
		t.Fatal("alice was not mapped through the directory")
	}
}

// A workload certificate naming no principal completes its handshake and is
// answered identity_unmapped over HTTP, recorded and closed before it binds:
// never a TLS alert the client cannot read (decision 40 ruling 3).
func TestAnUnmappedWorkloadIsAnsweredNotAlerted(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	two := f.workloadCert(t, wca, workloadID, "spiffe://corp.example.com/host/other")
	var refused []decision.Reason
	url, _ := startServerWith(t, f, func(l *Listener) {
		l.Refused = func(_, _ string, _ store.Credential, r decision.Reason) { refused = append(refused, r) }
	})
	code, body := postMint(t, clientWith(f, two), url)
	if code != http.StatusUnauthorized || !strings.Contains(body, `"identity_unmapped"`) ||
		!strings.Contains(body, "carries 2 URI SANs") {
		t.Fatalf("%d %s", code, body)
	}
	if len(refused) != 1 || refused[0] != decision.IdentityUnmapped {
		t.Fatalf("recorded %v", refused)
	}
}

// A workload's held connections count against its principal, as a person's
// do (decision 32): the cap's eviction names the SPIFFE ID. The gauge alone
// would pass with every workload held under "" (pre-flight M-8).
func TestAWorkloadsHeldConnectionsAreItsPrincipals(t *testing.T) {
	f, _, w := newWorkloadFixture(t)
	url, said := startServerWith(t, f, nil)
	for range DefaultListenerLimits.MaxPerPrincipal + 1 {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{w},
			RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}}
		if code, body := postMint(t, c, url); code != http.StatusOK {
			t.Fatalf("%d %s", code, body)
		}
	}
	// Only the workload holds connections here, so the held gauge is its.
	eventually(t, "the cap held", func() bool { return f.gauge("held") == float64(DefaultListenerLimits.MaxPerPrincipal) })
	// Nothing else in this test names the workload: the line is the eviction's.
	eventually(t, "the eviction named the workload", func() bool { return strings.Contains(said.String(), workloadID) })
}

// A listener given Map without Caller would map a workload's certificate
// through the directory as a person's: it serves nothing (pre-flight I-4).
func TestAListenerWithMapButNoCallerServesNothing(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	l := NewListener(Limit(ln, MaxConns), &tls.Config{}, DefaultListenerLimits, f.b.Metrics, f.b.Now, nil)
	l.Map = f.b.BindMap
	if _, err := l.Accept(); !errors.Is(err, ErrUnwired) {
		t.Fatalf("got %v", err)
	}
}

// BindMap never maps a workload's chain, whoever calls it: identity_unmapped,
// and the directory is not asked (decision 40 ruling 5; pre-flight I-4).
func TestBindMapNeverMapsAWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	_, ref := f.b.BindMap(context.Background(), *chainState(w, wca), store.Credential{})
	if ref == nil || ref.Reason != decision.IdentityUnmapped || f.b.Directory.Calls.Load() != 0 {
		t.Fatalf("refusal %+v, directory calls %d", ref, f.b.Directory.Calls.Load())
	}
}
```

`f.gauge`, `eventually` and `lockedBuffer` are `listen_test.go`'s and `server_test.go`'s.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/broker/ -run 'AWorkloadBinds|UnmappedWorkloadIsAnswered|AWorkloadsHeld|MapButNoCaller|BindMapNeverMaps' -count=1`
Expected: FAIL: `Listener.Caller`, `Broker.Wire` and `ErrUnwired` undefined.

- [ ] **Step 3: `Listener.Caller`, `Broker.Wire`, the handshake, and `BindMap`**

In `internal/broker/listen.go`, add to `Listener` after `Map`:

```go
	// Caller reads a connection's verified certificate as the broker does
	// (Broker.CertCallerOf; plan 8): a workload's principal is its SPIFFE ID,
	// never mapped. Broker.Wire sets it. Nil without Map reads a certificate
	// as before plan 8; nil with Map serves nothing (ErrUnwired).
	Caller func(cs *tls.ConnectionState, now time.Time) (CertCaller, error)
```

Add, before `NewListener`:

```go
// ErrUnwired is Accept's answer on a listener given Map without Caller: it
// would map a workload's certificate through the directory as a person's
// (decision 40 ruling 5), so it serves nothing and says why at start
// (pre-flight I-4).
var ErrUnwired = errors.New("broker: the listener has a directory Map but no Caller, so a workload certificate " +
	"would be mapped as a person's; wire it with Broker.Wire")

// Wire sets l's hooks from b: the one way port49d and port49-broker wire
// their listener (pre-flight I-4). Refused, Status and Caller always; Map
// under a directory. Caller is what keeps a workload out of Map.
func (b *Broker) Wire(l *Listener) {
	l.Refused = b.RefusedAtBind
	l.Status = b.BindStatus
	l.Caller = b.CertCallerOf
	l.Map = nil
	if b.Directory != nil {
		l.Map = b.BindMap
	}
}
```

At the top of `Accept`, before `l.startOnce.Do`, add:

```go
	if l.Map != nil && l.Caller == nil {
		return nil, ErrUnwired
	}
```

`http.Server.Serve` returns Accept's error, so the daemon's serve goroutine reports it and the
start fails rather than binding a workload as a person.

Add, after `handshake`:

```go
// callerOf is Caller's reading of cs, or, with none (and so no Map:
// Accept refuses that), the reading before plan 8: Identity.
func (l *Listener) callerOf(cs *tls.ConnectionState) (CertCaller, error) {
	if l.Caller != nil {
		return l.Caller(cs, l.now())
	}
	p, cred, err := Identity(cs, l.now())
	return CertCaller{Domain: DomainHumans, Principal: p, Cred: cred}, err
}
```

In `internal/broker/member.go`, at the top of `BindMap`, after the empty-chain check, add:

```go
	if machine, _ := b.machineChain(&cs); machine {
		// Defence in depth behind Listener.Caller (pre-flight I-4): a workload
		// is never mapped through the directory (decision 40 ruling 5).
		return directory.Answer{}, &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityUnmapped,
			Error: string(decision.IdentityUnmapped), Detail: "a workload certificate is never mapped through the " +
				"directory; the broker's listener is wired without Caller, so tell the operator"}
	}
```

In `internal/broker/member_test.go`, `serveThroughWith`'s hook `func(l *Listener) { l.Map =
f.b.BindMap }` becomes `func(l *Listener) { l.Caller = f.b.CertCallerOf; l.Map = f.b.BindMap }`:
with `Map` alone the listener now serves nothing.

In `handshake`, replace the block from `// The handshake's VerifyConnection ran Identity a moment ago`
through `certKey := store.CertKey(cred.Issuer, cred.Serial)` with:

```go
		// The handshake's VerifyConnection read the certificate a moment ago;
		// this reads the same answer, which a clock step alone could change.
		cc, err := l.callerOf(&cs)
		principal, legacy, cred := cc.Principal, cc.Legacy, cc.Cred
		if errors.Is(err, ErrWorkloadUnmapped) {
			// Answered over HTTP and recorded, never a TLS alert the
			// workload's client cannot read (decision 40 ruling 3).
			l.m.BrokerConnectionEvents.WithLabelValues("identity_refused").Inc()
			l.say("identity_unmapped", "broker: answering a connection from %s identity_unmapped and closing it "+
				"before it bound: %s", c.src, printsafe.Line(err.Error(), 300))
			l.answerRefused(tc, http.StatusUnauthorized, api.Error{Error: string(decision.IdentityUnmapped),
				Detail: err.Error()}, 0, "", cred, decision.IdentityUnmapped)
			return
		}
		if err != nil {
			l.refuse(c, tc, "identity_refused", err)
			return
		}
		// A workload is never mapped: its principal is its SPIFFE ID
		// (decision 40 ruling 5).
		mapped := l.Map != nil && cc.Domain != DomainMachines
		certKey := store.CertKey(cred.Issuer, cred.Serial)
```

then replace the `if l.Map != nil {` left in the rest of the block (the one before
`markedOf`) with `if mapped {`. Import `errors` and `internal/printsafe` if `listen.go` does not
already.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/broker/ -count=1 && go test -race ./internal/broker/ -run 'Listen|Workload|Server' -count=1`
Expected: PASS, every existing listener test included.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/listen.go internal/broker/member.go internal/broker/member_test.go internal/broker/workload_listen_test.go
git commit -m "feat(broker): the listener binds a workload as its SPIFFE ID and answers an unmapped one

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: Revoke and explain take a `spiffe://` principal; a workload certificate's mark says it does not follow a renewal

**Files:**
- Modify: `internal/broker/revoke.go` (`principalPrefixes`, `normalPrincipal`, `RevokeReport`,
  `Revoke`, `markText`)
- Modify: `internal/broker/workload.go` (`Workload.issuers`, `noteIssuer`, `Issued`; `CertCallerOf`
  notes a machine chain's issuer)
- Modify: `internal/testpki/testpki.go` (`CA.IssueCA`)
- Test: `internal/broker/revoke_test.go`, `internal/broker/explain_api_test.go`

**Interfaces:**
- Consumes: Task 2's `spiffe.Scheme`, `spiffe.ParseWorkload`, `spiffe.MaxLen`; Task 4's
  `Broker.Workload`; Task 5's `Workload.mu`.
- Produces:
  - `normalPrincipal` accepts a workload's SPIFFE ID verbatim;
  - `(*Workload).Issued(issuerDN string) bool`: the workload anchor's subject, or a leaf issuer
    this broker has seen on a verified machine chain (pre-flight M-1);
  - `RevokeReport.workload bool` (unexported), set when a certificate revocation's issuer is
    `Issued`;
  - `testpki.CA.IssueCA(cn string, notBefore, notAfter time.Time) (*CA, error)` (Task 8 reads it).

- [ ] **Step 1: Write the failing tests**

In `internal/broker/revoke_test.go`, add:

```go
// A workload's principal is revoked as the log spells it, verbatim: every
// certificate it renews to is refused, and its unspent tokens deleted
// (decision 40 rulings 8 and 15).
func TestARevokedPrincipalRefusesEveryCertificateOfTheWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	if res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"); res.Code != http.StatusOK {
		t.Fatalf("%s", answer(res))
	}
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: workloadID, Origin: "admin_socket uid 0"})
	if err != nil || rep.TokenKeys != 1 || rep.Mark.Key != workloadID {
		t.Fatalf("%+v %v", rep, err)
	}
	renewed := f.workloadCert(t, wca, workloadID) // a new serial, the same ID
	if res := f.post(context.Background(), chainState(renewed, wca), mintLeaf1, "k2"); res.Code != http.StatusUnauthorized ||
		!strings.Contains(res.Body.String(), "credential_revoked") {
		t.Fatalf("the renewed certificate: %s", answer(res))
	}
}

func TestASpiffePrincipalIsNormalisedVerbatimOrRefused(t *testing.T) {
	for in, want := range map[string]string{
		workloadID: workloadID,
		"spiffe://corp.example.com/ns/Netops/sa/Oxidized": "spiffe://corp.example.com/ns/Netops/sa/Oxidized",
	} {
		if got, err := normalPrincipal(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"SPIFFE://corp.example.com/x", "spiffe://Corp.example.com/x", "spiffe://corp.example.com",
		"system:serviceaccount:netops:oxidized"} {
		if got, err := normalPrincipal(in); !errors.Is(err, ErrBadRevocation) {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}

// A mark by certificate names (issuer, serial), and a renewal brings a new
// serial: the answer says so for the workload anchor's certificates
// (decision 40 ruling 8).
func TestRevokingAWorkloadCertificateSaysItDoesNotFollowARenewal(t *testing.T) {
	f, _, w := newWorkloadFixture(t)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Issuer: w.Leaf.Issuer.String(),
		Serial: w.Leaf.SerialNumber.Text(16), Origin: "admin_socket uid 0"})
	if err != nil {
		t.Fatal(err)
	}
	if text := rep.Text(); !strings.Contains(text, "the workload renews it under a new serial this mark does not name") ||
		!strings.Contains(text, "port49 revoke --principal spiffe://") {
		t.Fatalf("%s", text)
	}
	alice, err := f.b.Revoke(context.Background(), RevokeRequest{Issuer: f.alice.Leaf.Issuer.String(),
		Serial: f.alice.Leaf.SerialNumber.Text(16), Origin: "admin_socket uid 0"})
	if err != nil || strings.Contains(alice.Text(), "renews it") {
		t.Fatalf("a person's certificate: %s %v", alice.Text(), err)
	}
}

// A workload certificate under an intermediate of the workload anchor gets
// the note too, once the broker has seen that intermediate issue a verified
// machine chain (pre-flight M-1).
func TestRevokingAWorkloadCertificateUnderAnIntermediateSaysItToo(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	sub, err := wca.IssueCA("Workloads Issuing CA", f.now.Add(-time.Hour), f.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	w := f.workloadCert(t, sub, workloadID)
	cs := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{w.Leaf, sub.Cert, wca.Cert}}}
	if _, err := f.b.CertCallerOf(cs, f.now); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Issuer: w.Leaf.Issuer.String(),
		Serial: w.Leaf.SerialNumber.Text(16), Origin: "admin_socket uid 0"})
	if err != nil || !strings.Contains(rep.Text(), "the workload renews it under a new serial this mark does not name") {
		t.Fatalf("%s %v", rep.Text(), err)
	}
}

// Nothing found under a spiffe:// principal is said in a workload's terms.
func TestAnUnknownWorkloadPrincipalIsSaidInItsOwnTerms(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: "spiffe://corp.example.com/host/nobody",
		Origin: "admin_socket uid 0"})
	if err != nil || !strings.Contains(rep.Text(), "a workload's principal is its certificate's SPIFFE ID, verbatim") {
		t.Fatalf("%s %v", rep.Text(), err)
	}
}
```

In `internal/broker/explain_api_test.go`, add:

```go
// explain_others reaches a workload principal by its SPIFFE ID.
func TestExplainNamesAWorkload(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(workloadPolicy, "username: alice, enable: token,",
		"username: alice, api: [explain_others], enable: token,", 1))
	res := f.call(context.Background(), f.state(f.alice), "POST", "/v1/explain",
		`{"device":"leaf1","command":"show running-config","principal":"`+workloadID+`"}`)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"principal":"`+workloadID+`"`) ||
		!strings.Contains(res.Body.String(), `"verdict":"permit"`) {
		t.Fatalf("%s", answer(res))
	}
}
```

Import `errors`, `crypto/tls`, `crypto/x509`, `time` and `net/http` where those files do not
already.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/broker/ -run 'RevokedPrincipalRefusesEvery|SpiffePrincipal|DoesNotFollowARenewal|UnderAnIntermediate|UnknownWorkloadPrincipal|ExplainNamesAWorkload' -count=1`
Expected: FAIL: `normalPrincipal` refuses `spiffe://`; `IssueCA` undefined.

- [ ] **Step 3: `testpki.CA.IssueCA`; the issuers a workload's chains show; `normalPrincipal`, the
  report, the text**

In `internal/testpki/testpki.go`, after `Issue`, add:

```go
// IssueCA signs a subordinate CA under ca, valid from notBefore to notAfter:
// an issuing CA beneath a root, as the workload anchor's tests need.
func (ca *CA) IssueCA(cn string, notBefore, notAfter time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore,
		NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}
```

In `internal/broker/workload.go`, add to `Workload`, after `late`:

```go
	// issuers are the leaf issuers seen on verified machine chains since the
	// start, at most maxIssuers: an intermediate under the anchor, which the
	// revoke note must know (pre-flight M-1). Per replica.
	issuers map[string]bool
```

and add:

```go
// maxIssuers bounds Workload.issuers: a workload CA has a handful.
const maxIssuers = 64

// noteIssuer records a verified machine chain's leaf issuer.
func (w *Workload) noteIssuer(dn string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.issuers == nil {
		w.issuers = map[string]bool{}
	}
	if len(w.issuers) < maxIssuers {
		w.issuers[dn] = true
	}
}

// Issued reports whether a certificate whose issuer is dn is a workload's as
// far as this broker knows: the anchor issued it, or dn issued a verified
// machine chain here.
func (w *Workload) Issued(dn string) bool {
	if dn == w.Anchor.Subject.String() {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.issuers[dn]
}
```

In `CertCallerOf`, in the machine branch, after `cc.Principal = p`, add
`b.Workload.noteIssuer(leaf.Issuer.String())`.

In `internal/broker/revoke.go`:

- Replace `principalPrefixes` and its comment with:

  ```go
// principalPrefixes are the forms a verifier gives a principal (spec §2):
// user: for people, app: for an OIDC machine (plan 7h), spiffe:// for a
// workload certificate (plan 8). system:serviceaccount: is refused until
// its verifier exists (plan 10), rather than marked under a key nothing
// spells.
var principalPrefixes = []string{"user:", "app:", spiffe.Scheme}
  ```

- In `normalPrincipal`, before the length check, add:

  ```go
	if strings.HasPrefix(strings.ToLower(p), spiffe.Scheme) {
		// Verbatim: the path is case-sensitive, and the verifier gives the
		// ID only in the form ParseWorkload accepts (decision 40 ruling 4).
		if _, err := spiffe.ParseWorkload(p); err != nil {
			return "", fmt.Errorf("%w: %s is not a workload's SPIFFE ID as the broker spells one (%v)",
				ErrBadRevocation, printsafe.Line(p, 200), err)
		}
		return p, nil
	}
  ```

  and widen the final refusal's examples to
  `"(user:alice@example.com, app:port49-ci, spiffe://corp.example.com/host/oxidized-01)"`.
- Add to `RevokeReport`, beside `decimal`:

  ```go
	// workload is set when a certificate revocation's issuer is a workload's
	// (Workload.Issued): the workload renews under a new serial (decision 40
	// ruling 8).
	workload bool
  ```

- In `Revoke`, after `rep := RevokeReport{Request: req, By: kind, Mark: mark, decimal: decimal}`, add:

  ```go
	rep.workload = kind == store.RevocationCert && b.Workload != nil && b.Workload.Issued(req.Issuer)
  ```

- In `markText`, replace the "nothing was found" lead's tail so a workload principal is said in
  its own terms:

  ```go
		spelled := "the broker spells a certificate's principal user:<lower-case email>"
		if strings.HasPrefix(r.Request.Principal, spiffe.Scheme) {
			spelled = "a workload's principal is its certificate's SPIFFE ID, verbatim"
		}
		fmt.Fprintf(&b, "%s; %s, so check the spelling (the mark is written anyway)\n", lead, spelled)
  ```

  and after the `decimal` paragraph add:

  ```go
	if r.Mark.Kind == store.RevocationCert && r.workload {
		b.WriteString("\nthis certificate's issuer is the workload trust anchor (broker.identity.machines): the " +
			"workload renews it under a new serial this mark does not name; revoke its principal too (port49 " +
			"revoke --principal spiffe://…), and revoke the certificate at your CA so it cannot be renewed")
	}
  ```

Import `internal/spiffe` (and `internal/printsafe` if needed). A test that asserted the old
refusal's example list exactly is updated to the new one, said in the commit message.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/broker/... ./internal/testpki/ ./cmd/port49/ -count=1 && go test -race ./internal/broker/ -run 'Revok|Workload' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/revoke.go internal/broker/workload.go internal/broker/revoke_test.go internal/broker/explain_api_test.go internal/testpki/testpki.go
git commit -m "feat(broker): revoke and explain a workload by its SPIFFE ID; a certificate mark says renewal escapes it

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: port49d and port49-broker run the workload verifier

**Files:**
- Modify: `internal/broker/server.go` (`ReadAnchor`, factored out of `LoadTLSAnchor`)
- Modify: `internal/port49d/main.go` (`buildBrokerAnchor`, `brk.Wire(bl)`, certificate status)
- Modify: `internal/port49d/brokerd.go` (`brk.Wire(bl)`, certificate status)
- Modify: `internal/port49d/certstatus.go` (`certStatusConfig`, `uncoveredIssuers`,
  `uncoveredAnchor`, `anchorCoverLine`)
- Modify: `internal/port49d/identity.go` (`announceIdentity`, `announceWorkloadIdentities`)
- Create: `internal/port49d/workload_test.go`
- Modify: `internal/port49d/certstatus_test.go` (the changed signature)

**Interfaces:**
- Consumes: Task 3's `BrokerConfig.WorkloadCAFile`, `oidc.Config.X509Machine`; Task 4's
  `broker.Workload`, `Broker.CertCallerOf`; Task 6's `Broker.Wire`; Task 7's `testpki.CA.IssueCA`;
  Task 2's `Policy.SPIFFEIdentities`.
- Produces:
  - `broker.ReadAnchor(path string) (*x509.Certificate, error)` (one certificate, as
    `LoadTLSAnchor` requires);
  - `buildBrokerAnchor(...) (*http.Server, *broker.Broker, []namedAnchor, error)` with
    `type namedAnchor struct{ key string; cert *x509.Certificate }`;
  - `distinctAnchors(human, workload namedAnchor) error`;
  - `certStatusConfig(cs config.CertificateStatusConfig, anchors []*x509.Certificate, stateDir
    string) (certstatus.Config, error)`;
  - `uncoveredAnchor(cfg certstatus.Config, anchor *x509.Certificate) bool` (no CRL covers it);
  - `anchorCoverLine(a namedAnchor, cfg certstatus.Config) string` (what the start says of it, both
    daemons);
  - `announceWorkloadIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy)`.

- [ ] **Step 1: Write the failing tests**

`internal/port49d/workload_test.go`:

```go
package port49d

import (
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
)

// withWorkloadAnchor writes ca as the workload anchor of cfg's broker, for
// corp.example.com, beside the human anchor brokerConfig wrote.
func withWorkloadAnchor(t *testing.T, cfg *config.Config, ca *testpki.CA) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(cfg.Broker.ClientCAFile), "workloads-ca.pem")
	if err := os.WriteFile(path, ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.WorkloadCAFile = path
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: cfg.Broker.ClientCAFile, Timing: oidc.DefaultTiming,
		X509Machine: &oidc.X509Machine{AnchorFile: path, TrustDomains: []string{"corp.example.com"}}}
	return path
}

// workloadPolicyBody is minimalPolicy with a workload subject naming id.
func workloadPolicyBody(id string) string {
	return strings.NewReplacer(
		`subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]`,
		`subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s},
           {name: svc, identity: ["`+id+`"], username: svc-oxidized, token_ttl: 60s}]`,
		`grants: [{subject: s, scope: all_devices, roles: [r]}]`,
		`grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: svc, scope: all_devices, roles: [r]}]`,
	).Replace(minimalPolicy)
}

func TestAWorkloadBrokerBuildsAndSaysWhatItTrusts(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfg := brokerConfig(t, workloadPolicyBody("spiffe://lab.example.net/host/x"))
	ca, err := testpki.NewCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := withWorkloadAnchor(t, &cfg, ca)
	_, b, anchors, err := buildBrokerAnchor(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), newMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if b.Workload == nil || !b.Workload.Anchor.Equal(ca.Cert) || len(anchors) != 2 ||
		anchors[1].key != "broker.identity.machines' x509 trust_anchor_file" {
		t.Fatalf("workload %+v anchors %+v", b.Workload, anchors)
	}
	for _, want := range []string{
		"identity: machines: x509 (trust anchor " + path + "; SPIFFE trust domains corp.example.com; principal: the certificate's one URI SAN)",
		"identity: workload certificates are issued and renewed by your CA, never by port49",
		"policy: 1 workload identities mint for no one: spiffe://lab.example.net/host/x (subject svc): no machines x509 verifier lists trust domain lab.example.net",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// With no workload verifier, a spiffe:// identity mints for no one, said so.
func TestASpiffeIdentityWithNoWorkloadVerifierIsSaid(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfg := brokerConfig(t, workloadPolicyBody("spiffe://corp.example.com/host/oxidized-01"))
	if err := buildWith(cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mint for no one: spiffe://corp.example.com/host/oxidized-01 (subject svc): no "+
		"broker.identity.machines x509 verifier is configured") {
		t.Fatalf("%s", out.String())
	}
}

func TestTheSameAnchorTwiceRefusesTheStart(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	raw, err := os.ReadFile(cfg.Broker.ClientCAFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "copy.pem")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.WorkloadCAFile = path
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: cfg.Broker.ClientCAFile, Timing: oidc.DefaultTiming,
		X509Machine: &oidc.X509Machine{AnchorFile: path, TrustDomains: []string{"corp.example.com"}}}
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "holds the same certificate as") {
		t.Fatalf("got %v", err)
	}
}

func TestAnAnchorSignedByTheOtherRefusesTheStart(t *testing.T) {
	root, err := testpki.NewCA("Corp Root", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := root.IssueCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ human, workload *x509.Certificate }{
		"the human anchor signs the workload anchor": {root.Cert, sub.Cert},
		"the workload anchor signs the human anchor": {sub.Cert, root.Cert},
	} {
		err := distinctAnchors(namedAnchor{key: "broker.client_ca_file", cert: c.human},
			namedAnchor{key: "broker.identity.machines' x509 trust_anchor_file", cert: c.workload})
		if err == nil || !strings.Contains(err.Error(), "chains to both anchors and is refused at every request; anchor each "+
			"list at its own issuing CA") {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := distinctAnchors(namedAnchor{cert: root.Cert}, namedAnchor{cert: other.Cert}); err != nil {
		t.Fatalf("two unrelated anchors: %v", err)
	}
}

// A CRL under either anchor is a source; one under neither is refused; an
// anchor no source covers is said (decision 40 ruling 7).
func TestCertificateStatusCoversBothAnchors(t *testing.T) {
	human, _ := testpki.NewCA("Users CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	work, _ := testpki.NewCA("Workloads CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	stranger, _ := testpki.NewCA("Stranger CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	dir := t.TempDir()
	write := func(name string, ca *testpki.CA) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, ca.PEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cs := config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{
		{Name: "users", File: "/x", IssuerFile: write("users.pem", human)}}}
	ccfg, err := certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if uncoveredAnchor(ccfg, human.Cert) || !uncoveredAnchor(ccfg, work.Cert) {
		t.Fatal("coverage: the users' anchor is covered and the workloads' is not")
	}
	wa := namedAnchor{key: "broker.identity.machines' x509 trust_anchor_file", cert: work.Cert}
	if line := anchorCoverLine(wa, ccfg); !strings.Contains(line, "every certificate under CN=Workloads CA "+
		"(broker.identity.machines' x509 trust_anchor_file) will be refused") || !strings.Contains(line, "turn the CA's CRL on") {
		t.Fatalf("uncovered: %q", line)
	}
	// OCSP alone is said as unchecked for the anchor, never as cover
	// (pre-flight M-18).
	ccfg.OCSP = &certstatus.OCSPConfig{}
	if line := anchorCoverLine(wa, ccfg); !strings.Contains(line, "are covered by OCSP alone, unchecked for this anchor") {
		t.Fatalf("OCSP alone: %q", line)
	}
	cs.CRLs = append(cs.CRLs, config.CertificateStatusCRL{Name: "work", File: "/y", IssuerFile: write("work.pem", work)})
	if ccfg, err = certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir); err != nil ||
		uncoveredAnchor(ccfg, work.Cert) || anchorCoverLine(wa, ccfg) != "" {
		t.Fatalf("a CRL under the workload anchor: %v", err)
	}
	cs.CRLs = append(cs.CRLs, config.CertificateStatusCRL{Name: "stranger", File: "/z", IssuerFile: write("s.pem", stranger)})
	if _, err := certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir); err == nil ||
		!strings.Contains(err.Error(), "is neither a trust anchor's certificate nor signed by one") {
		t.Fatalf("a CRL under neither anchor: %v", err)
	}
}
```

`testpki.CA.IssueCA` is Task 7's. `syncBuffer`, `brokerConfig`, `buildWith`, `seedMinter`,
`minimalPolicy` and `newMetrics` are the package's test helpers; import `io`, `internal/certstatus`,
`internal/decision` and `internal/store/memory` for the build call, as `buildWith` does.

In `internal/port49d/certstatus_test.go`, change each `certStatusConfig(cs, anchor, dir)` call to
`certStatusConfig(cs, []*x509.Certificate{anchor}, dir)`, and each expected
`"is neither broker.client_ca_file's certificate nor signed by it"` to
`"is neither a trust anchor's certificate nor signed by one"`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/port49d/ -run 'Workload|SameAnchorTwice|AnchorSignedByTheOther|CoversBothAnchors|SpiffeIdentityWithNo' -count=1`
Expected: FAIL: `namedAnchor`, `distinctAnchors`, `uncoveredAnchor`, `anchorCoverLine` undefined.

- [ ] **Step 3: `broker.ReadAnchor`**

In `internal/broker/server.go`, factor the anchor read out of `LoadTLSAnchor` into:

```go
// ReadAnchor reads a trust anchor file: exactly one certificate, as
// client_ca_file and each trust_anchor_file must hold (design §19 step 3;
// plan 8 for the workload anchor).
func ReadAnchor(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var anchors []*x509.Certificate
	for rest := raw; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) != 1 {
		return nil, fmt.Errorf("%s holds %d certificates; exactly one trust anchor is accepted (design §19 step 3)",
			path, len(anchors))
	}
	return anchors[0], nil
}
```

and have `LoadTLSAnchor` call it, wrapping its error as `fmt.Errorf("broker: client_ca_file %w", err)`
so `TestLoadTLSTakesExactlyOneAnchor`'s expected text still matches (adjust the wrap to the exact
text that test asserts).

- [ ] **Step 4: `buildBrokerAnchor` reads the workload anchor; the hooks; the lines**

In `internal/port49d/main.go`:

- Add:

  ```go
// namedAnchor is a trust anchor the broker read, and the key naming its
// file, for every line about it (plan 8).
type namedAnchor struct {
	key  string
	cert *x509.Certificate
}

// distinctAnchors refuses a workload anchor that is the human anchor, or
// that signs it or is signed by it (decision 40 ruling 2): a certificate
// under the subordinate would chain to both, refused at every request or not
// as its client's intermediates fall. A nil human anchor (people by OIDC)
// has nothing to cross.
func distinctAnchors(human, workload namedAnchor) error {
	if human.cert == nil {
		return nil
	}
	subj := func(c *x509.Certificate) string { return printsafe.Line(c.Subject.String(), 200) }
	switch {
	case bytes.Equal(human.cert.Raw, workload.cert.Raw):
		return fmt.Errorf("%s: holds the same certificate as %s; a certificate it verifies would be a person's and "+
			"a workload's at once", workload.key, human.key)
	case workload.cert.CheckSignatureFrom(human.cert) == nil, human.cert.CheckSignatureFrom(workload.cert) == nil:
		signer, signed := human, workload
		if human.cert.CheckSignatureFrom(workload.cert) == nil {
			signer, signed = workload, human
		}
		return fmt.Errorf("%s: %s signs %s (%s): a certificate under the one chains to both anchors and is refused "+
			"at every request; anchor each list at its own issuing CA", workload.key, subj(signer.cert),
			subj(signed.cert), human.key)
	}
	return nil
}
  ```

- Change `buildBrokerAnchor`'s third result to `[]namedAnchor`. After the server certificate is
  loaded, build the list:

  ```go
	var anchors []namedAnchor
	human := namedAnchor{key: "broker.client_ca_file", cert: anchorCert}
	if id := cfg.Broker.Identity; id != nil && !id.Shorthand {
		human.key = "broker.identity.humans' x509 trust_anchor_file"
	}
	if anchorCert != nil {
		anchors = append(anchors, human)
	}
	var workload *broker.Workload
	if f := cfg.Broker.WorkloadCAFile; f != "" {
		wa, err := broker.ReadAnchor(f)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("broker.identity.machines' x509 trust_anchor_file %s: %w", f, err)
		}
		w := namedAnchor{key: "broker.identity.machines' x509 trust_anchor_file", cert: wa}
		if err := distinctAnchors(human, w); err != nil {
			return nil, nil, nil, err
		}
		anchors = append(anchors, w)
		workload = &broker.Workload{Anchor: wa, TrustDomains: cfg.Broker.Identity.X509Machine.TrustDomains}
	}
  ```

  set `b.Workload = workload` beside `b.NoX509 = …`, call
  `announceWorkloadIdentities(stderr, proc, cfg, pol)` beside `announceDirectory(stderr, proc,
  cfg, pol)`, and return `anchors`. Like decision 38 ruling 17's group-subject line, which
  `announceDirectory` says, it is said at start only; neither is said at a policy reload
  (pre-flight M-9: the two stay alike).
- In `buildBroker`, ignore the third result as before.
- Where `run` builds the listener, replace the four hook lines (`bl.Refused = brk.RefusedAtBind`,
  `bl.Status = brk.BindStatus`, and the `if brk.Directory != nil { bl.Map = brk.BindMap }` block)
  with `brk.Wire(bl)` (pre-flight I-4: one wiring for both daemons, tested in Task 6).
- In the certificate status block, replace `certStatusConfig(*cs, anchorCert, …)` with
  `certStatusConfig(*cs, certsOf(anchors), …)`, and the `uncoveredIssuers` loop with:

  ```go
			for _, a := range anchors {
				if line := anchorCoverLine(a, ccfg); line != "" {
					fmt.Fprintf(stderr, "port49d: %s\n", line)
					continue
				}
				for _, subject := range uncoveredIssuers(ccfg, a.cert) { // re-check R3
					fmt.Fprintf(stderr, "port49d: broker: certificate status: certificates issued by %s will be refused: "+
						"nothing covers %s itself; name the root CA's CRL\n", subject, subject)
				}
			}
  ```

  with `func certsOf(as []namedAnchor) []*x509.Certificate` beside `namedAnchor`.

In `internal/port49d/brokerd.go`, make the same three changes: the `anchorCert` result renamed
`anchors`; the four hook lines replaced with `brk.Wire(bl)`; and the coverage loop, saying each
line through `brokerSay`.

Then check that neither daemon sets a hook by hand:
`grep -n 'bl\.\(Map\|Caller\|Refused\|Status\) =' internal/port49d/*.go` prints nothing.

- [ ] **Step 5: `certStatusConfig` takes every anchor; `uncoveredIssuers` reads one anchor's
  sources; `uncoveredAnchor`**

In `internal/port49d/certstatus.go`:

- Change the signature to `certStatusConfig(cs config.CertificateStatusConfig, anchors
  []*x509.Certificate, stateDir string)`, and replace the issuer check with:

  ```go
		under := slices.ContainsFunc(anchors, func(a *x509.Certificate) bool {
			return bytes.Equal(issuer.Raw, a.Raw) || issuer.CheckSignatureFrom(a) == nil
		})
		if !under {
			return certstatus.Config{}, fmt.Errorf("%s: %s is neither a trust anchor's certificate nor signed by "+
				"one (broker.client_ca_file, or broker.identity's trust_anchor_file); CRL %s would vouch for "+
				"certificates the broker does not trust", key, printsafe.Line(issuer.Subject.String(), 200), src.Name)
		}
  ```

- In `uncoveredIssuers`, read only the sources under `anchor`: skip a source whose issuer
  `anchor` did not sign (`src.Issuer.CheckSignatureFrom(anchor) != nil`) when collecting
  subjects, so one anchor's intermediates are never named under the other.
- Add:

  ```go
// uncoveredAnchor reports whether no CRL covers anchor: none whose issuer is
// anchor or a CA it signed. OCSP is not read here: whether a responder
// answers for this anchor's certificates cannot be known at start
// (anchorCoverLine says so; pre-flight M-18).
func uncoveredAnchor(cfg certstatus.Config, anchor *x509.Certificate) bool {
	for _, src := range cfg.CRLs {
		if bytes.Equal(src.Issuer.Raw, anchor.Raw) || src.Issuer.CheckSignatureFrom(anchor) == nil {
			return false
		}
	}
	return true
}

// anchorCoverLine is what the start says of an anchor no CRL covers, "" when
// one does. With no OCSP either, under on_unavailable: refuse every
// certificate under it is refused; with OCSP alone, the cover is unchecked
// for this anchor. The start never refuses itself over it (decision 40 ruling
// 7): a refused port49d start takes device AAA down for everyone. It names
// the safe path, never on_unavailable: allow.
func anchorCoverLine(a namedAnchor, cfg certstatus.Config) string {
	if !uncoveredAnchor(cfg, a.cert) {
		return ""
	}
	subj := printsafe.Line(a.cert.Subject.String(), 200)
	if cfg.OCSP != nil {
		return fmt.Sprintf("broker: certificate status: certificates under %s (%s) are covered by OCSP alone, "+
			"unchecked for this anchor: one with no OCSP URL, or one its responder does not answer for, is refused",
			subj, a.key)
	}
	return fmt.Sprintf("broker: certificate status: every certificate under %s (%s) will be refused: no crls "+
		"entry is that anchor or a CA it signed, and no ocsp is set; turn the CA's CRL on and name it in crls, "+
		"or sync it to a file: source", subj, a.key)
}
  ```

  `namedAnchor` is `main.go`'s, in the same package.

- [ ] **Step 6: The start lines**

In `internal/port49d/identity.go`, `announceIdentity`, after the OIDC loop that fills `machines`,
add:

```go
	if m := id.X509Machine; m != nil {
		machines = append([]string{fmt.Sprintf("x509 (trust anchor %s; SPIFFE trust domains %s; principal: the "+
			"certificate's one URI SAN)", m.AnchorFile, strings.Join(m.TrustDomains, ", "))}, machines...)
	}
```

and after the `machines` line is printed:

```go
	if id.X509Machine != nil {
		fmt.Fprintf(w, "%s: identity: workload certificates are issued and renewed by your CA, never by port49; "+
			"one presented with under a quarter of its validity left is said here and counted in "+
			"port49_workload_certificates_renewal_late_total\n", proc)
	}
```

Add:

```go
// announceWorkloadIdentities says the policy's spiffe:// identities no
// verifier can give (decision 40 ruling 16): with no workload verifier, all
// of them; with one, those whose trust domain it does not list. The policy
// still loads, as a group subject without a directory does.
func announceWorkloadIdentities(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	ids := pol.SPIFFEIdentities()
	if len(ids) == 0 || cfg.Broker == nil {
		return
	}
	var m *oidc.X509Machine
	if cfg.Broker.Identity != nil {
		m = cfg.Broker.Identity.X509Machine
	}
	var lines []string
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		parsed, err := spiffe.ParseWorkload(id)
		switch {
		case err != nil:
			continue // the policy's load refused it already
		case m == nil:
			lines = append(lines, fmt.Sprintf("%s (subject %s): no broker.identity.machines x509 verifier is configured",
				id, ids[id]))
		case !slices.Contains(m.TrustDomains, parsed.TrustDomain):
			lines = append(lines, fmt.Sprintf("%s (subject %s): no machines x509 verifier lists trust domain %s",
				id, ids[id], parsed.TrustDomain))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintf(w, "%s: policy: %d workload identities mint for no one: %s\n", proc, len(lines),
			strings.Join(lines, "; "))
	}
}
```

importing `maps`, `slices`, `internal/policy` and `internal/spiffe`.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/port49d/ ./internal/broker/ -count=1 && go test -race ./internal/port49d/ -run 'Workload|Anchor|CertificateStatus|Identity|Broker' -count=1 && make vet`
Expected: PASS, the existing start-line, certificate status and broker-run tests included (they
now run through `brk.Wire`).

- [ ] **Step 8: Commit**

```bash
git add internal/broker/server.go internal/port49d
git commit -m "feat(port49d): run the workload verifier; refuse crossed anchors; say what each covers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: `internal/workload`, the agentless client

**Files:**
- Create: `internal/workload/client.go`, `internal/workload/client_test.go`

**Interfaces:**
- Consumes: Task 5's `api.LateRenewal` and `api.UncoveredStatus`; `internal/broker/api`'s
  `Config`, `MintRequest`, `MintResponse`, `Identity`, `Error`; `keyfile.LoadX509KeyPair`.
- Produces (Task 10 and Task 11 call these):
  - `type Config struct{ Broker string; BrokerCA *x509.CertPool; CertFile, KeyFile string;
    Deadline time.Duration; Now func() time.Time; Warn func(format string, args ...any) }`;
  - `const DefaultDeadline = 2 * time.Minute`; `var ErrTemporary`;
  - `type CertError struct{ File string; NotBefore, NotAfter time.Time; Expired bool }`;
  - `type APIError struct{ Status int; Code, Detail string }`;
  - `type TemporaryError struct{ Unminted []string; Last error; Deadline time.Duration }`
    (`errors.Is(err, ErrTemporary)`);
  - `func LoadCertificate(certFile, keyFile string, now time.Time, warn func(string, ...any))
    (tls.Certificate, error)`;
  - `func New(cfg Config) (*Client, error)`;
  - `type MintOptions struct{ Devices []string; Enable bool; TTL time.Duration; Purpose string }`;
  - `func (c *Client) Mint(ctx context.Context, o MintOptions) (api.MintResponse, error)`: the
    results of every page minted, and, when a page was not, a `*TemporaryError` naming every device
    from that page on, or the final `*APIError` (an uncovered certificate status among them);
  - `func (c *Client) Identity(ctx context.Context) (api.Identity, error)`.

- [ ] **Step 1: Write the failing tests**

`internal/workload/client_test.go`:

```go
package workload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// fakeBroker answers /v1/config with batchMax and each /v1/tokens call with
// the next of answers (the last repeating), recording what it was sent.
type fakeBroker struct {
	mu       sync.Mutex
	batchMax int
	answers  []func(w http.ResponseWriter, req api.MintRequest)
	keys     []string
	bodies   []api.MintRequest
	presents []string // the client certificate's fingerprint, per request
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		f.presents = append(f.presents, hex.EncodeToString(sum[:]))
	}
	switch r.URL.Path {
	case "/v1/config":
		_ = json.NewEncoder(w).Encode(api.Config{BatchMax: f.batchMax})
	case "/v1/identity":
		_ = json.NewEncoder(w).Encode(api.Identity{Principal: "spiffe://corp.example.com/host/oxidized-01", Method: "cert"})
	case "/v1/tokens":
		var req api.MintRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
		f.bodies = append(f.bodies, req)
		i := min(len(f.keys)-1, len(f.answers)-1)
		f.answers[i](w, req)
	}
}

func permitAll(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Username: "svc-oxidized",
			Login: "TOKEN" + d})
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func refuse(status int, code, retryAfter string) func(http.ResponseWriter, api.MintRequest) {
	return func(w http.ResponseWriter, _ api.MintRequest) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(api.Error{Error: code, Detail: code + " detail"})
	}
}

type harness struct {
	f       *fakeBroker
	cfg     Config
	now     time.Time
	slept   []time.Duration
	ca      *testpki.CA
	dir     string
	sleepFn func(context.Context, time.Duration) error
}

// newHarness starts a TLS broker that requires a client certificate from
// ca, writes a workload certificate valid for notAfter-from-now into dir
// (0600), and a Config whose clock moves only when the client sleeps.
func newHarness(t *testing.T, f *fakeBroker, life time.Duration) *harness {
	t.Helper()
	h := &harness{f: f, now: time.Now().Truncate(time.Second), dir: t.TempDir()}
	ca, err := testpki.NewCA("workloads", h.now.Add(-time.Hour), h.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.ca = ca
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: h.now.Add(-time.Hour), NotAfter: h.now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(life))
	h.cfg = Config{Broker: srv.URL, BrokerCA: ca.Pool(), CertFile: filepath.Join(h.dir, "w.pem"),
		KeyFile: filepath.Join(h.dir, "w-key.pem"), Now: func() time.Time { return h.now }}
	h.sleepFn = func(_ context.Context, d time.Duration) error {
		h.slept = append(h.slept, d)
		h.now = h.now.Add(d)
		return nil
	}
	return h
}

func (h *harness) writeCert(t *testing.T, notBefore, notAfter time.Time) {
	t.Helper()
	u, _ := url.Parse("spiffe://corp.example.com/host/oxidized-01")
	c, err := h.ca.Issue(testpki.Leaf{CommonName: "oxidized-01", URIs: []*url.URL{u}, Client: true,
		NotBefore: notBefore, NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "w.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "w-key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = h.sleepFn
	return c
}

func devices(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "leaf"+string(rune('1'+i)))
	}
	return out
}

func TestPagesByBatchMaxEachUnderItsOwnKey(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(5), TTL: 15 * time.Minute})
	if err != nil || len(resp.Results) != 5 || resp.Results[4].Device != "leaf5" || resp.Subject != "svc_oxidized" {
		t.Fatalf("%+v %v", resp, err)
	}
	if len(f.keys) != 3 || f.keys[0] == f.keys[1] || f.keys[1] == f.keys[2] || f.keys[0] == "" ||
		f.bodies[0].TTLSeconds != 900 || len(f.bodies[2].Devices) != 1 {
		t.Fatalf("keys %v bodies %+v", f.keys, f.bodies)
	}
}

func TestARetryReusesTheKeyAndHonoursRetryAfter(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusServiceUnavailable, "store_unavailable", "7"),
		refuse(http.StatusConflict, "idempotency_in_progress", "1"),
		permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)}); err != nil {
		t.Fatal(err)
	}
	if len(f.keys) != 3 || f.keys[0] != f.keys[1] || f.keys[1] != f.keys[2] {
		t.Fatalf("a retry under another key: %v", f.keys)
	}
	if len(h.slept) != 2 || h.slept[0] != 7*time.Second || h.slept[1] != time.Second {
		t.Fatalf("slept %v", h.slept)
	}
}

func TestTheDeadlineEndsWithTheUnmintedDevices(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){
		permitAll, refuse(http.StatusServiceUnavailable, "store_unavailable", "30")}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(4)})
	var te *TemporaryError
	if !errors.As(err, &te) || !errors.Is(err, ErrTemporary) || strings.Join(te.Unminted, ",") != "leaf3,leaf4" ||
		len(resp.Results) != 2 || !strings.Contains(err.Error(), "503 store_unavailable") {
		t.Fatalf("%+v %v", resp, err)
	}
	if total := sum(h.slept); total > DefaultDeadline {
		t.Fatalf("slept %v past the deadline", total)
	}
}

func TestAFinalRefusalIsNotRetried(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusUnauthorized, "credential_revoked", "")}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "credential_revoked" || len(f.keys) != 1 || len(h.slept) != 0 {
		t.Fatalf("%v keys %v", err, f.keys)
	}
}

// statusUnavailable answers as the broker does when it cannot establish a
// certificate's status, cause in its detail (certcheck.go).
func statusUnavailable(cause string) func(http.ResponseWriter, api.MintRequest) {
	return func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "certificate_status_unavailable",
			Detail: "the broker cannot establish this certificate's revocation status (" + cause + "); try again"})
	}
}

// No status source covers the workload anchor: the broker answers 503 with
// Retry-After, but nothing changes until the operator adds a CRL or OCSP, so
// it is final here, never "run again" every night (Ruling 7; pre-flight I-2).
func TestAnUncoveredCertificateStatusIsFinal(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		statusUnavailable(api.UncoveredStatus + ` "CN=Workloads Issuing CA"`), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var ae *APIError
	if !errors.As(err, &ae) || errors.Is(err, ErrTemporary) || ae.Code != "certificate_status_unavailable" ||
		!strings.Contains(err.Error(), api.UncoveredStatus) || len(f.keys) != 1 || len(h.slept) != 0 {
		t.Fatalf("%v; keys %v slept %v", err, f.keys, h.slept)
	}
}

// A CRL past its next update is temporary: retried under the same key.
func TestAStaleCRLIsRetried(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		statusUnavailable("CRL workloads is past its next update, 2026-10-07T03:00:00Z"), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil ||
		len(f.keys) != 2 || f.keys[0] != f.keys[1] || len(h.slept) != 1 || h.slept[0] != time.Minute {
		t.Fatalf("%v; keys %v slept %v", err, f.keys, h.slept)
	}
}

func TestAnExpiredCertificateNeverConnects(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, time.Hour)
	h.now = h.now.Add(2 * time.Hour)
	_, err := New(h.cfg)
	var ce *CertError
	if !errors.As(err, &ce) || !ce.Expired || !strings.Contains(err.Error(), "renew it against your CA (only the "+
		"first enrollment is manual)") || len(f.presents) != 0 {
		t.Fatalf("%v; requests %d", err, len(f.presents))
	}
}

func TestALateCertificateWarns(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 4*time.Hour)
	h.now = h.now.Add(3*time.Hour + 30*time.Minute) // about 30m of 4h left
	var warned []string
	h.cfg.Warn = func(format string, args ...any) { warned = append(warned, format) }
	h.client(t)
	if len(warned) != 1 || !strings.Contains(warned[0], "its renewal is late; renew it against your CA") {
		t.Fatalf("%v", warned)
	}
}

// A renewal writes the certificate, then the key: a read in between is read
// again rather than handshaking with a pair that cannot (decision 40 ruling 10).
// The renewer's second write happens in the wait between reads, so the test
// races no clock.
func TestAMismatchedPairIsReadAgain(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	oldKey, _ := os.ReadFile(h.cfg.KeyFile)
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(24*time.Hour))
	newKey, _ := os.ReadFile(h.cfg.KeyFile)
	if err := os.WriteFile(h.cfg.KeyFile, oldKey, 0o600); err != nil { // mid-renewal: new cert, old key
		t.Fatal(err)
	}
	waits := 0
	prev := betweenReads
	t.Cleanup(func() { betweenReads = prev })
	betweenReads = func() {
		waits++
		_ = os.WriteFile(h.cfg.KeyFile, newKey, 0o600) // the renewer's second write
	}
	if _, err := LoadCertificate(h.cfg.CertFile, h.cfg.KeyFile, h.now, nil); err != nil || waits != 1 {
		t.Fatalf("the pair was not read again: %v (waited %d times)", err, waits)
	}
}

// The files are read at each New: a renewal on disk needs no restart.
func TestARenewalOnDiskIsPresentedAtTheNextRun(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	ctx := context.Background()
	if _, err := h.client(t).Identity(ctx); err != nil {
		t.Fatal(err)
	}
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(24*time.Hour))
	if _, err := h.client(t).Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.presents) != 2 || f.presents[0] == f.presents[1] {
		t.Fatalf("presented %v", f.presents)
	}
}

func sum(ds []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return t
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/workload/ -count=1`
Expected: FAIL: the package does not exist.

- [ ] **Step 3: Write `internal/workload/client.go`**

```go
// Package workload is the agentless client a workload mints with (plan 8;
// design §17: "machine workloads require no agent: identity is a file and
// minting is a single request"). It reads its certificate and key from their
// files at each New, so a renewal on disk needs no restart; holds no session
// and writes no socket; pages a sweep by the broker's batch_max, one
// Idempotency-Key per page, and retries a page under its key while the broker
// cannot answer now, until a deadline (spec §13 decision 40 ruling 10). It
// never returns a token in an error.
package workload

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/keyfile"
)

// DefaultDeadline is how long a run retries a broker that cannot answer now.
const DefaultDeadline = 2 * time.Minute

// ErrTemporary is a run the deadline ended with devices unminted: try again
// later (port49 workload exits 75, EX_TEMPFAIL).
var ErrTemporary = errors.New("workload: the broker could not answer now")

// pairWait is how long LoadCertificate waits before reading a pair that did
// not match again.
const pairWait = 500 * time.Millisecond

// betweenReads is that wait. A test replaces it with the renewer's second
// write, so it races no clock.
var betweenReads = func() { time.Sleep(pairWait) }

// Config is a workload's broker and its certificate files.
type Config struct {
	Broker            string // https://host:port
	BrokerCA          *x509.CertPool
	CertFile, KeyFile string
	Deadline          time.Duration // 0 is DefaultDeadline
	Now               func() time.Time
	// Warn says a late renewal; nil says nothing.
	Warn func(format string, args ...any)
}

// CertError is a certificate the client will not present.
type CertError struct {
	File                string
	NotBefore, NotAfter time.Time
	Expired             bool
}

func (e *CertError) Error() string {
	if e.Expired {
		return fmt.Sprintf("the certificate %s expired at %s: renew it against your CA (only the first enrollment is "+
			"manual)", e.File, e.NotAfter.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("the certificate %s is not valid until %s: check this host's clock", e.File,
		e.NotBefore.UTC().Format(time.RFC3339))
}

// APIError is the broker's final answer: a retry would get it again.
type APIError struct {
	Status       int
	Code, Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Detail) }

// TemporaryError is the deadline passing with Unminted not minted; Last is
// the broker's last answer, or the connection's failure.
type TemporaryError struct {
	Unminted []string
	Last     error
	Deadline time.Duration
}

func (e *TemporaryError) Error() string {
	return fmt.Sprintf("the broker did not answer within %s (the last answer: %v)", e.Deadline, e.Last)
}

func (e *TemporaryError) Unwrap() error { return ErrTemporary }

// LoadCertificate reads the pair, again up to twice more pairWait apart when
// the two do not match (a renewal writes one file, then the other), and
// refuses one outside its validity before anything connects. One with under
// a quarter of its validity left is said through warn (decision 40 ruling 9).
func LoadCertificate(certFile, keyFile string, now time.Time, warn func(string, ...any)) (tls.Certificate, error) {
	var cert tls.Certificate
	var err error
	for i := range 3 {
		if cert, err = keyfile.LoadX509KeyPair(certFile, keyFile); err == nil ||
			!strings.Contains(err.Error(), "private key does not match public key") {
			break
		}
		if i < 2 {
			betweenReads()
		}
	}
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the certificate %s and key %s: %w", certFile, keyFile, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the certificate %s: %w", certFile, err)
	}
	switch {
	case now.After(leaf.NotAfter):
		return tls.Certificate{}, &CertError{File: certFile, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Expired: true}
	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, &CertError{File: certFile, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	case warn != nil && api.LateRenewal(leaf, now):
		warn("the certificate %s expires %s (in %s) with under a quarter of its validity left: its renewal is late; "+
			"renew it against your CA", certFile, leaf.NotAfter.UTC().Format(time.RFC3339),
			strings.TrimSuffix(leaf.NotAfter.Sub(now).Round(time.Minute).String(), "0s"))
	}
	cert.Leaf = leaf
	return cert, nil
}

// Client is one run's connection to the broker.
type Client struct {
	cfg   Config
	http  *http.Client
	sleep func(ctx context.Context, d time.Duration) error
}

// New reads the certificate (LoadCertificate) and makes the run's client.
// The certificate is always presented, whatever CA hint the broker sends.
func New(cfg Config) (*Client, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Deadline == 0 {
		cfg.Deadline = DefaultDeadline
	}
	cfg.Broker = strings.TrimRight(cfg.Broker, "/")
	cert, err := LoadCertificate(cfg.CertFile, cfg.KeyFile, cfg.Now(), cfg.Warn)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.BrokerCA,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}, sleep: sleepCtx}, nil
}

// MintOptions is one run's mint.
type MintOptions struct {
	Devices []string
	Enable  bool
	TTL     time.Duration
	Purpose string
}

// Mint mints Devices a page of the broker's batch_max at a time, each page
// under its own Idempotency-Key. It returns every page's results it got;
// when a page was not minted by the deadline, a *TemporaryError naming every
// device from that page on.
func (c *Client) Mint(ctx context.Context, o MintOptions) (api.MintResponse, error) {
	deadline := c.cfg.Now().Add(c.cfg.Deadline)
	var conf api.Config
	if err := c.do(ctx, deadline, http.MethodGet, "/v1/config", nil, "", &conf); err != nil {
		return api.MintResponse{}, unminted(err, o.Devices)
	}
	page := max(conf.BatchMax, 1)
	var out api.MintResponse
	for i := 0; i < len(o.Devices); i += page {
		devs := o.Devices[i:min(i+page, len(o.Devices))]
		body, err := json.Marshal(api.MintRequest{Devices: devs, Enable: o.Enable,
			TTLSeconds: int(o.TTL / time.Second), Purpose: o.Purpose})
		if err != nil {
			return out, err
		}
		key, err := newKey()
		if err != nil {
			return out, err
		}
		var resp api.MintResponse
		if err := c.do(ctx, deadline, http.MethodPost, "/v1/tokens", body, key, &resp); err != nil {
			return out, unminted(err, o.Devices[i:])
		}
		if out.Principal == "" {
			out.Principal, out.Subject, out.Subjects = resp.Principal, resp.Subject, resp.Subjects
		}
		out.Results = append(out.Results, resp.Results...)
	}
	return out, nil
}

// Identity is what the broker resolves this certificate to.
func (c *Client) Identity(ctx context.Context) (api.Identity, error) {
	var id api.Identity
	err := c.do(ctx, c.cfg.Now().Add(c.cfg.Deadline), http.MethodGet, "/v1/identity", nil, "", &id)
	return id, err
}

func unminted(err error, devices []string) error {
	var te *TemporaryError
	if errors.As(err, &te) {
		te.Unminted = slices.Clone(devices)
	}
	return err
}

// do sends one request, and again under the same key while the broker
// cannot answer now: a 503 (but an uncovered certificate status), a 429, a
// 409 idempotency_in_progress after its Retry-After (5s when absent, 60s at
// most), a failed connection after 1s doubling to 30s; until deadline. Any
// other answer is final.
func (c *Client) do(ctx context.Context, deadline time.Time, method, path string, body []byte, key string, out any) error {
	wait := time.Second
	for {
		req, err := http.NewRequestWithContext(ctx, method, c.cfg.Broker+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		var last error
		var pause time.Duration
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			last, pause = fmt.Errorf("no answer: %w", err), wait
			wait = min(wait*2, 30*time.Second)
		} else {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("the broker's answer to %s is not JSON: %w", path, err)
				}
				return nil
			}
			var e api.Error
			_ = json.Unmarshal(raw, &e)
			ae := &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
			if !retriable(resp.StatusCode, e) {
				return ae
			}
			last, pause = ae, retryAfter(resp.Header)
		}
		if !c.cfg.Now().Add(pause).Before(deadline) {
			return &TemporaryError{Last: last, Deadline: c.cfg.Deadline}
		}
		if err := c.sleep(ctx, pause); err != nil {
			return err
		}
	}
}

// retriable is an answer a later try may change. A certificate status no
// source covers is not one: the broker answers it 503 with Retry-After, but
// it holds until the operator adds a CRL or OCSP for that issuer, so it is
// final here (decision 40 ruling 7; pre-flight I-2). A CRL past its next
// update is temporary.
func retriable(status int, e api.Error) bool {
	if status == http.StatusServiceUnavailable && e.Error == "certificate_status_unavailable" &&
		strings.Contains(e.Detail, api.UncoveredStatus) {
		return false
	}
	return status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests ||
		(status == http.StatusConflict && e.Error == "idempotency_in_progress")
}

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, time.Minute)
	}
	return 5 * time.Second
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func newKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
```

`keyfile.LoadX509KeyPair` refuses a key file readable by others; the harness writes 0600. If its
mismatch error is wrapped with other text, match on `tls.X509KeyPair`'s phrase as written above.
Confirm it with a one-off run in Step 4, and change the `strings.Contains` to what it says.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/workload/ -count=1 && go test -race ./internal/workload/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/workload
git commit -m "feat(workload): an agentless client that pages, retries under its key, and reads its files each run

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: `port49 workload token` and `port49 workload identity`

**Files:**
- Create: `cmd/port49/workload.go`, `cmd/port49/workload_test.go`
- Modify: `cmd/port49/main.go` (`usage`, the `workload` case)

**Interfaces:**
- Consumes: Task 9's `workload.New`, `Config`, `MintOptions`, `Client.Mint`, `Client.Identity`,
  `CertError`, `APIError`, `TemporaryError`, `ErrTemporary`; `printIdentity` (identity.go).
- Produces:
  - `func workloadCmd(args []string, stdout, stderr io.Writer) int`;
  - `const exitTemporary = 75` and `const exitFinal = 77` (pre-flight I-1);
  - `func writePrivate(path string, data []byte) error` (0600, temporary file renamed over
    `path`);
  - the TSV columns, in order: `device`, `address`, `platform`, `username`, `login`, then `enable`
    with `--enable`, then `expires_at`. There is no header line, and one line per permitted device.
    Task 12's wrapper reads them.

- [ ] **Step 1: Write the failing tests**

`cmd/port49/workload_test.go`:

```go
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// workloadBroker serves /v1/config and /v1/tokens as answer says, over TLS
// requiring a client certificate, and returns the flags that reach it.
func workloadBroker(t *testing.T, answer func(w http.ResponseWriter, req api.MintRequest)) []string {
	t.Helper()
	return workloadBrokerPaged(t, 100, answer)
}

// workloadBrokerPaged is workloadBroker with /v1/config's batch_max.
func workloadBrokerPaged(t *testing.T, batchMax int, answer func(w http.ResponseWriter, req api.MintRequest)) []string {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()
	ca, err := testpki.NewCA("workloads", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, _ := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	u, _ := url.Parse("spiffe://corp.example.com/host/oxidized-01")
	cli, _ := ca.Issue(testpki.Leaf{CommonName: "w", URIs: []*url.URL{u}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	certPEM, keyPEM, _ := testpki.PEMs(cli)
	for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "w.pem": certPEM, "w-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/config":
			_ = json.NewEncoder(w).Encode(api.Config{BatchMax: batchMax})
		case "/v1/tokens":
			var req api.MintRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			answer(w, req)
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(api.Identity{Principal: "spiffe://corp.example.com/host/oxidized-01",
				Method: "cert", Subject: "svc_oxidized"})
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return []string{"--broker", srv.URL, "--broker-ca", filepath.Join(dir, "ca.pem"),
		"--cert", filepath.Join(dir, "w.pem"), "--key", filepath.Join(dir, "w-key.pem"), "--deadline", "1s"}
}

func mixed(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		if d == "fw1" {
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "no_grants_matched"})
			continue
		}
		resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1",
			Platform: "arista_eos", Username: "svc-oxidized", Login: "TOKEN-" + d, ExpiresAt: "2026-10-08T03:00:00Z"})
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func TestWorkloadTokenWritesTSV(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb)
	want := "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" +
		"leaf2\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf2\t2026-10-08T03:00:00Z\n"
	if code != 0 || out.String() != want || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, out.String(), errb.String())
	}
}

// 0 all permitted; 1 one denied (the permitted still written, no token on
// stderr); 77 every device denied, or a final refusal before anything was
// minted, with nothing written; 75 nothing minted by the deadline; 2 usage
// (pre-flight I-1).
func TestExitCodesTellCronWhatHappened(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "fw1"), &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "TOKEN-leaf1") || !strings.Contains(errb.String(), "fw1: deny no_grants_matched") ||
		strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("one denied: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, flags...), "fw1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "fw1: deny no_grants_matched") {
		t.Fatalf("every device denied: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	revoked := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "credential_revoked", Detail: "this principal is revoked"})
	})
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, revoked...), "leaf1", "leaf2"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "401 credential_revoked") ||
		!strings.Contains(errb.String(), "2 of 2 devices were not minted") {
		t.Fatalf("revoked: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	busy := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "the broker's store did not answer"})
	})
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, busy...), "leaf1", "leaf2"), &out, &errb); code != exitTemporary ||
		out.Len() != 0 || !strings.Contains(errb.String(), "2 of 2 devices were not minted; run again") {
		t.Fatalf("busy: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if code := run([]string{"workload", "token", "leaf1"}, &out, &errb); code != 2 {
		t.Fatalf("no flags: exit %d", code)
	}
}

// A final refusal on page two after page one minted: page one is written and
// the run exits 1, so the wrapper still queues those nodes; a token never
// reaches stderr (pre-flight I-1).
func TestAFinalRefusalOnPageTwoWritesPageOne(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		if req.Devices[0] == "leaf2" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "credential_revoked", Detail: "this principal is revoked"})
			return
		}
		mixed(w, req)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb)
	if code != 1 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "401 credential_revoked") ||
		!strings.Contains(errb.String(), "1 of 2 devices were not minted") || strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// An expired certificate is final: said before anything connects, nothing
// written, exit 77 (pre-flight I-1).
func TestAnExpiredCertificateIsFinal(t *testing.T) {
	flags := workloadBroker(t, mixed)
	now := time.Now()
	ca, err := testpki.NewCA("expired", now.Add(-72*time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	old, err := ca.Issue(testpki.Leaf{CommonName: "w", Client: true, NotBefore: now.Add(-48 * time.Hour),
		NotAfter: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(old)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string][]byte{"w.pem": certPEM, "w-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A flag given twice takes its last value.
	flags = append(flags, "--cert", filepath.Join(dir, "w.pem"), "--key", filepath.Join(dir, "w-key.pem"))
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "renew it against your CA") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// --out is 0600 and renamed into place; --devices-file reads one name a line,
// skipping blanks and # comments.
func TestWorkloadTokenWritesItsOutputPrivately(t *testing.T) {
	flags := workloadBroker(t, mixed)
	dir := t.TempDir()
	list := filepath.Join(dir, "nodes")
	if err := os.WriteFile(list, []byte("# backed up nightly\nleaf1\n\nleaf2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "tokens.tsv")
	if err := os.WriteFile(outFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := append(append([]string{"workload", "token"}, flags...), "--devices-file", list, "--out", outFile, "--format", "json")
	if code := run(args, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	fi, err := os.Stat(outFile)
	raw, _ := os.ReadFile(outFile)
	var resp api.MintResponse
	if err != nil || fi.Mode().Perm() != 0o600 || json.Unmarshal(raw, &resp) != nil || len(resp.Results) != 2 {
		t.Fatalf("mode %v err %v body %s", fi.Mode(), err, raw)
	}
}

func TestWorkloadIdentityPrintsTheWorkload(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "spiffe://corp.example.com/host/oxidized-01") ||
		!strings.Contains(out.String(), "svc_oxidized") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if code := run([]string{"workload", "identity"}, &out, &errb); code != 2 { // pre-flight M-6
		t.Fatalf("no flags: exit %d", code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/port49/ -run 'Workload|ExitCodesTellCron|PageTwo|ExpiredCertificateIsFinal' -count=1`
Expected: FAIL: `workload` is not a command.

- [ ] **Step 3: Write `cmd/port49/workload.go`**

```go
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/workload"
)

// exitTemporary is EX_TEMPFAIL: the broker could not answer by the deadline,
// and a later run may succeed (decision 40 ruling 10). The pages minted
// before it are written.
const exitTemporary = 75

// exitFinal is EX_NOPERM: nothing was minted, and a run again will not change
// that until someone acts (the certificate, a final refusal, every device
// denied). Nothing is written, so a wrapper keeps its last output
// (pre-flight I-1).
const exitFinal = 77

// errWorkloadUsage is a run missing a required flag: usage, exit 2.
var errWorkloadUsage = errors.New("--broker, --broker-ca, --cert and --key are all required")

// workloadCmd is `port49 workload`: a workload's own commands, with no agent
// (design §17; plan 8).
func workloadCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "token":
		return workloadToken(args[1:], stdout, stderr)
	case "identity":
		return workloadIdentity(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// workloadFlags are a workload's broker and certificate files.
type workloadFlags struct {
	broker, brokerCA, cert, key string
	deadline                    time.Duration
}

func (w *workloadFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&w.broker, "broker", "", "the broker, https://host:port")
	fs.StringVar(&w.brokerCA, "broker-ca", "", "the CA that issued the broker's certificate (PEM)")
	fs.StringVar(&w.cert, "cert", "", "the workload's certificate (PEM), read at every run")
	fs.StringVar(&w.key, "key", "", "its private key (PEM), readable by its owner alone")
	fs.DurationVar(&w.deadline, "deadline", workload.DefaultDeadline, "how long to retry a broker that cannot answer now")
}

func (w *workloadFlags) client(stderr io.Writer, cmd string) (*workload.Client, error) {
	if w.broker == "" || w.brokerCA == "" || w.cert == "" || w.key == "" {
		return nil, errWorkloadUsage
	}
	caPEM, err := os.ReadFile(w.brokerCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", w.brokerCA)
	}
	return workload.New(workload.Config{Broker: w.broker, BrokerCA: pool, CertFile: w.cert, KeyFile: w.key,
		Deadline: w.deadline, Warn: func(format string, args ...any) {
			fmt.Fprintf(stderr, cmd+": "+format+"\n", args...)
		}})
}

func workloadToken(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 workload token"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var wf workloadFlags
	wf.register(fs)
	devicesFile := fs.String("devices-file", "", "a file of device names, one a line (# comments and blank lines skipped)")
	enable := fs.Bool("enable", false, "mint an enable token beside each login one")
	ttl := fs.Duration("ttl", 0, "ask for this lifetime; the broker clamps it to the subject's token_ttl")
	purpose := fs.String("purpose", "", "said in the mint record, e.g. \"oxidized nightly backup\"")
	format := fs.String("format", "tsv", "tsv (device, address, platform, username, login[, enable], expires_at) or json")
	out := fs.String("out", "", "write the tokens here (0600, replaced whole) instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	devices := fs.Args()
	if *devicesFile != "" {
		more, err := readDevices(*devicesFile)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
			return 2
		}
		devices = append(devices, more...)
	}
	if len(devices) == 0 || (*format != "tsv" && *format != "json") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	c, err := wf.client(stderr, cmd)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		var ce *workload.CertError
		if errors.As(err, &ce) {
			return exitFinal // nothing can mint until the certificate is renewed
		}
		return 2
	}
	resp, err := c.Mint(context.Background(), workload.MintOptions{Devices: devices, Enable: *enable, TTL: *ttl,
		Purpose: *purpose})
	code := 0
	var te *workload.TemporaryError
	switch {
	case errors.As(err, &te):
		fmt.Fprintf(stderr, "%s: %v: %d of %d devices were not minted; run again\n", cmd, err, len(te.Unminted), len(devices))
		code = exitTemporary
	case err != nil:
		// A final answer, perhaps after earlier pages minted: those are
		// still written (pre-flight I-1).
		fmt.Fprintf(stderr, "%s: %v: %d of %d devices were not minted\n", cmd, err, len(devices)-len(resp.Results),
			len(devices))
		code = 1
	}
	var permitted []api.MintItem
	for _, it := range resp.Results {
		if it.Verdict != "permit" || it.Login == "" {
			// The item's own words, never its token (there is none on a deny).
			reason := it.Reason
			if it.Error != "" {
				reason = it.Error
			}
			fmt.Fprintf(stderr, "%s: %s: %s %s\n", cmd, it.Device, it.Verdict, reason)
			code = max(code, 1)
			continue
		}
		permitted = append(permitted, it)
	}
	if len(permitted) == 0 {
		// Nothing to write: the last output stays as it was. Temporary, or
		// final until someone acts.
		if code == exitTemporary {
			return exitTemporary
		}
		return exitFinal
	}
	body, err := render(*format, resp, permitted, *enable)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if *out == "" {
		_, _ = stdout.Write(body)
		return code
	}
	if err := writePrivate(*out, body); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	return code
}

// render is the permitted items as format says: TSV with no header, one line
// each, or the broker's answer as JSON with only the permitted results.
func render(format string, resp api.MintResponse, permitted []api.MintItem, enable bool) ([]byte, error) {
	if format == "json" {
		resp.Results = permitted
		return json.Marshal(resp)
	}
	var b strings.Builder
	for _, it := range permitted {
		cols := []string{it.Device, it.Address, it.Platform, it.Username, it.Login}
		if enable {
			cols = append(cols, it.Enable)
		}
		cols = append(cols, it.ExpiresAt)
		for _, c := range cols {
			if strings.ContainsAny(c, "\t\n") {
				return nil, fmt.Errorf("%s: a field holds a tab or a newline, which TSV cannot carry", it.Device)
			}
		}
		b.WriteString(strings.Join(cols, "\t") + "\n")
	}
	return []byte(b.String()), nil
}

// writePrivate writes data to path 0600, through a temporary file in the same
// directory renamed over it, so a reader never sees half a file and the
// tokens are never readable by others, whatever the umask.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after the rename there is nothing at name
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// readDevices is a file's device names, one a line, blank lines and # comments skipped.
func readDevices(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func workloadIdentity(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 workload identity"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var wf workloadFlags
	wf.register(fs)
	asJSON := fs.Bool("json", false, "print the broker's answer as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	c, err := wf.client(stderr, cmd)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		var ce *workload.CertError
		switch {
		case errors.Is(err, errWorkloadUsage):
			return 2 // as workload token (pre-flight M-6)
		case errors.As(err, &ce):
			return exitFinal
		}
		return 1
	}
	id, err := c.Identity(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		var ae *workload.APIError
		switch {
		case errors.Is(err, workload.ErrTemporary):
			return exitTemporary
		case errors.As(err, &ae):
			return exitFinal
		}
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(id)
		return 0
	}
	printIdentity(stdout, id)
	return 0
}
```

In `cmd/port49/main.go`:

- Add to `usage`, after the `port49 identity` line:

  ```
  port49 workload token --broker URL --broker-ca FILE --cert FILE --key FILE [--devices-file FILE]
                        [--enable] [--ttl DURATION] [--purpose TEXT] [--format tsv|json] [--out FILE]
                        [--deadline DURATION] [DEVICE...]
                        (no agent: the certificate and key are read each run; under cron, always
                        --out, since cron mails a job's stdout; exits 1 when some devices were
                        written and some not, 75 when the broker did not answer by the deadline,
                        77 when nothing was minted and a run again will not change that)
  port49 workload identity --broker URL --broker-ca FILE --cert FILE --key FILE [--json]
  ```

- Add the case `case "workload": return workloadCmd(args[1:], stdout, stderr)` beside
  `"identity"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/port49/ -count=1 && go test -race ./cmd/port49/ -run 'Workload|ExitCodes' -count=1 && make vet`
Expected: PASS. The `usage` golden test, if there is one, is updated to the new text.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49
git commit -m "feat(cli): port49 workload token and identity, with no agent

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: A workload mints through port49d end to end

**Files:**
- Modify: `internal/testpki/testpki.go` (`WriteWorkloadLab`, its file names)
- Create: `internal/port49d/workload_e2e_test.go`

**Interfaces:**
- Consumes: Tasks 3–10; port49d's `run`, `writeRunConfig`'s shape, `waitForCount`, `syncBuffer`,
  `tacacsClient` (broker_test.go and its neighbours).
- Produces:
  - `testpki.WriteWorkloadLab(dir, id string, now time.Time) error`, writing
    `testpki.WorkloadCA` (`workload-ca.pem`), `WorkloadCert` (`workload.pem`) and `WorkloadKey`
    (`workload-key.pem`, 0600) from a CA of its own;
  - `testpki.RenewWorkload(dir, id string, now time.Time) error`: a new certificate, the same
    ID, a new key and serial, from the CA `WriteWorkloadLab` wrote (its key kept as
    `workload-ca-key.pem`, 0600);
  - `testpki.WriteWorkloadLabFrom(caDir, dir, id string, now time.Time) error`: a second
    workload's certificate from the CA in `caDir`.
  Task 13's lab reads all three.

- [ ] **Step 1: Write the failing tests**

`internal/port49d/workload_e2e_test.go`:

```go
package port49d

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/workload"
)

const (
	e2eWorkloadID  = "spiffe://port49.test/host/oxidized-01"
	e2eWorkload2ID = "spiffe://port49.test/host/oxidized-02"
)

// writeWorkloadRunConfig is writeRunConfig with broker.identity: the lab
// anchor for people and the workload anchor in pki for machines, and a
// policy giving the workload svc-oxidized on leaf1.
func writeWorkloadRunConfig(t *testing.T, b *config.BrokerConfig, pki string) string {
	t.Helper()
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := fmt.Sprintf("  identity:\n    humans: [{type: x509, trust_anchor_file: %s}]\n"+
		"    machines: [{type: x509, trust_anchor_file: %s, spiffe_trust_domains: [port49.test]}]\n",
		b.ClientCAFile, filepath.Join(pki, testpki.WorkloadCA))
	text := strings.Replace(string(raw), fmt.Sprintf("  client_ca_file: %s\n", b.ClientCAFile), identity, 1)
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

const e2eWorkloadPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: svc, identity: ["` + e2eWorkloadID + `", "` + e2eWorkload2ID + `"], username: svc-oxidized,
     token_ttl: 600s}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: svc, scope: all_devices, roles: [r]}]
`

// startWorkloadDaemon runs port49d with a workload verifier; out is its
// stderr and recs its decision log (stdout).
func startWorkloadDaemon(t *testing.T) (brokerAddr, tacacsAddr, pki, workDir string, out, recs *syncBuffer) {
	t.Helper()
	out, recs = &syncBuffer{}, &syncBuffer{}
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = out, recs
	b := brokerConfig(t, e2eWorkloadPolicy).Broker
	pki = filepath.Dir(b.ClientCAFile)
	workDir = t.TempDir()
	if err := testpki.WriteWorkloadLab(workDir, e2eWorkloadID, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeWorkloadRunConfig(t, b, workDir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("run did not return")
		}
	})
	waitForCount(t, out, "port49d: broker listening on ", 1)
	brokerAddr = regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	tacacsAddr = regexp.MustCompile(`port49d: listening on ([^,\s]+),`).FindStringSubmatch(out.String())[1]
	return brokerAddr, tacacsAddr, pki, workDir, out, recs
}

func workloadClient(t *testing.T, brokerAddr, pki, workDir string) *workload.Client {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(pki, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	c, err := workload.New(workload.Config{Broker: "https://" + brokerAddr, BrokerCA: pool,
		CertFile: filepath.Join(workDir, testpki.WorkloadCert), KeyFile: filepath.Join(workDir, testpki.WorkloadKey)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A workload certificate mints through port49d's real listener, its token
// logs in on the TACACS+ side under the declared username, and alice's
// certificate still mints beside it (decision 40; spec §14).
func TestAWorkloadMintsAndLogsInThroughPort49d(t *testing.T) {
	brokerAddr, tacacsAddr, pki, workDir, out, _ := startWorkloadDaemon(t)
	for _, want := range []string{"identity: machines: x509 (trust anchor ", "SPIFFE trust domains port49.test"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the start lines lack %q:\n%s", want, out.String())
		}
	}
	resp, err := workloadClient(t, brokerAddr, pki, workDir).Mint(context.Background(),
		workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil || resp.Principal != e2eWorkloadID || len(resp.Results) != 1 || resp.Results[0].Login == "" {
		t.Fatalf("%+v %v", resp, err)
	}
	dev := tacacsClient{t: t, addr: tacacsAddr, key: []byte("run-test-secret")}
	if st := dev.login("svc-oxidized", resp.Results[0].Login); st != wire.AuthenStatusPass {
		t.Fatalf("the workload's login: status %d", st)
	}
	if status, body, err := postAsAlice(pki, brokerAddr); err != nil || status != 200 {
		t.Fatalf("alice beside it: %d %s %v", status, body, err)
	}
}

// A renewal on disk is the same principal at the next run: nothing in port49
// changes (decision 40 ruling 8).
func TestARenewedCertificateMintsAsTheSamePrincipal(t *testing.T) {
	brokerAddr, _, pki, workDir, _, _ := startWorkloadDaemon(t)
	first, err := workloadClient(t, brokerAddr, pki, workDir).Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := testpki.RenewWorkload(workDir, e2eWorkloadID, time.Now()); err != nil {
		t.Fatal(err)
	}
	renewed, err := workloadClient(t, brokerAddr, pki, workDir).Identity(context.Background())
	if err != nil || renewed.Principal != e2eWorkloadID || renewed.Fingerprint == first.Fingerprint {
		t.Fatalf("first %+v renewed %+v %v", first, renewed, err)
	}
}

// Two identities of one subject log in to one device: they mint one
// username, the second login replaces the first's context, the redeem record
// says so, and a command is still the subject's to run (decision 40 ruling
// 11; spec §5.6).
func TestTwoIdentitiesOfOneSubjectShareTheDevice(t *testing.T) {
	brokerAddr, tacacsAddr, pki, workDir, _, recs := startWorkloadDaemon(t)
	other := t.TempDir()
	if err := testpki.WriteWorkloadLabFrom(workDir, other, e2eWorkload2ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := workloadClient(t, brokerAddr, pki, workDir).Mint(ctx, workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := workloadClient(t, brokerAddr, pki, other).Mint(ctx, workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "svc" || b.Subject != "svc" || b.Principal != e2eWorkload2ID ||
		a.Results[0].Username != b.Results[0].Username {
		t.Fatalf("%+v %+v", a, b)
	}
	dev := tacacsClient{t: t, addr: tacacsAddr, key: []byte("run-test-secret")}
	if dev.login("svc-oxidized", a.Results[0].Login) != wire.AuthenStatusPass ||
		dev.login("svc-oxidized", b.Results[0].Login) != wire.AuthenStatusPass {
		t.Fatal("a login failed")
	}
	if !dev.permits("svc-oxidized", "show", "running-config") {
		t.Fatal("the subject's command was refused after the replace")
	}
	waitFor(t, recs, `"replaced_ctx_id"`)
}
```

`waitFor`, `waitForCount`, `syncBuffer` and `tacacsClient` (with `login` and `permits`) are the
package's (`run_test.go`, `broker_test.go`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/port49d/ -run 'AWorkloadMintsAndLogsIn|ARenewedCertificate|TwoIdentitiesOfOneSubjectShare' -count=1`
Expected: FAIL: `testpki.WriteWorkloadLab` undefined.

- [ ] **Step 3: `testpki.WriteWorkloadLab`, `RenewWorkload`, `WriteWorkloadLabFrom`**

In `internal/testpki/testpki.go`, add:

```go
// The file names WriteWorkloadLab writes (plan 8): a workload CA of its own,
// its key (so RenewWorkload can issue again), and one workload certificate.
const (
	WorkloadCA    = "workload-ca.pem"
	WorkloadCAKey = "workload-ca-key.pem"
	WorkloadCert  = "workload.pem"
	WorkloadKey   = "workload-key.pem"
)

// WriteWorkloadLab writes a workload PKI into dir: a CA, and a client
// certificate whose one URI SAN is id, valid for a day from now. Keys are
// 0600.
func WriteWorkloadLab(dir, id string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, err := NewCA("port49 lab workloads CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCA), ca.PEM()); err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCAKey), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY",
		Bytes: keyDER})); err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

// RenewWorkload issues dir's workload certificate again from the CA
// WriteWorkloadLab wrote there: the same id, a new key and serial, as a
// renewal against a real CA gives.
func RenewWorkload(dir, id string, now time.Time) error {
	ca, err := readCA(dir)
	if err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

// WriteWorkloadLabFrom issues a second workload certificate for id from the
// CA in caDir, into dir: a second workload under one anchor.
func WriteWorkloadLabFrom(caDir, dir, id string, now time.Time) error {
	ca, err := readCA(caDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

func issueWorkload(ca *CA, dir, id string, now time.Time) error {
	u, err := url.Parse(id)
	if err != nil {
		return err
	}
	c, err := ca.Issue(Leaf{CommonName: id, URIs: []*url.URL{u}, Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := PEMs(c)
	if err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCert), certPEM); err != nil {
		return err
	}
	return writeFresh(filepath.Join(dir, WorkloadKey), keyPEM)
}

func readCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, WorkloadCA))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, WorkloadCAKey))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("testpki: %s holds no workload CA", dir)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}
```

`writeFresh` writes 0600 and refuses to follow a link (it is the package's). Import `net/url` and
`encoding/pem` if the file does not.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/port49d/ ./internal/testpki/ -count=1 && go test -race ./internal/port49d/ -run 'Workload|TwoIdentities|Renewed' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/testpki internal/port49d/workload_e2e_test.go
git commit -m "test(port49d): a workload mints and logs in end to end; a renewal is the same principal

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: Oxidized, the day-one consumer: `examples/oxidized/`

**Files:**
- Create: `examples/oxidized/port49-oxidized-run` (mode 0755)
- Create: `examples/oxidized/config` (Oxidized's configuration)
- Create: `examples/oxidized/policy.yaml` (the port49 policy snippet)
- Create: `examples/oxidized/README.md` (how the three fit, for an operator; the source plan 13's
  page is built from)
- Create: `examples/oxidized/run_test.go`

**Interfaces:**
- Consumes: Task 10's `port49 workload token` (its flags, its TSV columns, its exit codes).
- Produces: the wrapper's environment (`PORT49_BROKER`, `PORT49_BROKER_CA`, `PORT49_CERT`,
  `PORT49_KEY`, `OXIDIZED_NODES`, `OXIDIZED_ROUTER_DB`, `OXIDIZED_REST`, `PORT49_TTL`, `PORT49_BIN`)
  and its exit codes (0, 1, 75, 77, other). It replaces `router.db` and reloads Oxidized only when
  it has a node to write (pre-flight I-1). Task 14 runs it against real Oxidized.

The script, the Oxidized config and the role are **provisional on L49** (spec §15 rule 2). Each
file says so in its first lines, and Task 14 corrects each to what L49 measured.

- [ ] **Step 1: Write the failing test**

`examples/oxidized/run_test.go`:

```go
// Package oxidized holds the Oxidized example's test: the wrapper run against
// a fake port49 and a fake Oxidized REST API (plan 8, Task 12). The real
// Oxidized is lab L49's (tests/lab).
package oxidized

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeOxidized struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeOxidized) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	_, _ = w.Write([]byte("{}"))
}

// run runs the wrapper with a fake port49 that writes tsv to --out and exits
// with exit, against a fake Oxidized; it returns the exit code, stderr, the
// REST calls and the router.db path.
func run(t *testing.T, tsv string, exit int, oldDB string) (int, string, []string, string) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed: the wrapper needs it", tool)
		}
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "port49")
	script := `#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done
printf '%s' "$FAKE_TSV" > "$out"
exit $FAKE_EXIT
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "router.db")
	if oldDB != "" {
		if err := os.WriteFile(db, []byte(oldDB), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodes := filepath.Join(dir, "nodes")
	if err := os.WriteFile(nodes, []byte("leaf1\nvjunos1\nfw7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeOxidized{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cmd := exec.Command("bash", "port49-oxidized-run")
	cmd.Env = append(os.Environ(), "PORT49_BIN="+fake, "PORT49_BROKER=https://broker.example:8443",
		"PORT49_BROKER_CA=/ca.pem", "PORT49_CERT=/w.pem", "PORT49_KEY=/w-key.pem", "OXIDIZED_NODES="+nodes,
		"OXIDIZED_ROUTER_DB="+db, "OXIDIZED_REST="+srv.URL, "FAKE_TSV="+tsv, "FAKE_EXIT="+strconv.Itoa(exit))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return code, stderr.String(), append([]string(nil), f.calls...), db
}

const minted = "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n" +
	"vjunos1\t10.0.0.21\tjuniper_junos\tsvc-oxidized\tTOKENJUNOS1\t2026-10-08T03:00:00Z\n" +
	"fw7\t10.0.0.77\tpaloalto_panos\tsvc-oxidized\tTOKENFW7\t2026-10-08T03:00:00Z\n"

func TestTheRunWritesRouterDBAndQueuesEachNode(t *testing.T) {
	code, stderr, calls, db := run(t, minted, 0, "")
	raw, err := os.ReadFile(db)
	fi, _ := os.Stat(db)
	want := "leaf1\t10.0.0.11\teos\tsvc-oxidized\tTOKENLEAF1\nvjunos1\t10.0.0.21\tjunos\tsvc-oxidized\tTOKENJUNOS1\n"
	if code != 0 || err != nil || string(raw) != want || fi.Mode().Perm() != 0o600 {
		t.Fatalf("exit %d mode %v router.db %q stderr %s", code, fi.Mode(), raw, stderr)
	}
	if !strings.Contains(stderr, "fw7: platform paloalto_panos has no Oxidized model in this script; skipped") {
		t.Fatalf("stderr %s", stderr)
	}
	if strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1,PUT /node/next/vjunos1" {
		t.Fatalf("calls %v", calls)
	}
	if strings.Contains(stderr, "TOKEN") {
		t.Fatalf("a token on stderr: %s", stderr)
	}
}

// 75 from port49: nothing was minted, so Oxidized keeps its last router.db
// and is not reloaded, and the run exits 75 for cron.
func TestATemporaryFailureLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := run(t, "", 75, "old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no tokens minted (port49 workload token exited 75); Oxidized keeps its last router.db and was not reloaded") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// 1 from port49: one device was not permitted; the rest are queued, and the
// run exits 1.
func TestADeniedNodeStillQueuesTheRest(t *testing.T) {
	code, _, calls, _ := run(t, "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 1, "")
	if code != 1 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" {
		t.Fatalf("exit %d calls %v", code, calls)
	}
}

// 77 from port49 (the certificate expired while the CA was down, a revoked
// principal, every node denied): nothing was minted, so Oxidized keeps its
// last router.db and is not reloaded, never an empty one (pre-flight I-1).
func TestAnExpiredCertificateLeavesOxidizedAlone(t *testing.T) {
	code, stderr, calls, db := run(t, "", 77, "old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 77 || string(raw) != "old\tdb\n" || len(calls) != 0 ||
		!strings.Contains(stderr, "no tokens minted (port49 workload token exited 77); Oxidized keeps its last router.db and was not reloaded") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// 75 with a page minted before the deadline: the minted nodes are written
// and queued, the run says not every node was, and exits 75 (pre-flight M-7).
func TestAPartialRunQueuesWhatWasMinted(t *testing.T) {
	code, stderr, calls, db := run(t, "leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 75,
		"old\tdb\n")
	raw, _ := os.ReadFile(db)
	if code != 75 || string(raw) != "leaf1\t10.0.0.11\teos\tsvc-oxidized\tTOKENLEAF1\n" ||
		strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" ||
		!strings.Contains(stderr, "not every node was minted (port49 workload token exited 75") ||
		strings.Contains(stderr, "no tokens minted") {
		t.Fatalf("exit %d router.db %q calls %v stderr %s", code, raw, calls, stderr)
	}
}

// A node name goes into a REST path: one outside A-Z a-z 0-9 . _ - is
// skipped with a line, never put in a path (pre-flight M-13).
func TestANodeNameOutsideTheSafeSetIsSkipped(t *testing.T) {
	code, stderr, calls, _ := run(t, "core/sw#1\t10.0.0.9\tarista_eos\tsvc-oxidized\tTOKENBAD\t2026-10-08T03:00:00Z\n"+
		"leaf1\t10.0.0.11\tarista_eos\tsvc-oxidized\tTOKENLEAF1\t2026-10-08T03:00:00Z\n", 0, "")
	if code != 0 || strings.Join(calls, ",") != "GET /reload,PUT /node/next/leaf1" ||
		!strings.Contains(stderr, "core/sw#1: a node name outside A-Z a-z 0-9 . _ - is never put in a REST path; skipped") ||
		strings.Contains(stderr, "TOKEN") {
		t.Fatalf("exit %d calls %v stderr %s", code, calls, stderr)
	}
}
```

The test's working directory is `examples/oxidized/`, so `bash port49-oxidized-run` finds the
script beside it.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./examples/oxidized/ -count=1`
Expected: FAIL: `port49-oxidized-run` does not exist.

- [ ] **Step 3: Write the wrapper, the Oxidized config, the policy and the README**

`examples/oxidized/port49-oxidized-run`:

```bash
#!/usr/bin/env bash
# port49-oxidized-run: give Oxidized one port49 token per node and back every
# node up now (port49 plan 8). PROVISIONAL ON LAB L49 (policy engine spec §15):
# the REST calls and the model names below are what L49 measures.
#
# Run it from cron as the user Oxidized runs as, once per backup window:
#   17 2 * * *  PORT49_BROKER=... /usr/local/bin/port49-oxidized-run
# Oxidized's own schedule is set a week out (interval in ./config), so it never
# tries a node with a token that expired; this script asks for each node's run.
#
# Environment:
#   PORT49_BROKER       https://port49-broker.example.com:8443 (required)
#   PORT49_BROKER_CA    the CA that issued the broker's certificate (required)
#   PORT49_CERT         this host's workload certificate, renewed by your CA (required)
#   PORT49_KEY          its key, readable by this user alone (required)
#   OXIDIZED_NODES      the device names to back up, one a line (default /etc/port49/oxidized-nodes)
#   OXIDIZED_ROUTER_DB  Oxidized's CSV source (default ~/.config/oxidized/router.db)
#   OXIDIZED_REST       Oxidized's REST API (default http://127.0.0.1:8888)
#   PORT49_TTL          the tokens' lifetime: about one backup run (default 15m);
#                       size it to the whole sweep, since every node is queued at once
#   PORT49_BIN          the port49 binary (default port49 on PATH)
#
# Exit: 0 every node minted and queued; 1 some node not permitted (port49 said
# which, and the rest are queued); 75 the broker did not answer in time (the
# nodes minted before it are queued; with none, Oxidized was left as it was:
# try the next window); 77 nothing minted until someone acts (an expired
# certificate, a revoked principal, every node denied, a certificate status
# nothing covers), and Oxidized was left as it was; anything else, a fault,
# said on stderr. router.db is replaced, and Oxidized reloaded, only when there
# is a node to write: never with an empty file.
# No token is ever printed: they go to a 0600 file and into router.db (0600).
set -euo pipefail
umask 077

: "${PORT49_BROKER:?}" "${PORT49_BROKER_CA:?}" "${PORT49_CERT:?}" "${PORT49_KEY:?}"
nodes=${OXIDIZED_NODES:-/etc/port49/oxidized-nodes}
routerdb=${OXIDIZED_ROUTER_DB:-$HOME/.config/oxidized/router.db}
rest=${OXIDIZED_REST:-http://127.0.0.1:8888}
port49=${PORT49_BIN:-port49}

tsv=$(mktemp "${routerdb}.tsv.XXXXXX")
db=$(mktemp "${routerdb}.XXXXXX")
trap 'rm -f "$tsv" "$db"' EXIT

status=0
"$port49" workload token --broker "$PORT49_BROKER" --broker-ca "$PORT49_BROKER_CA" \
  --cert "$PORT49_CERT" --key "$PORT49_KEY" --devices-file "$nodes" \
  --ttl "${PORT49_TTL:-15m}" --purpose "oxidized backup" --format tsv --out "$tsv" || status=$?
case $status in
0 | 1 | 75) ;; # 75 may carry the pages minted before the deadline
*)
  echo "port49-oxidized-run: no tokens minted (port49 workload token exited $status); Oxidized keeps its last router.db and was not reloaded" >&2
  exit "$status"
  ;;
esac

# port49's platform names to Oxidized's models (L49). A node name goes into a
# REST path, so one outside A-Z a-z 0-9 . _ - is skipped, never escaped.
awk -F'\t' 'BEGIN { OFS = "\t"
    m["arista_eos"] = "eos"; m["cisco_nxos"] = "nxos"; m["cisco_iosxe"] = "ios"; m["juniper_junos"] = "junos" }
  $1 !~ /^[A-Za-z0-9._-]+$/ { printf "port49-oxidized-run: %s: a node name outside A-Z a-z 0-9 . _ - is never put in a REST path; skipped\n", $1 > "/dev/stderr"; next }
  !($3 in m) { printf "port49-oxidized-run: %s: platform %s has no Oxidized model in this script; skipped\n", $1, $3 > "/dev/stderr"; next }
  { print $1, $2, m[$3], $4, $5 }' "$tsv" >"$db"

# Only a router.db with a node in it replaces the last one: an empty one
# would drop every node from Oxidized.
if [ ! -s "$db" ]; then
  if [ ! -s "$tsv" ]; then
    echo "port49-oxidized-run: no tokens minted (port49 workload token exited $status); Oxidized keeps its last router.db and was not reloaded" >&2
  else
    echo "port49-oxidized-run: no minted node has a name and a model this script can use; Oxidized keeps its last router.db and was not reloaded" >&2
  fi
  if [ "$status" -eq 0 ]; then status=1; fi
  exit "$status"
fi
mv -f "$db" "$routerdb"
if [ "$status" -eq 75 ]; then
  echo "port49-oxidized-run: not every node was minted (port49 workload token exited 75: the broker did not answer in time); the minted nodes are queued, the rest wait for the next window" >&2
fi

curl -fsS -o /dev/null "$rest/reload?format=json"
cut -f1 "$routerdb" | while IFS= read -r node; do
  curl -fsS -o /dev/null -X PUT "$rest/node/next/$node?format=json"
done
exit "$status"
```

`examples/oxidized/config`:

```yaml
---
# Oxidized for port49 (plan 8). PROVISIONAL ON LAB L49 (policy engine spec §15).
# Each node's username and password come from router.db, which
# port49-oxidized-run rewrites with a fresh token per node before each run.
# Oxidized's own interval is a week, so it never tries a node with an expired
# token; port49-oxidized-run asks for each node's run through the REST API.
username: unused-see-router-db
password: unused-see-router-db
model: eos
resolve_dns: false
interval: 604800
use_syslog: false
debug: false
threads: 8
timeout: 30
# A failed login retried is the same token failing again (L49 measures it).
retries: 0
rest: 127.0.0.1:8888
next_adds_job: false
vars: {}
groups: {}
input:
  default: ssh
  debug: false
  ssh:
    # Host keys are verified against ~/.ssh/known_hosts (design §17: a device
    # address is a fact from the source of truth, trusted no further than its
    # host key). Populate it once per device; never set secure: false.
    secure: true
output:
  default: git
  git:
    user: oxidized
    email: oxidized@example.com
    repo: "~/.config/oxidized/configs.git"
source:
  default: csv
  csv:
    file: "~/.config/oxidized/router.db"
    delimiter: !ruby/regexp /\t/
    map:
      name: 0
      ip: 1
      model: 2
      username: 3
      password: 4
```

`examples/oxidized/policy.yaml`:

```yaml
# The port49 policy for Oxidized (plan 8): merge into your policy file.
# PROVISIONAL ON LAB L49 (policy engine spec §15): the permits are the commands
# Oxidized's models send, as L49 measures them per platform.
#
# The principal is the workload certificate's SPIFFE ID, verbatim; the
# username is declared, since a workload has no directory entry (spec §2).
roles:
  - name: config_backup
    # show running-config needs level 15 on EOS and IOS-XE: privilege decides
    # what the device offers, the permits what port49 allows within it (spec §2).
    privilege: admin
    permit:
      - "show running-config **"
      - "show startup-config"
      - "show inventory"
      - "show version"
      - "terminal length *"
      - "terminal width *"
subjects:
  - name: svc_oxidized
    identity: ["spiffe://corp.example.com/host/oxidized-01"]
    username: svc-oxidized
    token_ttl: 900s
grants:
  - {subject: svc_oxidized, scope: all_devices, roles: [config_backup], max_privilege: admin}
tests:
  - {subject: svc_oxidized, device: leaf-01, command: "show running-config", expect: permit}
  - {subject: svc_oxidized, device: leaf-01, command: "configure terminal", expect: deny}
  - {subject: svc_oxidized, device: leaf-01, command: "reload", expect: deny}
```

`examples/oxidized/README.md` says, in this order:
1. **What runs where.** Oxidized and `port49-oxidized-run` on one host, under one user; the
   certificate and key in that user's files; cron.
2. **Enrollment, once.** A certificate whose one URI SAN is the host's SPIFFE ID, from your
   workload CA (step-ca shown, as L48 measured it; any CA that puts one URI SAN on a client
   certificate works). Its key is readable by the Oxidized user alone.
3. **The workload CA is the trust root** (pre-flight M-11). Whoever can get it to issue a
   certificate naming a SPIFFE ID *is* that workload to port49, and `spiffe_trust_domains` does
   not stop one workload impersonating another within a domain. Restrict each provisioner to the
   host's own ID: on step-ca, the provisioner's x509 name policy allowing that one URI (L48
   measures that it refuses another; provisional on L48 until it closes).
4. **Renewal.** It is your CA's renewer's job (step's `step ca renew --daemon` or its systemd
   timer). port49 needs nothing at a renewal. A late one shows in cron mail and in
   `port49_workload_certificates_renewal_late_total`, which each broker replica counts once per
   certificate a day: alert on its increase.
5. **The broker.** `broker.identity.machines: [{type: x509, trust_anchor_file: …,
   spiffe_trust_domains: […]}]`. The anchor is the CA that issues the workload certificates (on
   step-ca, its intermediate, L48).
   - **Its hierarchy.** The workload anchor and the human anchor must be in unrelated
     hierarchies. The start refuses one that signs the other directly; one further down is refused
     at every request whose chain shows it (pre-flight M-2).
   - **Its status.** `certificate_status` must cover it: name the CA's CRL in `crls`. An https
     CRL endpoint under a private root needs that root in the broker's trust store
     (`SSL_CERT_FILE`, L48), or sync the CRL to a `file:` source; the deployment shapes are plan
     12's (pre-flight I-3). With no source, every certificate is refused, and `port49 workload`
     exits 77, not 75: turning status checking off for everyone is not the fix.
6. **Check before cron.** `port49 workload identity --broker … --broker-ca … --cert … --key …`
   prints the SPIFFE ID, the subject and the grants.
7. **Under cron**, always `--out`, as the wrapper does: cron mails a job's stdout, tokens
   included (pre-flight M-12). Size `PORT49_TTL` to the whole sweep, since the wrapper queues
   every node at once; a fleet larger than one sweep's TTL mints in waves (design §17).
8. **On a bad day.**
   - **Exit 75**: the broker or its store did not answer within the deadline. The nodes minted
     before it are queued; with none, Oxidized kept its last `router.db`. Try the next window.
   - **Exit 77**: nothing was minted and running again will not change it: an expired
     certificate (said before anything connects), a revoked principal, every node denied, or a
     certificate status nothing covers. Oxidized kept its last `router.db`. The stderr line says
     which.
   - **Exit 1**: a node not permitted, or not minted after a final refusal. Its line on stderr
     says why; the rest are queued.
   - **To stop the workload**: `port49 revoke --principal spiffe://…`, and revoke the certificate
     at the CA.
9. **Provisional on L49**, until the row closes.

- [ ] **Step 4: Check the policy snippet and run the test**

Run:

```bash
chmod 0755 examples/oxidized/port49-oxidized-run
go test ./examples/oxidized/ -count=1
```

Expected: PASS.

Then check the snippet loads and its tests hold. Write a scratch policy (not committed) that
declares `scopes: [{name: all_devices, match: {}}]` and the snippet's `roles`, `subjects`, `grants`
and `tests`, with the tests' device renamed to one in `tests/lab/inventory-lab.yaml`. Run
`go run ./cmd/port49 policy test --policy <scratch> --inventory tests/lab/inventory-lab.yaml`.
Expected: every test passes. If one does not, the snippet is wrong; fix the snippet, not the test.

- [ ] **Step 5: Commit**

```bash
git add examples/oxidized
git commit -m "docs(examples): Oxidized driven by port49 workload token (provisional on L49)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: (lab harness, on beehive) step-ca for L48, Oxidized on the compose stack for L49

**Files:**
- Create: `tests/lab/workload/compose.yaml` (step-ca, project `port49labstepca`)
- Create: `tests/lab/compose/oxidized.yaml` (the Oxidized overlay on the compose stack)
- Create: `tests/lab/stepca_test.go` (`//go:build lab`): `stepCA`, `startStepCA`, `issue`, `renew`,
  `renewDaemon`, `revoke`, `crl`, `enableCRL`, `stopCA`, `startCA`
- Create: `tests/lab/localbroker_test.go` (`//go:build lab`): `startLocalBroker`, a port49d from
  `bin/port49d` with a broker and a workload verifier, no device
- Create: `tests/lab/oxidized_test.go` (`//go:build lab`): `oxidized`, `startOxidized` (through
  `startComposeWith`), `nodeStatus`, `fetchConfig`, `oxidizedCommands`
- Create: `tests/lab/workload_unit_test.go` (`//go:build lab`, `make lab-unit`): the pure helpers'
  tests
- Modify: `Makefile` (`lab-workload`, `lab-oxidized`), `tests/lab/README.md` ("Workload CA and
  Oxidized")

**Interfaces:**
- Consumes: Task 10's `bin/port49 workload token` and `identity`; Task 11's
  `testpki.WriteWorkloadLab`; Task 12's `examples/oxidized/*`; the lab's `dockerCmd`,
  `startComposeWith`, `composeOptions`, `l.capture`, `l.mark`, `l.recordsSince`, `leakIn`,
  `oidcNote`'s note shape.
- Produces: what Task 14 runs.
  - `TestL48StepCA` (`make lab-workload`): step-ca alone, with a local port49d. No device.
  - `TestL49Oxidized` (`PORT49_LAB_PLATFORMS=<one> make lab-oxidized`): the compose stack, one
    platform per invocation.
  - The note writer `workloadNote(row, platform, claim, observation, evidencePath, run, version
    string) string`.

A fault in the setup (an image that will not pull, step-ca that never answers, Oxidized that never
loads its nodes) stops the test with `t.Fatal` before the note: it is INVALID, never a measured
"no". A step that ran and did not do what the claim says is a failed cell, and the note records it
(7h Task 15's rule).

- [ ] **Step 1: Pin the images (execution-time values)**

On beehive:

```bash
sg docker -c 'docker pull smallstep/step-ca:latest && docker pull oxidized/oxidized:latest'
sg docker -c "docker inspect --format '{{index .RepoDigests 0}}' smallstep/step-ca:latest oxidized/oxidized:latest"
sg docker -c 'docker run --rm smallstep/step-ca:latest step-ca version; docker run --rm --entrypoint oxidized oxidized/oxidized:latest --version'
```

Write each image as `<repo>:<version>@<digest>`, using the version the last command printed, in
two places:
- the compose files;
- `stepCAImage` and `oxidizedImage` in the Go files.

A unit test holds the two equal, as `kcImage`'s does: `TestTheWorkloadImagesArePinnedOnce` in
`workload_unit_test.go` reads both compose files and compares.

- [ ] **Step 2: step-ca's compose file, and the harness**

`tests/lab/workload/compose.yaml`:

```yaml
# step-ca for plan 8's lab (L48): a workload CA, initialised at first start
# into tests/lab/logs/workload/step (git-ignored), its provisioner "lab" a JWK
# whose password the image generates under secrets/ (never printed).
# The image is pinned by digest (stepCAImage in stepca_test.go names the same
# reference, and a unit test holds the two equal); the note records
# `step-ca version` and the image ID.
name: port49labstepca

services:
  step-ca:
    image: smallstep/step-ca:<version>@sha256:<digest>   # Step 1
    environment:
      DOCKER_STEPCA_INIT_NAME: port49 lab workloads
      DOCKER_STEPCA_INIT_DNS_NAMES: step-ca.port49.lab,localhost,127.0.0.1
      DOCKER_STEPCA_INIT_PROVISIONER_NAME: lab
    volumes:
      - ../logs/workload/step:/home/step
    ports:
      - "127.0.0.1:19000:9000"
```

`tests/lab/stepca_test.go` holds the harness. Every `step` command runs inside the container through
`dockerCmd("compose", "-f", stepCACompose, "exec", "-T", "step-ca", "step", …)`. Each passes
`--ca-url https://localhost:9000` and `--root /home/step/certs/root_ca.crt`, and the provisioner
password comes from `--provisioner-password-file /home/step/secrets/password`. A command's output is
kept for the note only after `leakIn` finds no key material in it.

```go
//go:build lab

package lab

// stepCA is the lab's workload CA (L48). dir is its state on the host
// (tests/lab/logs/workload/step); the workload's files are dir/w/w.pem and
// dir/w/w-key.pem, written by step inside the container as /home/step/w/....
type stepCA struct {
	t   *testing.T
	dir string
}

const (
	stepCAImage   = "smallstep/step-ca:<version>@sha256:<digest>" // Step 1
	stepCACompose = "tests/lab/workload/compose.yaml"
	l48ID         = "spiffe://port49.lab/host/oxidized-01"
)

// startStepCA brings step-ca up fresh (its state directory emptied), waits
// for /health, and takes it down with t.Cleanup.
func startStepCA(t *testing.T) *stepCA

// step runs `step args...` in the container with the CA URL and root, and
// returns its combined output.
func (s *stepCA) step(args ...string) (string, error)

// issue asks for a certificate for id, valid for life, into w/.
func (s *stepCA) issue(id string, life time.Duration) (*x509.Certificate, error)

// renew is `step ca renew --force` of w/; renewDaemon starts `step ca renew
// --daemon` on it in the background and returns a func that stops it.
func (s *stepCA) renew() (*x509.Certificate, error)
func (s *stepCA) renewDaemon() (stop func(), err error)

// revoke is `step ca revoke --cert w/w.pem --key w/w-key.pem`.
func (s *stepCA) revoke() error

// enableCRL adds {"crl": {"enabled": true, "generateOnRevoke": true}} to
// ca.json on the host side of the volume and restarts the container; crl
// fetches https://127.0.0.1:19000/1.0/crl (trusting the CA's root) and
// parses it with x509.ParseRevocationList.
func (s *stepCA) enableCRL() error
func (s *stepCA) crl() (*x509.RevocationList, []byte, error)

// allowURI sets the lab provisioner's x509 name policy in ca.json to allow
// the one URI id (step-ca's provisioner policy, x509 allow uri) and restarts
// the container (pre-flight M-11).
func (s *stepCA) allowURI(id string) error

// root is certs/root_ca.crt on the host side of the volume: what the local
// broker's CRL fetch trusts, through SSL_CERT_FILE (pre-flight I-3).
func (s *stepCA) root() string

// stopCA and startCA stop and start the container, for the outage cells.
func (s *stepCA) stopCA() error
func (s *stepCA) startCA() error

// intermediate is certs/intermediate_ca.crt, the workload anchor (L48 measures
// that a CRL covers it there).
func (s *stepCA) intermediate() *x509.Certificate
```

Each of these is 10 to 30 lines over `dockerCmd`, `os`, `encoding/json`, `net/http` and
`crypto/x509`, and each returns its error rather than calling `t.Fatal`, so the test decides what is
INVALID and what is a cell.

Add the note writer in the same file. It has `oidcNote`'s shape (`oidc_test.go`) with its own
platform line:

```go
// workloadNote is a results note in spec §15 rule 3's form, not yet checked
// for leaks (leakIn runs on it before it is written).
func workloadNote(row, platform, claim, observation, evidencePath, run, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", row, platform)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Run:** %s\n", run)
	fmt.Fprintf(&b, "- **Platform:** %s\n", platform)
	fmt.Fprintf(&b, "- **Image version:** %s\n", version)
	fmt.Fprintf(&b, "- **Capture:** `%s`\n", evidencePath)
	fmt.Fprintf(&b, "- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are "+
		"never written; certificates are public.\n")
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	return b.String()
}
```

Task 14 calls it as `workloadNote("L48", "step_ca", …)` and `workloadNote("L49", l.p.name, …)`,
with `run` the commit and the test run as 7g's notes carry it. Write the harness, and in
`workload_unit_test.go` test the two pure pieces:
- `caJSONWithCRL(raw []byte) ([]byte, error)` keeps every other key of `ca.json` and sets `crl`;
- `caJSONAllowingURI(raw []byte, provisioner, id string) ([]byte, error)` keeps every other key and
  sets that provisioner's x509 allow list to `id` alone;
- `renewFraction(notBefore, notAfter, renewedAt time.Time) float64`.

`tests/lab/localbroker_test.go`:

```go
//go:build lab

package lab

// localBroker is bin/port49d run with a broker and the workload verifier,
// memory store, one inventory device (leaf1 at 127.0.0.1) and no device
// behind it: L48 measures what the broker does with step-ca's certificates,
// and a mint touches no device.
type localBroker struct {
	addr, stderrPath, pki string
	cmd                   *exec.Cmd
}

// startLocalBroker writes port49d.yaml into dir with broker.identity's
// humans anchor from testpki.WriteLab and machines anchor anchorFile,
// spiffe_trust_domains [port49.lab], and certificate_status from crlURL and
// crlIssuer ("" for disabled: true, refresh_interval 1m otherwise); a policy
// granting l48ID svc-oxidized on leaf1; and starts bin/port49d on it,
// waiting for "broker listening on". crlRoot, when set, is given to the
// process as SSL_CERT_FILE: step-ca serves its CRL over https under its own
// private root, and certstatus fetches with the system roots (pre-flight
// I-3). t.Cleanup stops it.
func startLocalBroker(t *testing.T, dir, anchorFile, crlURL, crlIssuer, crlRoot string) *localBroker

// workloadToken runs bin/port49 workload token against b with certFile and
// keyFile for leaf1, and returns its exit code, stdout and stderr (stdout
// holds a token: it is never written to a note, only its presence).
func (b *localBroker) workloadToken(certFile, keyFile string) (int, string, string)

// said is everything the broker has written to stderr so far.
func (b *localBroker) said() string
```

The two mirror how `l.restart` starts a daemon (`harness_test.go`). It is a separate process and a
memory store, with `PORT49_LAB_ENC_KEY` and `PORT49_LAB_KEY` from the harness defaults.

- [ ] **Step 3: Oxidized on the compose stack**

`tests/lab/compose/oxidized.yaml`:

```yaml
# Oxidized on the lab's compose stack (plan 8, L49): host networking, so it
# reaches the containerlab devices as a host on the management bridge would,
# its REST API on 127.0.0.1:18888. Everything under ${PORT49_COMPOSE_LOCAL}/oxidized
# (config, router.db, known_hosts) is written by TestL49Oxidized before `up`.
# The image is pinned (oxidizedImage in oxidized_test.go names the same
# reference, and a unit test holds the two equal).
services:
  oxidized:
    image: oxidized/oxidized:<version>@sha256:<digest>   # Step 1
    network_mode: host
    environment:
      CONFIG_RELOAD_INTERVAL: "0"
    volumes:
      - ${PORT49_COMPOSE_LOCAL}/oxidized:/home/oxidized/.config/oxidized
```

`tests/lab/oxidized_test.go` holds:
- `startOxidized(t, l)`. It brings the compose stack up with this overlay (`startComposeWith`,
  `composeOptions{Overlay: "oxidized.yaml", Files: …, Prepare: …}`), where:
  - **`Files`** gives `port49-broker.yaml` the identity block (the stack's human anchor, and the
    workload anchor `testpki.WriteWorkloadLab` writes for `spiffe://port49.lab/host/oxidized-01`,
    `spiffe_trust_domains: [port49.lab]`) and the policy. Phase A's role permits `["**"]`; phases B
    and C use `examples/oxidized/policy.yaml`'s role.
  - **`Prepare`** writes the workload PKI and Oxidized's directory. That is
    `examples/oxidized/config` with `rest: 127.0.0.1:18888`, `known_hosts` filled by
    `ssh-keyscan -T 10 <l.p.addr>`, and `router.db` empty. The directory is owned by the
    container's `oxidized` user, mode 0700: its uid from `dockerCmd("run", "--rm",
    "--entrypoint", "id", oxidizedImage, "-u", "oxidized")`, then chowned as the 7h harness does
    (`oidc_test.go`), with no sudo: `dockerCmd("run", "--rm", "--user", "root", "--entrypoint",
    "chown", "-v", dir+":/d", oxidizedImage, "-R", uid+":"+uid, "/d")` (pre-flight M-10).
- `nodeStatus(node string) (string, time.Time, error)`: `GET
  http://127.0.0.1:18888/node/show/<node>?format=json`, the last run's status and end time.
- `fetchConfig(node string) (string, error)`: `GET /node/fetch/<node>?format=json`.
- `oxidizedCommands(recs []map[string]any, username string) []string`: the commands in the
  daemon's `authorize_command` records for `username`, in order and once each.
- `runWrapper(t, c, ttl string) (int, string)`: `bash examples/oxidized/port49-oxidized-run` with
  `PORT49_BIN=bin/port49`, the stack's broker URL and CA, the workload files, `OXIDIZED_NODES`
  holding `l.p.node`, `OXIDIZED_ROUTER_DB` the volume's `router.db`, `OXIDIZED_REST`, and
  `PORT49_TTL=ttl`. It returns the exit code and stderr.

`workload_unit_test.go` tests `oxidizedCommands` on a recorded set (two commands, one repeated, one
other user's), and `TestTheWorkloadImagesArePinnedOnce`.

- [ ] **Step 4: The Makefile and the README**

```make
# The workload CA lab (plan 8, L48): step-ca as a container and a local
# port49d, no devices. Needs Docker with Compose v2.24.4+ and `make build`.
lab-workload:
	go test -tags lab ./tests/lab/ -run 'TestL48' -count=1 -v -timeout 45m

# Oxidized end to end (plan 8, L49): the compose stack with one platform, as
# `make lab` runs one at a time. Needs containerlab, the platform's image and
# `make build`.
lab-oxidized:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-oxidized platform: $$p ==="; \
	  if ! PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL49' -count=1 -v -timeout 90m; then \
	    echo "=== lab-oxidized platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done
```

`tests/lab/README.md` gains "Workload CA and Oxidized":
- the two targets;
- the images pinned by digest;
- that `bin/` must be built first;
- that the Oxidized volume is chowned through a root container, as the 7h harness does, so no
  sudo is needed;
- that L48's broker trusts step-ca's root for the CRL fetch through `SSL_CERT_FILE`, and that a
  CRL fetch failing TLS is INVALID, never a measured "no".

- [ ] **Step 5: The unit tests pass, and the harness builds**

Run: `make lab-unit && go vet -tags lab ./tests/lab/`
Expected: PASS. No lab test runs here.

- [ ] **Step 6: Commit**

```bash
git add tests/lab Makefile
git commit -m "test(lab): step-ca and Oxidized harnesses for L48 and L49

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: (lab, on beehive) L48 and L49 measured; the example corrected to what they show

**Files:**
- Create: `tests/lab/l48_test.go`, `tests/lab/l49_test.go` (`//go:build lab`)
- Create: `tests/lab/results/L48-step_ca.md`, `tests/lab/results/L49-oxidized-<platform>.md` (one
  per platform measured), `tests/lab/evidence/…`
- Modify: `examples/oxidized/*` (only where L49 measured otherwise), the spec's §15 rows L48 and
  L49 (a separate `docs:` commit)

**Interfaces:**
- Consumes: Task 13's harness.
- Produces: the notes and their evidence; the row status lines; any correction to the example, said
  in its own commit.

- [ ] **Step 1: `TestL48StepCA`, the claim and its cells**

`tests/lab/l48_test.go`. The claim constant is the §15 row's text. The cells, in order:

1. **Issue.**
   - `issue(l48ID, 24h)`.
   - Record: the URI SANs, the DNS SANs, the EKUs, `IsCA`, the issuer, and the lifetime.
   - `startLocalBroker` with the intermediate as the anchor and status `disabled: true`.
   - `port49 workload identity` prints `l48ID`, and `workload token` exits 0.
2. **Renew.**
   - `renew()`. Record: the same URI SAN, the same public key (yes or no), a new serial.
   - `workload token` exits 0 with no change to port49.
3. **Daemon timing.**
   - `issue(l48ID, 15m)`, then `renewDaemon()`, then wait for `w.pem`'s change, up to 15m.
   - Record the fraction of the lifetime at which it renewed (`renewFraction`).
4. **The CA down.**
   - `issue(l48ID, 6m)` (step-ca's default minimum is 5m), then `stopCA()`.
   - `renew()`: record its error.
   - Run `workload token` every 30s until 7m:
     - record when the broker's "its renewal is late" line first appears (expected near 4.5m);
     - record when the CLI's warning first appears;
     - record the first exit that is not 0 (expected 77, after 6m), and its stderr (expected the
       CLI's "expired at … renew it against your CA").
   - `startCA()`.
5. **The CRL.**
   - `enableCRL()`, then `crl()`. Record: DER (yes or no), the issuer (`intermediate`'s subject or
     not), `nextUpdate`, and the number of entries.
   - `issue(l48ID, 24h)`, and `startLocalBroker` again with `crls: [{name: stepca, url:
     https://127.0.0.1:19000/1.0/crl, issuer_file: <intermediate>}]`, `refresh_interval: 1m`, and
     `crlRoot` = `root()`, so the fetch trusts step-ca's root (pre-flight I-3; the note says so).
     Record its "certificate status" start lines.
   - **A TLS failure is INVALID.** If the broker's stderr names a certificate verification failure
     for the CRL fetch (`x509: certificate signed by unknown authority` or like it), stop with
     `t.Fatal`: a harness fault, fixed and run again, never a measured "step-ca's CRL is
     unusable".
   - `workload token` exits 0.
   - `revoke()`. Then poll `workload token` every 10s up to 3m. Record when it first exits 77 with
     `credential_revoked`.
   - `renew()` of the revoked certificate: record step-ca's answer.
6. **The name policy** (pre-flight M-11).
   - `allowURI(l48ID)`, then `issue(l48ID, 24h)`: record that it is issued.
   - `issue("spiffe://port49.lab/host/other", 24h)`: record step-ca's answer, expected a refusal
     naming the policy.

Write the note with `workloadNote("L48", "step_ca", l48Claim, obs, evidencePath, run, version)`,
where `version` is `step-ca version` and the image ID. The evidence (`tests/lab/evidence/L48-step_ca.json`) holds:
- each certificate's PEM, which is public, and its parsed SANs;
- the CRL's DER as base64;
- the broker's start lines;
- each `workload token` exit and its stderr, never its stdout.

Run it through `leakIn` against the provisioner password and the workload's key before it is
written.

- [ ] **Step 2: `TestL49Oxidized`, the claim and its cells, per platform**

`tests/lab/l49_test.go`, under `l.capture(t, "L49-oxidized")`, with `startOxidized`:

- **A. What Oxidized sends** (role `**`).
  - `mark := l.mark()`, then `runWrapper(…, "15m")`, then wait for `nodeStatus` to be `success`,
    up to 5m.
  - Record:
    - `oxidizedCommands(l.recordsSince(mark), "svc-oxidized")`;
    - the `redeem` records' count (authentications per run);
    - that `fetchConfig` holds the device's hostname line (from a breakglass `show running-config`
      or `show configuration` taken through `l.login`) and is over 1 KiB;
    - the `mint` record's principal, which should be `spiffe://port49.lab/host/oxidized-01`.
- **B. A stale token** (role from `examples/oxidized/policy.yaml`).
  - `runWrapper(…, "60s")`, and wait for success.
  - The token is now spent, and its receipt would replay it for `receipt_idle_ttl` (15m by
    default). For this phase the stack's `port49d.yaml` sets the top-level `receipt_idle_ttl: 2m`
    (`Files` writes it; the note says so). Wait 3m, past both the token's 60s and the receipt's
    2m.
  - `PUT /node/next/<node>` **without** a new mint. Record:
    - the `redeem` records since (their count and reasons);
    - `nodeStatus` (expected `no_connection` or `fail`);
    - the authentications one node's run cost.
  - Then `runWrapper(…, "60s")` again: the node succeeds, which shows the credential is read at
    `/reload`.
- **C. The example's role.** A's run again with the snippet's role. Record every
  `authorize_command` record's verdict. Every one is `permit`, or the note names the command the
  snippet lacks.
- **D. No token in Oxidized's log.** `docker logs` of the container, through `leakIn` against every
  token minted in A to C.

Write the note per platform with `workloadNote("L49", l.p.name, l49Claim, obs, evidencePath, run,
l.p.version+", Oxidized "+oxidizedVersion)`. The evidence is the redacted capture (`make evidence`
at the end, as `make lab` does) and a JSON of the records' commands and verdicts.

- [ ] **Step 3: Run L48**

On beehive, from a pinned worktree at the commit under test, with the watchdog armed:

```bash
make build && make lab-workload 2>&1 | tee tests/lab/logs/l48.log
```

Expected: `TestL48StepCA` PASS (a measurement, whatever it measured), and
`tests/lab/results/L48-step_ca.md` written. An INVALID stop (setup) is fixed and run again, never
recorded as a cell.

- [ ] **Step 4: Run L49 on each platform**

```bash
for p in eos nxos iosxe vjunos vsrx; do PORT49_LAB_PLATFORMS=$p make lab-oxidized 2>&1 | tee tests/lab/logs/l49-$p.log; done
make evidence
```

Expected: one note per platform. Copy the raw captures to `main`'s `tests/lab/captures/` before
removing the worktree.

- [ ] **Step 5: Correct the example to what L49 measured**

For each platform's note, compare the measurements with the example:
- **The commands.** Add any command the note's A lists that `examples/oxidized/policy.yaml` does
  not permit. Remove none that a platform needs.
- **The models.** Change any model name that did not load the node.
- **The REST calls.** Change any call that answered other than 200.
- **The retries.** Change `retries` if B showed a retry costs more authentications than it buys.

Each correction is its own commit, `fix(examples): … (L49, <platform>)`, citing the note (register
rule 4). If none is needed, say so in Task 15.

- [ ] **Step 6: Close what was measured, and commit**

For each row, rule 3 and rule 5:
- **L48** closes when its note exists with:
  - the platform (step-ca and its version);
  - the image ID;
  - each cell's observation;
  - the evidence pointer.

  Edit its §15 Status to `closed — measured <date>; tests/lab/results/L48-step_ca.md`.
- **L49** closes only when all five images have a note. Otherwise its Status names the platforms
  measured and the notes, and stays `open`.

If L48's CRL cells, run with the fetch trusting step-ca's root (cell 5), show step-ca's CRL is
unusable with port49, L48 still closes (it measured), and Task 15 brings the per-verifier
certificate-status question to Ryan with the note: decision 40 ruling 7's one revisit condition. A
CRL fetch that failed TLS is INVALID and never reaches that question.

L50 is plan 8b's and stays open.

```bash
git add tests/lab/l48_test.go tests/lab/l49_test.go tests/lab/results/L48-step_ca.md tests/lab/results/L49-oxidized-*.md tests/lab/evidence
git commit -m "test(lab): L48 on step-ca and L49 Oxidized end to end

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L48 (and L49 where every platform measured)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 15: Plan 8 as built

**Files:**
- Modify: `docs/superpowers/plans/README.md` (a "Plan 8 — As built" section after "Plan 8 —
  Workload certificates"; **not** the status line, which the controller updates after the merge)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (decision 40's text, only where execution
  departed from a ruling)

**Interfaces:**
- Consumes: every task's commits, the ledger's rulings, L48 and L49's notes, the controller's
  rulings on Q1–Q3 and any override by Ryan.
- Produces: the roadmap's record of plan 8, for plans 9, 10 and 13.

- [ ] **Step 1: Write "Plan 8 — As built"**

In the house style of "Plan 7h — As built":
- **Per task:** the commits, and any ruling made during execution.
- **The rulings, as made:** decision 40's rulings 1–16, each "stood" or what changed, with the
  commit.
- **Q1–Q3:** the controller's rulings on recommendation (decision 40), and any override Ryan made.
- **The lab:** L48's and L49's findings, the rows closed, and the example corrections L49 caused.
- **The interfaces plan 8 added:**
  - `spiffe.*`;
  - `broker.Workload` (with `Issued`), `CertCaller`, `CertCallerOf`, `WorkloadPrincipal`,
    `ErrWorkloadUnmapped`, `ReadAnchor`;
  - `Listener.Caller`, `Broker.Wire`, `ErrUnwired`;
  - `api.LateRenewal`, `api.UncoveredStatus`;
  - `workload.*`;
  - `config.BrokerConfig.WorkloadCAFile`, `oidc.X509Machine`;
  - `testpki.WriteWorkloadLab`, `RenewWorkload`, `WriteWorkloadLabFrom`, `CA.IssueCA`;
  - `Policy.SPIFFEIdentities`;
  - the metric.
- **Carried forward:**
  - **Plan 8b:** a workload certificate's directory groups, constrained to machine-scoped group
    subjects (the roadmap's "Plan 8b", Task 1; L50), unless Ryan cancels it.
  - **Plan 9:** mint by scope (already in the roadmap's "Plan 9", written at pre-flight); the
    agent's per-user config file may later serve `port49 workload` too.
  - **Plan 10:** the `k8s` verifier joins `machines`. `CertCallerOf` is untouched by it, and a
    subject listing `spiffe://` and `system:serviceaccount:` is the migration spec §2 describes.
  - **Plan 12:** the alert `increase(port49_workload_certificates_renewal_late_total[1h]) > 0`
    (summed over replicas); the workload anchor's CRL in each deployment shape, a private CA's
    https CRL endpoint included (`SSL_CERT_FILE`, or a `file:` source).
  - **A lab recheck, unassigned** (pre-flight M-15): a Keycloak back-channel logout against a
    broker with a workload verifier, which sends a `CertificateRequest` L45 was not measured with.
  - **Plan 13:**
    - the operator notes below;
    - `examples/oxidized/README.md` as the Oxidized page;
    - the enrollment page for step-ca, and one CA more if a later row measures it.
  - **Pre-beta review:** anything parked.
- **The operator notes, as built:** this plan's notes, corrected by what the lab measured.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/README.md docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: plan 8 as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Operator-facing notes (for the pull request body)

- **Workload certificates** (decision 40).
  - **Configuration.** `broker.identity.machines: [{type: x509, trust_anchor_file: <the CA that
    issues your workload certificates>, spiffe_trust_domains: [<yours>]}]`. At most one, beside at
    most one human `x509` verifier.
  - **The two anchors** must be different certificates in unrelated hierarchies. The start
    refuses one certificate in both files, or one anchor signing the other, naming both files. An
    anchor further down the other's hierarchy is refused at each request whose chain shows it.
  - **Certificate status.** `broker.certificate_status` is required with any x509 verifier, and
    covers both anchors, with no per-verifier opt-out. An anchor no CRL covers is said at start.
    For a workload CA with no CRL, turn its CRL on (step-ca's `crl.enabled`), or sync it to a
    `file:` source, or stop workloads by principal; never `on_unavailable: allow` or `disabled:
    true`, which weaken it for people too. A private CA's https CRL endpoint needs its root in the
    broker's trust store (`SSL_CERT_FILE`), or a `file:` source.
  - **The TLS handshake changes for everyone** (pre-flight M-15). A workload verifier makes even
    an OIDC-only broker ask every client for a certificate (`VerifyClientCertIfGiven`), so
    every connection sees a `CertificateRequest`, Keycloak's back-channel logout included. L45
    was measured without one; a recheck is carried.
  - **The workload CA is the trust root.** Whoever can get it to issue a certificate naming a
    SPIFFE ID is that workload. Restrict each provisioner to its host's own ID (step-ca's x509
    name policy, L48).
- **The principal** is the certificate's one URI SAN, a SPIFFE ID with a path
  (`spiffe://corp.example.com/host/oxidized-01`), verbatim.
  - Anything else is refused `identity_unmapped`, over HTTP with the reason.
  - Upper case is refused, never folded.
  - The policy refuses a `spiffe://` identity outside that form at load. The start says which
    identities no verifier can give.
- **No directory for a workload.** It mints with every DC down, never matches a `group:` subject,
  and declares its `username:`. Directory groups for workloads, through a machine-scoped group
  subject only, are plan 8b's.
- **A declared username stands.** Declaring a username a directory user holds locks that user out
  at the next refresh, and CI cannot see it in advance; `username_collision` names both
  claimants (decision 38 ruling 3).
- **Renewal is your CA's job.**
  - port49 needs nothing at a renewal.
  - A certificate presented with under a quarter of its life left is said once a day and counted
    in `port49_workload_certificates_renewal_late_total`. Each broker replica counts it once, so
    alert on its increase, not on a count.
  - **To stop a workload**, revoke its principal (`port49 revoke --principal spiffe://…`). A mark by
    certificate does not follow a renewal, and `port49 revoke` says so. Revoke at the CA too.
- **`port49 workload token`** mints with no agent, reading the certificate and key each run.
  - It pages by `batch_max` under one `Idempotency-Key` per page, and retries 503, 409
    in-progress, 429 and dropped connections within `--deadline` (2m). A 503 for a certificate
    status nothing covers is final, not retried.
  - Tokens go to stdout or `--out` (0600). Output is `--format tsv|json`. Under cron, always
    `--out`: cron mails a job's stdout.
  - Exit 0 all permitted and written; 1 some written, some not; 2 usage; 75 the broker did not
    answer in time (pages minted before it are written); 77 nothing minted, and a run again will
    not change it (expired certificate, revoked principal, every device denied, uncovered
    status). On 77, and on 75 with nothing minted, nothing is written.
- **`port49 workload identity`** shows what the broker makes of a workload's certificate. Run it
  after enrollment.
- **Oxidized:** `examples/oxidized/` (the wrapper for cron, Oxidized's config, a policy snippet).
  Provisional on L49 until that row closes. The wrapper replaces `router.db` only when it has a
  node to write, so a bad night leaves Oxidized's last one in place.
- **`/v1/config`'s `methods`** names how a person authenticates: `x509` only with a human anchor.
- **Lab:** L48 (step-ca) and L49 (Oxidized on five images), as measured; see the notes. L50 is
  open for plan 8b.

## Self-review against the spec

**Coverage.** Each roadmap plan-8 item and each spec section the plan cites, with the task that
builds it:
- **The `x509` machine verifier:** Tasks 3, 4, 5, 6, 8.
- **The principal (spec §2's row):** Tasks 2 and 4.
- **Trust-domain separation:** Tasks 4 and 8; Review Focus 1.
- **Multi-identity subjects:** Tasks 5 and 11.
- **`username` on machine subjects, and the collision:** Tasks 1 and 5.
- **Enrollment and self-renewal (relying party's part):** Tasks 5, 9, 10 and 11; L48.
- **Revocation of a workload:** Task 7.
- **Certificate status over both anchors:** Tasks 3 and 8.
- **The agentless client (design §17):** Tasks 9 and 10.
- **Oxidized, the day-one consumer:** Tasks 12 to 14; L49.
- **Spec and design text:** Task 1. **As built:** Task 15.
- **The directory carry (`Resolver.Map`, decision 16):** deferred to plan 8b, constrained (Ruling
  5); Task 1 writes the deferral into decision 16, design §7, §2, §5.1.3, the roadmap's "Plan 8b"
  and L50. Nothing specified is cut.
- **Mint by scope (design §17):** plan 9's, in the roadmap's "Plan 9" since pre-flight.
- **The listener's wiring, both daemons:** Tasks 6 and 8 (`Broker.Wire`, `ErrUnwired`, the
  `BindMap` guard).

**Placeholders.** None but execution-time values: the images' tags and digests (Task 13 Step 1),
the measured dates, versions and fractions in the notes, and the PR number. The step-ca harness
signatures in Task 13 are declarations whose 10-to-30-line bodies the harness step describes.

**Type consistency.**
- **`CertCaller`** (Task 4) is what Task 5's `authenticate`, `callerOf` and `noteRenewal` read, and
  what Task 6's `Listener.Caller` returns. Its `Domain` is compared to `DomainMachines` everywhere.
- **`Broker.Workload`** (Task 4) is set by Task 8 from `config.BrokerConfig.WorkloadCAFile` and
  `oidc.Config.X509Machine.TrustDomains` (Task 3).
- **`api.LateRenewal`** (Task 5) is the one threshold for the broker and `workload.LoadCertificate`
  (Task 9).
- **`api.UncoveredStatus`** (Task 5) is what `unknownClass` and Task 9's `retriable` key on, and
  Task 5's certstatus test pins certstatus's detail to it.
- **`Workload`** is used through a pointer only; its `mu` (Task 5) guards `late` (Task 5) and
  `issuers` (Task 7).
- **`Broker.Wire`** (Task 6) is what Task 6's `startServerWith` and both daemons (Task 8) call.
- **`workload.TemporaryError.Unminted`** (Task 9) is what Task 10 counts; on a final error Task 10
  counts `len(devices) - len(resp.Results)`.
- **The exit codes** (Task 10: 0, 1, 2, 75, 77; `exitFinal = 77`) are what Task 12's wrapper
  reads: 0, 1 and 75 may carry nodes, and it writes `router.db` only when one survives its
  filters.
- **The TSV columns** (Task 10) are what Task 12's `awk` reads: `$1` device, `$2` address, `$3`
  platform, `$4` username, `$5` login. Without `--enable` the wrapper never asks for the enable
  column.
- **`testpki.WriteWorkloadLab`'s file names** (Task 11) are what Task 13's L49 harness reads.

**Review Focus.** Each of the six has its test in the owning task, named in the section, the
pre-flight's additions included (Tasks 6, 9, 10 and 12).

**Pre-flight.** Applied 2026-10-07: C-1, I-1 to I-6 and M-1 to M-19, and the controller's
rulings on Q1–Q3 (`.superpowers/sdd/2026-10-07-08-workload-certificates/preflight.md`, "Applied").

