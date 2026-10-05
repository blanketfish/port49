# Plan 7g: The Directory — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve a certificate holder to exactly one LDAP or Active Directory entry, take
their username and their nested group membership from it, mint for group subjects, keep minting
through a directory outage within a grace window, and re-verify every live principal on a
schedule that stamps `refreshed_at`, with `session.staleness_ceiling` given a default in the
same change.

- **The certificate-to-directory mapping (design §7).**
  - Replaces the slice's email-SAN principal and declared human `username:` whenever
    `broker.directory` is set. Without it, today's path is unchanged.
  - Two strong mappings:
    - `issuer_serial`: AD's `altSecurityIdentities` `X509:<I>…<SR>…`;
    - `sid`: the certificate's SID extension, matched on `objectSid`.
  - Four weak ones: `san_upn`, `san_email`, `subject_dn`, `cn`. Each needs `allow_weak: true`
    and an `issuers:` pin.
  - Zero entries is `identity_unmapped`. Two or more is `identity_ambiguous`, loud and alertable
    on its own.
  - The mapping runs once per held connection, at bind, and is pinned to that connection.
- **The server pool (design §10).** Priority ordering, sticky selection, a circuit breaker per
  server, health checks, failback hysteresis (`stability_window`), and site awareness:
  - same-site servers first, then priority;
  - the broker's site from `site:` or the environment;
  - every site crossing logged as a consistency event and counted.
- **Binding.** SASL EXTERNAL over mTLS, GSSAPI with a keytab, or simple bind. All three run only
  over TLS (ldaps:// or StartTLS). GSSAPI is pure Go (go-ldap's `gssapi` and gokrb5 v8; no cgo).
- **Nested groups by configuration.** `nested_groups` is required, with no default (design §10):
  - `in_chain`: AD's `LDAP_MATCHING_RULE_IN_CHAIN`;
  - `recursive`: port49 walks `member`, loop-safe and depth-capped;
  - `direct`: one level, declared flat.
- **Group subjects mint.** A principal matches every subject whose group it is in, and every
  identity subject that lists it. The grants of all of them compose (spec §5.1, "subjects").
  - A composition no load-time joint check saw is checked at mint, and one that fails is
    `composition_refused` for that principal on that device alone.
  - A group subject's `api:` rights are held by its members (7c's carry).
- **Pre-warm and grace (design §10).**
  - **Membership in the store.** Each verified membership is written to the shared store,
    sealed, beside an index by mapping key. Every replica, and every restart, can read it.
  - **Pre-warm.** It runs hourly over the members of every group a policy names.
  - **Grace.** When no server answers, a mint uses the stored membership if it was verified
    within `directory.grace`, and the token carries when it was verified. The context's
    `refreshed_at` is that instant, never the redemption's, so a grace mint never resets the
    staleness clock.
- **The scheduled refresh (spec §5.1.3; plan 3's and 4b's carry).**
  - Every `broker.refresh_interval` (5m), the runner re-verifies each principal in
    `active_principals` against the directory. It judges the principal's contexts on the fresh
    membership, and stamps `refreshed_at` on each context it verified.
  - A principal the directory did not answer for is left unstamped. Its sessions deny
    `context_stale` once `session.staleness_ceiling` passes, which now defaults to 4h (OR-1).
  - Without a directory the pass still runs, re-resolving from the policy alone, so the ceiling
    bounds a broker outage too.
- **Lab (on beehive).** Two new register rows, on OpenLDAP and Samba AD containers built from
  Debian packages:
  - **L42:** nested-group resolution under each mode, loops included;
  - **L43:** the bind mechanisms each directory accepts.
  - **L44** opens beside them for Windows Server AD, and stays open: no Windows DC runs on
    beehive (OR-3).
  - Then an end-to-end run on the compose stack: a login granted through a nested group, a
    removal reaching the open session, and a directory outage served from grace until the
    ceiling.

**Architecture:**
- **`internal/directory`**, a new package, owns everything that speaks LDAP:
  - `Pool`: server selection, health checks, breakers, failback, sites;
  - `Conn`: one connection to one server, bound by one mechanism;
  - `Mapping`: the certificate to a filter;
  - `groups`: membership under the configured nested mode;
  - `Resolver`: the broker's one door. It maps at bind, verifies by principal, falls back to the
    store within grace, and pre-warms.
  - It imports `store` for the membership record and nothing from `policy` or `broker`.
- **`store`** gains three things:
  - The membership record: `PutMembership`, `GetMembership`, `MembershipByKey`. It is sealed,
    written only by the broker's role, and leased past the grace window.
  - The refresh stamp: `StampRefreshed`, compared on `PolicyRev`, raise-only. It never moves
    `PolicyRev`, so a stamp never costs a policy refresh its compare. `ContextPolicy` also gains
    `RefreshedAt`, so a changed context is stamped in the same write.
  - The token's `VerifiedAt`: the context `refreshed_at` the login writes.
- **`policy`** resolves a `Member` (principal, directory username, group DNs and the group
  names verified unique), not a principal string alone:
  - `ResolveMember` composes every matching subject;
  - `ResolveSubjects` recompiles a record's blob from its subjects, for replay;
  - `HasRightOf` holds rights through groups.
  - `Resolve(principal, …)` stays, as the identity-only member.
- **`broker`** asks the resolver:
  - at bind (`Listener.Map`, set to `Broker.BindMap`), pinning the principal to the connection;
  - at each mint, identity, explain or revoke request, for the membership;
  - in the refresh, for the stored membership on a policy pass, and for a fresh one on the
    scheduled pass (`RefreshDirectory`).
- **port49-broker's runner** runs the scheduled pass and the pre-warm among its duties. A
  port49d with a broker in the process runs them beside its reloader. The daemon never speaks
  to the directory (design §10: "Neither sits on the authentication hot path").

**Tech Stack:**
- Go 1.26, module `github.com/rhwendt/port49`, no cgo.
- `github.com/go-ldap/ldap/v3` v3.4.14 (pure Go; its `gssapi` subpackage).
- `github.com/jcmturner/gokrb5/v8` v8.4.4 (pure Go; go-ldap's own requirement).
- etcd v3.6.15 as today.
- Lab: Debian bookworm `slapd` (OpenLDAP 2.5) and `samba` (4.17, an AD DC), each built as a
  container on beehive (`sg docker -c`); containerlab with vEOS and vJunos-router for the
  end-to-end run.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2: the subject forms, the principal table's human x509 row, "The device-facing username",
    and API rights through a group;
  - §5.1: "subjects", plural;
  - §5.1.1: `refreshed_at`, the staleness clock;
  - §5.1.3: the scheduled refresh through `active_principals`, and the refresh's record table;
  - §5.6: teardown row 3a, the staleness ceiling;
  - §5.7: the reason codes, the record fields;
  - §12: the diff's gate on a subject's `group:`;
  - §13: decisions 15, 16, 21, 26, 33, 36 and 37 (read), and the new 38;
  - §15: the register rules, and the new L42, L43 and L44.
- `docs/design/2026-08-21-port49-design.md`:
  - §7: human identity, the certificate-to-directory mapping, trust domains;
  - §9: refresh-ahead, "Directory unavailable";
  - §10: directory, directory authentication, server pool, pre-warming, replication lag;
  - §12: the failure matrix's "Directory unavailable" and "Broker unavailable" rows, and the
    store interface's record table;
  - §19: step 7.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", the 7g bullet;
  - Plan 2's hand-off on `staleness_ceiling`;
  - Plan 4's "Hands to plan 7" (group subjects);
  - Plan 4b's "Hands to plan 7" (the scheduled directory refresh);
  - 7b's "Carried" (7g: the default and the schedule);
  - 7c's "Carried" (7g: rights through a group subject).
- The merged plan 7f (`2026-10-05-07f-go-dark-and-context-cache.md`), for house style. This
  plan is written against the code at `c0ca31d`.

**Prerequisite:** plan 7f merged (PR #28, merge `0cd6926`; `main` at `c0ca31d`).

## The carries: what 7g takes, and what it leaves

| Carry | Taken? | Where, or why not |
|---|---|---|
| LDAP and AD group resolution with design §10's server pool: priority, sticky, breaker, failback hysteresis, site awareness (roadmap 7g) | **Taken** | Rulings 7–9; Tasks 6, 7, 9 |
| Nested groups by configuration (roadmap 7g; design §10 "must be configuration rather than an assumed default") | **Taken**: `nested_groups` required, three modes | Ruling 6; Task 9; L42 |
| SASL EXTERNAL, GSSAPI or simple bind (roadmap 7g; design §10) | **Taken**: all three, TLS-only; GSSAPI pure Go (OR-2) | Ruling 8; Task 7; L43 |
| The certificate-to-directory mapping replacing the slice's declared `username:`: strong, or issuer-pinned weak, ambiguity failing closed (roadmap 7g; plan 3's carry; design §7) | **Taken** | Rulings 1–4; Tasks 8, 12 |
| Group subjects minting (plan 4's "Hands to plan 7") | **Taken** | Rulings 5, 13; Tasks 11, 13 |
| Rights held through a group subject (7c "Carried": `HasRight` refuses one today, pinned by ed06f3d) | **Taken** | Ruling 13; Task 13 |
| Pre-warm and grace (design §10, §12) | **Taken**, with membership kept in the store | Rulings 10, 11; Tasks 5, 10 |
| The scheduled refresh through `active_principals` stamping `refreshed_at`, and the `staleness_ceiling` default, in one change (plan 2's hand-off; 4b's "Hands to plan 7"; 7b's carry) | **Taken**, in Tasks 14 and 15, which merge together; Task 15 sets the default | Rulings 12, 14; OR-1 |
| The diff's gate on a subject's `group:` (spec §12: "the gate on them is that plan's") | **Taken**: a changed group fails the gate unless a session test names the subject | Ruling 15; Task 11 |
| A runtime username collision between a human the directory derives and a declared machine username (spec §2: "the broker checks at mint and refuses the later claimant") | **Taken**, and two directory entries sharing one username | Ruling 3; Task 8 |
| The `remote` and `p49-*` names a directory derives (spec §2: "the broker refuses to mint for one a directory derives") | **Taken** | Ruling 3; Task 8 |
| OIDC (`user:` + `preferred_username`), trust-domain verifier lists, `/v1/logout` | **Left to 7h** | Roadmap. 7g's resolver takes a principal, so 7h's OIDC principal resolves groups through `Verify` unchanged |
| Workload certificates mapping to a directory entry for groups (spec §13 decision 16's last clause) | **Left to plan 8** | Plan 8 owns the workload verifier; `Resolver.Map` takes any leaf, so plan 8 reuses it |
| L40 (Junos re-authorization more than once) | **Left unassigned** | Not a directory row |
| The restore guard's IOS-XE lockout (7f "Unassigned") | **Left unassigned** | Not a directory item |

## What this plan does not do

- **The daemon never speaks to the directory.** Nothing on the TACACS+ path waits on LDAP
  (design §9: refresh-ahead, never synchronous). A directory outage reaches a live session only
  through the staleness ceiling.
- **No group membership is ever read from a credential** (design §7). A certificate's groups,
  an `memberOf` the agent reports, an OIDC `groups` claim: none of them is read.
- **No quorum across directory servers** (design §10: explicitly rejected). One server's answer
  is the answer, from the sticky selection.
- **No bind as the user.** The broker binds as itself and reads.
- **No write to the directory.** The broker's account needs read access only.
- **No plaintext LDAP.** `ldap://` without StartTLS is refused at load, for every mechanism. A
  simple bind's password, a GSSAPI ticket and a group list never cross the wire in clear.
- **No device behaviour changes.** Every reply port49d sends is one it sends today. The new
  reasons are on `mint`, `refresh`, `identity`, `explain` and `revoke` (broker events). On the
  device path `context_stale` and `credential_revoked` already exist.
- **No OIDC** (7h), and no workload-certificate path (plan 8).
- **No Windows Server AD in the lab.** L42 and L43 measure OpenLDAP and Samba AD. L44 opens for
  Windows Server AD and stays open until the SER8 box measures it (OR-3).
- **No readiness change.** `/readyz` never follows the store or the directory (design §10,
  §12): a broker with every DC down and every breaker open stays ready, and serves from grace.

## Rulings where the design and spec are silent

Each takes the option that denies more, and is written into the tasks named. Spec §13 records
them as decision 38 (Task 1). Ryan may override any. OR-1 to OR-3 below are the three that need
his call.

1. **The mapping is configured, and it is one of six.**
   - **Shape.** `broker.directory.certificate_mapping` takes `kind` (required) and `attribute`
     (each kind has a default). Repointing a strong kind's `attribute` makes it as strong as
     the attribute it names, so `attribute` on `issuer_serial` or `sid` is refused at load
     unless `allow_weak: true` is set, which then also requires the `issuers:` pin.
   - **Strong:**
     - `issuer_serial` looks up `altSecurityIdentities=X509:<I>{issuer}<SR>{serial}`, AD's
       form (issuer RDNs most-significant first, serial bytes reversed, upper-case hex). The
       issuer is rendered from the leaf's raw DER issuer (`RawIssuer`, parsed into a
       `pkix.RDNSequence`) through an OID short-name table that includes `DC`
       (0.9.2342.19200300.100.1.25). Go's `pkix.Name` drops `DC=` RDNs and `Issuer.String()`
       renders them as dotted OIDs, so neither is ever used for a mapping or a pin.
     - `sid` reads the SID from the certificate's `szOID_NTDS_CA_SECURITY_EXT`
       (1.3.6.1.4.1.311.25.2) and looks up `objectSid`.
   - **Weak:**
     - `san_upn`: the one UPN otherName SAN → `userPrincipalName`;
     - `san_email`: the one rfc822Name SAN → `mail`;
     - `subject_dn`: the subject DN, RFC 4514 → `distinguishedName`, which an operator may
       repoint;
     - `cn`: the subject CN → `cn`.
   - **The weak opt-in.** A weak kind is refused at load without `allow_weak: true` and a
     non-empty `issuers:` list of issuer DNs. The leaf's issuer must equal one of them, compared
     as (OID, value) pairs: the leaf's from `RawIssuer`, the pin's from `ldap.ParseDN` through
     the same short-name table, values case-folded. It is checked at every mapping, before any search (design §7:
     "Weak mappings MUST be issuer-pinned … require explicit opt-in").
   - **Strong needs no pin.** A strong mapping binds a key-specific value. A strong mapping
     with `issuers:` set still checks the pin, since that only denies more.
   - **Values.** A certificate value the kind cannot find (no SID extension, zero or several
     UPN or email SANs) is `identity_unmapped`. Every value is escaped for the filter with
     `ldap.EscapeFilter`, `objectSid` byte by byte, so a SAN of `*)(uid=*` matches nothing.
   - **Mapping keys are canonical.** A `MapKey` hashes the kind and the value's canonical form,
     on both sides (the certificate's at bind, the entry's at pre-warm): a SID as its binary
     form re-encoded, an `issuer_serial` value upper-cased, a UPN or email lower-cased, a DN
     through `ldap.ParseDN` re-rendered lower-cased. The key stored for a verification is the
     one the search was made with (`Lookup.Key`).
2. **Exactly one entry, or no principal.**
   - **The search.** One search under `base_dn` with `(&{user_filter}({attribute}={value}))`, a
     size limit of 2, and the configured attributes only.
   - **Zero entries** is `identity_unmapped`.
   - **Two or more entries**, or the server's size-limit-exceeded, is `identity_ambiguous`. It
     is never "the first" (design §7). It is counted
     `port49_directory_lookups_total{outcome="ambiguous"}` and said once per (mapping key,
     hour) with both DNs.
   - **A server fault** is `directory_unavailable`, not unmapped (Ruling 10).
3. **The principal and the username come from the entry, and each must be unambiguous.**
   - **The principal** is `user:` plus the entry's `principal_attribute` (default
     `userPrincipalName`; OpenLDAP deployments name `mail`), lower-cased. It must be one value,
     printable ASCII, with an `@` (the policy's `user:` form). Otherwise `identity_unmapped`.
   - **The username** is the entry's `username_attribute` (default `sAMAccountName`; OpenLDAP:
     `uid`), lower-cased. It must then pass `token.CanonicalUsername` and not be
     `token.ReservedUsername`. Otherwise `identity_unmapped`, and the line names the value's
     length, never the value when it is unprintable.
   - **Two people under one principal.** A search, `({principal_attribute}={principal value})`
     under `base_dn`, with no `user_filter` and size limit 2, must return only this DN. If it
     does not, the result is `identity_ambiguous`, naming both DNs. Without it, a user who can
     write their own `mail` sets it to a colleague's address and binds as the colleague's
     principal: their identity subjects, `api:` rights and per-principal marks. Leaving
     `user_filter` out finds an entry outside it too, which only denies more.
   - **Two people under one username.** A second search, `({username_attribute}={username})`
     under `base_dn`, with no `user_filter` and size limit 2, must return only this DN. If it
     does not, the result is `username_collision`, naming both DNs. Two people under one
     username would share one `(nas, username)` context, which is impersonation. AD makes
     `sAMAccountName` unique; OpenLDAP does not make `uid` unique.
   - **The principal is pinned to its entry.** The stored membership names the entry the
     principal was verified on, by its immutable id: `objectGUID` (AD, Samba) or `entryUUID`
     (OpenLDAP), else its DN. Every verification, at a bind (`Map`) as on a re-verification
     (`Verify`, `Current`, pre-warm), finds the principal's stored record and refuses an entry
     with another id `identity_unmapped` (the scheduled pass revokes on it): a
     `principal_attribute` value moving between entries never carries the principal with it.
     A rename or an OU move keeps the id, so it keeps the principal.
     - **A refusal keeps the pin.** The refusal record written for a principal carries the
       entry id it was pinned to, so the refusal never opens the principal to the next
       claimant.
     - **How long a pin lasts.** As long as the record: `max(directory.grace, 24h)` after the
       principal's last verification or refusal. A value no one has verified for longer than
       that is the directory's to give to another entry, as a reassigned address is.
     - **The way out: `port49 directory forget <principal>`.** An entry deleted and re-created
       (a rehire, an AD restore from backup without its tombstones) has a new `objectGUID` or
       `entryUUID`, so it is refused like any other claimant. Each refusal renews the record,
       so a rehire who keeps trying never ages out. The operator's escape is an op on the
       broker's admin socket, the same socket as `port49 revoke` (mode 0600, `SO_PEERCRED`: the
       broker's own uid or root):
       - **What it does.** It deletes the principal's membership record, pin included, and
         writes a `directory_forget` record (spec §5.7, a report like `inventory_change`). The
         record names the principal, the entry id and DN it was pinned to, its last
         verification, and `origin: admin_socket uid <n>`.
       - **What happens next.** The principal's next verification pins whatever entry the
         directory then gives it.
       - **The rule for the operator.** It never asks the directory and grants nothing, so it
         is safe to run only after confirming the new entry is the same person.
       - **Where it is named.** The refusal's line names the command, so a 3am operator reading
         the log finds the way out without the docs.

       Built in Task 5 (`DeleteMembership`) and Task 13 (the op, the record, the command).
   - **Who may write the two attributes.** `principal_attribute` and `username_attribute`
     must be writable only by directory administrators. The start line and the operator notes
     say so, with OpenLDAP's default `by self write` on `mail` as the example to remove. The
     two uniqueness searches are the check that holds when that is not so: a self-edited value
     equal to someone else's refuses both people, and never makes one the other.
   - **A declared username.** A derived username equal to a username a policy subject declares
     is `username_collision`. The declared one is reviewed policy and stands; the directory's
     is the later claimant (spec §2).
4. **The mapping runs once per held connection, at bind, and is pinned.**
   - **Why there.** On the certificate path the session *is* the connection (design §7). The
     listener's per-principal cap, the marks check at bind and every request on the connection
     must agree on one principal.
   - **How.** The bind runs in this order: the certificate checks, the certificate-key mark,
     `Status`, then `Listener.Map`, bounded by `directory.query_timeout`, then `bind`'s
     principal mark. A revoked certificate is answered 401 `credential_revoked` before the
     directory is asked, so a directory outage never turns a revocation into a 503 the agent
     keeps its session on (the invariant at `internal/broker/listen.go:294–297`). `Map` puts
     the principal on the `trackedConn`, and `ConnContext` copies it into the `heldConn`.
     `authenticate` reads it from there.
   - **Marks made before the directory.** A certificate with exactly one email SAN had the
     principal `user:` + that SAN before a directory was configured. `bind` also checks
     principal marks against that legacy principal, so turning a directory on never lifts a
     revocation made by principal. It only denies more.
   - **What the agent sees.** A mapping refused is answered and closed like `Status`'s
     refusals:
     - 401 `identity_unmapped`, 401 `identity_ambiguous`, 401 `username_collision`;
     - 503 `directory_unavailable` with `Retry-After: 30`, which the agent retries as it does
       `certificate_status_unavailable`, with no session ended.
5. **A principal matches every subject that names it, and their grants compose.**
   - **Spec §5.1** reads "principal → subjects: match by LDAP group membership or any listed
     identity". The grants of every matching subject are unioned, as one subject's grants are
     today.
   - **The subject-level fields compose so as never to weaken any one subject's demand:**
     - `token_ttl` is the least among matching subjects with a grant on the device;
     - `enable` is the mechanism demanding the most proof among those that offer one:
       `token` over `auto` over `none`. A group that says `token` is never answered `auto`
       because another group says `auto`. Escalation is offered when any subject offers it,
       as the grants are unioned.
     - `api:` rights are the union (they act on no device).
   - **The joint check at mint.** A composition of more than one subject is one no load-time
     joint check saw (they run per subject, spec §10). The mint runs the same checks on it
     (`checkDeviceAt`'s body, lifted to a composition). One that fails is denied
     `composition_refused` for that principal on that device alone. It is never a quarantine,
     which would refuse everyone over one person's combination. The refresh revokes a live
     context the same way.
   - **The record.** `policy.subject` stays for one subject. With several, it is omitted and
     the new `policy.subjects` lists them, sorted.
6. **Nested groups are a required choice of three.**
   - **`in_chain`.** `(&{group_filter}(member:1.2.840.113556.1.4.1941:={user DN}))` under
     `groups_base_dn`: AD and Samba AD.
   - **`recursive`.** port49 walks: the groups whose `member` holds the DN, then the groups
     whose `member` holds each of those. Breadth-first, with a visited set (a loop ends at the
     first revisit, said once per loop per hour), and capped at `max_depth` (default 16, 1 to
     64).
     - **The cap.** A walk that reaches it keeps the groups it found and is said and counted
       (`port49_directory_walks_truncated_total`). Truncation only drops memberships, so it
       never grants.
   - **`direct`.** The first step of `recursive` alone. The operator declares the tree flat.
   - **No default.** An absent `nested_groups` is refused at load, naming the three. Design §10
     calls a wrong assumption here "the most common cause of authorization that silently
     fails to apply". L42 measures each mode on both directories.
7. **A group subject's `group:` is a name or a DN, and a name must be unique.**
   - **A DN** (`group:` holding `=`, parsed by `ldap.ParseDN`) matches a membership DN by
     `(*ldap.DN).EqualFold`.
   - **A name** matches a membership group whose `group_name_attribute` (default `cn`) equals
     it, case-insensitively, only if at verification exactly one group under
     `groups_base_dn` has that name. A name two groups share is dropped from every membership
     verified while it is shared.
     - **What the operator sees.** It is said each pre-warm and counted in
       `port49_directory_group_names_ambiguous`. A subject naming it then matches no one.
     - **Why.** Anyone who can create a group anywhere under the base could otherwise name it
       `NetOps-OnCall` and join it. Ambiguity fails closed: a denial of service, never an
       escalation.
   - **`groups_base_dn`** defaults to `base_dn`. The start line recommends the OU only
     directory administrators write.
8. **Binding is one of three mechanisms, always over TLS.**
   - **`external`.** The broker's own client certificate (`tls_cert_file`, `tls_key_file`
     through `keyfile.LoadX509KeyPair`), then `ExternalBind`.
   - **`gssapi`.**
     - **The keytab.** `keytab_file` is read through the new `keyfile.ReadSecret` (owner
       port49's user or root, no group or other bit, no link, at most 1 MiB). It is parsed by
       gokrb5, and its bytes are never logged.
     - **The rest.** `principal` and `krb5_conf`. The SPN is `ldap/{host}` from each server's
       URI.
   - **`simple`.** `bind_dn` and `password_env`: the password from the environment by name,
     as every port49 secret is. It is said at start as the weakest.
   - **TLS.** `ca_file` is required, server names are verified, and `ldap://` needs
     `start_tls: true`. GSSAPI negotiates no SASL security layer, so TLS is its
     confidentiality, and plain LDAP is refused for it as for the others.
   - **Never logged:** the password, the keytab's content, a Kerberos ticket. A bind failure is
     said with the server, the mechanism and the LDAP result code.
9. **The server pool.**
   - **Ranking.** Servers are ranked same-site first, then by `priority` descending, then in
     file order.
   - **Sticky.** The selected server serves every query until a query on it fails with a
     server fault, or its breaker opens.
   - **What a server fault is.** Network errors, timeouts, `busy` (51), `unavailable` (52),
     `unwillingToPerform` (53), `other` (80). Any other LDAP result is the query's answer.
   - **A refused dial or bind is "this server did not answer".** A rotated bind password
     (49), `strongAuthRequired`, `confidentialityRequired`, an expired EXTERNAL certificate or
     a KDC error fails the query over to the next server, and with none answering the query
     is `ErrUnavailable`, so grace applies. A bind refusal is said once per server per hour
     with the mechanism and the result code. A 49 is not a breaker fault (a wrong password
     is not a down server), and it never resets the fault count a health check has built.
   - **One query's timeout is its own.** Each search runs as `SearchAsync` under its own
     context, so a query that times out abandons its own message and leaves the shared
     connection and every other in-flight query alone. An error on a connection the pool
     closed itself is never counted a fault.
   - **Breakers.** Each server's breaker opens after `failure_threshold` consecutive faults
     (default 3). An open server is tried again only by the health check every `probe_interval`
     (60s), never by a query.
   - **Failover within a query.** It goes to the next closed server in rank, within
     `query_timeout` for the whole query.
   - **Health checks.** Every `health_check.interval` (30s), each server is dialled, bound and
     asked for its root DSE within `health_check.timeout` (2s). A pass closes its breaker; a
     fault counts toward opening it.
   - **Failback.** A better-ranked server than the selected one is selected only after it has
     passed every health check for `failback.stability_window` (5m).
   - **Sites.** The broker's site is `site:`, else the environment variable `site_env` names
     (default `PORT49_SITE`), else none. With none, every server ranks by priority alone, said
     at start.
     - **A site crossing** is selecting a server whose site differs from the broker's, or from
       the last selected when crossing back. It is a process-log consistency event naming both
       sites and both servers, counted `port49_directory_site_crossings_total` (design §10:
       "MUST be logged as consistency events").
     - **With no broker site,** a selection whose server's site differs from the previous
       selection's is the crossing, said and counted the same way.
10. **Membership lives in the shared store, sealed, and grace reads it.**
    - **The records.**
      - `mb/<principal>`: sealed, holding the DN, username, group DNs, verified-unique group
        names, the mapping keys it answers to, `verified_at`, server and site;
      - `mk/<sha256(kind, value)>`: the principal a mapping key resolved to. The principal is
        plaintext so a bind can find the record, but it binds nothing on its own: crypt's
        `MembershipByKey` opens `mb/<principal>` and requires the key in its sealed list, so a
        store writer who adds a victim's key to an admin's index entry gets `ErrNotFound`.
    - **Who writes them.** Every successful verification writes both: a bind, a mint, a
      scheduled pass, a pre-warm. The broker's role alone reads or writes them.
    - **A refusal is written too.** When the directory answers `identity_unmapped`,
      `identity_ambiguous` or `username_collision`, a refusal record (`Membership.Refused`,
      sealed, `VerifiedAt` the answer's instant) is written by principal (`Verify`,
      `Current`; and the entry's own principal when another entry holds its value or
      username), and by the searched key (`Map`). It keeps the principal's pin (Ruling 3). It supersedes an older grant-bearing record
      under the same "later `verified_at` wins" rule, on both indexes. Grace treats a refused
      record as nothing stored (`ErrUnavailable`), and a policy pass judges it as no groups.
      Without this, a user deleted from AD at T, refused by the pass at T+5m, would mint from
      grace when the DCs drop at T+10m: the directory answered "no", and grace must never
      overrule it.
    - **One key, one principal.** A key a live record of a different principal still lists is
      not repointed: it is written as an ambiguous marker (`Principal: ""`), which
      `MembershipByKey` answers `ErrNotFound`, so grace refuses that certificate rather than
      pick the last writer.
    - **The grace read has its own budget.** The resolver bounds the pool call by
      `query_timeout` itself, then reads the store on `context.WithoutCancel` with its own
      store timeout, so a DC slower than the request's deadline still reaches grace and is
      never blamed on the store.
    - **The lease** is `max(directory.grace, 24h)`, so a policy reload can judge a context by
      the membership its principal last had, on any replica and after a restart.
    - **Grace.** When no server answers, a bind, a mint or an identity request uses the stored
      membership if `now − verified_at ≤ directory.grace` (default 4h, OR-1). A grace mint:
      - is said once per principal per outage;
      - is counted `port49_directory_lookups_total{outcome="grace"}`;
      - carries `auth.directory.source: "grace"` and `verified_at` on its record.
    - **Past grace,** or with nothing stored: `directory_unavailable`, 503 on the request, and
      nothing minted.
    - **Why the store.** A process-memory cache would deny every operator a broker restart
      catches in a directory outage. It would also let two replicas answer one principal
      differently, and it would leave a policy reload with nothing to judge a restarted
      replica's contexts by.
11. **A grace mint never resets the staleness clock.**
    - **The token** carries `VerifiedAt`, the membership's verification instant.
    - **The login** writes the context's `refreshed_at` as the earlier of that and now.
    - **Why.** Otherwise a mint at hour 3 of a directory outage would hand a fresh session
      another full ceiling on membership verified three hours ago.
    - **A join** takes the joining login's, as it does today (`store.Join`).
12. **The scheduled refresh.**
    - **When.** Every `broker.refresh_interval` (default 5m, 1m to 1h), on the runner (or in
      a port49d with a broker inside), whether or not anything changed.
    - **Which principals.** Only `user:` principals are verified against the directory. A
      machine principal (`spiffe://`, `system:serviceaccount:`, `app:`) is judged as
      `policy.MemberOf(principal)` and stamped with the pass's instant, as without a directory;
      the directory holds no entry for it, and `identity_unmapped` would revoke every one.
    - **The policy is held.** Per principal, the pass takes `pol, release := b.Policy.Hold()`
      around judging and writing, as the existing passes do, so a reload in between never has
      a superseded policy written over its own.
    - **What it does per principal** in `ActivePrincipals`:
      - **Verifies.** `Resolver.Verify`, which searches by `principal_attribute`, fresh, never
        grace.
      - **On success,** it writes the membership and judges each of the principal's contexts
        against the policy in force with that membership, as a policy refresh does. A changed
        context is written by `SetContextPolicy` with `RefreshedAt` set; an unchanged one is
        stamped by `StampRefreshed`. Both are compared on `PolicyRev`, so a login that landed
        between the read and the write is read again.
      - **On a fault,** the principal's contexts are left untouched and unstamped, counted
        `unverified`, and said once per outage.
      - **The entry gone** (`identity_unmapped`), **two entries** (`identity_ambiguous`), or
        **a username taken** (`username_collision`): every context of the principal is
        revoked, with a `refresh` deny record under that reason, and the refusal is written
        to the store (Ruling 10).
      - **Tokens.** The unspent tokens of every principal the pass narrowed or revoked are
        superseded, as a policy refresh supersedes those of the principals it changed.
    - **The stamp** is the membership's `VerifiedAt`.
    - **Without a directory,** the pass judges on the policy alone and stamps the pass's
      instant. A live broker is what the ceiling's "broker unreachable" half asks for.
    - **A policy-reload pass** (4b's) never stamps (4b: "nothing about the directory was
      re-verified"). It judges with the stored membership. A principal with no stored
      membership, a refused one, or one verified longer ago than `directory.grace`, is
      judged with no groups, which can only remove grants (fail closed): a reload that adds a
      grant to a group during a 20h outage never writes it into contexts of members last
      verified 20h ago.
    - **Superseded tokens reach group members.** A policy refresh supersedes unspent tokens
      over the identity-declared principals and every principal holding a membership record
      (`store.MembershipPrincipals`), so a reload withdrawing a group's grant leaves no member's
      token redeemable.
13. **Rights and identity through groups.**
    - **Rights.** `HasRightOf(member, right)` is the union over every matching subject.
      `revoke_others` and `explain_others` held through a group work for its members, from the
      membership verified at that request (grace included).
    - **Revoking one's own never needs the directory.** A `POST /v1/revoke` naming only the
      caller's own principal (`mine`) never asks the resolver; the membership is looked up only
      when the request names another principal or a key. A user can always revoke themselves.
    - **Machine principals** (`spiffe://`, `system:serviceaccount:`, `app:`) are never sent to
      the directory: their member is `policy.MemberOf(principal)`.
    - **`GET /v1/identity`** answers the subjects, the group names and DNs that matched, the
      username, and the membership's `verified_at` and source.
14. **`session.staleness_ceiling` defaults to 4h (OR-1), with an explicit `0s` to disable it.**
    - **Disabling.** `0s` is said at every start: `the staleness ceiling is off
      (session.staleness_ceiling: 0s): a live session keeps its access while the broker or
      the directory is unreachable, for as long as that lasts`.
    - **The lab says `0s`.** The lab's seeded contexts are judged by no broker, so
      `tests/lab/port49d-lab.yaml` sets `session.staleness_ceiling: 0s` explicitly, with a
      comment saying why. The authorizer's check is unchanged.
    - **One process.** Where port49d runs a broker inside (port49d's load, `RoleDaemon` with
      `broker:` set), the load refuses a `refresh_interval` above half the ceiling, and a
      `directory.grace` above the ceiling. A grace mint past the ceiling would mint a context
      that is stale at its first command. port49-broker's load shares the schema
      (`LoadBroker`) but never applies the ceiling, so these checks never run there: a split
      deployment with grace 8h loads.
    - **Design §9's "MUST be explicit configuration"** is amended (Task 1): the ceiling
      defaults to 4h, `0s` disables it, and either is said at every start.
    - **The split deployment.** The two values are in two files, so they are compared by
      neither process. The port49-broker start line states its own values so an operator can.
15. **The diff gates a changed `group:`.**
    - A subject whose `group:` changed fails `port49 policy diff` unless a passing session test
      naming that subject asserts the access it resolves to. That is the acknowledgement a
      changed username has (spec §12). Who holds a group subject's access is the group.
    - A new group subject is gated as a new subject's principals are.
16. **A directory-derived username never meets a declared human one.**
    - **With a directory** (`policy.Env.Directory` `DirectoryOn`), a `user:` identity subject
      declaring `username:` is refused at the broker's load: `the directory supplies human
      usernames; remove username`. A principal's username is the directory's.
    - **Without one** (`DirectoryOff`), it is required, as today.
    - **The offline tools and the inventory service** load with `DirectoryUnknown` and accept
      both.
17. **Group subjects with no directory mint for no one, and the start says so,** naming them.
    The policy still loads, so a config change alone turns them on.
18. **What is never logged.** The bind password, the keytab, a Kerberos ticket, an LDAP
    server's message beyond `printsafe.Line`'s 300 bytes, and a certificate value the mapping
    found unprintable.
    - **What may be logged.** A principal, a DN and a group DN are identity, not secrets, and
      may be logged. Each is passed through `printsafe.Line`: a DN is attacker-influenced text
      when someone else can write the directory.
19. **The metrics.** No label names a device or a principal. `server` is the configured URI, a
    bounded set.
    - `port49_directory_queries_total{server,outcome}`: `ok`, `fault`, `error`, `refused` (a
      dial or bind the server refused without a fault).
    - `port49_directory_server_up{server}`: 1 while its breaker is closed.
    - `port49_directory_selected{server}`: 1 for the sticky selection.
    - `port49_directory_site_crossings_total`.
    - `port49_directory_lookups_total{outcome}`: `fresh`, `grace`, `unavailable`, `unmapped`,
      `ambiguous`, `collision`.
    - `port49_directory_walks_truncated_total`.
    - `port49_directory_group_names_ambiguous`.
    - `port49_directory_prewarm_principals`, and
      `port49_directory_prewarm_last_success_timestamp_seconds`.
    - `port49_directory_refresh_last_complete_timestamp_seconds`: the last scheduled pass that
      verified every active principal. Alert on `time() - it > 3 × refresh_interval`.
    - `port49_context_refreshes_total{outcome}` gains `unverified`.
20. **Pre-warm.**
    - **When.** Every `directory.prewarm.interval` (default 1h; `0s` off, said), on the runner,
      starting 30s after it takes the keyspace.
    - **The population.** The members of every group a policy group subject names, each
      enumerated under the nested mode:
      - `in_chain`: `(memberOf:1.2.840.113556.1.4.1941:={group DN})` under `base_dn`;
      - `recursive`: a downward walk of `member` with the same visited set and cap;
      - `direct`: the group's `member` values.
    - **Each member** is verified and written with every mapping key its entry answers to:
      - `issuer_serial`: each `altSecurityIdentities` value;
      - `sid`: `objectSid`;
      - `san_upn`, `san_email`: the attribute's values;
      - `subject_dn`: its DN;
      - `cn`: its `cn`.
    - **The bound.** At most `prewarm.max_principals` (default 10000, said if reached). One
      query at a time, on the sticky server.
    - **What it buys.** An operator who has never logged in before can log in during an outage
      within grace (design §10).

### Open for Ryan

Execution proceeds on each recommendation unless Ryan rules otherwise. Task 19 records the
answer.

**OR-1. The defaults: `session.staleness_ceiling` 4h, `directory.grace` 4h,
`broker.refresh_interval` 5m.**
- **Why it matters at 3am.** When the directory, or every broker, has been unreachable longer
  than the ceiling, every live token session's next command is denied `context_stale`. That is a
  FAIL from a reachable port49, so break-glass does not help on a session already open (L4: only
  an unreachable port49 lets break-glass in). New logins are refused once grace passes too.
- **For shorter (1h).** A removal from a group made on a directory the broker cannot reach
  takes effect within the hour. Today, until something calls the refresh, the ceiling is off,
  which is "never".
- **For longer (12h or more).** A long DC outage, or a broker left down overnight, does not
  deny everyone at the ceiling. Revocation by `port49 revoke` (marks) works throughout, needs
  no directory, and reaches a session at its next command; the ceiling governs only
  directory-driven changes and broker outages.
- **Recommended:** 4h, 4h and 5m. It is half a working shift, many multiples of the refresh, and
  long enough for a DC fix or a broker restart, while a directory removal still lands the same
  day. `0s` stays available, said at every start.
- **Not taken:**
  - 1h, where one long DC maintenance window denies the fleet;
  - 24h, where a removal in an outage waits a day.
- **The runbook line (Task 19's operator notes, and the spec's alerting paragraph).** At the
  ceiling, live sessions deny `context_stale` from a reachable port49d, so break-glass does
  not help on them. The 3am escapes: set `session.staleness_ceiling: 0s` and restart port49d,
  or stop port49d so devices fall back to break-glass (L4). Alert at half the ceiling,
  `time() - port49_directory_refresh_last_complete_timestamp_seconds > ceiling / 2`, so the
  page comes two hours before the fleet denies.
- **The upgrade order.** Upgrade every broker before port49d. A new port49d (4h default)
  beside an old broker that never stamps `refreshed_at` denies every session 4h after its
  login. An operator who cannot order the upgrade sets `session.staleness_ceiling: 0s` on
  port49d until the brokers are new, then removes it.

**OR-2. GSSAPI through go-ldap's `gssapi` package and gokrb5 v8.**
- **What it adds.** Pure Go, no cgo. It brings about eight modules: `jcmturner/gokrb5/v8`,
  `aescts`, `dnsutils`, `gofork`, `goidentity`, `rpc`, and `hashicorp/go-uuid`. go-ldap itself
  requires them, so they are in `go.sum` either way, and they are linked only by the `gssapi`
  import.
- **The alternative:** ship EXTERNAL and simple now, and GSSAPI later. That cuts a mechanism
  design §10 names as "usually the easiest to get approved" in AD shops.
- **Recommended:** take it, behind the config's choice. L43 measures it against Samba's KDC.

**OR-3. Windows Server AD is its own register row, L44, open until measured.**
- **What the lab can measure.** beehive runs Linux containers. Samba 4 implements
  `LDAP_MATCHING_RULE_IN_CHAIN`, `altSecurityIdentities`, `objectSid` and an AD-compatible KDC.
  L42 and L43 name OpenLDAP and Samba AD as their platforms, and close on those two alone.
- **What it cannot.** It does not prove a Windows DC's behaviour: `in_chain` on a real DC,
  EXTERNAL's certificate mapping, GSSAPI against a Windows KDC, `altSecurityIdentities`
  matching port49's `X509:<I><SR>` form, or KB5014754's strong-mapping enforcement.
- **So the Windows half is its own row.** Task 1 opens **L44** (Platforms: Windows Server AD)
  for exactly those claims. Decision 38's `in_chain`, `issuer_serial`/`sid` and bind bullets
  stay "provisional on L44" for Windows Server AD after L42 and L43 close (CLAUDE.md lab
  rules 2 and 3). No doc asserts a Windows DC's behaviour from the Samba measurement.
- **Recommended:** run L44 on a Windows Server evaluation VM on the SER8 lab box before beta,
  as a register measurement, not a plan. Until then the AD-only mechanisms ship, said as
  measured on Samba AD only, and the operator notes say so.

**Worth reading before the merge** (rulings, not open questions):
- **Ruling 5.** Several subjects compose. A principal in two groups can hold a combination no
  load-time check saw, and the mint checks it (`composition_refused`).
- **Ruling 7.** A `group:` name two groups share matches no one. A deployment whose groups
  repeat names must use DNs.
- **Ruling 10.** Membership is in the store, sealed. Group lists are confidential to the
  broker's etcd role, and port49d's role cannot read them (`CheckIdentity` probes it).
- **Ruling 12.** A principal the directory stops answering for is never revoked by the
  scheduled pass. Only the ceiling ends its sessions.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **A broker start with a directory** (Task 16):

  ```
  port49-broker: directory: 3 servers (ldaps://dc-01.corp.example.com us-west 100, ldaps://dc-02.corp.example.com us-west 90, ldaps://dc-03.corp.example.com us-east 50); this broker's site is us-west (PORT49_SITE); bind gssapi as port49$@CORP.EXAMPLE.COM
  port49-broker: directory: certificates map by issuer_serial (strong) through altSecurityIdentities; principal from userPrincipalName, username from sAMAccountName; nested groups in_chain under OU=port49-groups,DC=corp,DC=example,DC=com
  port49-broker: directory: userPrincipalName and sAMAccountName must be writable only by directory administrators: two entries holding one value are both refused (identity_ambiguous, username_collision) until it is fixed
  port49-broker: directory: grace 4h0m0s; pre-warm every 1h0m0s; the scheduled refresh every 5m0s stamps refreshed_at (port49d's session.staleness_ceiling denies a session past it)
  port49-broker: directory: selected ldaps://dc-01.corp.example.com (us-west, priority 100)
  ```

  With a simple bind:

  ```
  port49-broker: directory: bind simple as CN=port49,OU=svc,DC=corp,DC=example,DC=com: the weakest of the three (design §10); a password in PORT49_LDAP_PASSWORD
  ```

  With no directory and group subjects in the policy:

  ```
  port49-broker: policy: 2 group subjects (netops_oncall, netops_ro) mint for no one: no broker.directory is configured
  ```
- **A server fails over** (Task 6):

  ```
  port49-broker: directory: ldaps://dc-01.corp.example.com: 3 faults in a row (the last: dial tcp 10.0.0.11:636: i/o timeout); its breaker is open; probed every 1m0s
  port49-broker: directory: selected ldaps://dc-02.corp.example.com (us-west, priority 90)
  ```

  and crossing sites:

  ```
  port49-broker: directory: consistency event: crossing from site us-west to us-east (ldaps://dc-02.corp.example.com to ldaps://dc-03.corp.example.com); membership read there may lag replication from us-west
  ```

  and a bind the server refuses (Task 6), once an hour per server:

  ```
  port49-broker: directory: ldaps://dc-01.corp.example.com refused the bind (gssapi): LDAP Result Code 49 "Invalid Credentials": bind gssapi as port49$@CORP.EXAMPLE.COM refused (LDAP result 49); queries fail over, and with no server answering a membership verified within directory.grace serves
  ```

  and back after the window:

  ```
  port49-broker: directory: ldaps://dc-01.corp.example.com passed every health check for 5m0s (failback.stability_window); selected again
  ```
- **No server answers** (Tasks 10, 13):

  ```
  port49-broker: directory: no server answered (the last: ldaps://dc-03.corp.example.com: LDAP Result Code 52 "Unavailable"); minting from memberships verified within 4h0m0s (directory.grace)
  port49-broker: directory: user:alice@corp.example.com minted from a membership verified 1h12m ago (grace)
  ```

  and for someone the directory refused before it stopped answering (Task 10), as an error the
  mint's 503 carries, never a grace mint:

  ```
  directory: no server answered: the directory refused user:mallory@corp.example.com at 2026-10-05T09:12:00Z, before it stopped answering; grace never overrules a refusal
  ```

  and once grace has passed for someone:

  ```
  port49-broker: directory: user:bob@corp.example.com: no server answered and the membership stored was verified 4h3m ago, past directory.grace (4h0m0s); refused directory_unavailable
  ```
- **The scheduled refresh in an outage** (Task 15):

  ```
  port49-broker: refresh: the directory did not answer for 14 principals; their 31 contexts keep their last verification (oldest 1h50m ago) and deny context_stale past port49d's session.staleness_ceiling
  ```
- **An ambiguous certificate** (Task 8), once per key per hour:

  ```
  port49-broker: directory: identity_ambiguous: a certificate (issuer CN=Corp Users CA, serial 3a9f…) maps by san_email to 2 entries (CN=Alice Smith,OU=Staff,…; CN=Alice Smith,OU=Contractors,…); refusing it: two people matching one certificate is an impersonation path (design §7)
  ```
- **A principal claimed by another entry** (Task 10), once per principal per hour. A rehire
  or a restored entry reads the same way, with the same DN:

  ```
  port49-broker: directory: identity_unmapped: user:alice@corp.example.com is pinned to entry guid:0a1b2c3d and is now claimed by CN=Alice Smith,OU=Staff,DC=corp,DC=example,DC=com (guid:9f8e7d6c); a userPrincipalName value moved between entries never carries a principal with it (Ruling 3); if this is the same person's entry re-created (a rehire, a restore), confirm that and run `port49 directory forget user:alice@corp.example.com` against the broker's admin_socket
  ```

  and the escape (Task 13), printed by `port49 directory forget` and logged by the broker:

  ```
  forgot user:alice@corp.example.com: it was pinned to entry guid:0a1b2c3d (CN=Alice Smith,OU=Staff,DC=corp,DC=example,DC=com), last verified 2026-10-05T09:12:00Z; its next verification pins the entry the directory gives it then
  port49-broker: directory: admin_socket uid 0 forgot user:alice@corp.example.com, pinned to entry guid:0a1b2c3d (CN=Alice Smith,OU=Staff,DC=corp,DC=example,DC=com)
  ```
- **New config refusals** (Task 4; the one-process checks, Task 15):
  - `broker.directory.nested_groups is required: in_chain (Active Directory), recursive (port49 walks member) or direct (the groups are flat); design §10`;
  - `broker.directory.certificate_mapping.kind san_email is a weak mapping: set allow_weak: true and list the issuers it is pinned to (design §7)`;
  - `broker.directory.servers[0].uri ldap://dc-01:389: plain LDAP is refused; use ldaps:// or set start_tls: true`;
  - `broker.directory.bind.mechanism is required: external, gssapi or simple`;
  - `broker.directory.grace 5h0m0s: above session.staleness_ceiling (4h0m0s), a grace mint would be stale at its first command` (one process only);
  - `session.staleness_ceiling is off (0s)` is a start line, not a refusal.
- **New metrics:** Ruling 19.

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, **no cgo**.
  GSSAPI is gokrb5 (pure Go).
- snake_case everywhere it is data: YAML keys, JSON log keys, config, metric names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). This plan adds
  four: `identity_unmapped`, `identity_ambiguous`, `directory_unavailable`,
  `composition_refused`. Task 1 adds them to the spec table first; Task 2 adds the constants.
- The log never contains a token, password, challenge or response. Credentials appear only as
  `credential_sha256`. An unvalidated body is never logged.
  - **The directory's secrets:** a bind password, a keytab's bytes and a Kerberos ticket are
    never formatted into any line, record or error. Each secret-bearing type has a `String`
    method that withholds it (Task 7's test).
- No device identity in metric labels. No principal in metric labels.
- **Fail closed, never widen:**
  - an ambiguity (two entries, a shared username, a shared group name) never grants;
  - a directory outage never adds a grant, and never resets the staleness clock;
  - a truncated walk only drops groups.
- The daemon never speaks to the directory.
- Verify with `make test && make vet` and report the real output. Every test that speaks to a
  real directory is a lab test (`//go:build lab`, Tasks 17 and 18, `make lab-directory`, on
  beehive), so `go test ./...` needs no LDAP server: the unit tests run on `fakeDir`.
- **Deployment is not prescriptive.** Nothing requires a directory; without one, 7f's behaviour
  is unchanged except the ceiling's new default (Ruling 14).
- **Readiness never follows the directory** (design §10, §12). No task adds a directory or
  breaker condition to `/readyz`; Task 16 pins it.
- **A refusal is never overruled by grace** (Ruling 10), and **a principal is unique to one
  DN** (Ruling 3). A self-editable attribute can refuse people; it can never make one person
  another.
- The lab register rules (CLAUDE.md 1–4). L42, L43 and L44 open in Task 1. L42 and L43 close
  in Task 17 (the lab run) on OpenLDAP and Samba AD, the platforms they name, only if their
  notes exist with platform, image version, observation and a capture pointer. L44 (Windows
  Server AD) stays open.
- Conventional Commits; commit messages end with
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc`.

## Review Focus

The seven inputs or conditions no task's tests exercise by accident and most likely to bite a
person, with the test that pins each:

1. **A certificate whose mapped value is a filter metacharacter string** (`*`, `)(`, a NUL, a
   backslash). The operator expects it to match nothing, or exactly its literal entry, never
   every user. Pinned by Task 8's `TestAMappedValueIsEscapedInTheFilter` and
   `TestAnObjectSidIsEscapedByteByByte`.
2. **One DC slow, not down** (answers after `query_timeout`, then answers the health check in
   time). The operator expects the query to fail over within `query_timeout`, the breaker to
   open after `failure_threshold` such queries, and selection not to bounce back until
   `stability_window` passes. Pinned by Task 6's `TestASlowServerFailsOverWithinTheQueryTimeout`
   and `TestFailbackWaitsForTheStabilityWindow`.
3. **A group loop and a deep chain under `recursive`.** The operator expects the walk to end,
   keep what it found, and say so. Pinned by Task 9's `TestARecursiveWalkEndsOnALoop` and
   `TestAWalkAtMaxDepthKeepsWhatItFound`.
4. **A broker restarted during a directory outage.** The operator expects a principal verified
   within grace to log in from the stored membership, and one past grace to be refused
   `directory_unavailable`, never minted. Pinned by Task 10's
   `TestGraceReadsTheStoreAfterARestart` and Task 13's `TestAMintPastGraceIsRefused`.
5. **A login redeemed from a grace mint.** The operator expects the context's `refreshed_at` to
   be the membership's verification time, so the ceiling counts from then. Pinned by Task 3's
   `TestALoginTakesTheTokensVerifiedAt` and Task 16's
   `TestAGraceMintsSessionGoesStaleFromItsVerification`.
6. **A user who edits their own `mail` to a colleague's.** The operator expects neither to be
   the other: both are refused `identity_ambiguous` while the values collide. Pinned by Task
   8's `TestAPrincipalTwoEntriesHoldIsAmbiguous` and Task 10's
   `TestAPrincipalOnAnotherEntryIsUnmapped`.
7. **A user deleted from the directory, then the directory goes down.** The operator expects
   the deletion to hold through the outage. Pinned by Task 10's
   `TestARefusedPrincipalIsNotServedFromGrace`.

## Conflict scan: where tasks share a file or an interface

- `internal/store/store.go`: Task 3 (the stamp, `RefreshedAt`, `VerifiedAt`) and Task 5 (the
  membership record). Task 5 builds on Task 3.
- `internal/store/memory/memory.go`, `internal/store/crypt/crypt.go`, `internal/store/etcd/*`,
  `internal/store/guard/guard.go`, `internal/store/storetest/storetest.go`: Tasks 3 and 5, in
  that order.
- `internal/config/config.go`: Task 4 alone (the directory block lives in a new
  `internal/config/directory.go`).
- `internal/daemon/metrics/metrics.go`: Task 6 (pool), Task 10 (lookups), Task 15 (refresh).
- `internal/policy/*`: Task 11 alone.
- `internal/broker/identity.go`, `listen.go`, `server.go`, `broker.go`: Task 12 (bind) and Task
  13 (mint). Task 13 builds on Task 12's `principalOf(r)`.
- `internal/broker/refresh.go`: Task 14 (judging with a member, the report's new fields,
  `count`'s `unverified`) and Task 15 (the scheduled pass, which only calls it). Tasks 14 and
  15 are committed in order on one branch, green after each.
- `internal/directory/fake_test.go`: Task 6 creates it; Task 10 adds `closeAll`.
- `internal/broker/listen.go`'s `bind` and `broker.go`'s `revocation`: Task 12 changes their
  signatures and every caller (tests included) in the same commit.
- `internal/port49d/runner.go`: Task 16 alone. `main.go`, `brokerd.go`: Task 13 sets the
  admin socket's `Forget` (one field each, beside `Revoke`), and Task 16 builds the directory.
  Task 16 builds on Task 13.
- `internal/decision/log.go`, `reasons.go`: Task 2 (reasons, `Policy.Subjects`,
  `Auth.Directory`) and Task 13 (`EventDirectoryForget`, `Record.Forget`), in that order.
- `internal/store/*`: Task 5's `DeleteMembership` is the op Task 13 calls; nothing else calls
  it.
- Spec §5.7, §13, §15: Task 1 writes them; Task 17 closes the rows (a docs commit in that task).

## Running the lab (Tasks 17 and 18)

- On beehive, from a pinned worktree of the branch at the commit under test. Copy any raw
  captures to `main`'s `tests/lab/captures/` before removing the worktree (the labpcap audit).
- Run a background stall watchdog during each run, and re-arm it on wake.
- Before a run: `df -h` and `sg docker -c 'docker compose version'` (≥ v2.24.4).
- Docker is reached as `sg docker -c '…'` on beehive. The lab's Go tests call `docker` through
  a `dockerCmd` helper that prefixes it.

## File Structure

**Create:**
- `internal/directory/doc.go`: the package comment (what speaks LDAP, and what never does).
- `internal/directory/config.go` (+ `config_test.go`): `Config`, `Server`, `Mapping`, the
  resolved defaults.
- `internal/directory/pool.go` (+ `pool_test.go`): `Pool`, ranking, breakers, failback, sites.
- `internal/directory/conn.go` (+ `conn_test.go`): `Conn`, `Dial`, the three binds, `String`s
  that withhold.
- `internal/directory/mapping.go` (+ `mapping_test.go`): the six kinds, the issuer pin, AD's
  issuer-serial form, the SID extension, filter escaping, `MapKey`.
- `internal/directory/entry.go` (+ `entry_test.go`): one entry by filter, principal and
  username derivation, the username's uniqueness.
- `internal/directory/groups.go` (+ `groups_test.go`): the three nested modes, the walk, group
  name uniqueness.
- `internal/directory/resolver.go` (+ `resolver_test.go`): `Resolver`: `Map`, `Verify`,
  `Current`, `Stored`, grace.
- `internal/directory/prewarm.go` (+ `prewarm_test.go`): `Prewarm`.
- `internal/directory/fake_test.go`: an in-memory `Searcher` the unit tests share.
- `internal/directory/static.go`: `ForTestsStaticResolver`, a resolver answering from a map, never for production; for
  the broker's and port49d's tests (Task 12).
- `internal/config/directory.go` (+ `directory_test.go`): `broker.directory`, its checks.
- `internal/store/storetest/membership.go`, `stamp.go`: the new properties.
- `internal/store/etcd/membership.go`: `mb/`, `mk/`.
- `internal/broker/member.go` (+ `member_test.go`): `BindMap`, `directoryRefusal`, `memberFor`,
  `directoryAuth`, the pinned principal.
- `internal/broker/scheduled.go` (+ `scheduled_test.go`): `RefreshDirectory`.
- `internal/broker/forget.go` (+ `forget_test.go`): `Forget`, Ruling 3's escape.
- `cmd/port49/directory.go` (+ `directory_linux_test.go`): `port49 directory forget`.
- `internal/port49d/directory.go` (+ `directory_test.go`): building the resolver, the start
  lines, the scheduled and pre-warm loops.
- `tests/lab/directory/openldap/` (`Dockerfile`, `config.ldif`, `seed.ldif`, `entrypoint.sh`),
  `tests/lab/directory/samba/` (`Dockerfile`, `entrypoint.sh`, `seed.sh`),
  `tests/lab/directory/compose.yaml`: the two directories.
- `tests/lab/compose/directory.yaml`: the compose overlay for the end-to-end run.
- `tests/lab/directory_test.go`, `l42_test.go`, `l43_test.go`, `directory_e2e_test.go`:
  `//go:build lab`.

**Modify:**
- `go.mod`, `go.sum`: go-ldap, gokrb5.
- `Makefile`: `lab-directory` (Tasks 17 and 18's runs).
- `internal/decision/reasons.go`, `log.go`: four reasons, `Policy.Subjects`, `Auth.Directory`;
  the `directory_forget` report (`EventDirectoryForget`, `Forget`).
- `internal/broker/api/identity.go`: `Subjects`, `Username`, `GroupDNs`, `VerifiedAt`,
  `Source`.
- `internal/store/store.go`, `apply.go`, `memory/memory.go`, `crypt/crypt.go`,
  `etcd/contexts.go`, `etcd/records.go`, `etcd/keys.go`, `etcd/roles.go` (`mb/` and `mk/` in
  `daemonNever`, and their probes; the broker's role already spans the keyspace),
  `etcd/roles_test.go` (the daemon refused `mb/` and `mk/`), `guard/guard.go`,
  `storetest/storetest.go`.
- `internal/keyfile/keyfile.go`: `ReadSecret`.
- `internal/token/minter.go`: `Subject.VerifiedAt` onto the token.
- `internal/daemon/authen/authen.go`: `loginContext`'s `RefreshedAt`.
- `tests/lab/port49d-lab.yaml`: `session.staleness_ceiling: 0s`.
- `internal/config/config.go`: `Broker.Directory`, `Broker.RefreshInterval`, the ceiling's
  default, the one-process checks.
- `internal/policy/load.go`, `resolve.go`, `scope.go`, `explain.go`, `diff.go`: `Member`,
  composition, `Env.Directory`, the gate.
- `internal/broker/identity.go`, `listen.go`, `server.go`, `broker.go`, `identity_api.go`,
  `explain_api.go`, `revoke_api.go`, `refresh.go`, `sessionrefresh.go`, `reindex.go`.
- `internal/daemon/metrics/metrics.go`.
- `internal/port49d/main.go`, `brokerd.go`, `runner.go`, `revocations.go` (`adminForget`).
- `internal/daemon/admin/admin.go` (+ `admin_test.go`): the `directory_forget` op.
- `cmd/port49/policy.go`: `blobSource` through `ResolveSubjects`.
- `cmd/port49/main.go`: `directory` in the usage and the dispatch.
- `deploy/compose/config/port49-broker.yaml`, `port49d.yaml`, `deploy/compose/README.md`.
- `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`.
- `tests/lab/README.md`, `tests/lab/compose/lab.yaml`.
- `docs/superpowers/plans/README.md`.

---

### Task 1: The spec and the design say what 7g builds, and L42, L43 and L44 open

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §2, §5.1, §5.1.3, §5.7 (reason
  table, record fields), §12 (the diff's group gate), §13 (decision 38), §14 (test
  assertions), §15 (L42, L43, L44)
- Modify: `docs/design/2026-08-21-port49-design.md`: §7, §9, §10, §12

**Interfaces:**
- Consumes: Rulings 1–20 above.
- Produces: the four reason codes' rows (Tasks 2, 8, 10, 11, 13, 15 cite them), decision 38,
  register rows L42 and L43 (Task 17 closes them) and L44 (Windows Server AD; stays open).

- [ ] **Step 1: The reason table (spec §5.7, "Reason codes")**

After the `username_collision` row, add four rows, and widen `username_collision` and
`credential_revoked`:

```markdown
| `username_collision` | `mint`: the derived username is already held by a subject in another trust domain (§2); or the directory derives a username a policy subject declares, or a second directory entry holds the same username under `broker.directory.username_attribute` (§13 decision 38). At the broker's bind and on `refresh` likewise; on `refresh` every context of the principal is revoked. The process log names both claimants |
| `identity_unmapped` | at the broker's bind, and on `mint`, `identity`, `explain` and `revoke`: the client certificate maps to no directory entry under `broker.directory.certificate_mapping`; or the value the mapping reads is not in the certificate (no SID extension; zero or several UPN or email SANs); or a weak mapping's issuer is not one its `issuers:` pins (design §7); or the entry's `principal_attribute` or `username_attribute` is absent, has several values, is not printable ASCII, gives a principal with no `@`, or a username that is not already canonical or is reserved (§2); or the principal it gives is pinned to another entry, by `objectGUID` or `entryUUID` (else DN), for as long as that principal's membership record lives or until an operator runs `port49 directory forget` (§13 decision 38). The API answers 401 and the connection is closed. On `refresh`: the principal's entry is gone or no longer usable, and every context of it is revoked |
| `identity_ambiguous` | as `identity_unmapped`, when the certificate maps to two or more entries, or the server refuses the search for its size limit; or when a second entry holds the same `broker.directory.principal_attribute` value as the mapped entry, so two people would share one principal (§13 decision 38). Never resolved to the first entry (design §7). MUST be alertable on its own: two people matching one certificate is an impersonation path. On `refresh`: every context of the principal is revoked |
| `directory_unavailable` | at the broker's bind, and on `mint`, `identity`, `explain` and `revoke`: no directory server answered within `broker.directory.query_timeout`, and the membership the store holds for the principal or the certificate was verified longer ago than `broker.directory.grace`, or there is none (§13 decision 38). Nothing is minted. The API answers 503 with `Retry-After`, to be retried, and no agent session is ended. Never on `refresh`: a principal the directory does not answer for keeps its contexts unstamped, and `context_stale` takes over at the ceiling |
| `composition_refused` | `mint`: the principal matches more than one subject, and their grants together compose on this device to a session reply a joint check refuses (§10): a level above the grants' ceiling, a reply over 255 bytes, an attribute the platform does not accept, or a blob the daemon would refuse. Refused for this principal on this device alone, never a quarantine. On `refresh`: the live context is revoked the same way. The process log names the subjects and the check |
```

In `credential_revoked`'s list of causes, after "a subject's username changed", add "the
principal's directory entry gone, ambiguous or renamed to a username another holds, their
subjects' composition refused". In the paragraph after the table, add: "`identity_ambiguous`
MUST be alertable on its own, as `credential_revoked` is; a rise in `directory_unavailable`
means no directory server has answered for longer than `broker.directory.grace` for someone.
Alert at half the ceiling, `time() - port49_directory_refresh_last_complete_timestamp_seconds >
session.staleness_ceiling / 2`: at the ceiling every live session denies `context_stale` from a
reachable port49d, and the escapes are `session.staleness_ceiling: 0s` with a port49d restart,
or stopping port49d so break-glass applies (L4)."

- [ ] **Step 2: The record fields (spec §5.7, "Events")**

Where the `policy` object's fields are listed, add:

```markdown
- `policy.subjects`: on `mint`, `refresh`, `identity` and `explain`, when the principal matches more than one subject, every one of them, sorted; `policy.subject` is then absent. With one subject, `policy.subject` alone, as before (§13 decision 38).
```

Where the `auth` object's fields are listed, add:

```markdown
- `auth.directory`: on a broker event decided with a directory membership, `{source, verified_at, server, site}`: `source` is `fresh` (read from a directory server for this request) or `grace` (the store's, verified at `verified_at`, no server answering); `server` and `site` are where it was read. It names no group: `policy.subjects` says which subjects matched.
```

In the events intro, "plus four report events (`account`, `account_gap`, `blob`,
`inventory_change`)" becomes "plus five report events (`account`, `account_gap`, `blob`,
`inventory_change`, `directory_forget`)". After the `inventory_change` paragraph, add:

```markdown
A fourteenth, `directory_forget`, is a report too: an operator ran `port49 directory forget <principal>` on the broker's admin socket, deleting the principal's directory membership and with it the entry the principal was pinned to (§13 decision 38) — `{"principal": ..., "forget": {"entry_id": ..., "dn": ..., "verified_at": ..., "refused": true|absent, "origin": "admin_socket uid N"}}`. `verified_at` is the record's last verification or refusal. The principal's next verification pins the entry the directory gives it then, so this record is the trail for a principal moving to another entry by an operator's hand.
```

- [ ] **Step 3: Subjects, plural (spec §2 and §5.1)**

In §2, after "it has exactly two forms — an LDAP group, or one or more literal identities",
add:

```markdown
A group is named by its name (the entry's `broker.directory.group_name_attribute`, `cn` by
default), matched only while exactly one group under `broker.directory.groups_base_dn` has it,
or by its DN. A principal matches every subject whose group it is in, transitively under
`broker.directory.nested_groups`, and the one identity subject that lists it, if any; the
grants of all of them compose (§5.1; §13 decision 38).
```

In §2's principal table, replace the human x509 row's cell with "`user:` + the entry's
`principal_attribute` (default `userPrincipalName`), lower-cased, from the certificate-to-directory
mapping (design §7); without `broker.directory`, `user:` + the certificate's one email SAN".
In "The device-facing username", after the identity-path table, add: "With
`broker.directory`, a `user:` identity subject declares no `username:`; the broker refuses
one at load. Without it, one is required, as before plan 7g."

In §5.1, after the composition paragraph about `max_privilege`, add:

```markdown
**Several subjects compose.** A principal in two groups, or listed by an identity subject and
in a group, holds the union of their grants, as one subject's grants compose. What a subject
declares for itself composes so as never to weaken any one subject's demand: `token_ttl` is
the least, among the matching subjects with a grant on the device; `enable` is the mechanism
demanding the most proof among those that offer one (`token`, then `auto`, then `none`); `api:`
rights are the union. The joint checks of §10 run per subject at load; a composition of more
than one subject is checked at mint, and one a check refuses is `composition_refused` for that
principal on that device (§13 decision 38).
```

- [ ] **Step 4: The scheduled refresh (spec §5.1.3)**

Replace the sentence "The directory-driven scheduled refresh through `active_principals` is
plan 7's." with:

```markdown
**The scheduled refresh** (plan 7g; §13 decision 38) runs every `broker.refresh_interval`
(default 5m) on the broker holding the keyspace. For each principal in `active_principals` it
reads the principal's directory entry and groups again, from a server, never from grace; judges
each live context against the policy in force with that membership, writing as a policy refresh
does; and stamps `refreshed_at` with the membership's verification time on every context it
judged, changed or not. A principal the directory did not answer for is left as it is and
unstamped, counted `unverified` in `port49_context_refreshes_total`, and its sessions deny
`context_stale` once `session.staleness_ceiling` passes (§5.1.1). A principal whose entry is gone
or ambiguous has every context revoked. Without `broker.directory`, the pass judges against the
policy alone and stamps its own instant: the ceiling then bounds a broker outage. A policy
refresh never stamps `refreshed_at`, and judges a group member by the membership last verified
(held in the store; design §12), or by no groups where none is held, where the directory refused
the principal, or where it was verified longer ago than `broker.directory.grace`: a policy
refresh can narrow on an old membership, never widen.
```

In §5.1.1, replace "`refreshed_at` is written at creation and on every refresh." with
"`refreshed_at` is written at creation (the membership's verification time, on a directory
login) and on every scheduled refresh that verified the membership (§5.1.3); a policy refresh
never writes it."

Add rows to the refresh's record table:

```markdown
| revoked it: the principal's directory entry is gone, or no longer gives a usable principal or username | `deny` | `identity_unmapped` |
| revoked it: the principal now maps to two or more entries | `deny` | `identity_ambiguous` |
| revoked it: another entry, or a declared subject, now holds the principal's username | `deny` | `username_collision` |
| revoked it: the principal's subjects compose on the device to a reply a joint check refuses | `deny` | `composition_refused` |
```

and, below the table: "A scheduled pass that stamps `refreshed_at` on a context whose answer did
not change writes no record."

Add `unverified` to the list of `port49_context_refreshes_total`'s outcomes.

- [ ] **Step 5: The diff's gate (spec §12)**

Replace "A subject's `group:` changing is reported; group subjects mint for no one until the
directory arrives (plan 7), and the gate on them is that plan's." with: "A subject's `group:`
changing fails the gate unless a passing session test naming that subject asserts the access it
resolves to, as a changed `username:` does: who holds a group subject's access is the group (§13
decision 38)."

- [ ] **Step 6: Decision 38 (spec §13)**

After decision 37, add decision 38. Heading: `**38. The directory: one entry per certificate or
no principal, membership kept in the store, every matching subject composes, and a scheduled
refresh stamps refreshed_at.** *Plan 7g, 2026-10-05.*` Then one bullet per Ruling 1–20 of this
plan, in the plan's words, each ending with the task that builds it. Its first line states the
defaults OR-1 asks about, "provisional on Ryan's answer to OR-1". The nested-modes bullet ends
"provisional on L42; on Windows Server AD, on L44"; the bind bullet ends "provisional on L43;
on Windows Server AD, on L44"; the mapping bullet's `issuer_serial` and `sid` end "provisional
on L44 (Windows Server AD)". The principal-uniqueness and refusal-record bullets (Rulings 3 and
10) are rulings, not device claims, and are not provisional.

- [ ] **Step 7: The register (spec §15)**

Append:

```markdown
| **L42** | Nested-group resolution, per directory. The fixture: a user three levels below a granted group (`alice` ∈ `g-leaf` ∈ `g-mid` ∈ `netops-oncall`), a loop (`dave` ∈ `g-loop-a` ∈ `g-loop-b` ∈ `g-loop-a`), and a user in the granted group directly (`carol` ∈ `netops-oncall`). For each user: which groups a search under the groups base returns with `member:1.2.840.113556.1.4.1941:=<user DN>` (`in_chain`), whether that search answers, errors or is refused on the loop, and how long it takes; whether the user entry's `memberOf` lists only its direct groups; what port49's `recursive` walk and `direct` read return; and whether a directory that does not implement the matching rule refuses the filter or answers it empty. | `broker.directory.nested_groups` and its three modes (§13 decision 38); design §10's "`memberOf` is not transitive" | OpenLDAP (slapd 2.5, `memberof` overlay), Samba AD (4.17) | open — added 2026-10-05 (plan 7g) |
| **L43** | Which bind mechanisms each directory accepts from port49-broker, and how each refusal reads: SASL EXTERNAL over LDAPS with a client certificate (OpenLDAP mapping it by `olcAuthzRegexp`); GSSAPI with a keytab and no SASL security layer, over LDAPS (Samba AD's KDC); simple bind over LDAPS; and a simple bind over plain LDAP to a directory configured to require TLS. | `broker.directory.bind` (§13 decision 38); design §10's three mechanisms | OpenLDAP (EXTERNAL, simple), Samba AD (EXTERNAL, GSSAPI, simple) | open — added 2026-10-05 (plan 7g) |
| **L44** | The Active Directory claims on a Windows DC: on L42's fixture and its loop, which groups `member:1.2.840.113556.1.4.1941:=<user DN>` returns and how the loop is answered; SASL EXTERNAL over LDAPS with a client certificate; GSSAPI with a keytab and no SASL security layer against the Windows KDC; whether `altSecurityIdentities` values written in port49's `X509:<I>{issuer}<SR>{serial}` form (issuer from the raw DER, `DC=` included) match the certificate the DC itself maps; whether the SID extension's value equals `objectSid`; and how KB5014754's strong-mapping enforcement treats each. | `broker.directory.nested_groups: in_chain`, the strong mappings `issuer_serial` and `sid`, and `broker.directory.bind` on AD (§13 decision 38, provisional on this row) | Windows Server AD | open — added 2026-10-05 (plan 7g); for the SER8 lab box |
```

L42 and L43 name OpenLDAP and Samba AD only. Samba stands in for nothing: what a Windows DC
does is L44's, and no doc asserts it before L44 closes (OR-3).

- [ ] **Step 8: Test assertions (spec §14)**

Under "Username resolution", add: "With `broker.directory`, a certificate mapping to zero
entries is `identity_unmapped`, to two `identity_ambiguous`; a derived username a declared
subject holds, or a second entry holds, is `username_collision`; a mapped value carrying
filter metacharacters matches only its literal entry." Add a "Directory" heading:

```markdown
- **Directory.** A grace mint's context has `refreshed_at` equal to the membership's
  verification time. A scheduled pass with no server answering stamps nothing and revokes
  nothing. A principal in two subjects holds the union of their grants, the least `token_ttl`
  and the most demanding `enable`. A group name two groups share matches no one. A recursive
  walk ends on a loop. A broker restarted in a directory outage mints within grace from the
  store and refuses past it. A principal the directory refused before an outage is refused
  through it. Two entries holding one `principal_attribute` value are both
  `identity_ambiguous`. A policy refresh never widens on a membership older than grace.
```

- [ ] **Step 9: The design**

- **§7, "Certificate-to-directory mapping".** Append: "As built (plan 7g; policy engine spec
  §13 decision 38): `broker.directory.certificate_mapping` takes one of six kinds. The strong
  ones are `issuer_serial` (AD's `altSecurityIdentities`) and `sid` (the SID extension, on
  `objectSid`). The weak ones are `san_upn`, `san_email`, `subject_dn` and `cn`, each refused
  at load without `allow_weak: true` and an `issuers:` pin. The mapping runs once per held
  connection and is pinned to it. The entry's principal and username must each be held by
  that entry alone, or both people are refused; the attributes they come from must be
  writable only by directory administrators. A principal is pinned to the entry's immutable
  id; an entry deleted and re-created is refused until an operator who has confirmed it is
  the same person runs `port49 directory forget <principal>` on the broker's admin socket. A
  Windows DC's behaviour is register row L44's, open until measured."
- **§9, "Directory unavailable".** Replace "The ceiling is a security parameter and MUST be
  explicit configuration:" with "The ceiling is a security parameter: it defaults to 4h, `0s`
  disables it, and either is said at every start (plan 7g; policy engine spec §13 decision
  38):". After "Revocation does not function during the grace window", add "except for a
  principal the directory refused before the outage: a refusal is stored and grace never
  overrules it".
- **§10, after "Replication lag".** Add an "As built (plan 7g)" paragraph:
  - the pool's ranking, breakers, health checks, failback and site crossings (Ruling 9);
  - the three binds, TLS-only (Ruling 8);
  - `nested_groups` (Ruling 6);
  - membership in the store and grace (Ruling 10);
  - pre-warm's population (Ruling 20);
  - the scheduled refresh's stamp (Ruling 12).
- **§12's failure matrix, "Directory unavailable".**
  - New session: "⚠ within `broker.directory.grace` from the membership the store holds;
    else refused 503 `directory_unavailable`, retried by the agent".
  - New device login: "⚠ ok within grace (the token carries the membership's verification
    time); else denied `directory_unavailable`".
  - Active login: "✓ stale context to `session.staleness_ceiling` (default 4h), counted from
    the last verification; then `context_stale`".
- **§12's store interface table.** Add two rows:

  ```markdown
  | membership | `principal` | broker, at each verification (bind, mint, scheduled refresh, pre-warm), and at each refusal (a refusal record); keeps the later `verified_at` | broker: grace, a policy refresh's judgement, token supersession | `max(directory.grace, 24h)` | yes — DN, entry id (the pin), username, groups, mapping keys, `verified_at`, refused |
  | membership key | `sha256(kind, canonical value)` of a mapping value | broker, with the membership; a key two principals claim is written ambiguous | broker, at a bind in grace, honoured only if the sealed record lists the key | as the membership | no — a principal |
  ```

- [ ] **Step 10: Check and commit**

Run: `grep -n "identity_unmapped\|identity_ambiguous\|directory_unavailable\|composition_refused" docs/design/2026-08-23-policy-engine-spec.md | head -20`
Expected: the four rows in §5.7, decision 38's bullets, §5.1.3's table.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: spec and design for plan 7g, decision 38, four reason codes, L42, L43 and L44 opened" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: The vocabulary: four reasons, `policy.subjects`, `auth.directory`, the identity answer

**Files:**
- Modify: `internal/decision/reasons.go:10-17` (the mint block), `:121-130` (`reasons`)
- Modify: `internal/decision/log.go:53-70` (`Auth`), `:186-203` (`Policy`)
- Modify: `internal/broker/api/identity.go:7-20` (`Identity`)
- Test: `internal/decision/reasons_test.go`, `internal/decision/log_test.go`

**Interfaces:**
- Consumes: Task 1's rows.
- Produces:

```go
// decision
const (
	IdentityUnmapped     Reason = "identity_unmapped"
	IdentityAmbiguous    Reason = "identity_ambiguous"
	DirectoryUnavailable Reason = "directory_unavailable"
	CompositionRefused   Reason = "composition_refused"
)
type Directory struct {
	Source     string `json:"source"`      // "fresh" | "grace"
	VerifiedAt string `json:"verified_at"` // FormatTime
	Server     string `json:"server,omitempty"`
	Site       string `json:"site,omitempty"`
}
// Auth gains:   Directory *Directory `json:"directory,omitempty"`
// Policy gains: Subjects []string   `json:"subjects,omitempty"`

// api.Identity gains:
Subjects   []string `json:"subjects,omitempty"`
Username   string   `json:"username,omitempty"`
GroupDNs   []string `json:"group_dns,omitempty"`
VerifiedAt string   `json:"verified_at,omitempty"`
Source     string   `json:"source,omitempty"`
```

- [ ] **Step 1: The failing tests**

Append to `internal/decision/reasons_test.go`:

```go
// The directory's four reasons are in §5.7's vocabulary (plan 7g), so a
// policy test may expect them and the metrics count them.
func TestTheDirectoryReasonsAreKnown(t *testing.T) {
	for r, want := range map[Reason]string{IdentityUnmapped: "identity_unmapped",
		IdentityAmbiguous: "identity_ambiguous", DirectoryUnavailable: "directory_unavailable",
		CompositionRefused: "composition_refused"} {
		if !Known(r) || string(r) != want {
			t.Errorf("%q", r)
		}
	}
}
```

Append to `internal/decision/log_test.go`:

```go
// policy.subjects replaces policy.subject when several matched, and
// auth.directory names where the membership came from and never a group
// (spec §5.7; decision 38).
func TestSubjectsAndDirectoryShapes(t *testing.T) {
	var b bytes.Buffer
	l := NewJSONLines(&b)
	l.Emit(Record{TS: time.Unix(1_000_000, 0), Event: EventMint, Verdict: VerdictPermit, Reason: GrantsMatched,
		Principal: "user:alice@corp.example.com",
		Auth: &Auth{Method: "cert", Directory: &Directory{Source: "grace", VerifiedAt: "1970-01-12T13:46:40Z",
			Server: "ldaps://dc-01", Site: "us-west"}},
		Policy: &Policy{Bundle: "sha256:b", Subjects: []string{"netops_oncall", "netops_ro"}}})
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	p := m["policy"].(map[string]any)
	if _, ok := p["subject"]; ok || len(p["subjects"].([]any)) != 2 {
		t.Fatalf("policy %v", p)
	}
	d := m["auth"].(map[string]any)["directory"].(map[string]any)
	if d["source"] != "grace" || d["verified_at"] != "1970-01-12T13:46:40Z" || d["server"] != "ldaps://dc-01" {
		t.Fatalf("auth.directory %v", d)
	}
	if strings.Contains(b.String(), "group") {
		t.Fatalf("a record names no group: %s", b.String())
	}
}
```

(Add `"encoding/json"`, `"strings"`, `"time"` to the test file's imports if absent.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/decision/ -run 'TestTheDirectoryReasonsAreKnown|TestSubjectsAndDirectoryShapes' -count=1`
Expected: FAIL, undefined `IdentityUnmapped`, `Directory`, `Subjects`.

- [ ] **Step 3: The constants, the fields**

In `reasons.go`'s mint block, after `CandidateCapReached`:

```go
	// IdentityUnmapped: the client certificate maps to no usable
	// directory entry (spec §5.7; decision 38). IdentityAmbiguous: to two
	// or more, never the first (design §7). DirectoryUnavailable: no
	// directory server answered and no membership verified within
	// directory.grace is held. CompositionRefused: the principal's
	// subjects compose on the device to a reply a joint check refuses.
	IdentityUnmapped     Reason = "identity_unmapped"
	IdentityAmbiguous    Reason = "identity_ambiguous"
	DirectoryUnavailable Reason = "directory_unavailable"
	CompositionRefused   Reason = "composition_refused"
```

and add the four to `reasons` after `CandidateCapReached`. In `log.go`, add `Directory` beside
`Auth`, and the two fields with their comments as in Interfaces. In `api/identity.go`, add
the five fields after `Subject`.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/decision/ ./internal/broker/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/decision internal/broker/api/identity.go
git commit -m "feat(decision): the directory's four reasons, policy.subjects and auth.directory" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The store stamps `refreshed_at`, and a login takes the token's `VerifiedAt`

**Files:**
- Modify: `internal/store/store.go:100-131` (`Token`), `:519-545` (`ContextPolicy`), the
  `Store` interface after `SetContextPolicy` (`:861`)
- Modify: `internal/store/apply.go:89-` (`ApplyContextPolicy`), add `ApplyStamp`
- Modify: `internal/store/memory/memory.go:797` (beside `SetContextPolicy`)
- Modify: `internal/store/crypt/crypt.go:171-184` (`tokenSecret`), `:366-396`
  (`sealToken`, `openToken`), `:800` (beside `SetContextPolicy`)
- Modify: `internal/store/etcd/records.go:30-60` (`tokenRec`), `internal/store/etcd/contexts.go:555`
  (beside `SetContextPolicy`)
- Modify: `internal/store/guard/guard.go:43` (the method→pool table), `:522` (beside
  `SetContextPolicy`)
- Modify: `internal/token/minter.go:134-142` (`Subject`), `:451-456` (the `PutToken`)
- Modify: `internal/daemon/authen/authen.go:670-676` (`loginContext`)
- Create: `internal/store/storetest/stamp.go`; Modify: `internal/store/storetest/storetest.go`
  (the property list in `Run`)
- Test: `internal/daemon/authen/authen_test.go`, `internal/token/minter_test.go`

**Interfaces:**
- Consumes: `store.ApplyContextPolicy`, `(*memory.Store).SetContextPolicy`'s shape,
  `(*etcd.Store).mutate`, `(*wrapped).rewrite`, `(*guarded).do`.
- Produces:

```go
// store
type Token struct { /* … */ VerifiedAt time.Time } // when the membership it was minted on was verified; zero: the mint
type ContextPolicy struct { /* … */ RefreshedAt time.Time } // non-zero: raise RefreshedAt to it
// StampRefreshed raises k's RefreshedAt to at, only while its PolicyRev is
// policyRev; it never moves PolicyRev. ErrConflict, ErrNotFound.
StampRefreshed(ctx context.Context, k ContextKey, policyRev uint64, at time.Time) error
func ApplyStamp(c *Context, at time.Time)

// token
type Subject struct { /* … */ VerifiedAt time.Time }

// storetest
func StampRaisesRefreshedAtAndKeepsPolicyRev(t *testing.T, b Backend)
func APolicyWriteCarriesItsRefreshedAt(t *testing.T, b Backend)
```

- [ ] **Step 1: The failing properties**

Create `internal/store/storetest/stamp.go`:

```go
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// StampRaisesRefreshedAtAndKeepsPolicyRev: the scheduled refresh's stamp
// (plan 7g, Ruling 12) raises RefreshedAt, never lowers it, compares the
// policy revision the caller read and does not move it, so a stamp never
// costs a policy refresh its compare.
func StampRaisesRefreshedAtAndKeepsPolicyRev(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
		BlobHash: "sha256:a", AuthTime: t0.Add(-time.Hour), RefreshedAt: t0.Add(-time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StampRefreshed(ctx, k, c.PolicyRev, t0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetContext(ctx, k)
	if !got.RefreshedAt.Equal(t0.Add(-time.Minute)) || got.PolicyRev != c.PolicyRev {
		t.Fatalf("after a stamp: refreshed_at %v policy_rev %d (was %d)", got.RefreshedAt, got.PolicyRev, c.PolicyRev)
	}
	if err := s.StampRefreshed(ctx, k, got.PolicyRev, t0.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetContext(ctx, k); !again.RefreshedAt.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("an earlier stamp lowered refreshed_at to %v", again.RefreshedAt)
	}
	if err := s.SetPrivilege(ctx, k, 15); err != nil { // moves PolicyRev
		t.Fatal(err)
	}
	if err := s.StampRefreshed(ctx, k, c.PolicyRev, t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stamp on a moved policy revision: %v, want ErrConflict", err)
	}
	if err := s.StampRefreshed(ctx, store.ContextKey{NAS: "leaf-09", Username: "x"}, 1, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stamp on no context: %v, want ErrNotFound", err)
	}
}

// APolicyWriteCarriesItsRefreshedAt: a scheduled pass that changed a
// context stamps it in the same write; a policy reload's write (zero
// RefreshedAt) leaves the clock alone (spec §5.1.3).
func APolicyWriteCarriesItsRefreshedAt(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
		BlobHash: "sha256:a", AuthTime: t0.Add(-time.Hour), RefreshedAt: t0.Add(-time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(ctx, k)
	if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:b"}); err != nil {
		t.Fatal(err)
	}
	c, _ = s.GetContext(ctx, k)
	if !c.RefreshedAt.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("a policy reload's write moved refreshed_at to %v", c.RefreshedAt)
	}
	if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:c", RefreshedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.GetContext(ctx, k); !c.RefreshedAt.Equal(t0) || c.BlobHash != "sha256:c" {
		t.Fatalf("a scheduled write: %+v", c)
	}
}
```

Add both to `Run`'s list in `storetest.go`, after `SupersededIsTheLaterAndExpires`:

```go
		{"StampRaisesRefreshedAtAndKeepsPolicyRev", StampRaisesRefreshedAtAndKeepsPolicyRev},
		{"APolicyWriteCarriesItsRefreshedAt", APolicyWriteCarriesItsRefreshedAt},
```

Append to `internal/daemon/authen/authen_test.go`:

```go
// A token minted from a membership verified earlier (a grace mint, plan
// 7g Ruling 11) gives its context that instant as refreshed_at, so the
// staleness ceiling counts from the directory's last answer, not the
// redemption. A token with none (no directory) is the redemption's now.
func TestALoginTakesTheTokensVerifiedAt(t *testing.T) {
	for _, c := range []struct {
		name     string
		verified time.Duration // before f.now; 0 is none
		want     time.Duration
	}{{"a grace mint", 3 * time.Hour, 3 * time.Hour}, {"no directory", 0, 0}} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			secret := f.tag() + "veriveriveriveriveri0123"
			tok := store.Token{ID: "v", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", BlobHash: "sha256:b", AuthTime: f.now, Enable: "token",
				MaxPrivilege: 15, ExpiresAt: f.now.Add(time.Minute)}
			if c.verified > 0 {
				tok.VerifiedAt = f.now.Add(-c.verified)
			}
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}, tok); err != nil {
				t.Fatal(err)
			}
			f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
				AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
				Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
			got, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if err != nil || !got.RefreshedAt.Equal(f.now.Add(-c.want)) {
				t.Fatalf("refreshed_at %v, want %v (%v)", got.RefreshedAt, f.now.Add(-c.want), err)
			}
		})
	}
}

// A VerifiedAt after the redemption (a broker clock ahead of port49d's)
// is never written: the context is not given a staleness clock in the
// future.
func TestAVerifiedAtAheadOfTheDaemonIsNow(t *testing.T) {
	f := setup(t)
	secret := f.tag() + "aheadaheadaheadahead0123"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", BlobHash: "sha256:b", AuthTime: f.now, VerifiedAt: f.now.Add(time.Hour),
			ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
	if got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !got.RefreshedAt.Equal(f.now) {
		t.Fatalf("refreshed_at %v, want now", got.RefreshedAt)
	}
}
```

Append to `internal/token/minter_test.go`, on `TestEveryTokenCarriesItsMintTime`'s pattern:

```go
// A token carries the membership's verification time the broker hands
// it (plan 7g, Ruling 11), on both kinds.
func TestEveryTokenCarriesItsVerifiedAt(t *testing.T) {
	at := time.Unix(1_757_041_495, 0)
	st := memory.New(func() time.Time { return at })
	m := NewMinter(st, decision.NewJSONLines(&bytes.Buffer{}), rand.Reader, TagKey([]byte("k")), func() time.Time { return at }, 3)
	s := subject()
	s.AuthTime, s.VerifiedAt = at.Add(-time.Hour), at.Add(-2*time.Hour)
	if _, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", WithEnable: true, TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"})
	for _, tok := range c {
		if !tok.VerifiedAt.Equal(s.VerifiedAt) {
			t.Fatalf("%s token: verified_at %v, want %v", tok.Kind, tok.VerifiedAt, s.VerifiedAt)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/... ./internal/daemon/authen/ ./internal/token/ -run 'Stamp|PolicyWriteCarries|VerifiedAt' -count=1`
Expected: FAIL, `StampRefreshed` undefined, unknown field `VerifiedAt`, `RefreshedAt`.

- [ ] **Step 3: The store's types and the rule**

In `store.go`, add to `Token` after `MintedAt`:

```go
	// VerifiedAt is when the directory membership this token was minted on
	// was verified (plan 7g, Ruling 11): the login writes it as the
	// context's RefreshedAt, so a grace mint never resets the staleness
	// clock. Zero is a mint with no directory: the redemption's now.
	VerifiedAt time.Time
```

to `ContextPolicy` after `MaxSessionAge`:

```go
	// RefreshedAt, when non-zero, raises the context's RefreshedAt to it:
	// the scheduled refresh verified the directory (plan 7g, Ruling 12). A
	// policy reload leaves it zero: nothing about the directory was
	// re-verified (spec §5.1.3).
	RefreshedAt time.Time
```

and to the `Store` interface after `SetContextPolicy`:

```go
	// StampRefreshed raises k's RefreshedAt to at, only while its PolicyRev
	// is still policyRev, and moves neither PolicyRev nor the expiry: the
	// scheduled refresh's stamp on a context whose answer it found
	// unchanged (plan 7g, Ruling 12). A context changed since the read is
	// ErrConflict, read again; an earlier at than the one held leaves it.
	// ErrNotFound if the key is absent or expired.
	StampRefreshed(ctx context.Context, k ContextKey, policyRev uint64, at time.Time) error
```

In `apply.go`:

```go
// ApplyStamp raises RefreshedAt to at, never lowering it (plan 7g).
func ApplyStamp(c *Context, at time.Time) {
	if at.After(c.RefreshedAt) {
		c.RefreshedAt = at
	}
}
```

and at the end of `ApplyContextPolicy`'s non-revoking branch, add `ApplyStamp(c, p.RefreshedAt)`
(a zero `p.RefreshedAt` is never after, so a reload's write leaves it).

- [ ] **Step 4: The four backends**

`memory.go`, after `SetContextPolicy`:

```go
// StampRefreshed is the scheduled refresh's stamp under the one lock: it
// compares the policy revision and moves only Rev (store.Store).
func (s *Store) StampRefreshed(_ context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	if e.policyRev != policyRev {
		return store.ErrConflict
	}
	store.ApplyStamp(&e.c, at)
	e.rev = s.nextRevLocked()
	s.contexts[k] = e
	return nil
}
```

`etcd/contexts.go`, after `SetContextPolicy`:

```go
// StampRefreshed is SetContextPolicy's compare with ApplyStamp's write,
// and PolicyMoved left false, so the policy revision stays.
func (s *Store) StampRefreshed(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
		if uint64(r.PolicyRev) != policyRev {
			return false, store.ErrConflict
		}
		applyTo(r, rev, func(c *store.Context) (bool, error) { store.ApplyStamp(c, at); return true, nil })
		return false, nil
	})
}
```

Read `mutate`'s and `applyTo`'s comments before writing it: `SetContextPolicy` sets
`r.PolicyMoved = true` to move the policy revision, and this must not. If `applyTo` itself
moves `PolicyRev`, follow how `TouchContext`'s etcd path avoids it instead, and say which in
the commit.

`crypt/crypt.go`, after `SetContextPolicy`:

```go
// StampRefreshed is a rewrite compared on the policy revision that does
// not move it: RefreshedAt is sealed, and a stamp is no policy write.
func (w *wrapped) StampRefreshed(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	return w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
		if c.PolicyRev != policyRev {
			return false, store.ErrConflict
		}
		store.ApplyStamp(c, at)
		return false, nil
	})
}
```

`guard/guard.go`: add `"StampRefreshed": Context,` to the method→pool table at `:43`, and:

```go
func (g *guarded) StampRefreshed(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.StampRefreshed(ctx, k, policyRev, at) })
}
```

Check every other `store.Store` implementation compiles: `go build ./... && go vet ./...`.
Test doubles that embed `store.Store` inherit it. One that implements the interface by hand
gets a method returning `errors.New("not implemented")`, and the build names each.

- [ ] **Step 5: The token carries it, the login reads it**

- **`crypt.go`.**
  - `tokenSecret` gains ``VerifiedAt time.Time `json:"verified_at"` `` (sealed: in the clear
    a store write could move it and extend a grace mint's session).
  - `sealToken` copies `t.VerifiedAt` in, and `openToken` copies it out.
- **`etcd/records.go`.** `tokenRec` gains ``VerifiedAt time.Time `json:"verified_at"` ``, copied
  both ways in `tokenRecOf` and `token()`.
- **`token/minter.go`.**
  - `Subject` gains `VerifiedAt time.Time // the membership's verification; zero: none`;
  - the `PutToken` at `:451` passes `VerifiedAt: r.Subject.VerifiedAt`.
- **`authen.go`'s `loginContext`.** Replace `RefreshedAt: now,` with
  `RefreshedAt: refreshedAt(winner.VerifiedAt, now),` and add:

```go
// refreshedAt is a new context's staleness clock (spec §5.1.1): the
// directory membership's verification when the token carries one and it
// is not after now, else now. A grace mint must not hand a session a
// fresh ceiling on membership verified hours ago (plan 7g, Ruling 11),
// and a broker clock ahead of this one must not hand it one in the future.
func refreshedAt(verified, now time.Time) time.Time {
	if !verified.IsZero() && verified.Before(now) {
		return verified
	}
	return now
}
```

- [ ] **Step 6: Run them to verify they pass**

Run: `go test ./internal/store/... ./internal/daemon/... ./internal/token/ -count=1`
Expected: PASS. The etcd properties need the embedded etcd the package's tests start, as they
do today.

- [ ] **Step 7: Commit**

```bash
git add internal/store internal/token internal/daemon/authen
git commit -m "feat(store): StampRefreshed, a policy write's RefreshedAt, and a token's VerifiedAt as the login's refreshed_at" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: `broker.directory` and `broker.refresh_interval`

**Files:**
- Create: `internal/directory/doc.go`, `internal/directory/config.go`
- Create: `internal/config/directory.go`, `internal/config/directory_test.go`
- Modify: `internal/config/config.go:183-234` (`BrokerConfig`), `:1184` (`checkBroker`)
- Modify: `internal/keyfile/keyfile.go`: export `ReadSecret`
- Test: `internal/keyfile/keyfile_test.go`

**Interfaces:**
- Consumes: `checkBroker(c Config, b BrokerConfig, role Role) (*BrokerConfig, error)`,
  `readableFile(name, path string) error`, `keyfile.readPrivate`.
- Produces:

```go
// internal/directory (config.go), the resolved form every later task reads
type Server struct {
	URI      string
	Priority int
	Site     string
	StartTLS bool
}
type BindMechanism string // "external" | "gssapi" | "simple"
type Bind struct {
	Mechanism            BindMechanism
	TLSCertFile, TLSKeyFile string // external
	KeytabFile, Principal, KRB5Conf string // gssapi
	BindDN, PasswordEnv  string // simple
}
type MappingKind string
const (
	MapIssuerSerial MappingKind = "issuer_serial"
	MapSID          MappingKind = "sid"
	MapSANUPN       MappingKind = "san_upn"
	MapSANEmail     MappingKind = "san_email"
	MapSubjectDN    MappingKind = "subject_dn"
	MapCN           MappingKind = "cn"
)
type Mapping struct {
	Kind      MappingKind
	Attribute string   // resolved: the kind's default when unset
	AllowWeak bool
	Issuers   []string // RFC 4514 issuer DNs a weak kind is pinned to
}
type Nested string // "in_chain" | "recursive" | "direct"
type Config struct {
	Servers                []Server
	Site                   string // resolved: site, else os.Getenv(site_env), else ""
	SiteFrom               string // "site", "PORT49_SITE" (the env var), or "" for none
	CAFile                 string
	Bind                   Bind
	BaseDN, GroupsBaseDN   string
	UserFilter, GroupFilter string
	PrincipalAttribute, UsernameAttribute, GroupNameAttribute, MemberAttribute string
	Mapping                Mapping
	Nested                 Nested
	MaxDepth               int
	QueryTimeout           time.Duration
	HealthInterval, HealthTimeout time.Duration
	FailureThreshold       int
	ProbeInterval          time.Duration
	StabilityWindow        time.Duration
	Grace                  time.Duration
	PrewarmInterval        time.Duration
	PrewarmMax             int
}
func (m MappingKind) Strong() bool

// internal/config
// BrokerConfig gains:
Directory       *directory.Config `yaml:"-"`
DirectorySet    *directoryYAML    `yaml:"directory"`
RefreshInterval time.Duration     `yaml:"refresh_interval"` // default 5m; 1m to 1h
func checkDirectory(d directoryYAML, getenv func(string) string) (*directory.Config, error)

// internal/keyfile
func ReadSecret(path string) ([]byte, error)
```

- [ ] **Step 1: The failing tests**

Create `internal/config/directory_test.go`:

```go
package config

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
)

func dirYAML(t *testing.T) directoryYAML {
	t.Helper()
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	return directoryYAML{
		Servers: []serverYAML{
			{URI: "ldaps://dc-01.corp.example.com", Priority: 100, Site: "us-west"},
			{URI: "ldaps://dc-03.corp.example.com", Priority: 50, Site: "us-east"},
		},
		CAFile:             ca,
		Bind:               bindYAML{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "PORT49_LDAP_PASSWORD"},
		BaseDN:             "DC=corp,DC=example,DC=com",
		CertificateMapping: mappingYAML{Kind: "issuer_serial"},
		NestedGroups:       "in_chain",
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// The defaults of Rulings 6–10 and 20, and the site from the environment
// (design §10: "derive its own site from the environment").
func TestDirectoryDefaults(t *testing.T) {
	d, err := checkDirectory(dirYAML(t), env(map[string]string{"PORT49_SITE": "us-west", "PORT49_LDAP_PASSWORD": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Site != "us-west" || d.SiteFrom != "PORT49_SITE" || d.GroupsBaseDN != d.BaseDN ||
		d.PrincipalAttribute != "userPrincipalName" || d.UsernameAttribute != "sAMAccountName" ||
		d.GroupNameAttribute != "cn" || d.MemberAttribute != "member" || d.Mapping.Attribute != "altSecurityIdentities" ||
		d.MaxDepth != 16 || d.QueryTimeout != 5*time.Second || d.HealthInterval != 30*time.Second ||
		d.HealthTimeout != 2*time.Second || d.FailureThreshold != 3 || d.ProbeInterval != time.Minute ||
		d.StabilityWindow != 5*time.Minute || d.Grace != 4*time.Hour || d.PrewarmInterval != time.Hour ||
		d.PrewarmMax != 10000 || d.UserFilter != "(objectClass=person)" {
		t.Fatalf("%+v", d)
	}
}

func TestDirectoryRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*directoryYAML)
		want string
	}{
		{"no nested_groups", func(d *directoryYAML) { d.NestedGroups = "" },
			"broker.directory.nested_groups is required: in_chain (Active Directory), recursive (port49 walks member) or direct (the groups are flat); design §10"},
		{"a weak mapping without opt-in", func(d *directoryYAML) { d.CertificateMapping = mappingYAML{Kind: "san_email"} },
			"broker.directory.certificate_mapping.kind san_email is a weak mapping: set allow_weak: true and list the issuers it is pinned to (design §7)"},
		{"a weak mapping with no issuers", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "san_upn", AllowWeak: true}
		}, "certificate_mapping.issuers"},
		{"plain LDAP", func(d *directoryYAML) { d.Servers[0].URI = "ldap://dc-01:389" },
			"broker.directory.servers[0].uri ldap://dc-01:389: plain LDAP is refused; use ldaps:// or set start_tls: true"},
		{"no bind mechanism", func(d *directoryYAML) { d.Bind = bindYAML{} },
			"broker.directory.bind.mechanism is required: external, gssapi or simple"},
		{"a simple bind with no password in the environment", func(d *directoryYAML) { d.Bind.PasswordEnv = "UNSET_VAR" },
			"broker.directory.bind.password_env UNSET_VAR is not set"},
		{"an unknown kind", func(d *directoryYAML) { d.CertificateMapping.Kind = "email" },
			"broker.directory.certificate_mapping.kind email: one of issuer_serial, sid, san_upn, san_email, subject_dn, cn"},
		{"grace too long", func(d *directoryYAML) { d.Grace = dur(25 * time.Hour) },
			"broker.directory.grace 25h0m0s: must be 0s to 24h"},
		{"a timeout above its interval", func(d *directoryYAML) {
			d.HealthCheck = &healthYAML{Interval: 10 * time.Second, Timeout: 20 * time.Second}
		}, "broker.directory.health_check.timeout 20s: must be at most health_check.interval (10s)"},
		{"no servers", func(d *directoryYAML) { d.Servers = nil }, "broker.directory.servers: list at least one"},
		{"no base", func(d *directoryYAML) { d.BaseDN = "" }, "broker.directory.base_dn is required"},
		{"a negative depth under recursive", func(d *directoryYAML) { d.NestedGroups = "recursive"; d.MaxDepth = -1 },
			"broker.directory.max_depth -1: must be 1 to 64"},
		{"a user_filter that does not compile", func(d *directoryYAML) { d.UserFilter = "(objectClass=person" },
			`broker.directory.user_filter "(objectClass=person": `},
		{"a group_filter that does not compile", func(d *directoryYAML) { d.GroupFilter = "objectClass=group" },
			`broker.directory.group_filter "objectClass=group": `},
		{"an attribute that is no descriptor", func(d *directoryYAML) { d.PrincipalAttribute = "mail)(uid=*" },
			`broker.directory.principal_attribute "mail)(uid=*": not an attribute descriptor`},
		{"a strong kind repointed without opt-in", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "sid", Attribute: "description"}
		}, "broker.directory.certificate_mapping.attribute description: repointing sid makes it as strong as description; " +
			"set allow_weak: true and list the issuers it is pinned to (design §7)"},
		{"a strong kind repointed with opt-in and no issuers", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "issuer_serial", Attribute: "description", AllowWeak: true}
		}, "certificate_mapping.issuers"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := dirYAML(t)
			c.edit(&d)
			_, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"}))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
}

// Each kind's default attribute (Ruling 1), and the weak kinds' pin parsed
// as DNs, so a pin with a typo is a load error, not a pin nothing matches.
func TestMappingKindsAndPins(t *testing.T) {
	for kind, attr := range map[string]string{"issuer_serial": "altSecurityIdentities", "sid": "objectSid",
		"san_upn": "userPrincipalName", "san_email": "mail", "subject_dn": "distinguishedName", "cn": "cn"} {
		d := dirYAML(t)
		d.CertificateMapping = mappingYAML{Kind: kind, AllowWeak: true, Issuers: []string{"CN=Corp Users CA,O=Example"}}
		got, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"}))
		if err != nil || got.Mapping.Attribute != attr || got.Mapping.Kind.Strong() != (kind == "issuer_serial" || kind == "sid") {
			t.Errorf("%s: %+v %v", kind, got, err)
		}
	}
	d := dirYAML(t)
	d.CertificateMapping = mappingYAML{Kind: "cn", AllowWeak: true, Issuers: []string{"not a dn"}}
	if _, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"})); err == nil ||
		!strings.Contains(err.Error(), `broker.directory.certificate_mapping.issuers[0] "not a dn"`) {
		t.Fatalf("%v", err)
	}
}

// broker.refresh_interval: 5m by default, 1m to 1h (Ruling 12).
func TestRefreshIntervalBounds(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want time.Duration
		err  string
	}{{0, 5 * time.Minute, ""}, {time.Minute, time.Minute, ""}, {30 * time.Second, 0, "broker.refresh_interval 30s: must be 1m to 1h"},
		{2 * time.Hour, 0, "broker.refresh_interval 2h0m0s: must be 1m to 1h"}} {
		got, err := refreshInterval(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%v: %v", c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v: %v %v", c.in, got, err)
		}
	}
}

var _ = directory.MapCN
```

`writeTemp` and `testCAPEM` are the helpers `internal/config/broker_test.go` uses for the
broker's TLS files. If they have other names there, use those. If none exists, write a CA with
`internal/testpki` as `broker_test.go`'s fixtures do. `dur(d)` is a one-line helper returning
`*time.Duration`, to tell an explicit `0s` from absent (Grace is a pointer in the YAML type).

Append to `internal/keyfile/keyfile_test.go` a test that `ReadSecret` refuses a file with mode
0640 and accepts one with 0600, mirroring the existing `readPrivate` test.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/config/ ./internal/keyfile/ -run 'Directory|Mapping|RefreshInterval|ReadSecret' -count=1`
Expected: FAIL, undefined `directoryYAML`, `checkDirectory`, `ReadSecret`.

- [ ] **Step 3: The package's config types**

Create `internal/directory/doc.go`:

```go
// Package directory is port49's one door to LDAP and Active Directory
// (design §10; plan 7g): the server pool, the bind, the
// certificate-to-directory mapping, nested group membership, the
// membership kept in the store, grace and pre-warm.
//
// Only the broker imports it. port49d never speaks to a directory: a
// directory outage reaches a live session through the staleness ceiling
// alone (design §9). Nothing here reads a group from a credential, writes
// to a directory, or binds as a user.
//
// Nothing here formats a bind password, a keytab's bytes or a Kerberos
// ticket into a line, a record or an error.
package directory
```

Create `internal/directory/config.go` with the types in Interfaces, and:

```go
// Strong reports whether a kind binds a key-specific value (design §7):
// issuer and serial, or the SID extension. The others bind a name, and
// must be issuer-pinned.
func (k MappingKind) Strong() bool { return k == MapIssuerSerial || k == MapSID }

// DefaultAttribute is the entry attribute each kind looks up by default.
func (k MappingKind) DefaultAttribute() string {
	switch k {
	case MapIssuerSerial:
		return "altSecurityIdentities"
	case MapSID:
		return "objectSid"
	case MapSANUPN:
		return "userPrincipalName"
	case MapSANEmail:
		return "mail"
	case MapSubjectDN:
		return "distinguishedName"
	case MapCN:
		return "cn"
	}
	return ""
}

// Kinds is every MappingKind, in the order the refusal lists them.
var Kinds = []MappingKind{MapIssuerSerial, MapSID, MapSANUPN, MapSANEmail, MapSubjectDN, MapCN}
```

- [ ] **Step 4: The YAML and its checks**

Create `internal/config/directory.go`:

```go
package config

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/directory"
)

type serverYAML struct {
	URI      string `yaml:"uri"`
	Priority int    `yaml:"priority"`
	Site     string `yaml:"site"`
	StartTLS bool   `yaml:"start_tls"`
}

type bindYAML struct {
	Mechanism   string `yaml:"mechanism"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	KeytabFile  string `yaml:"keytab_file"`
	Principal   string `yaml:"principal"`
	KRB5Conf    string `yaml:"krb5_conf"`
	BindDN      string `yaml:"bind_dn"`
	PasswordEnv string `yaml:"password_env"`
}

type mappingYAML struct {
	Kind      string   `yaml:"kind"`
	Attribute string   `yaml:"attribute"`
	AllowWeak bool     `yaml:"allow_weak"`
	Issuers   []string `yaml:"issuers"`
}

type healthYAML struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type breakerYAML struct {
	FailureThreshold int           `yaml:"failure_threshold"`
	ProbeInterval    time.Duration `yaml:"probe_interval"`
}

type failbackYAML struct {
	StabilityWindow *time.Duration `yaml:"stability_window"`
}

type prewarmYAML struct {
	Interval      *time.Duration `yaml:"interval"`
	MaxPrincipals int            `yaml:"max_principals"`
}

// directoryYAML is broker.directory (design §10; plan 7g).
type directoryYAML struct {
	Servers            []serverYAML   `yaml:"servers"`
	Site               string         `yaml:"site"`
	SiteEnv            string         `yaml:"site_env"`
	CAFile             string         `yaml:"ca_file"`
	Bind               bindYAML       `yaml:"bind"`
	BaseDN             string         `yaml:"base_dn"`
	GroupsBaseDN       string         `yaml:"groups_base_dn"`
	UserFilter         string         `yaml:"user_filter"`
	GroupFilter        string         `yaml:"group_filter"`
	PrincipalAttribute string         `yaml:"principal_attribute"`
	UsernameAttribute  string         `yaml:"username_attribute"`
	GroupNameAttribute string         `yaml:"group_name_attribute"`
	MemberAttribute    string         `yaml:"member_attribute"`
	CertificateMapping mappingYAML    `yaml:"certificate_mapping"`
	NestedGroups       string         `yaml:"nested_groups"`
	MaxDepth           int            `yaml:"max_depth"`
	QueryTimeout       time.Duration  `yaml:"query_timeout"`
	HealthCheck        *healthYAML    `yaml:"health_check"`
	CircuitBreaker     *breakerYAML   `yaml:"circuit_breaker"`
	Failback           *failbackYAML  `yaml:"failback"`
	Grace              *time.Duration `yaml:"grace"`
	Prewarm            *prewarmYAML   `yaml:"prewarm"`
}

// checkDirectory resolves broker.directory, refusing what Rulings 1, 6,
// 8 and 9 refuse. getenv is os.Getenv outside tests.
func checkDirectory(y directoryYAML, getenv func(string) string) (*directory.Config, error) {
	const p = "broker.directory."
	d := &directory.Config{CAFile: y.CAFile, BaseDN: y.BaseDN,
		GroupsBaseDN:       or(y.GroupsBaseDN, y.BaseDN),
		UserFilter:         or(y.UserFilter, "(objectClass=person)"),
		GroupFilter:        or(y.GroupFilter, "(|(objectClass=group)(objectClass=groupOfNames))"),
		PrincipalAttribute: or(y.PrincipalAttribute, "userPrincipalName"),
		UsernameAttribute:  or(y.UsernameAttribute, "sAMAccountName"),
		GroupNameAttribute: or(y.GroupNameAttribute, "cn"),
		MemberAttribute:    or(y.MemberAttribute, "member"),
		MaxDepth:           orI(y.MaxDepth, 16),
		QueryTimeout:       orD(y.QueryTimeout, 5*time.Second),
		HealthInterval:     30 * time.Second, HealthTimeout: 2 * time.Second,
		FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: 5 * time.Minute,
		Grace: 4 * time.Hour, PrewarmInterval: time.Hour, PrewarmMax: 10000}
	if len(y.Servers) == 0 {
		return nil, fmt.Errorf("config: %sservers: list at least one", p)
	}
	for i, s := range y.Servers {
		u, err := url.Parse(s.URI)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap"):
			return nil, fmt.Errorf("config: %sservers[%d].uri %q: an ldaps:// or ldap:// URI with a host", p, i, s.URI)
		case u.Scheme == "ldap" && !s.StartTLS:
			return nil, fmt.Errorf("config: %sservers[%d].uri %s: plain LDAP is refused; use ldaps:// or set start_tls: true",
				p, i, s.URI)
		case u.Scheme == "ldaps" && s.StartTLS:
			return nil, fmt.Errorf("config: %sservers[%d]: start_tls is for ldap://; %s is TLS already", p, i, s.URI)
		}
		d.Servers = append(d.Servers, directory.Server{URI: s.URI, Priority: s.Priority, Site: s.Site, StartTLS: s.StartTLS})
	}
	switch {
	case y.Site != "":
		d.Site, d.SiteFrom = y.Site, "site"
	default:
		name := or(y.SiteEnv, "PORT49_SITE")
		if v := getenv(name); v != "" {
			d.Site, d.SiteFrom = v, name
		}
	}
	if y.CAFile == "" {
		return nil, fmt.Errorf("config: %sca_file is required: the directory's server certificates are verified", p)
	}
	if err := readableFile(p+"ca_file", y.CAFile); err != nil {
		return nil, err
	}
	if y.BaseDN == "" {
		return nil, fmt.Errorf("config: %sbase_dn is required", p)
	}
	for _, dn := range []struct{ key, v string }{{"base_dn", d.BaseDN}, {"groups_base_dn", d.GroupsBaseDN}} {
		if _, err := ldap.ParseDN(dn.v); err != nil {
			return nil, fmt.Errorf("config: %s%s %q: %v", p, dn.key, dn.v, err)
		}
	}
	b, err := checkBind(y.Bind, getenv)
	if err != nil {
		return nil, err
	}
	d.Bind = b
	m, err := checkMapping(y.CertificateMapping)
	if err != nil {
		return nil, err
	}
	d.Mapping = m
	switch directory.Nested(y.NestedGroups) {
	case "in_chain", "recursive", "direct":
		d.Nested = directory.Nested(y.NestedGroups)
	case "":
		return nil, fmt.Errorf("config: %snested_groups is required: in_chain (Active Directory), recursive (port49 "+
			"walks member) or direct (the groups are flat); design §10", p)
	default:
		return nil, fmt.Errorf("config: %snested_groups %q: in_chain, recursive or direct", p, y.NestedGroups)
	}
	if d.MaxDepth < 1 || d.MaxDepth > 64 {
		return nil, fmt.Errorf("config: %smax_depth %d: must be 1 to 64", p, y.MaxDepth)
	}
	if d.QueryTimeout < time.Second || d.QueryTimeout > 30*time.Second {
		return nil, fmt.Errorf("config: %squery_timeout %s: must be 1s to 30s", p, d.QueryTimeout)
	}
	if h := y.HealthCheck; h != nil {
		d.HealthInterval, d.HealthTimeout = orD(h.Interval, d.HealthInterval), orD(h.Timeout, d.HealthTimeout)
	}
	if d.HealthInterval < 5*time.Second || d.HealthInterval > 5*time.Minute {
		return nil, fmt.Errorf("config: %shealth_check.interval %s: must be 5s to 5m", p, d.HealthInterval)
	}
	if d.HealthTimeout > d.HealthInterval {
		return nil, fmt.Errorf("config: %shealth_check.timeout %s: must be at most health_check.interval (%s)", p,
			d.HealthTimeout, d.HealthInterval)
	}
	if cb := y.CircuitBreaker; cb != nil {
		d.FailureThreshold, d.ProbeInterval = orI(cb.FailureThreshold, 3), orD(cb.ProbeInterval, time.Minute)
	}
	if d.FailureThreshold < 1 || d.FailureThreshold > 20 {
		return nil, fmt.Errorf("config: %scircuit_breaker.failure_threshold %d: must be 1 to 20", p, d.FailureThreshold)
	}
	if d.ProbeInterval < 5*time.Second || d.ProbeInterval > 10*time.Minute {
		return nil, fmt.Errorf("config: %scircuit_breaker.probe_interval %s: must be 5s to 10m", p, d.ProbeInterval)
	}
	if f := y.Failback; f != nil && f.StabilityWindow != nil {
		d.StabilityWindow = *f.StabilityWindow
	}
	if d.StabilityWindow < 0 || d.StabilityWindow > time.Hour {
		return nil, fmt.Errorf("config: %sfailback.stability_window %s: must be 0s to 1h", p, d.StabilityWindow)
	}
	if y.Grace != nil {
		d.Grace = *y.Grace
	}
	if d.Grace < 0 || d.Grace > 24*time.Hour {
		return nil, fmt.Errorf("config: %sgrace %s: must be 0s to 24h", p, d.Grace)
	}
	if pw := y.Prewarm; pw != nil {
		if pw.Interval != nil {
			d.PrewarmInterval = *pw.Interval
		}
		d.PrewarmMax = orI(pw.MaxPrincipals, d.PrewarmMax)
	}
	if d.PrewarmInterval != 0 && (d.PrewarmInterval < 5*time.Minute || d.PrewarmInterval > 24*time.Hour) {
		return nil, fmt.Errorf("config: %sprewarm.interval %s: must be 0s (off) or 5m to 24h", p, d.PrewarmInterval)
	}
	if d.PrewarmMax < 1 || d.PrewarmMax > 1_000_000 {
		return nil, fmt.Errorf("config: %sprewarm.max_principals %d: must be 1 to 1000000", p, d.PrewarmMax)
	}
	return d, nil
}

func checkBind(b bindYAML, getenv func(string) string) (directory.Bind, error) {
	const p = "broker.directory.bind."
	out := directory.Bind{Mechanism: directory.BindMechanism(b.Mechanism), TLSCertFile: b.TLSCertFile,
		TLSKeyFile: b.TLSKeyFile, KeytabFile: b.KeytabFile, Principal: b.Principal, KRB5Conf: b.KRB5Conf,
		BindDN: b.BindDN, PasswordEnv: b.PasswordEnv}
	switch b.Mechanism {
	case "external":
		if b.TLSCertFile == "" || b.TLSKeyFile == "" {
			return out, fmt.Errorf("config: %stls_cert_file and tls_key_file are required for external", p)
		}
	case "gssapi":
		if b.KeytabFile == "" || b.Principal == "" || b.KRB5Conf == "" {
			return out, fmt.Errorf("config: %skeytab_file, principal and krb5_conf are required for gssapi", p)
		}
		if err := readableFile(p+"krb5_conf", b.KRB5Conf); err != nil {
			return out, err
		}
	case "simple":
		if b.BindDN == "" || b.PasswordEnv == "" {
			return out, fmt.Errorf("config: %sbind_dn and password_env are required for simple", p)
		}
		if getenv(b.PasswordEnv) == "" {
			return out, fmt.Errorf("config: %spassword_env %s is not set", p, b.PasswordEnv)
		}
	case "":
		return out, fmt.Errorf("config: %smechanism is required: external, gssapi or simple", p)
	default:
		return out, fmt.Errorf("config: %smechanism %q: external, gssapi or simple", p, b.Mechanism)
	}
	return out, nil
}

func checkMapping(m mappingYAML) (directory.Mapping, error) {
	const p = "broker.directory.certificate_mapping."
	kind := directory.MappingKind(m.Kind)
	if !slices.Contains(directory.Kinds, kind) {
		names := make([]string, len(directory.Kinds))
		for i, k := range directory.Kinds {
			names[i] = string(k)
		}
		return directory.Mapping{}, fmt.Errorf("config: %skind %s: one of %s", p, or(m.Kind, `""`), strings.Join(names, ", "))
	}
	out := directory.Mapping{Kind: kind, Attribute: or(m.Attribute, kind.DefaultAttribute()), AllowWeak: m.AllowWeak}
	// A strong kind repointed at another attribute is as strong as that
	// attribute (pre-flight M-4): it takes the weak opt-in and its pin.
	repointed := kind.Strong() && m.Attribute != "" && m.Attribute != kind.DefaultAttribute()
	if repointed && !m.AllowWeak {
		return directory.Mapping{}, fmt.Errorf("config: %sattribute %s: repointing %s makes it as strong as %s; set "+
			"allow_weak: true and list the issuers it is pinned to (design §7)", p, m.Attribute, kind, m.Attribute)
	}
	for i, iss := range m.Issuers {
		if _, err := ldap.ParseDN(iss); err != nil || !strings.Contains(iss, "=") {
			return directory.Mapping{}, fmt.Errorf("config: %sissuers[%d] %q: not an RFC 4514 DN", p, i, iss)
		}
		out.Issuers = append(out.Issuers, iss)
	}
	if repointed && len(out.Issuers) == 0 {
		return directory.Mapping{}, fmt.Errorf("config: %sissuers: a repointed strong mapping is pinned to its "+
			"issuers; list at least one (design §7)", p)
	}
	if !kind.Strong() {
		if !m.AllowWeak {
			return directory.Mapping{}, fmt.Errorf("config: %skind %s is a weak mapping: set allow_weak: true and list "+
				"the issuers it is pinned to (design §7)", p, kind)
		}
		if len(out.Issuers) == 0 {
			return directory.Mapping{}, fmt.Errorf("config: %sissuers: a weak mapping is pinned to its issuers; list "+
				"at least one (design §7)", p)
		}
	}
	return out, nil
}

// refreshInterval resolves broker.refresh_interval (Ruling 12).
func refreshInterval(d time.Duration) (time.Duration, error) {
	d = orD(d, 5*time.Minute)
	if d < time.Minute || d > time.Hour {
		return 0, fmt.Errorf("config: broker.refresh_interval %s: must be 1m to 1h", d)
	}
	return d, nil
}

// descriptor is an LDAP attribute description: a name or a numeric OID
// (RFC 4512 §1.4). A value outside it would be pasted into a filter.
var descriptor = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)+)$`)

// checkSearchShape refuses, at load, a filter that does not compile and an
// attribute that is no descriptor: otherwise a typo is an "error" on every
// query and never a load error.
func checkSearchShape(d *directory.Config) error {
	const p = "broker.directory."
	for _, f := range []struct{ key, v string }{{"user_filter", d.UserFilter}, {"group_filter", d.GroupFilter}} {
		if _, err := ldap.CompileFilter(f.v); err != nil {
			return fmt.Errorf("config: %s%s %q: %v", p, f.key, f.v, err)
		}
	}
	for _, a := range []struct{ key, v string }{{"principal_attribute", d.PrincipalAttribute},
		{"username_attribute", d.UsernameAttribute}, {"group_name_attribute", d.GroupNameAttribute},
		{"member_attribute", d.MemberAttribute}, {"certificate_mapping.attribute", d.Mapping.Attribute}} {
		if !descriptor.MatchString(a.v) {
			return fmt.Errorf("config: %s%s %q: not an attribute descriptor", p, a.key, a.v)
		}
	}
	return nil
}
```

Call `checkSearchShape(d)` in `checkDirectory` just before `return d, nil`, returning its error.

(`go-ldap` is added to `go.mod` here: `go get github.com/go-ldap/ldap/v3@v3.4.14`, then `go mod
tidy`. Task 7 adds the `gssapi` import.)

In `config.go`'s `BrokerConfig`, add:

```go
	// Directory is broker.directory resolved (plan 7g): nil is no
	// directory, and the slice's email-SAN principal and declared human
	// usernames stand.
	Directory    *directory.Config `yaml:"-"`
	DirectorySet *directoryYAML    `yaml:"directory"`
	// RefreshInterval is how often the runner re-verifies every live
	// principal and stamps refreshed_at (spec §5.1.3; plan 7g Ruling 12).
	// Default 5m; 1m to 1h.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
```

In `checkBroker`, after the existing checks:

```go
	if b.DirectorySet != nil {
		d, err := checkDirectory(*b.DirectorySet, os.Getenv)
		if err != nil {
			return nil, err
		}
		b.Directory = d
	}
	ri, err := refreshInterval(b.RefreshInterval)
	if err != nil {
		return nil, err
	}
	b.RefreshInterval = ri
```

Read `checkBroker`'s first lines for how it returns the copy it validated, and follow that.

In `keyfile.go`, export the reader:

```go
// ReadSecret reads a secret file with ReadX509KeyPair's checks: no symlink,
// owned by port49's user or root, no group or other mode bit, at most
// 1 MiB. The directory's keytab is read through it (plan 7g, Ruling 8).
func ReadSecret(path string) ([]byte, error) { return readPrivate(path) }
```

- [ ] **Step 5: Run them to verify they pass**

Run: `go test ./internal/config/ ./internal/keyfile/ ./internal/directory/ -count=1 && go vet ./internal/config/ ./internal/directory/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/directory internal/config internal/keyfile
git commit -m "feat(config): broker.directory and broker.refresh_interval" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: Membership in the store, sealed, with an index by mapping key

**Files:**
- Modify: `internal/store/store.go` (types; the `Store` interface after `SupersededAt`)
- Modify: `internal/store/memory/memory.go`, `internal/store/crypt/crypt.go`,
  `internal/store/guard/guard.go`
- Create: `internal/store/etcd/membership.go`
- Modify: `internal/store/etcd/keys.go:35-50` (two families), `internal/store/etcd/roles.go:47`
  (`daemonNever`), `:130-143` (four probes)
- Create: `internal/store/storetest/membership.go`; Modify: `storetest.go` (`Run`)
- Test: `internal/store/crypt/crypt_test.go`, `internal/store/etcd/roles_test.go:165-190`

**Interfaces:**
- Consumes: `cas` (`etcd/commit.go:96`), `(*wrapped).keys.SealBound/OpenBound`,
  `(*wrapped).openErr` (`crypt.go:346`), `guard`'s `Token` pool.
- Produces:

```go
// store
type Membership struct {
	Principal  string
	DN         string   // sealed
	EntryID    string   // sealed: the entry's immutable id, the principal's pin (Ruling 3)
	Username   string   // sealed
	GroupDNs   []string // sealed
	GroupNames []string // sealed: names verified unique under groups_base_dn
	MapKeys    []string // sealed and in the clear: MapKey of every mapping value the entry answers to
	Refused    bool     // sealed and in the clear: the directory answered no (Ruling 10)
	VerifiedAt time.Time
	Server     string
	Site       string
	Sealed     []byte
}
func MapKey(kind, canonicalValue string) string
// PutMembership writes m under m.Principal and indexes each of m.MapKeys,
// keeping a record verified later than m whole; ttl from now. A key a live
// record of another principal still lists is written ambiguous. A refused
// m (Refused, no groups) supersedes an older record the same way.
PutMembership(ctx context.Context, m Membership, ttl time.Duration) error
// RefuseMapKeys marks each key refused as of at, unless a later
// verification holds it: MembershipByKey then answers ErrNotFound.
RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error
// GetMembership is the record for principal, or ErrNotFound.
GetMembership(ctx context.Context, principal string) (Membership, error)
// MembershipByKey is the record a mapping key indexes, or ErrNotFound when
// none does, the key is ambiguous or refused, or the record no longer
// lists the key.
MembershipByKey(ctx context.Context, mapKey string) (Membership, error)
// MembershipPrincipals is every principal with a live membership record,
// refused ones included, sorted: the set a policy refresh supersedes
// group members' tokens over.
MembershipPrincipals(ctx context.Context) ([]string, error)
// DeleteMembership removes principal's record, refused or not, and with
// it the entry the principal is pinned to, and returns what it held; or
// ErrNotFound when no live record is held. Its mapping keys are left to
// expire: MembershipByKey answers ErrNotFound for a key whose record is
// gone, and a claim treats it as unclaimed. `port49 directory forget`
// alone calls it (Ruling 3's escape; Task 13).
DeleteMembership(ctx context.Context, principal string) (Membership, error)

// storetest
func MembershipKeepsTheLaterAndIsFoundByKey(t *testing.T, b Backend)
func MembershipKeyClaimedTwiceIsAmbiguous(t *testing.T, b Backend)
func MembershipRefusalSupersedes(t *testing.T, b Backend)
func MembershipPrincipalsListsTheLive(t *testing.T, b Backend)
func MembershipExpires(t *testing.T, b Backend)
func MembershipForgetRemovesThePin(t *testing.T, b Backend)
```

- [ ] **Step 1: The failing properties**

Create `internal/store/storetest/membership.go`:

```go
package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// MembershipKeepsTheLaterAndIsFoundByKey: a membership is read back whole
// by principal and by each mapping key it lists; a write verified earlier
// than the one held never replaces it (a slow replica's stale answer must
// not undo a removal another replica verified); a record that stopped
// listing a key is not found by it (plan 7g, Ruling 10).
func MembershipKeepsTheLaterAndIsFoundByKey(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k1, k2 := store.MapKey("issuer_serial", "X509:<I>CN=CA<SR>01"), store.MapKey("issuer_serial", "X509:<I>CN=CA<SR>02")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b2c3d", Username: "alice", GroupDNs: []string{"CN=netops-oncall,OU=G,DC=corp"},
		GroupNames: []string{"netops-oncall"}, MapKeys: []string{k1}, VerifiedAt: t0.Add(-time.Minute),
		Server: "ldaps://dc-01", Site: "us-west"}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMembership(ctx, alice.Principal)
	if err != nil || got.DN != alice.DN || got.EntryID != alice.EntryID || got.Username != "alice" ||
		!slices.Equal(got.GroupDNs, alice.GroupDNs) ||
		!slices.Equal(got.GroupNames, alice.GroupNames) || !slices.Equal(got.MapKeys, alice.MapKeys) ||
		!got.VerifiedAt.Equal(alice.VerifiedAt) || got.Site != "us-west" || got.Refused {
		t.Fatalf("by principal: %+v %v", got, err)
	}
	if byKey, err := s.MembershipByKey(ctx, k1); err != nil || byKey.Principal != alice.Principal {
		t.Fatalf("by key: %+v %v", byKey, err)
	}
	older := alice
	older.GroupDNs, older.GroupNames, older.VerifiedAt = nil, nil, t0.Add(-time.Hour)
	if err := s.PutMembership(ctx, older, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetMembership(ctx, alice.Principal); len(got.GroupDNs) != 1 {
		t.Fatalf("an earlier verification replaced a later one: %+v", got)
	}
	moved := alice
	moved.MapKeys, moved.VerifiedAt = []string{k2}, t0
	if err := s.PutMembership(ctx, moved, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MembershipByKey(ctx, k1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key the record no longer lists: %v, want ErrNotFound", err)
	}
	if _, err := s.GetMembership(ctx, "user:nobody@corp.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no record: %v", err)
	}
}

// MembershipKeyClaimedTwiceIsAmbiguous: a key a live record of another
// principal still lists is never repointed to the last writer. It is
// ambiguous, MembershipByKey answers ErrNotFound, and grace refuses the
// certificate (pre-flight I-5). Once the first record stops listing the
// key, the next verification of the second points it there.
func MembershipKeyClaimedTwiceIsAmbiguous(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.MapKey("san_email", "shared@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,DC=corp", Username: "alice",
		MapKeys: []string{k}, VerifiedAt: t0.Add(-2 * time.Minute)}
	bob := store.Membership{Principal: "user:bob@corp.example.com", DN: "CN=Bob,DC=corp", Username: "bob",
		MapKeys: []string{k}, VerifiedAt: t0.Add(-time.Minute)}
	for _, m := range []store.Membership{alice, bob} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key two live records list: %+v %v, want ErrNotFound", m, err)
	}
	alice.MapKeys, alice.VerifiedAt = nil, t0.Add(-30*time.Second)
	bob.VerifiedAt = t0
	for _, m := range []store.Membership{alice, bob} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := s.MembershipByKey(ctx, k); err != nil || m.Principal != bob.Principal {
		t.Fatalf("once alice stops listing it: %+v %v, want bob", m, err)
	}
}

// MembershipRefusalSupersedes: a refusal (the directory answered
// identity_unmapped, identity_ambiguous or username_collision) replaces an
// older grant-bearing record on both indexes, and an older grant-bearing
// write after it never brings the groups back (pre-flight C-1). A key
// refused by itself answers ErrNotFound while the principal's record by
// name stands.
func MembershipRefusalSupersedes(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k1, k3 := store.MapKey("sid", "S-1-5-21-1-2-3-1104"), store.MapKey("sid", "S-1-5-21-1-2-3-1105")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,DC=corp", Username: "alice",
		GroupDNs: []string{"CN=netops-oncall,DC=corp"}, MapKeys: []string{k1}, VerifiedAt: t0.Add(-time.Minute)}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	refusal := store.Membership{Principal: alice.Principal, EntryID: "guid:0a1b", Refused: true, VerifiedAt: t0}
	if err := s.PutMembership(ctx, refusal, time.Hour); err != nil {
		t.Fatal(err)
	}
	stale := alice
	stale.VerifiedAt = t0.Add(-30 * time.Second)
	if err := s.PutMembership(ctx, stale, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || !got.Refused || len(got.GroupDNs) != 0 ||
		got.EntryID != "guid:0a1b" {
		t.Fatalf("by principal after a refusal: %+v %v, want refused with no groups and its pin", got, err)
	}
	if _, err := s.MembershipByKey(ctx, k1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key after a refusal: %v, want ErrNotFound", err)
	}
	carol := store.Membership{Principal: "user:carol@corp.example.com", DN: "CN=Carol,DC=corp", Username: "carol",
		MapKeys: []string{k3}, VerifiedAt: t0.Add(-time.Minute)}
	if err := s.PutMembership(ctx, carol, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.RefuseMapKeys(ctx, []string{k3}, t0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MembershipByKey(ctx, k3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused key: %v, want ErrNotFound", err)
	}
	if got, err := s.GetMembership(ctx, carol.Principal); err != nil || got.Refused {
		t.Fatalf("a key refused leaves the principal's record: %+v %v", got, err)
	}
}

// MembershipPrincipalsListsTheLive: every principal with a live record,
// refused ones included, sorted (pre-flight I-13).
func MembershipPrincipalsListsTheLive(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	for _, m := range []store.Membership{
		{Principal: "user:bob@corp.example.com", Username: "bob", VerifiedAt: t0},
		{Principal: "user:alice@corp.example.com", Refused: true, VerifiedAt: t0},
	} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: "user:gone@corp.example.com", VerifiedAt: t0},
		time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	got, err := s.MembershipPrincipals(ctx)
	if err != nil || !slices.Equal(got, []string{"user:alice@corp.example.com", "user:bob@corp.example.com"}) {
		t.Fatalf("%v %v", got, err)
	}
}

// MembershipExpires: past its ttl a membership is gone by principal and by
// key, so grace never reads a record the lease has reclaimed.
func MembershipExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	k := store.MapKey("san_email", "carol@corp.example.com")
	m := store.Membership{Principal: "user:carol@corp.example.com", DN: "CN=Carol,DC=corp", Username: "carol",
		MapKeys: []string{k}, VerifiedAt: t0}
	if err := s.PutMembership(ctx, m, time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by principal past ttl: %v", err)
	}
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key past ttl: %v", err)
	}
}

// MembershipForgetRemovesThePin: DeleteMembership returns the record it
// removed, pin included, and leaves nothing to find by principal, by key or
// in the list. A refusal record is forgotten like a membership. A second
// forget finds nothing. Afterwards a write verified earlier than the
// forgotten record is taken, and pins the principal to another entry, and a
// key the forgotten record listed is another principal's to claim, never
// ambiguous (plan 7g, Ruling 3's escape).
func MembershipForgetRemovesThePin(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.MapKey("san_email", "alice@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b", Username: "alice", MapKeys: []string{k}, VerifiedAt: t0}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: alice.Principal, EntryID: "guid:0a1b", Refused: true,
		VerifiedAt: t0.Add(time.Second)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.DeleteMembership(ctx, alice.Principal)
	if err != nil || got.EntryID != "guid:0a1b" || !got.Refused || !got.VerifiedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("forget: %+v %v, want the refusal with its pin", got, err)
	}
	if _, err := s.GetMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by principal after forget: %v", err)
	}
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key after forget: %v", err)
	}
	if ps, err := s.MembershipPrincipals(ctx); err != nil || slices.Contains(ps, alice.Principal) {
		t.Fatalf("listed after forget: %v %v", ps, err)
	}
	if _, err := s.DeleteMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second forget: %v", err)
	}
	rehired := alice
	rehired.EntryID, rehired.VerifiedAt = "guid:9f8e", t0.Add(-time.Minute)
	if err := s.PutMembership(ctx, rehired, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || got.EntryID != "guid:9f8e" {
		t.Fatalf("after forget, the next write pins: %+v %v", got, err)
	}
	if got, err := s.DeleteMembership(ctx, alice.Principal); err != nil || got.EntryID != "guid:9f8e" {
		t.Fatalf("forget again: %+v %v", got, err)
	}
	bob := store.Membership{Principal: "user:bob@corp.example.com", EntryID: "guid:b0b0", Username: "bob",
		MapKeys: []string{k}, VerifiedAt: t0.Add(2 * time.Second)}
	if err := s.PutMembership(ctx, bob, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.MembershipByKey(ctx, k); err != nil || got.Principal != bob.Principal {
		t.Fatalf("a forgotten record's key: %+v %v, want bob's", got, err)
	}
}
```

Add all six to `Run`'s list. For etcd, read how `SupersededIsTheLaterAndExpires` gets expiry
from a moved clock (the `etcd` backend's `now` drives `live`), and use the same: expiry is
judged on read against the record's `expires_at`, with the lease as the reclaim.

Add two crypt-only tests in `internal/store/crypt/crypt_test.go`, each through `crypt.Wrap`
over memory, each asserting the alarm counter
`port49_crypt_open_failures_total{record="membership"}` moved:
- `TestAMembershipsVerifiedAtMovedInTheClearIsRefused`: rewrite the inner record's plaintext
  `VerifiedAt` an hour later; `GetMembership` returns an error. A store write must not extend
  grace.
- `TestAMembershipKeyAddedInTheClearIsRefused` (pre-flight I-6): put alice (an admin, key
  `k1`) through crypt. On the inner memory store, read alice's record with
  `inner.GetMembership`, append a victim's key `k2` to its plaintext `MapKeys`, and put it back
  on the inner store with the same `VerifiedAt` (an equal-time write replaces the held one, and
  claims `k2` for alice). `MembershipByKey(k2)` through crypt answers an error, never alice's
  membership. Then put a refusal for carol through crypt, flip the inner record's plaintext
  `Refused` to false the same way, and assert `GetMembership(carol)` through crypt returns an
  error.

Extend `TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord`
(`internal/store/etcd/roles_test.go:165-190`) with two cases (pre-flight I-7):

```go
		{etcdtest.Grant{Role: RoleDaemon, Key: membership, RangeEnd: clientv3.GetPrefixRangeEnd(membership)},
			"it was allowed reading " + membership},
		{etcdtest.Grant{Role: RoleDaemon, Key: membershipK, RangeEnd: clientv3.GetPrefixRangeEnd(membershipK)},
			"it was allowed reading " + membershipK},
```

with `membership, membershipK := newKeys(prefix).family(famMembership), newKeys(prefix).family(famMembershipK)`
beside `ledger, superseded`, and the doc comment's first sentence extended: "… or any access to
sp/, mb/ or mk/ …: the last two hold every principal's groups (plan 7g, Ruling 10)".

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/store/... -run 'Membership|CheckIdentityRefuses' -count=1`
Expected: FAIL, undefined `PutMembership`, `MapKey`, `famMembership`.

- [ ] **Step 3: The type, the key, the interface**

In `store.go`, after `SupersededFor`:

```go
// Membership is one principal's directory answer as the broker last
// verified it (plan 7g; decision 38): the entry its certificate mapped to,
// the username and groups read from it, and when and where. The broker's
// role alone reads or writes it.
type Membership struct {
	Principal string
	DN        string // sealed
	// EntryID is the entry's immutable id ("guid:" + objectGUID hex,
	// "uuid:" + entryUUID, else "dn:" + the canonical DN): the entry the
	// principal is pinned to (Ruling 3). A refusal keeps it.
	EntryID    string   // sealed
	Username   string   // sealed
	GroupDNs   []string // sealed: every group the entry is in, under the nested mode
	GroupNames []string // sealed: their names, those verified unique under groups_base_dn
	// MapKeys are MapKey(kind, value) for every certificate-mapping value the
	// entry answers to: the index a bind in grace finds the principal by.
	// Sealed, and in the clear for the backend's index; crypt refuses a
	// record whose two differ, so a store write cannot add a victim's key
	// to an admin's record.
	MapKeys []string
	// Refused is the directory's "no" (identity_unmapped,
	// identity_ambiguous, username_collision) as of VerifiedAt: no groups,
	// and grace never serves it (Ruling 10). Sealed and in the clear, as
	// MapKeys.
	Refused    bool
	VerifiedAt time.Time // sealed too: in the clear alone, a store write could extend grace
	Server     string
	Site       string
	Sealed     []byte // written by internal/store/crypt; nil in plaintext form
}

// MapKey is the index key of one certificate-mapping value: a hash, so the
// plaintext index names no certificate value. canonicalValue is the
// mapping's canonical form (the directory package's canonicalValue), the
// same on the certificate's side and the entry's.
func MapKey(kind, canonicalValue string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + canonicalValue))
	return hex.EncodeToString(sum[:])
}
```

and the six methods in the interface, after `SupersededAt`, with the comments of Interfaces.

- [ ] **Step 4: memory, crypt, guard**

`memory.go`: two maps under `s.mu`, `memberships map[string]membershipEntry` (the record and
its expiry) and `memberKeys map[string]memberKeyEntry` (`principal`, `prior`, `verifiedAt`,
`expires`). It mirrors etcd's rules exactly (pre-flight M-2):
- `PutMembership`: keep the held, live record when its `VerifiedAt` is after `m.VerifiedAt`
  (and then write no key); else store a deep copy, slices cloned, and for each of `m.MapKeys`
  apply `claimKey` below.
- `claimKey(key, m)`: a held, live entry verified after `m` stands. One naming `m.Principal`
  is renewed. Otherwise let `other` be the entry's `principal`, or its `prior` when that is
  empty. If `other` is non-empty and `other`'s live, unrefused record lists `key`, write the
  ambiguous entry `{principal: "", prior: other, verifiedAt: m.VerifiedAt}`; else point the key
  at `m.Principal`.
- `RefuseMapKeys`: for each key, unless a held, live entry is verified after `at`, write
  `{principal: "", prior: "", verifiedAt: at}`.
- `GetMembership`: expired → delete, `ErrNotFound`.
- `MembershipByKey`: key → entry; `ErrNotFound` when absent, expired or `principal == ""`;
  then the record, `ErrNotFound` unless it is unrefused and `slices.Contains(rec.MapKeys, key)`.
- `MembershipPrincipals`: the live records' principals, sorted.
- `DeleteMembership`: remove the record and return a deep copy of it; an absent or expired
  one is `ErrNotFound` (an expired one is removed all the same). `memberKeys` is left alone,
  as etcd leaves `mk/`.

`crypt.go`:

```go
// membershipSecret is a membership's sealed part, bound to its principal.
// MapKeys and Refused are sealed as well as kept in the clear: the clear
// copies are the backend's index, the sealed ones the truth.
type membershipSecret struct {
	DN         string    `json:"dn"`
	EntryID    string    `json:"entry_id"`
	Username   string    `json:"username"`
	GroupDNs   []string  `json:"group_dns"`
	GroupNames []string  `json:"group_names"`
	MapKeys    []string  `json:"map_keys"`
	Refused    bool      `json:"refused"`
	VerifiedAt time.Time `json:"verified_at"`
}

var (
	errVerifiedMoved = errors.New("crypt: a membership's plaintext verified_at differs from its sealed one")
	errMembershipMoved = errors.New("crypt: a membership's plaintext map keys or refusal differ from its sealed ones")
	// errKeyNotSealed is a key the index points at a record whose sealed
	// list does not hold it: a store write, answered as no membership.
	errKeyNotSealed = fmt.Errorf("crypt: a membership key its sealed record does not list: %w", store.ErrNotFound)
)

func membershipAAD(principal string) []byte { return []byte("membership\x00" + principal) }

func (w *wrapped) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	b, err := json.Marshal(membershipSecret{DN: m.DN, EntryID: m.EntryID, Username: m.Username, GroupDNs: m.GroupDNs,
		GroupNames: m.GroupNames, MapKeys: m.MapKeys, Refused: m.Refused, VerifiedAt: m.VerifiedAt})
	if err != nil {
		return err
	}
	sealed, err := w.keys.SealBound(b, membershipAAD(m.Principal))
	if err != nil {
		return err
	}
	return w.inner.PutMembership(ctx, store.Membership{Principal: m.Principal, MapKeys: m.MapKeys,
		Refused: m.Refused, VerifiedAt: m.VerifiedAt, Server: m.Server, Site: m.Site, Sealed: sealed}, ttl)
}

func (w *wrapped) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	return w.inner.RefuseMapKeys(ctx, mapKeys, at, ttl)
}

func (w *wrapped) openMembership(m store.Membership, err error) (store.Membership, error) {
	if err != nil {
		return store.Membership{}, err
	}
	b, err := w.keys.OpenBound(m.Sealed, membershipAAD(m.Principal))
	if err != nil {
		return store.Membership{}, w.openErr("membership", m.Sealed, err)
	}
	var ms membershipSecret
	if err := json.Unmarshal(b, &ms); err != nil {
		return store.Membership{}, w.openErr("membership", m.Sealed, err)
	}
	if !ms.VerifiedAt.Equal(m.VerifiedAt) {
		return store.Membership{}, w.openErr("membership", m.Sealed, errVerifiedMoved)
	}
	if ms.Refused != m.Refused || !slices.Equal(ms.MapKeys, m.MapKeys) {
		return store.Membership{}, w.openErr("membership", m.Sealed, errMembershipMoved)
	}
	m.DN, m.EntryID, m.Username, m.GroupDNs, m.GroupNames, m.Sealed = ms.DN, ms.EntryID, ms.Username, ms.GroupDNs,
		ms.GroupNames, nil
	return m, nil
}

func (w *wrapped) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	return w.openMembership(w.inner.GetMembership(ctx, principal))
}

func (w *wrapped) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	m, err := w.openMembership(w.inner.MembershipByKey(ctx, mapKey))
	if err != nil {
		return store.Membership{}, err
	}
	// The sealed list is the truth (pre-flight I-6): the inner backend
	// checked the clear one, which openMembership has proved equal, and this
	// check stands should that ever change.
	if m.Refused || !slices.Contains(m.MapKeys, mapKey) {
		return store.Membership{}, w.openErr("membership", nil, errKeyNotSealed)
	}
	return m, nil
}

func (w *wrapped) MembershipPrincipals(ctx context.Context) ([]string, error) {
	return w.inner.MembershipPrincipals(ctx)
}

// DeleteMembership removes the record whatever it holds, and returns it
// opened. A record that does not open has been removed all the same: it
// served nothing, and forgetting it is what the operator asked. It is
// returned with its sealed part empty, its failure counted by openErr.
func (w *wrapped) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	m, err := w.inner.DeleteMembership(ctx, principal)
	if err != nil {
		return store.Membership{}, err
	}
	opened, err := w.openMembership(m, nil)
	if err != nil {
		m.Sealed = nil
		return m, nil
	}
	return opened, nil
}
```

Read `openErr` (`crypt.go:346`) first: it counts `crypt_open_failures_total{record}` and calls
`onUnopenable(record, SealedKeyID(sealed), err)`; `SealedKeyID(nil)` returns `""`
(`crypt.go:300`). If the counter pre-registers labels, add `membership` there.

`guard.go`: `"PutMembership": Token, "RefuseMapKeys": Token, "GetMembership": Token,
"MembershipByKey": Token, "MembershipPrincipals": Token, "DeleteMembership": Token` in the table
(the broker's pool; never the context pool authorization reads), and six wrappers through
`g.do(ctx, Token, …)`.

- [ ] **Step 5: etcd**

In `keys.go`, add the families and key functions:

```go
	famMembership  = "mb/" // mb/<principal>: a directory membership (plan 7g), the broker's alone
	famMembershipK = "mk/" // mk/<map key>: the principal a mapping value resolved to
```

```go
func (k keys) membership(principal string) string { return k.root + famMembership + esc(principal) }
func (k keys) membershipKey(mapKey string) string { return k.root + famMembershipK + esc(mapKey) }
```

In `roles.go`, add both to `daemonNever`, and add four probes to `CheckIdentity`'s list,
after the superseded ones: `reading` and `writing` for each of `famMembership` and
`famMembershipK`. The broker must hold them, and the daemon must be refused them; a daemon
allowed either fails its start with `ErrNotSeparated`.

Create `internal/store/etcd/membership.go`:

```go
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// membershipRec is mb/<principal> (plan 7g, Ruling 10): what crypt sealed,
// the plaintext the backend keeps the later of, and its expiry.
type membershipRec struct {
	Principal  string    `json:"principal"`
	DN         string    `json:"dn,omitempty"`
	EntryID    string    `json:"entry_id,omitempty"`
	Username   string    `json:"username,omitempty"`
	GroupDNs   []string  `json:"group_dns,omitempty"`
	GroupNames []string  `json:"group_names,omitempty"`
	MapKeys    []string  `json:"map_keys,omitempty"`
	Refused    bool      `json:"refused,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	Server     string    `json:"server,omitempty"`
	Site       string    `json:"site,omitempty"`
	Sealed     []byte    `json:"sealed,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// membershipKeyRec is mk/<map key>: the principal, and the verification
// that pointed it there, so a later one wins. Principal "" is a key no
// grace bind may use: ambiguous (Prior names the principal whose live
// record still claims it) or refused (Prior "").
type membershipKeyRec struct {
	Principal  string    `json:"principal"`
	Prior      string    `json:"prior,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// PutMembership keeps the later verification at mb/, by a compare on the
// record's revision, then claims each key the same way. The two are not
// one transaction: a reader finding a key whose record no longer lists it
// is answered ErrNotFound (MembershipByKey), so a torn write is a miss,
// never another principal's membership.
func (s *Store) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	now := s.now()
	exp := now.Add(ttl)
	kept := false
	err := cas(ctx, s.tok, s.tokLeases, s.k.membership(m.Principal),
		func(r membershipRec) bool { return r.ExpiresAt.After(now) },
		func(r *membershipRec, found bool) (bool, time.Time, bool, error) {
			if found && r.VerifiedAt.After(m.VerifiedAt) {
				kept = true
				return false, time.Time{}, false, nil
			}
			*r = membershipRec{Principal: m.Principal, DN: m.DN, EntryID: m.EntryID, Username: m.Username, GroupDNs: m.GroupDNs,
				GroupNames: m.GroupNames, MapKeys: m.MapKeys, Refused: m.Refused, VerifiedAt: m.VerifiedAt,
				Server: m.Server, Site: m.Site, Sealed: m.Sealed, ExpiresAt: exp}
			return true, exp, false, nil
		})
	if err != nil || kept {
		return err
	}
	for _, key := range m.MapKeys {
		if err := s.claimKey(ctx, key, m.Principal, m.VerifiedAt, exp, now); err != nil {
			return err
		}
	}
	return nil
}

// claimKey points key at principal as of at, unless a later verification
// holds it, or a live record of another principal still lists it: then the
// key is ambiguous (pre-flight I-5), never the last writer's.
func (s *Store) claimKey(ctx context.Context, key, principal string, at, exp, now time.Time) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
		func(r membershipKeyRec) bool { return r.ExpiresAt.After(now) },
		func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
			if found && r.VerifiedAt.After(at) {
				return false, time.Time{}, false, nil
			}
			other := ""
			if found && r.Principal != principal {
				other = r.Principal
				if other == "" {
					other = r.Prior
				}
			}
			if other != "" {
				held, err := s.GetMembership(ctx, other)
				switch {
				case err == nil && !held.Refused && slices.Contains(held.MapKeys, key):
					*r = membershipKeyRec{Principal: "", Prior: other, VerifiedAt: at, ExpiresAt: exp}
					return true, exp, false, nil
				case err != nil && !errors.Is(err, store.ErrNotFound):
					return false, time.Time{}, false, err
				}
			}
			*r = membershipKeyRec{Principal: principal, VerifiedAt: at, ExpiresAt: exp}
			return true, exp, false, nil
		})
}

// RefuseMapKeys marks each key refused as of at (Ruling 10): the
// directory answered no for it, and grace must not answer yes.
func (s *Store) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	now := s.now()
	exp := now.Add(ttl)
	for _, key := range mapKeys {
		if err := cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
			func(r membershipKeyRec) bool { return r.ExpiresAt.After(now) },
			func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
				if found && r.VerifiedAt.After(at) {
					return false, time.Time{}, false, nil
				}
				*r = membershipKeyRec{VerifiedAt: at, ExpiresAt: exp}
				return true, exp, false, nil
			}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	var r membershipRec
	if err := s.getLive(ctx, s.k.membership(principal), &r, func() bool { return r.ExpiresAt.After(s.now()) }); err != nil {
		return store.Membership{}, err
	}
	return r.membership(), nil
}

func (r membershipRec) membership() store.Membership {
	return store.Membership{Principal: r.Principal, DN: r.DN, EntryID: r.EntryID, Username: r.Username,
		GroupDNs: r.GroupDNs, GroupNames: r.GroupNames, MapKeys: r.MapKeys, Refused: r.Refused, VerifiedAt: r.VerifiedAt,
		Server: r.Server, Site: r.Site, Sealed: r.Sealed}
}

// DeleteMembership deletes mb/<principal> in one op that returns what it
// held (Ruling 3's escape). Its mk/ keys stay until their leases end:
// MembershipByKey answers ErrNotFound for a key whose record is gone, and
// claimKey treats it as unclaimed. A record that does not decode is
// deleted all the same and returned as its principal alone.
func (s *Store) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	resp, err := s.tok.Delete(ctx, s.k.membership(principal), clientv3.WithPrevKV())
	if err != nil {
		return store.Membership{}, unavailable(err)
	}
	if len(resp.PrevKvs) == 0 {
		return store.Membership{}, store.ErrNotFound
	}
	var r membershipRec
	if json.Unmarshal(resp.PrevKvs[0].Value, &r) != nil {
		return store.Membership{Principal: principal}, nil
	}
	if !r.ExpiresAt.After(s.now()) {
		return store.Membership{}, store.ErrNotFound
	}
	return r.membership(), nil
}

func (s *Store) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	var kr membershipKeyRec
	if err := s.getLive(ctx, s.k.membershipKey(mapKey), &kr, func() bool { return kr.ExpiresAt.After(s.now()) }); err != nil {
		return store.Membership{}, err
	}
	if kr.Principal == "" {
		return store.Membership{}, store.ErrNotFound
	}
	m, err := s.GetMembership(ctx, kr.Principal)
	if err != nil {
		return store.Membership{}, err
	}
	if m.Refused || !slices.Contains(m.MapKeys, mapKey) {
		return store.Membership{}, store.ErrNotFound
	}
	return m, nil
}

// MembershipPrincipals pages mb/ as eachIndexed pages ix/: 500 at a time,
// a record that does not decode skipped and said.
func (s *Store) MembershipPrincipals(ctx context.Context) ([]string, error) {
	prefix := s.k.family(famMembership)
	end := clientv3.GetPrefixRangeEnd(prefix)
	now := s.now()
	var out []string
	for from := prefix; ; {
		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
		if err != nil {
			return nil, unavailable(err)
		}
		for _, kv := range resp.Kvs {
			var r membershipRec
			if json.Unmarshal(kv.Value, &r) != nil {
				continue // the key names the principal; supersession over it is said by the caller's miss
			}
			if r.ExpiresAt.After(now) {
				out = append(out, r.Principal)
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			break
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	sort.Strings(out)
	return out, nil
}

// getLive reads key into v on the token pool, ErrNotFound when absent or
// when live() is false once decoded.
func (s *Store) getLive(ctx context.Context, key string, v any, live func() bool) error {
	resp, err := s.tok.Get(ctx, key)
	if err != nil {
		return unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return store.ErrNotFound
	}
	if json.Unmarshal(resp.Kvs[0].Value, v) != nil {
		return notDecoded(key)
	}
	if !live() {
		return store.ErrNotFound
	}
	return nil
}
```

`cas`'s callback returns `(write, exp, keep,
err)` (`commit.go:89-96`): `write false` leaves the record and returns nil, `exp` is the
lease's expiry, and `keep false` gives the write a fresh lease at `exp`. A record that does
not decode in `MembershipPrincipals` is skipped: say it through the store's existing
`undecodableIndex`-style line if one fits (read `indexes.go:111`), never its body.

- [ ] **Step 6: Run them to verify they pass**

Run: `go test ./internal/store/... -count=1 && go vet ./internal/store/...`
Expected: PASS: the six properties on memory, crypt, etcd and crypt-over-etcd; the two
crypt tamper tests; `roles_test.go` with `mb/` and `mk/` refused to the daemon.

- [ ] **Step 7: Commit**

```bash
git add internal/store
git commit -m "feat(store): a directory membership record, sealed, indexed by mapping key, refusable, the broker's alone" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The server pool: ranking, sticky selection, breakers, health checks, failback, sites

**Files:**
- Create: `internal/directory/pool.go`, `internal/directory/pool_test.go`,
  `internal/directory/fake_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (four series, registered beside the cert-status
  ones at `:605`)

**Interfaces:**
- Consumes: `directory.Config`, `directory.Server` (Task 4).
- Produces:

```go
// Searcher is what one query sees: a connection whose searches are bounded
// by that query's deadline. Everything above the pool uses it.
type Searcher interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}
// Client is one bound connection to one server, shared by concurrent
// queries. SearchContext past ctx abandons its own message and returns
// ctx.Err(), leaving the connection and every other search on it alone
// (pre-flight I-3). pagingSize 0 is one unpaged search. Task 7's dial
// returns one over *ldap.Conn's SearchAsync.
type Client interface {
	SearchContext(ctx context.Context, req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}
// Dialer opens and binds a connection to s within ctx.
type Dialer func(ctx context.Context, s Server) (Client, error)
var ErrUnavailable = errors.New("directory: no server answered")
func Fault(err error) bool
func NewPool(cfg Config, dial Dialer, check func(ctx context.Context, s Searcher) error,
	now func() time.Time, m *metrics.Metrics, say func(format string, args ...any)) *Pool
func (p *Pool) Do(ctx context.Context, f func(Searcher) error) (Server, error)
func (p *Pool) Check(ctx context.Context)
func (p *Pool) Run(ctx context.Context)
func (p *Pool) Selected() (Server, bool)
func (p *Pool) Ranked() []Server

// metrics.Metrics gains
DirectoryQueries        *prometheus.CounterVec // port49_directory_queries_total{server,outcome}: ok, fault, error, refused
DirectoryServerUp       *prometheus.GaugeVec   // port49_directory_server_up{server}
DirectorySelected       *prometheus.GaugeVec   // port49_directory_selected{server}
DirectorySiteCrossings  prometheus.Counter     // port49_directory_site_crossings_total
```

- [ ] **Step 1: The fakes**

Create `internal/directory/fake_test.go`:

```go
package directory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration)     { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func newClock() *fakeClock                   { return &fakeClock{now: time.Unix(1_000_000, 0).UTC()} }

// fakeDir is one directory server's data and behaviour, shared by every
// connection dialled to it. It answers a search by its exact filter
// string: what a test registers is the filter port49 must send, so a test
// asserts the filter as well as what is done with the answer. An
// unregistered filter answers no entries. err, keyed by filter, answers
// that error instead. delay holds every answer; slow, keyed by filter,
// holds that filter's alone. A fakeDir is itself a Searcher with no
// deadline, for the tests of Tasks 8 and 9 that search it directly.
type fakeDir struct {
	mu       sync.Mutex
	byFilter map[string][]*ldap.Entry
	err      map[string]error
	delay    time.Duration
	slow     map[string]time.Duration
	calls    []*ldap.SearchRequest
}

func newFakeDir() *fakeDir {
	return &fakeDir{byFilter: map[string][]*ldap.Entry{}, err: map[string]error{}, slow: map[string]time.Duration{}}
}

func (d *fakeDir) on(filter string, entries ...*ldap.Entry) { d.byFilter[filter] = entries }

// search answers req after its delay, or at once with ctx's error when ctx
// ends first (its own search abandoned, as SearchAsync does), or with a
// network error when closed is closed (the connection under it went).
func (d *fakeDir) search(ctx context.Context, closed <-chan struct{}, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.mu.Lock()
	d.calls = append(d.calls, req)
	delay := d.delay
	if s, ok := d.slow[req.Filter]; ok {
		delay = s
	}
	e, es := d.err[req.Filter], d.byFilter[req.Filter]
	d.mu.Unlock()
	select {
	case <-closed:
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(delay):
	}
	if e != nil {
		return nil, e
	}
	if req.SizeLimit > 0 && len(es) > req.SizeLimit {
		return &ldap.SearchResult{Entries: es[:req.SizeLimit]}, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
	}
	return &ldap.SearchResult{Entries: es}, nil
}

func (d *fakeDir) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return d.search(context.Background(), nil, req)
}

func (d *fakeDir) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return d.Search(req)
}

// fakeConn is one dialled connection to a fakeDir, with its own close, so
// a test sees what closing one connection does to the searches on it.
type fakeConn struct {
	d      *fakeDir
	closed chan struct{}
	once   sync.Once
}

func (c *fakeConn) SearchContext(ctx context.Context, req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return c.d.search(ctx, c.closed, req)
}

func (c *fakeConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// entry builds an entry from attribute pairs.
func entry(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

// fakeServers is a Dialer over per-URI behaviour: down refuses the dial
// with a network error, refuse[uri] refuses the bind with that error,
// dirs[uri] is the server a dial reaches, and each dial is a fresh
// fakeConn to it (pre-flight I-3), kept in conns. dialDelay holds each
// dial, so concurrent queries race to dial.
type fakeServers struct {
	mu        sync.Mutex
	dirs      map[string]*fakeDir
	down      map[string]bool
	refuse    map[string]error
	dials     map[string]int
	conns     map[string][]*fakeConn
	dialDelay time.Duration
}

func newFakeServers(uris ...string) *fakeServers {
	f := &fakeServers{dirs: map[string]*fakeDir{}, down: map[string]bool{}, refuse: map[string]error{},
		dials: map[string]int{}, conns: map[string][]*fakeConn{}}
	for _, u := range uris {
		f.dirs[u] = newFakeDir()
	}
	return f
}

func (f *fakeServers) dial(ctx context.Context, s Server) (Client, error) {
	f.mu.Lock()
	f.dials[s.URI]++
	down, refuse, delay := f.down[s.URI], f.refuse[s.URI], f.dialDelay
	f.mu.Unlock()
	time.Sleep(delay)
	switch {
	case down:
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dial tcp: connection refused"))
	case refuse != nil:
		return nil, refuse
	}
	c := &fakeConn{d: f.dirs[s.URI], closed: make(chan struct{})}
	f.mu.Lock()
	f.conns[s.URI] = append(f.conns[s.URI], c)
	f.mu.Unlock()
	return c, nil
}

// open is how many of uri's dialled connections are not closed.
func (f *fakeServers) open(uri string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.conns[uri] {
		if !c.isClosed() {
			n++
		}
	}
	return n
}

func (f *fakeServers) setRefuse(uri string, err error) { f.mu.Lock(); f.refuse[uri] = err; f.mu.Unlock() }

func (f *fakeServers) setDown(uri string, down bool) { f.mu.Lock(); f.down[uri] = down; f.mu.Unlock() }
```

- [ ] **Step 2: The failing tests**

Create `internal/directory/pool_test.go`:

```go
package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
)

func poolCfg(site string, servers ...Server) Config {
	return Config{Servers: servers, Site: site, QueryTimeout: time.Second, HealthInterval: 30 * time.Second,
		HealthTimeout: 2 * time.Second, FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: 5 * time.Minute}
}

type lines struct {
	mu sync.Mutex
	l  []string
}

func (s *lines) say(f string, a ...any) { s.mu.Lock(); s.l = append(s.l, fmt.Sprintf(f, a...)); s.mu.Unlock() }
func (s *lines) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, l := range s.l {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func (s *lines) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.l {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func noCheck(context.Context, Searcher) error { return nil }

var (
	west1 = Server{URI: "ldaps://dc-01", Priority: 100, Site: "us-west"}
	west2 = Server{URI: "ldaps://dc-02", Priority: 90, Site: "us-west"}
	east  = Server{URI: "ldaps://dc-03", Priority: 200, Site: "us-east"}
)

// Same site first, then priority, then file order (Ruling 9): dc-03's
// higher priority does not pull a us-west broker across sites.
func TestRankingIsSameSiteFirstThenPriority(t *testing.T) {
	p := NewPool(poolCfg("us-west", east, west2, west1), newFakeServers().dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	got := p.Ranked()
	if got[0] != west1 || got[1] != west2 || got[2] != east {
		t.Fatalf("%v", got)
	}
	p = NewPool(poolCfg("", east, west2, west1), newFakeServers().dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	if got := p.Ranked(); got[0] != east {
		t.Fatalf("with no site, priority alone: %v", got)
	}
}

// Sticky: every query goes to the selected server while it answers, and a
// query error that is the server's answer (no such object) is not a
// fault and moves nothing.
func TestStickyUntilAFault(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].err["(bad)"] = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	for i := 0; i < 5; i++ {
		srv, err := p.Do(context.Background(), func(s Searcher) error {
			_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
			return err
		})
		if err != nil || srv != west1 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	srv, err := p.Do(context.Background(), func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(bad)"})
		return err
	})
	if srv != west1 || !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("a query's answer: %v %v", srv, err)
	}
	if sel, _ := p.Selected(); sel != west1 {
		t.Fatalf("an answer moved the selection to %v", sel)
	}
}

// A slow server (answers after query_timeout) fails the query over to the
// next within the one query_timeout, and opens its breaker after
// failure_threshold such queries; queries do not retry it while open
// (Review Focus 2).
func TestASlowServerFailsOverWithinTheQueryTimeout(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].delay = 2 * time.Second
	cfg := poolCfg("us-west", west1, west2)
	cfg.QueryTimeout, cfg.HealthTimeout = 600*time.Millisecond, 300*time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	search := func(_ context.Context, s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
		return err
	}
	p := NewPool(cfg, f.dial, search, newClock().Now, m, say.say)
	query := func() (Server, error) {
		return p.Do(context.Background(), func(s Searcher) error { return search(context.Background(), s) })
	}
	start := time.Now()
	if _, err := query(); err != nil && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the first query: %v", err)
	}
	if time.Since(start) > cfg.QueryTimeout+300*time.Millisecond {
		t.Fatalf("the first query took %v; query_timeout bounds it", time.Since(start))
	}
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("a fault did not end dc-01's selection: %v", sel)
	}
	calls := len(f.dirs[west1.URI].calls)
	for i := 0; i < 2; i++ {
		if srv, err := query(); err != nil || srv != west2 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	if len(f.dirs[west1.URI].calls) != calls {
		t.Fatal("a query went back to dc-01 before failback")
	}
	for i := 0; i < 3; i++ { // dc-01 answers each check too late
		p.Check(context.Background())
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.URI)) != 0 || !say.has("its breaker is open") {
		t.Fatalf("the breaker did not open on slow checks: %v", say.l)
	}
}

// Failback waits for stability_window of passing health checks: a server
// that returns is not selected again at its first pass, and a fault inside
// the window starts it again (Review Focus 2).
func TestFailbackWaitsForTheStabilityWindow(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), say.say)
	f.setDown(west1.URI, true)
	for i := 0; i < 3; i++ {
		p.Check(context.Background())
		clk.Add(30 * time.Second)
	}
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("dc-01 down: selected %v", sel)
	}
	f.setDown(west1.URI, false)
	clk.Add(time.Minute) // past probe_interval
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("selected again at its first pass: %v", sel)
	}
	clk.Add(3 * time.Minute)
	f.setDown(west1.URI, true)
	p.Check(context.Background()) // a fault inside the window
	f.setDown(west1.URI, false)
	clk.Add(3 * time.Minute)
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("a fault inside the window did not restart it: %v", sel)
	}
	clk.Add(5 * time.Minute)
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west1 || !say.has("passed every health check for 5m0s") {
		t.Fatalf("after the window: %v %v", sel, say.l)
	}
}

// A breaker opens after failure_threshold faults, and only the health
// check probes it, once per probe_interval.
func TestTheBreakerOpensAfterThresholdAndOnlyTheCheckProbesIt(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	f.setDown(west1.URI, true)
	for i := 0; i < 3; i++ {
		p.Check(context.Background())
	}
	dials := f.dials[west1.URI]
	clk.Add(30 * time.Second)
	p.Check(context.Background()) // inside probe_interval: not dialled
	if f.dials[west1.URI] != dials {
		t.Fatal("an open breaker was dialled before probe_interval")
	}
	clk.Add(31 * time.Second)
	p.Check(context.Background())
	if f.dials[west1.URI] != dials+1 {
		t.Fatal("the probe did not dial")
	}
}

// A site crossing is a consistency event: said with both sites and both
// servers, and counted (design §10: "MUST be logged").
func TestASiteCrossingIsAConsistencyEvent(t *testing.T) {
	f := newFakeServers(west1.URI, east.URI)
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1, east), f.dial, noCheck, newClock().Now, m, say.say)
	f.setDown(west1.URI, true)
	if srv, err := p.Do(context.Background(), func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
		return err
	}); err != nil || srv != east {
		t.Fatalf("%v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectorySiteCrossings) != 1 ||
		!say.has("consistency event: crossing from site us-west to us-east (ldaps://dc-01 to ldaps://dc-03)") {
		t.Fatalf("%v", say.l)
	}
}

// A caller that went away is no fault: a cancelled mint must not open a
// healthy server's breaker.
func TestACallerThatWentAwayIsNoFault(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dirs[west1.URI].delay = 200 * time.Millisecond
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		_, _ = p.Do(ctx, func(s Searcher) error {
			_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
			return err
		})
	}
	if sel, ok := p.Selected(); !ok || sel != west1 {
		t.Fatalf("cancelled callers moved the selection: %v %v", sel, ok)
	}
}

// Fault is the server's, not the query's: network, timeout, busy,
// unavailable, unwilling, other, time limit; never no-such-object or
// invalid credentials of a query.
func TestFaultClassifies(t *testing.T) {
	for code, want := range map[uint16]bool{ldap.ErrorNetwork: true, ldap.LDAPResultBusy: true,
		ldap.LDAPResultUnavailable: true, ldap.LDAPResultUnwillingToPerform: true, ldap.LDAPResultOther: true,
		ldap.LDAPResultTimeLimitExceeded: true, ldap.LDAPResultNoSuchObject: false,
		ldap.LDAPResultSizeLimitExceeded: false, ldap.LDAPResultFilterError: false} {
		if got := Fault(ldap.NewError(code, errors.New("x"))); got != want {
			t.Errorf("code %d: %v", code, got)
		}
	}
	if !Fault(context.DeadlineExceeded) {
		t.Error("a deadline is a fault")
	}
}

func searchFor(filter string) func(Searcher) error {
	return func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: filter})
		return err
	}
}

// One query slow past query_timeout among twenty fast ones on the same
// connection: the slow one abandons its own search, the fast ones answer,
// the connection is never closed under them, and the breaker stays closed
// (pre-flight I-3).
func TestOneSlowQueryLeavesTheOthersAlone(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].delay = 50 * time.Millisecond
	f.dirs[west1.URI].slow["(slow)"] = 2 * time.Second
	cfg := poolCfg("us-west", west1, west2)
	cfg.QueryTimeout = 500 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, (&lines{}).say)
	if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(slow)")) }()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a fast query: %v", err)
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.URI)) != 1 {
		t.Fatal("one slow query opened dc-01's breaker")
	}
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.URI, "fault")); n > 1 {
		t.Fatalf("%v faults counted on dc-01; one slow query is one", n)
	}
	if f.dials[west1.URI] != 1 || f.open(west1.URI) != 1 {
		t.Fatalf("dc-01 dialled %d times, %d open: its connection was closed under the others",
			f.dials[west1.URI], f.open(west1.URI))
	}
}

// Queries racing to dial an idle server keep one connection and close the
// rest (pre-flight M-8).
func TestRacingQueriesKeepOneConnection(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dialDelay = 50 * time.Millisecond
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(x)")) }()
	}
	wg.Wait()
	if n := f.open(west1.URI); n != 1 {
		t.Fatalf("%d connections to dc-01 left open, want 1", n)
	}
}

// A refused bind is this server not answering (pre-flight I-2): the query
// fails over; with every server refusing it is ErrUnavailable, so grace
// applies above; the refusal is said once an hour per server with the
// mechanism and the result code; and a refusal neither opens the breaker
// nor resets the fault count the health checks built.
func TestABindRefusalFailsOverAndReachesUnavailable(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f.setRefuse(west1.URI, invalid)
	cfg := poolCfg("us-west", west1, west2)
	cfg.Bind.Mechanism = "simple"
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, say.say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("a refusal on dc-01 did not fail over: %v %v", srv, err)
	}
	f.setRefuse(west2.URI, invalid)
	for i := 0; i < 3; i++ {
		if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("every server refusing: %v, want ErrUnavailable", err)
		}
	}
	if n := say.count("ldaps://dc-01 refused the bind (simple): LDAP Result Code 49"); n != 1 {
		t.Fatalf("the refusal said %d times in the hour: %v", n, say.l)
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.URI)) != 1 {
		t.Fatal("invalid credentials opened the breaker")
	}
	f.setRefuse(west1.URI, nil)
	f.setDown(west1.URI, true)
	p.Check(context.Background())
	p.Check(context.Background()) // two faults in a row
	f.setDown(west1.URI, false)
	f.setRefuse(west1.URI, invalid)
	p.Check(context.Background()) // a refusal between: neither counted nor a reset
	f.setRefuse(west1.URI, nil)
	f.setDown(west1.URI, true)
	p.Check(context.Background()) // the third fault
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.URI)) != 0 {
		t.Fatal("a refusal reset the fault count the health checks built")
	}
}

// With no broker site, a selection whose server's site differs from the
// previous selection's is a crossing, said and counted (pre-flight M-7).
func TestACrossingWithNoBrokerSiteIsCounted(t *testing.T) {
	f := newFakeServers(east.URI, west1.URI)
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(poolCfg("", east, west1), f.dial, noCheck, newClock().Now, m, say.say)
	f.setDown(east.URI, true)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west1 {
		t.Fatalf("%v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectorySiteCrossings) != 1 ||
		!say.has("consistency event: crossing from site us-east to us-west (ldaps://dc-03 to ldaps://dc-01)") {
		t.Fatalf("%v", say.l)
	}
}
```

A query that times out on dc-01 has no budget left for dc-02 within the same
`query_timeout`, so the first query may return `ErrUnavailable`. The test allows that. What it
pins:
- the bound;
- the selection leaving dc-01 at its first fault;
- later queries going straight to dc-02;
- the health checks opening dc-01's breaker.

- [ ] **Step 3: Run them to verify they fail**

Run: `go test ./internal/directory/ -run 'Ranking|Sticky|Slow|Failback|Breaker|SiteCrossing|Crossing|WentAway|FaultClassifies|Racing|BindRefusal' -count=1`
Expected: FAIL, undefined `NewPool`, `Fault`, `Client`, `metrics.Metrics.DirectoryQueries`.

- [ ] **Step 4: The metrics**

In `metrics.go`, add the four fields with their `Help` and register them in the list at
`:605`:

```go
		DirectoryQueries: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_directory_queries_total",
			Help: "Directory queries by server (a configured URI) and outcome: ok, fault (the server's), error (the query's answer), refused (the server refused the dial or bind without a fault)."},
			[]string{"server", "outcome"}),
		DirectoryServerUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_server_up",
			Help: "1 while the directory server's breaker is closed."}, []string{"server"}),
		DirectorySelected: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_selected",
			Help: "1 for the directory server queries are sent to (sticky selection)."}, []string{"server"}),
		DirectorySiteCrossings: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_directory_site_crossings_total",
			Help: "Selections that crossed sites: consistency events, membership read there may lag replication (design §10)."}),
```

- [ ] **Step 5: The pool**

Create `internal/directory/pool.go`:

```go
package directory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Searcher is what one query sees: a connection whose searches are
// bounded by that query's deadline.
type Searcher interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

// Client is one bound connection to one server, shared by concurrent
// queries. SearchContext past ctx abandons its own message and returns
// ctx.Err(), leaving the connection and every other search on it alone
// (pre-flight I-3). pagingSize 0 is one unpaged search.
type Client interface {
	SearchContext(ctx context.Context, req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

// Dialer opens and binds a connection to s within ctx.
type Dialer func(ctx context.Context, s Server) (Client, error)

// ErrUnavailable is no server answering a query within query_timeout:
// directory_unavailable unless grace serves it (spec §5.7).
var ErrUnavailable = errors.New("directory: no server answered")

// Fault reports whether err is the server's fault rather than the query's
// answer (Ruling 9): it counts toward the server's breaker and fails the
// query over.
func Fault(err error) bool {
	var ne net.Error
	switch {
	case err == nil:
		return false
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne):
		return true
	}
	for _, code := range []uint16{ldap.ErrorNetwork, ldap.LDAPResultBusy, ldap.LDAPResultUnavailable,
		ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultOther, ldap.LDAPResultTimeLimitExceeded} {
		if ldap.IsErrorWithCode(err, code) {
			return true
		}
	}
	return false
}

type serverState struct {
	Server
	conn         Client
	gen          int       // bumped each time the pool closes or replaces conn
	refusedSaid  time.Time // the last bind refusal said (once an hour)
	faults       int       // consecutive
	open         bool      // the breaker
	openedAt     time.Time // its last probe or opening
	healthySince time.Time // the first pass since the last fault; zero while faulting
}

// Pool is design §10's server pool. One pool per broker process; every
// query and every health check goes through it.
type Pool struct {
	cfg   Config
	dial  Dialer
	check func(ctx context.Context, s Searcher) error
	now   func() time.Time
	m     *metrics.Metrics
	say   func(format string, args ...any)

	mu  sync.Mutex
	srv []*serverState // ranked
	sel int            // index into srv; -1 none yet
}

// NewPool ranks cfg.Servers same-site first, then by priority descending,
// then in file order. check is the health check's query on a bound
// connection (RootDSE outside tests).
func NewPool(cfg Config, dial Dialer, check func(ctx context.Context, s Searcher) error, now func() time.Time,
	m *metrics.Metrics, say func(format string, args ...any)) *Pool {
	p := &Pool{cfg: cfg, dial: dial, check: check, now: now, m: m, say: say, sel: -1}
	for _, s := range cfg.Servers {
		p.srv = append(p.srv, &serverState{Server: s})
		m.DirectoryServerUp.WithLabelValues(s.URI).Set(1)
		m.DirectorySelected.WithLabelValues(s.URI).Set(0)
	}
	slices.SortStableFunc(p.srv, func(a, b *serverState) int {
		if cfg.Site != "" {
			ah, bh := a.Site == cfg.Site, b.Site == cfg.Site
			if ah != bh {
				if ah {
					return -1
				}
				return 1
			}
		}
		return b.Priority - a.Priority
	})
	return p
}

// Ranked is the servers in the order selection prefers them.
func (p *Pool) Ranked() []Server {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Server, len(p.srv))
	for i, s := range p.srv {
		out[i] = s.Server
	}
	return out
}

// Selected is the sticky selection, and false before the first.
func (p *Pool) Selected() (Server, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel < 0 {
		return Server{}, false
	}
	return p.srv[p.sel].Server, true
}

// Do runs f on the selected server, failing over to the next closed one
// in rank on a server fault, within query_timeout for the whole query. A
// query error that is the server's answer is returned as it is, from the
// server that gave it. A dial or bind the server refused is that server
// not answering (pre-flight I-2): the query fails over. No server
// answering is ErrUnavailable, wrapping the last fault or refusal, so
// grace applies above. A caller that went away is no fault (its ctx's
// error).
func (p *Pool) Do(ctx context.Context, f func(Searcher) error) (Server, error) {
	qctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	tried := map[int]bool{}
	var last error
	for {
		if ctx.Err() != nil {
			return Server{}, ctx.Err()
		}
		if last != nil && qctx.Err() != nil {
			// The budget is spent: no server is charged a fault for time it
			// was never given.
			return Server{}, fmt.Errorf("%w (the last: %v)", ErrUnavailable, last)
		}
		i, conn, gen, err := p.acquire(qctx, tried)
		if i < 0 {
			if last == nil {
				last = errors.New("every server's breaker is open")
			}
			return Server{}, fmt.Errorf("%w (the last: %v)", ErrUnavailable, last)
		}
		tried[i] = true
		srv := p.srv[i].Server
		if err == nil {
			err = f(bound{ctx: qctx, c: conn})
		} else if ctx.Err() == nil && !Fault(err) {
			p.refused(i, err)
			p.moveFrom(i)
			last = fmt.Errorf("%s: %v", srv.URI, err)
			continue
		}
		if ctx.Err() != nil {
			// A caller that went away is no fault. Its own search was
			// abandoned; the connection stays for every other query.
			return Server{}, ctx.Err()
		}
		switch {
		case err == nil:
			p.answered(i, "ok")
			return srv, nil
		case !Fault(err):
			p.answered(i, "error")
			return srv, err
		}
		p.fault(i, gen, err)
		p.moveFrom(i)
		last = fmt.Errorf("%s: %v", srv.URI, err)
	}
}

// bound is a Client as one query sees it: every search under the query's
// deadline.
type bound struct {
	ctx context.Context
	c   Client
}

func (b bound) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return b.c.SearchContext(b.ctx, req, 0)
}

func (b bound) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return b.c.SearchContext(b.ctx, req, pagingSize)
}

// moveFrom ends the sticky selection of i after a query's fault on it:
// the next closed server in rank after i is selected, one with no faults
// first (Ruling 9). Only Check moves a selection back up.
func (p *Pool) moveFrom(i int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel != i {
		return
	}
	if j := p.bestLocked(i); j >= 0 {
		p.selectLocked(j, "")
	}
}

// bestLocked is the best-ranked closed server other than skip, one with
// no faults in a row before one with some; -1 for none.
func (p *Pool) bestLocked(skip int) int {
	fallback := -1
	for j, s := range p.srv {
		if j == skip || s.open {
			continue
		}
		if s.faults == 0 {
			return j
		}
		if fallback < 0 {
			fallback = j
		}
	}
	return fallback
}

// acquire is the server a query tries next: the selected one if its
// breaker is closed and it is untried, else the best-ranked such, which is
// then selected. It dials when the server holds no connection; queries
// racing to dial keep the first connection and close the others
// (pre-flight M-8). gen is the connection's generation, for fault. -1 is
// none.
func (p *Pool) acquire(ctx context.Context, tried map[int]bool) (int, Client, int, error) {
	p.mu.Lock()
	i := -1
	if p.sel >= 0 && !p.srv[p.sel].open && !tried[p.sel] {
		i = p.sel
	} else {
		for j, s := range p.srv {
			if !s.open && !tried[j] {
				i = j
				break
			}
		}
	}
	if i < 0 {
		p.mu.Unlock()
		return -1, nil, 0, nil
	}
	if i != p.sel {
		p.selectLocked(i, "")
	}
	s := p.srv[i]
	conn, gen := s.conn, s.gen
	p.mu.Unlock()
	if conn != nil {
		return i, conn, gen, nil
	}
	conn, err := p.dial(ctx, s.Server)
	if err != nil {
		return i, nil, gen, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.conn != nil {
		_ = conn.Close()
		return i, s.conn, s.gen, nil
	}
	s.conn = conn
	s.gen++
	return i, conn, s.gen, nil
}

func (p *Pool) answered(i int, outcome string) {
	p.m.DirectoryQueries.WithLabelValues(p.srv[i].URI, outcome).Inc()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.srv[i].faults = 0
}

// broken reports whether err leaves the connection unusable: a network
// error. A deadline abandons its own search alone (pre-flight I-3), and a
// server's busy or unavailable answer arrived on a working connection.
func broken(err error) bool {
	var ne net.Error
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || (errors.As(err, &ne) && !ne.Timeout())
}

// fault counts a server fault against i: a broken connection is dropped,
// its stability window restarts, and failure_threshold in a row open its
// breaker. gen is the generation of the connection the fault came on; an
// error on a connection the pool has since closed or replaced is no fault
// of the server's and counts nothing. A health check passes gen -1.
func (p *Pool) fault(i, gen int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.srv[i]
	if gen >= 0 && gen != s.gen {
		return
	}
	p.m.DirectoryQueries.WithLabelValues(s.URI, "fault").Inc()
	if s.conn != nil && gen >= 0 && broken(err) {
		_ = s.conn.Close()
		s.conn = nil
		s.gen++
	}
	s.faults++
	s.healthySince = time.Time{}
	if !s.open && s.faults >= p.cfg.FailureThreshold {
		s.open, s.openedAt = true, p.now()
		p.m.DirectoryServerUp.WithLabelValues(s.URI).Set(0)
		p.say("directory: %s: %d faults in a row (the last: %s); its breaker is open; probed every %s", s.URI,
			s.faults, printsafe.Line(err.Error(), 300), p.cfg.ProbeInterval)
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
			s.gen++
		}
	}
}

// refused is a dial or bind the server refused without a fault
// (pre-flight I-2): invalid credentials (49), strongAuthRequired,
// confidentialityRequired, a KDC's refusal. The query fails over; the
// breaker's count is left as it is, neither raised (a wrong password is
// not a down server) nor reset. Said once per server an hour, with the
// mechanism and the result code; the error carries neither the password
// nor the keytab (Task 7).
func (p *Pool) refused(i int, err error) {
	p.m.DirectoryQueries.WithLabelValues(p.srv[i].URI, "refused").Inc()
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.srv[i]
	now := p.now()
	if !s.refusedSaid.IsZero() && now.Sub(s.refusedSaid) < time.Hour {
		return
	}
	s.refusedSaid = now
	p.say("directory: %s refused the bind (%s): %s; queries fail over, and with no server answering a "+
		"membership verified within directory.grace serves", s.URI, p.cfg.Bind.Mechanism,
		printsafe.Line(err.Error(), 300))
}

// selectLocked makes i the sticky selection, saying so, and a site
// crossing as a consistency event (design §10). why, when set, is said
// instead of the plain line.
func (p *Pool) selectLocked(i int, why string) {
	prev := p.sel
	p.sel = i
	s := p.srv[i]
	for _, o := range p.srv {
		p.m.DirectorySelected.WithLabelValues(o.URI).Set(0)
	}
	p.m.DirectorySelected.WithLabelValues(s.URI).Set(1)
	if why != "" {
		p.say("%s", why)
	} else {
		p.say("directory: selected %s (%s, priority %d)", s.URI, or(s.Site, "no site"), s.Priority)
	}
	from, fromURI := p.cfg.Site, ""
	if prev >= 0 {
		from, fromURI = p.srv[prev].Site, p.srv[prev].URI
	}
	// With a broker site, the first selection is measured from it; without
	// one, a change between two selections is the crossing (pre-flight M-7).
	if (p.cfg.Site != "" || prev >= 0) && s.Site != from {
		p.m.DirectorySiteCrossings.Inc()
		p.say("directory: consistency event: crossing from site %s to %s (%s to %s); membership read there may lag "+
			"replication from %s", or(from, "none"), or(s.Site, "none"), or(fromURI, "none"), s.URI, or(from, "none"))
	}
}

// Check is one round of health checks (Ruling 9): every server whose
// breaker is closed, or open past probe_interval, is dialled, bound and
// checked within health_check.timeout, on a connection of its own that it
// closes. A refused bind is said and counts nothing. Then failback: a
// server ranked above the selection that has passed every check for
// stability_window is selected. With nothing selected, the best closed
// server is.
func (p *Pool) Check(ctx context.Context) {
	now := p.now()
	for i, s := range p.srv {
		p.mu.Lock()
		skip := s.open && now.Sub(s.openedAt) < p.cfg.ProbeInterval
		if s.open && !skip {
			s.openedAt = now // a probe resets its clock
		}
		p.mu.Unlock()
		if skip {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, p.cfg.HealthTimeout)
		conn, err := p.dial(cctx, s.Server)
		dialed := err == nil
		if dialed {
			err = p.check(cctx, bound{ctx: cctx, c: conn})
			_ = conn.Close()
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil && !dialed && !Fault(err):
			p.refused(i, err)
			continue
		case err != nil:
			p.fault(i, -1, err)
			continue
		}
		p.mu.Lock()
		s.faults = 0
		if s.open {
			s.open = false
			p.m.DirectoryServerUp.WithLabelValues(s.URI).Set(1)
			p.say("directory: %s answers its health check again; its breaker is closed", s.URI)
		}
		if s.healthySince.IsZero() {
			s.healthySince = now
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel < 0 || p.srv[p.sel].open {
		if j := p.bestLocked(-1); j >= 0 {
			p.selectLocked(j, "")
		}
		return
	}
	for j := 0; j < p.sel; j++ {
		s := p.srv[j]
		if !s.open && !s.healthySince.IsZero() && now.Sub(s.healthySince) >= p.cfg.StabilityWindow {
			p.selectLocked(j, fmt.Sprintf("directory: %s passed every health check for %s (failback.stability_window); "+
				"selected again", s.URI, p.cfg.StabilityWindow))
			return
		}
	}
}

// Run checks every health_check.interval until ctx ends, starting at once.
func (p *Pool) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.HealthInterval)
	defer t.Stop()
	for {
		p.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
```

`Do`'s first query with nothing selected selects through `acquire`. `Check` is what fails
back. A query never moves the selection *up*: only `Check` does, after the window. That is
the "no flapping" property design §10 asks for.

Nothing in the pool closes a shared connection on a query's timeout: only a network error
(the connection is broken) or the breaker opening drops it, and the generation it bumps keeps
every other query's error on that connection from counting as a further fault. `NewPool`
also needs `cfg.Bind.Mechanism` for the refusal line; Task 4's `Config` carries it.

- [ ] **Step 6: Run them to verify they pass**

Run: `go test ./internal/directory/ -race -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/directory internal/daemon/metrics/metrics.go
git commit -m "feat(directory): the server pool: same-site then priority, sticky, breakers, health checks, failback, site crossings" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: The connection: TLS always, and EXTERNAL, GSSAPI or simple

**Files:**
- Create: `internal/directory/conn.go`, `internal/directory/conn_test.go`
- Modify: `go.mod`, `go.sum` (the `gssapi` import pulls gokrb5 v8.4.4 into the build)

**Interfaces:**
- Consumes: `directory.Config`, `Bind`, `Server` (Task 4); `Searcher`, `Client`, `Dialer`
  (Task 6); `keyfile.LoadX509KeyPair`, `keyfile.ReadSecret`.
- Produces:

```go
type Credentials struct { /* unexported: the cert, the kerberos client, the password */ }
func LoadCredentials(b Bind, getenv func(string) string) (*Credentials, error)
func (c *Credentials) String() string   // the mechanism and who, never the secret
func (c *Credentials) GoString() string
func (c *Credentials) Who() string       // "port49$@CORP.EXAMPLE.COM", a bind DN, or the cert's subject
func NewDialer(cfg Config, cr *Credentials) (Dialer, error)
func RootDSE(ctx context.Context, s Searcher) error
type ldapClient struct{ c *ldap.Conn } // Client over SearchAsync
func tlsConfig(cfg Config, s Server, cr *Credentials) (*tls.Config, error)
```

- [ ] **Step 1: The failing tests**

Create `internal/directory/conn_test.go`:

```go
package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// A simple bind's password and a keytab's bytes never appear in any
// formatting of the credentials (Global Constraints; Ruling 18).
func TestCredentialsWithholdTheirSecrets(t *testing.T) {
	cr, err := LoadCredentials(Bind{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "P"},
		func(string) string { return "hunter2-very-secret" })
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(cr), fmt.Sprintf("%v", cr), fmt.Sprintf("%+v", cr), fmt.Sprintf("%#v", cr),
		fmt.Sprintf("%s", cr)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("the password leaked: %s", s)
		}
	}
	if cr.Who() != "CN=port49,DC=corp" || !strings.Contains(cr.String(), "simple") {
		t.Fatalf("%s / %s", cr.Who(), cr.String())
	}
}

// A keytab another user could read is refused, before gokrb5 sees it.
func TestAGroupReadableKeytabIsRefused(t *testing.T) {
	dir := t.TempDir()
	kt := filepath.Join(dir, "port49.keytab")
	if err := os.WriteFile(kt, []byte{0x05, 0x02}, 0o640); err != nil {
		t.Fatal(err)
	}
	krb := filepath.Join(dir, "krb5.conf")
	os.WriteFile(krb, []byte("[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n"), 0o644)
	_, err := LoadCredentials(Bind{Mechanism: "gssapi", KeytabFile: kt, Principal: "port49$@CORP.EXAMPLE.COM",
		KRB5Conf: krb}, os.Getenv)
	if err == nil || !strings.Contains(err.Error(), "keytab_file") {
		t.Fatalf("%v", err)
	}
}

// TLS verifies the server against ca_file under the URI's host name, and
// presents the broker's own certificate only for EXTERNAL.
func TestTLSConfigVerifiesTheServerName(t *testing.T) {
	pki, err := testpki.NewCA("lab directory CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pki.PEM(), 0o644)
	tc, err := tlsConfig(Config{CAFile: ca}, Server{URI: "ldaps://dc-01.corp.example.com:636"}, &Credentials{mech: "simple"})
	if err != nil || tc.ServerName != "dc-01.corp.example.com" || tc.InsecureSkipVerify || tc.RootCAs == nil ||
		len(tc.Certificates) != 0 {
		t.Fatalf("%+v %v", tc, err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/directory/ -run 'Credentials|Keytab|TLSConfig' -count=1`
Expected: FAIL, undefined `LoadCredentials`, `tlsConfig`.

- [ ] **Step 3: The connection**

Create `internal/directory/conn.go`:

```go
package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"github.com/rhwendt/port49/internal/keyfile"
)

// Credentials are how the broker binds (Ruling 8). The secret each holds is
// unexported and never formatted: String and GoString name the mechanism and
// who, nothing else.
type Credentials struct {
	mech     BindMechanism
	who      string
	cert     *tls.Certificate // external
	krb      *gssapi.Client   // gssapi
	krbMu    sync.Mutex       // a gssapi.Client holds one security context at a time
	password string           // simple
}

func (c *Credentials) String() string   { return fmt.Sprintf("directory bind %s as %s", c.mech, c.who) }
func (c *Credentials) GoString() string { return c.String() }
func (c *Credentials) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
func (c *Credentials) Who() string      { return c.who }

// LoadCredentials reads the bind's secret once, at start. A keytab is read
// through keyfile.ReadSecret: owned by port49's user or root, no group or
// other bit, no link.
func LoadCredentials(b Bind, getenv func(string) string) (*Credentials, error) {
	c := &Credentials{mech: b.Mechanism}
	switch b.Mechanism {
	case "external":
		cert, err := keyfile.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind tls_cert_file %s, tls_key_file %s: %w", b.TLSCertFile,
				b.TLSKeyFile, err)
		}
		c.cert = &cert
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			c.who = leaf.Subject.String()
		}
	case "gssapi":
		raw, err := keyfile.ReadSecret(b.KeytabFile)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.keytab_file %s: %w", b.KeytabFile, err)
		}
		kt := keytab.New()
		if err := kt.Unmarshal(raw); err != nil {
			return nil, fmt.Errorf("broker.directory.bind.keytab_file %s: not a keytab", b.KeytabFile)
		}
		conf, err := os.ReadFile(b.KRB5Conf)
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.krb5_conf: %w", err)
		}
		kc, err := krbconfig.NewFromString(string(conf))
		if err != nil {
			return nil, fmt.Errorf("broker.directory.bind.krb5_conf %s: %v", b.KRB5Conf, err)
		}
		user, realm := splitPrincipal(b.Principal)
		c.krb = &gssapi.Client{Client: krbclient.NewWithKeytab(user, realm, kt, kc, krbclient.DisablePAFXFAST(true))}
		c.who = b.Principal
	case "simple":
		c.password, c.who = getenv(b.PasswordEnv), b.BindDN
		if c.password == "" {
			return nil, fmt.Errorf("broker.directory.bind.password_env %s is not set", b.PasswordEnv)
		}
	default:
		return nil, fmt.Errorf("broker.directory.bind.mechanism %q", b.Mechanism)
	}
	return c, nil
}

// splitPrincipal is user and realm of "user@REALM".
func splitPrincipal(p string) (string, string) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '@' {
			return p[:i], p[i+1:]
		}
	}
	return p, ""
}

// tlsConfig verifies s against ca_file under its URI's host, TLS 1.2 or
// later, and presents the broker's certificate only for EXTERNAL.
func tlsConfig(cfg Config, s Server, cr *Credentials) (*tls.Config, error) {
	u, err := url.Parse(s.URI)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("broker.directory.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("broker.directory.ca_file %s holds no certificate", cfg.CAFile)
	}
	tc := &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if cr.cert != nil {
		tc.Certificates = []tls.Certificate{*cr.cert}
	}
	return tc, nil
}

// NewDialer dials, secures and binds one connection per call. Every
// search on it runs through SearchAsync under its query's deadline
// (ldapClient), and is bounded by query_timeout on the wire as well
// (SetTimeout). Nothing closes the connection on one query's timeout.
func NewDialer(cfg Config, cr *Credentials) (Dialer, error) {
	return func(ctx context.Context, s Server) (Client, error) {
		tc, err := tlsConfig(cfg, s, cr)
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{}
		if dl, ok := ctx.Deadline(); ok {
			d.Deadline = dl
		}
		opts := []ldap.DialOpt{ldap.DialWithDialer(d)}
		if !s.StartTLS {
			opts = append(opts, ldap.DialWithTLSConfig(tc))
		}
		conn, err := ldap.DialURL(s.URI, opts...)
		if err != nil {
			return nil, err
		}
		conn.SetTimeout(cfg.QueryTimeout)
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if s.StartTLS {
			if err := conn.StartTLS(tc); err != nil {
				conn.Close()
				return nil, err
			}
		}
		if err := bind(conn, s, cr); err != nil {
			conn.Close()
			return nil, err
		}
		return ldapClient{c: conn}, nil
	}, nil
}

// ldapClient is a bound *ldap.Conn as a Client (pre-flight I-3): every
// search runs through SearchAsync under the query's ctx, so a deadline
// abandons that search's message alone and the connection serves every
// other query on it. SearchAsync reports a cancelled search as no error
// (go-ldap search.go:625-630), so ctx's error is returned in its place.
// Paging follows SearchWithPaging (search.go:503): a paging control, the
// cookie from each page's done result, until it comes back empty.
type ldapClient struct{ c *ldap.Conn }

func (l ldapClient) Close() error { return l.c.Close() }

func (l ldapClient) SearchContext(ctx context.Context, req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	out := &ldap.SearchResult{}
	var paging *ldap.ControlPaging
	if pagingSize > 0 {
		paging = ldap.NewControlPaging(pagingSize)
		req.Controls = append(req.Controls, paging)
	}
	for {
		r := l.c.SearchAsync(ctx, req, 0)
		var controls []ldap.Control
		for r.Next() {
			if e := r.Entry(); e != nil {
				out.Entries = append(out.Entries, e)
			}
			if c := r.Controls(); len(c) > 0 {
				controls = c
			}
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if err := r.Err(); err != nil {
			return out, err
		}
		if paging == nil {
			return out, nil
		}
		pc, ok := ldap.FindControl(controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(pc.Cookie) == 0 {
			return out, nil
		}
		paging.SetCookie(pc.Cookie)
	}
}

// bind authenticates conn as the broker. Its error names the server, the
// mechanism and the result code, never a secret.
func bind(conn *ldap.Conn, s Server, cr *Credentials) error {
	var err error
	switch cr.mech {
	case "external":
		err = conn.ExternalBind()
	case "gssapi":
		u, _ := url.Parse(s.URI)
		cr.krbMu.Lock()
		err = conn.GSSAPIBind(cr.krb, "ldap/"+u.Hostname(), "")
		cr.krbMu.Unlock()
	case "simple":
		err = conn.Bind(cr.who, cr.password)
	}
	if err != nil {
		var le *ldap.Error
		if errors.As(err, &le) {
			return &ldap.Error{ResultCode: le.ResultCode, MatchedDN: le.MatchedDN,
				Err: fmt.Errorf("bind %s as %s refused (LDAP result %d)", cr.mech, cr.who, le.ResultCode)}
		}
		return fmt.Errorf("bind %s as %s: %w", cr.mech, cr.who, err)
	}
	return nil
}

// RootDSE is the health check's query: the root DSE's supported LDAP
// versions, base scope, which every directory answers to a bound client.
func RootDSE(ctx context.Context, s Searcher) error {
	_, err := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(timeLeft(ctx).Seconds())+1, false, "(objectClass=*)", []string{"supportedLDAPVersion"}, nil))
	return err
}

func timeLeft(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return time.Until(dl)
	}
	return 0
}
```

`bind` rewraps an LDAP error so the server's diagnostic message, which a directory may fill
with anything, never reaches a line. It keeps the result code: `Fault` classifies the bind
on that. A `busy` DC is a fault and fails over. Invalid credentials, `strongAuthRequired` or
`confidentialityRequired` is a refusal (Task 6's `refused`): the query fails over too, the
breaker's count is untouched, and the refusal is said once an hour per server with the
mechanism and the code. With every server refusing, the query is `ErrUnavailable` and grace
applies (pre-flight I-2). A gokrb5 error that is not a network error (a KDC refusing the
keytab) is a refusal the same way.

`ldapClient` needs a server, so it is exercised by Task 17's lab run (L43's binds, L42's
searches, one with a size limit). The pool's handling of the `Client` contract is pinned by
Task 6's `fakeConn`, which honours the same contract.

Run `go get github.com/go-ldap/ldap/v3/gssapi@v3.4.14 github.com/jcmturner/gokrb5/v8@v8.4.4 &&
go mod tidy` and check `go list -deps ./internal/directory | grep -c cgo` prints nothing
cgo-bearing: `CGO_ENABLED=0 go build ./...` must succeed.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/directory/ -count=1 && CGO_ENABLED=0 go build ./... && go vet ./internal/directory/`
Expected: PASS, and the build succeeds with cgo off.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/directory
git commit -m "feat(directory): TLS-only connections bound by EXTERNAL, GSSAPI (pure Go) or simple, secrets withheld" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: The certificate-to-directory mapping, one entry, and its principal and username

**Files:**
- Create: `internal/directory/mapping.go`, `internal/directory/mapping_test.go`,
  `internal/directory/entry.go`, `internal/directory/entry_test.go`

**Interfaces:**
- Consumes: `Mapping`, `MappingKind` (Task 4); `Searcher` and `fakeDir` (Task 6);
  `token.CanonicalUsername`, `token.ReservedUsername`; `store.MapKey` (Task 5).
- Produces:

```go
var (
	ErrUnmapped      = errors.New("directory: identity_unmapped")
	ErrAmbiguous     = errors.New("directory: identity_ambiguous")
	ErrUsernameTaken = errors.New("directory: username_collision")
)
// Lookup is one certificate's search: the attribute, the escaped filter,
// and the mapping key its value indexes (store.MapKey).
type Lookup struct{ Attribute, Filter, Key string }
func (m Mapping) Lookup(leaf *x509.Certificate, userFilter string) (Lookup, error)
func (m Mapping) KeysOf(e *ldap.Entry) []string  // every mapping key the entry answers to
func ADIssuerSerial(leaf *x509.Certificate) string // "" when the issuer does not parse
func SIDOf(leaf *x509.Certificate) (string, error)
func rdnsOf(raw []byte) (pkix.RDNSequence, error)  // RawIssuer / RawSubject, DER order
func nameString(raw []byte) string                 // RFC 4514, DC= kept
func pinned(leaf *x509.Certificate, issuers []string) bool
func canonicalValue(k MappingKind, v string) string
func sidBytes(sid string) ([]byte, error)
func sidString(b []byte) (string, error)

// entry.go
type Identity struct{ DN, EntryID, Principal, Username string }
func entryID(e *ldap.Entry) string // "guid:", "uuid:" or "dn:" (Ruling 3's pin)
func (c Config) oneEntry(s Searcher, filter string, attrs []string) (*ldap.Entry, error)
func (c Config) identityOf(e *ldap.Entry) (Identity, error)
func (c Config) usernameUnique(s Searcher, id Identity) error  // ErrUsernameTaken
func (c Config) principalUnique(s Searcher, id Identity) error // ErrAmbiguous (pre-flight C-2)
func (c Config) heldElsewhere(s Searcher, attr, value, dn string) (string, error)
func (c Config) entryAttrs() []string
```

- [ ] **Step 1: The failing tests**

Create `internal/directory/mapping_test.go`:

```go
package directory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidDC = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// issuingCA is a CA whose subject is rdns, written in DER as given (most
// significant first), so a DC= RDN reaches the leaf's RawIssuer as AD CS
// writes it and Go's pkix.Name cannot hide it (pre-flight I-1).
func issuingCA(t *testing.T, rdns pkix.RDNSequence) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), RawSubject: raw, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key
}

// corpCA is CN=corp-DC01-CA,DC=corp,DC=com.
func corpCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	return issuingCA(t, pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}},
		{{Type: oidCN, Value: "corp-DC01-CA"}}})
}

// issue is a client certificate from ca after mut edits its template,
// parsed back from DER: every mapping test reads what a real certificate
// carries, never a pkix.Name built in memory.
func issue(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, mut func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x1200000000AC11), Subject: pkix.Name{CommonName: "Alice Smith"},
		EmailAddresses: []string{"alice@corp.example.com"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	if mut != nil {
		mut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leaf(t *testing.T, mut func(*x509.Certificate)) *x509.Certificate {
	ca, key := corpCA(t)
	return issue(t, ca, key, mut)
}

var pin = []string{"CN=corp-DC01-CA,DC=corp,DC=com"}

// A weak mapping refuses a certificate from an issuer it is not pinned to,
// before any search (design §7). The pin compares the issuer's DER RDNs,
// DC= included, case-folded: a pin naming the CN alone is another issuer.
func TestAWeakMappingRefusesAnUnpinnedIssuer(t *testing.T) {
	m := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	if _, err := m.Lookup(leaf(t, nil), "(objectClass=person)"); err != nil {
		t.Fatal(err)
	}
	folded := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: []string{"cn=CORP-dc01-ca,dc=CORP,dc=com"}}
	if _, err := folded.Lookup(leaf(t, nil), "(objectClass=person)"); err != nil {
		t.Fatalf("a pin in another case: %v", err)
	}
	for _, issuers := range [][]string{{"CN=corp-DC01-CA"}, {"CN=corp-DC01-CA,DC=other,DC=com"}} {
		cnOnly := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: issuers}
		if _, err := cnOnly.Lookup(leaf(t, nil), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("pin %v matched CN=corp-DC01-CA,DC=corp,DC=com: %v", issuers, err)
		}
	}
	partner, partnerKey := issuingCA(t, pkix.RDNSequence{{{Type: oidCN, Value: "Partner CA"}}})
	other := issue(t, partner, partnerKey, nil)
	if _, err := m.Lookup(other, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) ||
		!strings.Contains(err.Error(), "not one broker.directory.certificate_mapping.issuers pins") {
		t.Fatalf("%v", err)
	}
}

// A mapped value carrying filter metacharacters matches only its literal
// entry (Review Focus 1).
func TestAMappedValueIsEscapedInTheFilter(t *testing.T) {
	m := Mapping{Kind: MapCN, Attribute: "cn", AllowWeak: true, Issuers: pin}
	l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.Subject.CommonName = `*)(uid=*` }), "(objectClass=person)")
	if err != nil {
		t.Fatal(err)
	}
	if l.Filter != `(&(objectClass=person)(cn=\2a\29\28uid=\2a))` {
		t.Fatalf("%s", l.Filter)
	}
	nul := leaf(t, nil)
	nul.Subject.CommonName = "a\x00b" // set after parsing: CN is read from Subject.CommonName
	if _, err := m.Lookup(nul, "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("a control character in a weak value: %v", err)
	}
}

// AD's altSecurityIdentities form: the issuer's DER RDNs most significant
// first, DC= included, serial bytes reversed, upper-case hex (KB5014754's
// own example has the DCs first).
func TestADIssuerSerial(t *testing.T) {
	got := ADIssuerSerial(leaf(t, nil))
	if got != "X509:<I>DC=com,DC=corp,CN=corp-DC01-CA<SR>11AC0000000012" {
		t.Fatalf("%s", got)
	}
	l, _ := Mapping{Kind: MapIssuerSerial, Attribute: "altSecurityIdentities"}.Lookup(leaf(t, nil), "(objectClass=person)")
	if !strings.HasPrefix(l.Filter, "(&(objectClass=person)(altSecurityIdentities=X509:<I>DC=com,DC=corp,CN=corp-DC01-CA<SR>") {
		t.Fatalf("%s", l.Filter)
	}
}

// subject_dn reads the subject's DER RDNs too, so a subject under DC=
// keeps them.
func TestASubjectDNKeepsItsDCs(t *testing.T) {
	m := Mapping{Kind: MapSubjectDN, Attribute: "distinguishedName", AllowWeak: true, Issuers: pin}
	raw, _ := asn1.Marshal(pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}},
		{{Type: oidCN, Value: "Alice Smith"}}})
	l, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.RawSubject = raw }), "(objectClass=person)")
	if err != nil || l.Filter != "(&(objectClass=person)(distinguishedName=cn=Alice Smith,dc=corp,dc=com))" {
		t.Fatalf("%s %v", l.Filter, err)
	}
}

// The SID extension parsed, and objectSid escaped byte by byte (Review
// Focus 1): a binary attribute has no other safe form.
func TestAnObjectSidIsEscapedByteByByte(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-512"
	l, err := Mapping{Kind: MapSID, Attribute: "objectSid"}.Lookup(leaf(t, func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, sidExtension(t, sid))
	}), "(objectClass=person)")
	if err != nil {
		t.Fatal(err)
	}
	want := `(&(objectClass=person)(objectSid=\01\05\00\00\00\00\00\05\15\00\00\00\dc\f4\dc\3b\83\3d\2b\46\82\8b\a6\28\00\02\00\00))`
	if l.Filter != want {
		t.Fatalf("%s\nwant %s", l.Filter, want)
	}
	if b, _ := sidBytes(sid); func() string { s, _ := sidString(b); return s }() != sid {
		t.Fatal("sidString(sidBytes(x)) != x")
	}
	if _, err := (Mapping{Kind: MapSID, Attribute: "objectSid"}).Lookup(leaf(t, nil), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("no SID extension: %v", err)
	}
}

// The key a certificate searches with equals the key its entry answers to
// (pre-flight M-2): a SID re-canonicalized from its binary form, an
// issuer_serial upper-cased, as AD matches it.
func TestMapKeysAreCanonicalOnBothSides(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-512"
	c := leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, sidExtension(t, sid)) })
	b, _ := sidBytes(sid)
	sm := Mapping{Kind: MapSID, Attribute: "objectSid"}
	l, _ := sm.Lookup(c, "(objectClass=person)")
	if keys := sm.KeysOf(ldap.NewEntry("CN=Alice,DC=corp", map[string][]string{"objectSid": {string(b)}})); len(keys) != 1 || keys[0] != l.Key {
		t.Fatalf("sid: %v vs %s", keys, l.Key)
	}
	im := Mapping{Kind: MapIssuerSerial, Attribute: "altSecurityIdentities"}
	l, _ = im.Lookup(c, "(objectClass=person)")
	lower := strings.ToLower(ADIssuerSerial(c))
	if keys := im.KeysOf(ldap.NewEntry("CN=Alice,DC=corp", map[string][]string{"altSecurityIdentities": {lower}})); len(keys) != 1 || keys[0] != l.Key {
		t.Fatalf("issuer_serial: %v vs %s", keys, l.Key)
	}
}

// Zero or several email SANs is no mapping, never the first (design §7).
func TestSeveralSANsAreUnmapped(t *testing.T) {
	m := Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	for _, emails := range [][]string{nil, {"a@x", "b@x"}} {
		if _, err := m.Lookup(leaf(t, func(c *x509.Certificate) { c.EmailAddresses = emails }), "(objectClass=person)"); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v: %v", emails, err)
		}
	}
}

// sidExtension builds szOID_NTDS_CA_SECURITY_EXT as AD CS writes it: a
// GeneralNames holding one otherName (1.3.6.1.4.1.311.25.2.1) whose value
// is the SID string as an OCTET STRING.
func sidExtension(t *testing.T, sid string) pkix.Extension {
	t.Helper()
	inner, _ := asn1.Marshal([]byte(sid))
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"explicit,tag:0"`
	}{oidSIDValue, asn1.RawValue{FullBytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	other[0] = 0xa0 // [0] IMPLICIT, constructed: the GeneralName otherName choice
	names, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	return pkix.Extension{Id: oidSIDExtension, Value: names}
}
```

Create `internal/directory/entry_test.go`:

```go
package directory

import (
	"errors"
	"strings"
	"testing"
)

func adCfg() Config {
	return Config{BaseDN: "DC=corp", GroupsBaseDN: "OU=G,DC=corp", UserFilter: "(objectClass=person)",
		GroupFilter: "(objectClass=group)", PrincipalAttribute: "userPrincipalName", UsernameAttribute: "sAMAccountName",
		GroupNameAttribute: "cn", MemberAttribute: "member", MaxDepth: 16}
}

// Two entries for one certificate is identity_ambiguous with both DNs,
// never the first; none is identity_unmapped (Ruling 2).
func TestOneEntryOrNone(t *testing.T) {
	d := newFakeDir()
	f := "(&(objectClass=person)(mail=alice@corp.example.com))"
	d.on(f, entry("CN=Alice,OU=Staff,DC=corp", nil), entry("CN=Alice,OU=Contractors,DC=corp", nil))
	_, err := adCfg().oneEntry(d, f, nil)
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "OU=Staff") || !strings.Contains(err.Error(), "OU=Contractors") {
		t.Fatalf("%v", err)
	}
	if d.calls[0].SizeLimit != 2 || d.calls[0].BaseDN != "DC=corp" {
		t.Fatalf("the search: %+v", d.calls[0])
	}
	if _, err := adCfg().oneEntry(d, "(&(objectClass=person)(mail=nobody@corp))", nil); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
}

// The principal and username are derived and checked (Ruling 3), and the
// entry's immutable id is its pin: objectGUID, else entryUUID, else the DN.
func TestIdentityOfAnEntry(t *testing.T) {
	c := adCfg()
	id, err := c.identityOf(entry("CN=Alice,DC=corp", map[string][]string{"userPrincipalName": {"Alice@Corp.Example.com"},
		"sAMAccountName": {"Alice"}, "objectGUID": {"\x0a\x1b\x2c\x3d"}}))
	if err != nil || id.Principal != "user:alice@corp.example.com" || id.Username != "alice" || id.EntryID != "guid:0a1b2c3d" {
		t.Fatalf("%+v %v", id, err)
	}
	if got := entryID(entry("CN=B,DC=corp", map[string][]string{"entryUUID": {"5F0E-AB"}})); got != "uuid:5f0e-ab" {
		t.Fatalf("entryUUID: %s", got)
	}
	if got := entryID(entry("CN=B,DC=Corp", nil)); got != "dn:cn=b,dc=corp" {
		t.Fatalf("no id attribute: %s", got)
	}
	for name, attrs := range map[string]map[string][]string{
		"no upn":            {"sAMAccountName": {"alice"}},
		"two upns":          {"userPrincipalName": {"a@x", "b@x"}, "sAMAccountName": {"alice"}},
		"a upn with no @":   {"userPrincipalName": {"alice"}, "sAMAccountName": {"alice"}},
		"a reserved name":   {"userPrincipalName": {"r@x"}, "sAMAccountName": {"remote"}},
		"a p49- name":       {"userPrincipalName": {"r@x"}, "sAMAccountName": {"p49-admin"}},
		"a domain prefix":   {"userPrincipalName": {"r@x"}, "sAMAccountName": {`CORP\alice`}},
		"an unprintable":    {"userPrincipalName": {"r@x"}, "sAMAccountName": {"al\tice"}},
	} {
		if _, err := c.identityOf(entry("CN=X,DC=corp", attrs)); !errors.Is(err, ErrUnmapped) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A username another entry holds is username_collision, naming both DNs
// (Ruling 3): two people under one username share one context.
func TestAUsernameTwoEntriesHoldCollides(t *testing.T) {
	d := newFakeDir()
	d.on("(sAMAccountName=alice)", entry("CN=Alice,DC=corp", nil), entry("CN=Alice2,DC=corp", nil))
	err := adCfg().usernameUnique(d, Identity{DN: "CN=Alice,DC=corp", Username: "alice"})
	if !errors.Is(err, ErrUsernameTaken) || !strings.Contains(err.Error(), "CN=Alice2,DC=corp") {
		t.Fatalf("%v", err)
	}
	d.on("(sAMAccountName=bob)", entry("CN=Bob,DC=corp", nil))
	if err := adCfg().usernameUnique(d, Identity{DN: "cn=bob,dc=corp", Username: "bob"}); err != nil {
		t.Fatalf("the same DN in another case: %v", err)
	}
	if f := d.calls[0].Filter; strings.Contains(f, "objectClass") {
		t.Fatalf("the uniqueness search is narrowed by user_filter: %s (pre-flight M-5)", f)
	}
}

// A principal another entry holds is identity_ambiguous, naming both DNs
// (pre-flight C-2): a user who sets their own mail or UPN to a colleague's
// never becomes the colleague, and the colleague is refused too while the
// two collide. Searched without user_filter, which finds more.
func TestAPrincipalTwoEntriesHoldIsAmbiguous(t *testing.T) {
	d := newFakeDir()
	d.on("(userPrincipalName=victim@corp.example.com)", entry("CN=Victim,DC=corp", nil), entry("CN=Mallory,DC=corp", nil))
	for _, dn := range []string{"CN=Mallory,DC=corp", "CN=Victim,DC=corp"} {
		err := adCfg().principalUnique(d, Identity{DN: dn, Principal: "user:victim@corp.example.com"})
		if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "CN=Victim,DC=corp") ||
			!strings.Contains(err.Error(), "CN=Mallory,DC=corp") {
			t.Fatalf("%s: %v", dn, err)
		}
	}
	d.on("(userPrincipalName=bob@corp.example.com)", entry("CN=Bob,DC=corp", nil))
	if err := adCfg().principalUnique(d, Identity{DN: "cn=bob,dc=corp", Principal: "user:bob@corp.example.com"}); err != nil {
		t.Fatalf("one entry: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/directory/ -run 'Weak|Escaped|ADIssuer|SubjectDN|ObjectSid|Canonical|SeveralSANs|OneEntry|IdentityOf|UsernameTwo|PrincipalTwo' -count=1`
Expected: FAIL, undefined `Lookup`, `ADIssuerSerial`, `oneEntry`.

- [ ] **Step 3: The mapping**

Create `internal/directory/mapping.go`:

```go
package directory

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

var (
	ErrUnmapped      = errors.New("directory: identity_unmapped")
	ErrAmbiguous     = errors.New("directory: identity_ambiguous")
	ErrUsernameTaken = errors.New("directory: username_collision")
)

var (
	oidSIDExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidSIDValue     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
	oidUPN          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	oidSAN          = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Lookup is one certificate's search under the mapping.
type Lookup struct {
	Attribute, Filter string
	Key               string // store.MapKey of the value: what a bind in grace finds the principal by
}

func unmapped(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnmapped, fmt.Sprintf(format, args...))
}

// Lookup is the search the mapping makes for leaf (Ruling 1): the issuer
// pin first, for a weak kind or any kind given one; then the value,
// exactly one, escaped. A value the kind cannot find is ErrUnmapped.
func (m Mapping) Lookup(leaf *x509.Certificate, userFilter string) (Lookup, error) {
	if len(m.Issuers) > 0 && !pinned(leaf, m.Issuers) {
		return Lookup{}, unmapped("the certificate's issuer %q is not one broker.directory.certificate_mapping.issuers "+
			"pins", printsafe.Line(nameString(leaf.RawIssuer), 300))
	}
	var value string
	switch m.Kind {
	case MapIssuerSerial:
		value = ADIssuerSerial(leaf)
	case MapSID:
		sid, err := SIDOf(leaf)
		if err != nil {
			return Lookup{}, unmapped("%v", err)
		}
		b, err := sidBytes(sid)
		if err != nil {
			return Lookup{}, unmapped("the SID extension holds %v", err)
		}
		return Lookup{Attribute: m.Attribute, Filter: fmt.Sprintf("(&%s(%s=%s))", userFilter, m.Attribute, escapeBytes(b)),
			Key: store.MapKey(string(m.Kind), canonicalValue(m.Kind, sid))}, nil
	case MapSANUPN:
		upns, err := upnsOf(leaf)
		if err != nil || len(upns) != 1 {
			return Lookup{}, unmapped("the certificate carries %d UPN SANs; exactly one maps", len(upns))
		}
		value = upns[0]
	case MapSANEmail:
		if len(leaf.EmailAddresses) != 1 {
			return Lookup{}, unmapped("the certificate carries %d email SANs; exactly one maps", len(leaf.EmailAddresses))
		}
		value = leaf.EmailAddresses[0]
	case MapSubjectDN:
		value = nameString(leaf.RawSubject)
	case MapCN:
		value = leaf.Subject.CommonName
	default:
		return Lookup{}, unmapped("mapping kind %q", m.Kind)
	}
	if value == "" || !printable(value) {
		return Lookup{}, unmapped("the certificate's %s value is empty or not printable (%d bytes)", m.Kind, len(value))
	}
	return Lookup{Attribute: m.Attribute, Filter: fmt.Sprintf("(&%s(%s=%s))", userFilter, m.Attribute,
		ldap.EscapeFilter(value)), Key: store.MapKey(string(m.Kind), canonicalValue(m.Kind, value))}, nil
}

// KeysOf is every mapping key entry e answers to under m: what pre-warm
// and every verification index (Ruling 20).
func (m Mapping) KeysOf(e *ldap.Entry) []string {
	var out []string
	switch m.Kind {
	case MapSID:
		for _, raw := range e.GetRawAttributeValues(m.Attribute) {
			if s, err := sidString(raw); err == nil {
				out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, s)))
			}
		}
	case MapSubjectDN:
		out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, e.DN)))
	default:
		for _, v := range e.GetAttributeValues(m.Attribute) {
			out = append(out, store.MapKey(string(m.Kind), canonicalValue(m.Kind, v)))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// canonicalValue is the form a key hashes, the same on the certificate's
// side and the entry's (pre-flight M-2): a DN as parsed RDNs lower-cased, a
// name lower-cased, an issuer_serial upper-cased (each of those matches
// case-insensitively in AD), a SID through its binary form and back.
func canonicalValue(k MappingKind, v string) string {
	switch k {
	case MapIssuerSerial:
		return strings.ToUpper(v)
	case MapSID:
		if b, err := sidBytes(v); err == nil {
			if s, err := sidString(b); err == nil {
				return s
			}
		}
		return v
	case MapSubjectDN:
		if dn, err := ldap.ParseDN(v); err == nil {
			var parts []string
			for _, rdn := range dn.RDNs {
				for _, a := range rdn.Attributes {
					parts = append(parts, strings.ToLower(a.Type)+"="+strings.ToLower(a.Value))
				}
			}
			return strings.Join(parts, ",")
		}
		return strings.ToLower(v)
	case MapSANUPN, MapSANEmail, MapCN:
		return strings.ToLower(v)
	}
	return v
}

// oidNames is each attribute type a mapping or a pin names, by OID, as AD
// and RFC 4514 write it. nameOIDs is the reverse, with the aliases a pin
// may use.
var (
	oidNames = map[string]string{"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S", "2.5.4.10": "O",
		"2.5.4.11": "OU", "2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
		"1.2.840.113549.1.9.1": "E"}
	nameOIDs = func() map[string]string {
		m := map[string]string{"ST": "2.5.4.8", "EMAILADDRESS": "1.2.840.113549.1.9.1", "DOMAINCOMPONENT": "0.9.2342.19200300.100.1.25"}
		for oid, n := range oidNames {
			m[n] = oid
		}
		return m
	}()
)

// rdnsOf parses raw, a certificate's RawIssuer or RawSubject, as its DER
// RDN sequence, most significant first. Go's pkix.Name drops DC= RDNs and
// Issuer.String() renders them as dotted OIDs (pre-flight I-1), so neither
// is used for a mapping or a pin.
func rdnsOf(raw []byte) (pkix.RDNSequence, error) {
	var seq pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("a malformed name")
	}
	return seq, nil
}

func typeName(oid asn1.ObjectIdentifier) string {
	if t, ok := oidNames[oid.String()]; ok {
		return t
	}
	return "OID." + oid.String()
}

// nameString is raw as an RFC 4514 DN, least significant first, each type
// by its short name (DC kept) and each value escaped by go-ldap's
// DN.String, which lower-cases the types; "" when raw does not parse.
func nameString(raw []byte) string {
	seq, err := rdnsOf(raw)
	if err != nil {
		return ""
	}
	dn := &ldap.DN{}
	for i := len(seq) - 1; i >= 0; i-- {
		rdn := &ldap.RelativeDN{}
		for _, atv := range seq[i] {
			rdn.Attributes = append(rdn.Attributes, &ldap.AttributeTypeAndValue{Type: typeName(atv.Type), Value: fmt.Sprint(atv.Value)})
		}
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn.String()
}

// rdnKeys is a name as the pin compares it: per RDN, most significant
// first, its (OID, case-folded value) pairs sorted.
func rdnKeys(seq pkix.RDNSequence) [][]string {
	out := make([][]string, len(seq))
	for i, rdn := range seq {
		for _, atv := range rdn {
			out[i] = append(out[i], atv.Type.String()+"="+strings.ToLower(fmt.Sprint(atv.Value)))
		}
		slices.Sort(out[i])
	}
	return out
}

// pinKeys is an RFC 4514 pin as rdnKeys, its RDNs reversed into DER order
// and each type through nameOIDs (or written as an OID); false for a type
// neither names, which then matches nothing.
func pinKeys(pin string) ([][]string, bool) {
	dn, err := ldap.ParseDN(pin)
	if err != nil {
		return nil, false
	}
	out := make([][]string, len(dn.RDNs))
	for i, rdn := range dn.RDNs {
		j := len(dn.RDNs) - 1 - i
		for _, a := range rdn.Attributes {
			t := strings.ToUpper(a.Type)
			oid, ok := nameOIDs[t]
			if !ok {
				oid = strings.TrimPrefix(t, "OID.")
				if strings.Trim(oid, "0123456789.") != "" || !strings.Contains(oid, ".") {
					return nil, false
				}
			}
			out[j] = append(out[j], oid+"="+strings.ToLower(a.Value))
		}
		slices.Sort(out[j])
	}
	return out, true
}

// pinned reports whether leaf's issuer, read from its DER, equals one of
// issuers (Ruling 1).
func pinned(leaf *x509.Certificate, issuers []string) bool {
	seq, err := rdnsOf(leaf.RawIssuer)
	if err != nil {
		return false
	}
	got := rdnKeys(seq)
	for _, iss := range issuers {
		if want, ok := pinKeys(iss); ok && slices.EqualFunc(got, want, slices.Equal[[]string]) {
			return true
		}
	}
	return false
}

func printable(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

// ADIssuerSerial is AD's altSecurityIdentities strong form: X509:<I> the
// issuer's RDNs most significant first, read from RawIssuer so DC= is kept,
// <SR> the serial's bytes reversed in upper-case hex (KB5014754). L43's run
// checks it against Samba's form, and L44 against a Windows DC's. "" when
// the issuer does not parse, which Lookup refuses.
func ADIssuerSerial(leaf *x509.Certificate) string {
	seq, err := rdnsOf(leaf.RawIssuer)
	if err != nil {
		return ""
	}
	var parts []string
	for _, rdn := range seq {
		for _, atv := range rdn {
			parts = append(parts, typeName(atv.Type)+"="+fmt.Sprint(atv.Value))
		}
	}
	b := leaf.SerialNumber.Bytes()
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return "X509:<I>" + strings.Join(parts, ",") + "<SR>" + strings.ToUpper(hex.EncodeToString(r))
}

// SIDOf is the SID string in leaf's szOID_NTDS_CA_SECURITY_EXT, exactly one.
func SIDOf(leaf *x509.Certificate) (string, error) {
	var found []string
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSIDExtension) {
			continue
		}
		for _, v := range otherNames(ext.Value, oidSIDValue) {
			var s []byte
			if _, err := asn1.Unmarshal(v, &s); err == nil {
				found = append(found, string(s))
			}
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("the certificate carries %d SID extension values; exactly one maps", len(found))
	}
	return found[0], nil
}

// upnsOf is every UPN otherName in leaf's SAN.
func upnsOf(leaf *x509.Certificate) ([]string, error) {
	var out []string
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		for _, v := range otherNames(ext.Value, oidUPN) {
			var s string
			if _, err := asn1.UnmarshalWithParams(v, &s, "utf8"); err == nil {
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// otherNames is the inner value of every otherName of type id in a
// GeneralNames: each GeneralName [0] IMPLICIT OtherName {type-id, [0]
// EXPLICIT value}.
func otherNames(der []byte, id asn1.ObjectIdentifier) [][]byte {
	var names []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &names); err != nil {
		return nil
	}
	var out [][]byte
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 0 {
			continue
		}
		var on struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"explicit,tag:0"`
		}
		if _, err := asn1.UnmarshalWithParams(n.FullBytes, &on, "tag:0"); err != nil || !on.ID.Equal(id) {
			continue
		}
		out = append(out, on.Value.Bytes)
	}
	return out
}

// sidBytes is a SID string in objectSid's binary form: revision, count,
// the 48-bit authority big-endian, each sub-authority little-endian.
func sidBytes(sid string) ([]byte, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" || len(parts)-3 > 15 {
		return nil, fmt.Errorf("a malformed SID")
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("a malformed SID")
	}
	b := []byte{1, byte(len(parts) - 3), 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auth >> (8 * (5 - i)))
	}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("a malformed SID")
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return b, nil
}

func sidString(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", fmt.Errorf("a malformed objectSid")
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}

func escapeBytes(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, `\%02x`, c)
	}
	return sb.String()
}
```

- [ ] **Step 4: One entry, its identity**

Create `internal/directory/entry.go`:

```go
package directory

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/token"
)

// Identity is one directory entry as a principal (Ruling 3). EntryID is
// the entry's immutable id, the pin a principal keeps.
type Identity struct{ DN, EntryID, Principal, Username string }

// entryAttrs is what an entry search reads: the principal and username
// attributes, the mapping's, for KeysOf, and both immutable ids, of which
// a directory holds one.
func (c Config) entryAttrs() []string {
	return []string{c.PrincipalAttribute, c.UsernameAttribute, c.Mapping.Attribute, "objectGUID", "entryUUID"}
}

// entryID is e's immutable id (Ruling 3): objectGUID's bytes in hex (AD,
// Samba), else entryUUID lower-cased (OpenLDAP, RFC 4530), else the DN
// canonicalized, which an OU move changes.
func entryID(e *ldap.Entry) string {
	if raw := e.GetRawAttributeValue("objectGUID"); len(raw) > 0 {
		return "guid:" + hex.EncodeToString(raw)
	}
	if u := e.GetAttributeValue("entryUUID"); u != "" {
		return "uuid:" + strings.ToLower(u)
	}
	return "dn:" + canonicalValue(MapSubjectDN, e.DN)
}

// oneEntry is the one entry filter finds under base_dn, size limit 2:
// none is ErrUnmapped, two (or the server's size-limit error) ErrAmbiguous
// naming both, never the first (design §7).
func (c Config) oneEntry(s Searcher, filter string, attrs []string) (*ldap.Entry, error) {
	res, err := s.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
		int(c.QueryTimeout.Seconds()), false, filter, attrs, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || (err == nil && len(res.Entries) > 1) {
		var dns []string
		if res != nil {
			for _, e := range res.Entries {
				dns = append(dns, printsafe.Line(e.DN, 200))
			}
		}
		return nil, fmt.Errorf("%w: %d or more entries (%s)", ErrAmbiguous, max(len(dns), 2), strings.Join(dns, "; "))
	}
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%w: no entry under %s", ErrUnmapped, c.BaseDN)
	}
	return res.Entries[0], nil
}

// identityOf derives the principal and username from e (Ruling 3).
func (c Config) identityOf(e *ldap.Entry) (Identity, error) {
	one := func(attr string) (string, error) {
		vs := e.GetAttributeValues(attr)
		if len(vs) != 1 {
			return "", fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
				printsafe.Line(e.DN, 200), len(vs), attr)
		}
		return vs[0], nil
	}
	p, err := one(c.PrincipalAttribute)
	if err != nil {
		return Identity{}, err
	}
	p = strings.ToLower(p)
	if !printable(p) || strings.ContainsAny(p, " \t") || !strings.Contains(p, "@") {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not a printable name with an @ (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.PrincipalAttribute, len(p))
	}
	u, err := one(c.UsernameAttribute)
	if err != nil {
		return Identity{}, err
	}
	u = strings.ToLower(u)
	switch {
	case !token.CanonicalUsername(u):
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not a canonical username (printable ASCII, no "+
			"DOMAIN\\ prefix, no @suffix; %d bytes)", ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	case token.ReservedUsername(u):
		return Identity{}, fmt.Errorf("%w: entry %s's %s %q is reserved: the device's own account (spec §2)",
			ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, u)
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: "user:" + p, Username: u}, nil
}

// heldElsewhere is the DN of an entry under base_dn other than dn whose
// attr equals value, "" for none: one search, size limit 2, and no
// user_filter, so an entry outside it is found too, which only denies more
// (pre-flight M-5). DNs compare as DNs.
func (c Config) heldElsewhere(s Searcher, attr, value, dn string) (string, error) {
	res, err := s.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
		int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(value)), []string{"dn"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return "", err
	}
	mine, _ := ldap.ParseDN(dn)
	if res != nil {
		for _, e := range res.Entries {
			if other, perr := ldap.ParseDN(e.DN); perr != nil || mine == nil || !other.EqualFold(mine) {
				return e.DN, nil
			}
		}
	}
	if err != nil { // more than two entries, none of the two returned another: still another
		return "(further entries past the size limit)", nil
	}
	return "", nil
}

// usernameUnique is ErrUsernameTaken when another entry under base_dn
// holds id's username (Ruling 3): two people under one username would
// share one (nas, username) context.
func (c Config) usernameUnique(s Searcher, id Identity) error {
	other, err := c.heldElsewhere(s, c.UsernameAttribute, id.Username, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: username %q is held by %s and by %s", ErrUsernameTaken, id.Username,
		printsafe.Line(id.DN, 200), printsafe.Line(other, 200))
}

// principalUnique is ErrAmbiguous when another entry under base_dn holds
// id's principal_attribute value (pre-flight C-2). Without it, a user who
// can write their own mail sets it to a colleague's address and binds as
// the colleague's principal; with it, both are refused while the two
// collide, and neither becomes the other.
func (c Config) principalUnique(s Searcher, id Identity) error {
	value := strings.TrimPrefix(id.Principal, "user:")
	other, err := c.heldElsewhere(s, c.PrincipalAttribute, value, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: %s %q is held by %s and by %s: two people under one principal is an impersonation path",
		ErrAmbiguous, c.PrincipalAttribute, value, printsafe.Line(id.DN, 200), printsafe.Line(other, 200))
}
```

(`QueryTimeout` is zero in `adCfg()`; the request's time limit is then 0, no limit, which
the fake ignores.)

The two uniqueness searches run on every verification (Task 10's `verify`), after the
mapping's search, on the same server. They are what makes a self-editable attribute safe:
the operator note still says the attributes must be writable only by directory
administrators (Ruling 3), because a collision refuses both people until it is fixed.

- [ ] **Step 5: Run them to verify they pass**

Run: `go test ./internal/directory/ -count=1`
Expected: PASS. `TestADIssuerSerial`'s expected string is the issuer's DER order, which is
the order KB5014754's own example uses (`X509:<I>DC=com,DC=contoso,CN=CONTOSO-DC-CA<SR>…`).
L43 checks it against Samba, and L44 against a Windows DC.

- [ ] **Step 6: Commit**

```bash
git add internal/directory
git commit -m "feat(directory): the certificate-to-directory mapping, one entry or none, and a unique username" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: Nested groups: `in_chain`, `recursive`, `direct`, and names that must be unique

**Files:**
- Create: `internal/directory/groups.go`, `internal/directory/groups_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`DirectoryWalksTruncated`,
  `DirectoryGroupNamesAmbiguous`)

**Interfaces:**
- Consumes: `Config`, `Searcher`, `fakeDir`, `adCfg` (Tasks 4, 6, 8).
- Produces:

```go
type Groups struct {
	DNs, Names []string // sorted; Names are those verified unique
	Truncated  bool
	Loops      int
	Ambiguous  []string // names dropped because two groups share them
	Unfound    []string // names dropped because their uniqueness search found no group
}
const inChainOID = "1.2.840.113556.1.4.1941"
func (c Config) groupsOf(s Searcher, userDN string) (Groups, error)
func (c Config) uniqueNames(s Searcher, names []string) (unique, ambiguous, unfound []string, err error)
func (c Config) membersOf(s Searcher, groupDN string, limit int) (dns []string, truncated bool, err error)
```

- [ ] **Step 1: The failing tests**

Create `internal/directory/groups_test.go`:

```go
package directory

import (
	"slices"
	"testing"
)

func grp(dn, cn string) *ldap.Entry { return entry(dn, map[string][]string{"cn": {cn}}) }

const (
	gLeaf   = "CN=g-leaf,OU=G,DC=corp"
	gMid    = "CN=g-mid,OU=G,DC=corp"
	gOnCall = "CN=netops-oncall,OU=G,DC=corp"
	gLoopA  = "CN=g-loop-a,OU=G,DC=corp"
	gLoopB  = "CN=g-loop-b,OU=G,DC=corp"
	alice   = "CN=Alice,OU=Staff,DC=corp"
	dave    = "CN=Dave,OU=Staff,DC=corp"
)

func memberFilter(dns ...string) string {
	if len(dns) == 1 {
		return "(&(objectClass=group)(member=" + dns[0] + "))"
	}
	f := "(&(objectClass=group)(|"
	for _, d := range dns {
		f += "(member=" + d + ")"
	}
	return f + "))"
}

func uniqueFilter(name string) string { return "(&(objectClass=group)(cn=" + name + "))" }

// in_chain is one search with the matching rule under groups_base_dn.
func TestInChainIsOneSearch(t *testing.T) {
	d := newFakeDir()
	d.on("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:="+alice+"))", grp(gLeaf, "g-leaf"), grp(gMid, "g-mid"), grp(gOnCall, "netops-oncall"))
	for _, g := range []struct{ dn, cn string }{{gLeaf, "g-leaf"}, {gMid, "g-mid"}, {gOnCall, "netops-oncall"}} {
		d.on(uniqueFilter(g.cn), grp(g.dn, g.cn))
	}
	c := adCfg()
	c.Nested = "in_chain"
	got, err := c.groupsOf(d, alice)
	if err != nil || !slices.Equal(got.DNs, []string{gLeaf, gMid, gOnCall}) || !slices.Contains(got.Names, "netops-oncall") {
		t.Fatalf("%+v %v", got, err)
	}
	if d.calls[0].BaseDN != "OU=G,DC=corp" {
		t.Fatalf("searched under %s", d.calls[0].BaseDN)
	}
	n := 0
	for _, c := range d.calls {
		if strings.Contains(c.Filter, inChainOID) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the matching-rule search was sent %d times, want once (pre-flight M-10)", n)
	}
}

// recursive walks member upward: alice ∈ g-leaf ∈ g-mid ∈ netops-oncall.
func TestARecursiveWalkFindsEveryLevel(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	d.on(memberFilter(gMid), grp(gOnCall, "netops-oncall"))
	for _, g := range []struct{ dn, cn string }{{gLeaf, "g-leaf"}, {gMid, "g-mid"}, {gOnCall, "netops-oncall"}} {
		d.on(uniqueFilter(g.cn), grp(g.dn, g.cn))
	}
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, alice)
	if err != nil || !slices.Equal(got.DNs, []string{gLeaf, gMid, gOnCall}) || got.Truncated || got.Loops != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	c.Nested = "direct"
	if got, _ = c.groupsOf(d, alice); !slices.Equal(got.DNs, []string{gLeaf}) {
		t.Fatalf("direct: %+v", got)
	}
}

// A loop ends the walk at the first revisit, counted (Review Focus 3).
func TestARecursiveWalkEndsOnALoop(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(dave), grp(gLoopA, "g-loop-a"))
	d.on(memberFilter(gLoopA), grp(gLoopB, "g-loop-b"))
	d.on(memberFilter(gLoopB), grp(gLoopA, "g-loop-a"))
	d.on(uniqueFilter("g-loop-a"), grp(gLoopA, "g-loop-a"))
	d.on(uniqueFilter("g-loop-b"), grp(gLoopB, "g-loop-b"))
	c := adCfg()
	c.Nested = "recursive"
	got, err := c.groupsOf(d, dave)
	if err != nil || !slices.Equal(got.DNs, []string{gLoopA, gLoopB}) || got.Loops != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if len(d.calls) > 10 {
		t.Fatalf("the walk did not end: %d searches", len(d.calls))
	}
}

// A chain deeper than max_depth keeps what it found, truncated, never
// more (Review Focus 3).
func TestAWalkAtMaxDepthKeepsWhatItFound(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	d.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	d.on(memberFilter(gMid), grp(gOnCall, "netops-oncall"))
	d.on(uniqueFilter("g-leaf"), grp(gLeaf, "g-leaf"))
	d.on(uniqueFilter("g-mid"), grp(gMid, "g-mid"))
	c := adCfg()
	c.Nested, c.MaxDepth = "recursive", 2
	got, err := c.groupsOf(d, alice)
	if err != nil || !got.Truncated || !slices.Equal(got.DNs, []string{gLeaf, gMid}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// A name two groups share is dropped from Names, and its DN kept: a DN
// subject still matches, a name subject does not (Ruling 7).
func TestASharedGroupNameMatchesNoOne(t *testing.T) {
	d := newFakeDir()
	evil := "CN=netops-oncall,OU=Users-Can-Create,DC=corp"
	d.on(memberFilter(alice), grp(evil, "netops-oncall"))
	d.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"), grp(evil, "netops-oncall"))
	c := adCfg()
	c.Nested = "direct"
	got, err := c.groupsOf(d, alice)
	if err != nil || len(got.Names) != 0 || !slices.Equal(got.Ambiguous, []string{"netops-oncall"}) ||
		!slices.Equal(got.DNs, []string{evil}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// A name whose uniqueness search finds no group is dropped and reported,
// never silently (pre-flight M-9).
func TestANameNoGroupAnswersIsReported(t *testing.T) {
	d := newFakeDir()
	d.on(memberFilter(alice), grp(gLeaf, "g-leaf")) // uniqueFilter("g-leaf") unregistered: no group
	c := adCfg()
	c.Nested = "direct"
	got, err := c.groupsOf(d, alice)
	if err != nil || len(got.Names) != 0 || !slices.Equal(got.Unfound, []string{"g-leaf"}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// in_chain pre-warm asks for one more than the limit and stops there
// (pre-flight M-8): a 50,000-member group is never paged in whole.
func TestMembersOfInChainStopsPastTheLimit(t *testing.T) {
	d := newFakeDir()
	f := "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=" + gOnCall + "))"
	d.on(f, entry("CN=A,DC=corp", nil), entry("CN=B,DC=corp", nil), entry("CN=C,DC=corp", nil))
	c := adCfg()
	c.Nested = "in_chain"
	got, truncated, err := c.membersOf(d, gOnCall, 2)
	if err != nil || !truncated || len(got) != 2 || d.calls[0].SizeLimit != 3 {
		t.Fatalf("%v %v %v; size limit %d", got, truncated, err, d.calls[0].SizeLimit)
	}
}
```

(Add `"strings"` and `"github.com/go-ldap/ldap/v3"` to its imports.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/directory/ -run 'InChain|RecursiveWalk|MaxDepth|SharedGroupName|NameNoGroup|MembersOfInChain' -count=1`
Expected: FAIL, undefined `groupsOf`.

- [ ] **Step 3: The walk**

Create `internal/directory/groups.go`:

```go
package directory

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// inChainOID is LDAP_MATCHING_RULE_IN_CHAIN (design §10).
const inChainOID = "1.2.840.113556.1.4.1941"

// Groups is an entry's membership under the nested mode (Ruling 6).
type Groups struct {
	DNs, Names []string
	Truncated  bool
	Loops      int
	Ambiguous  []string
}

// walkBatch is how many DNs one recursive step asks about in one search.
const walkBatch = 50

// groupsOf is userDN's groups under groups_base_dn: in_chain in one
// search, recursive by walking member upward, direct by its first step.
func (c Config) groupsOf(s Searcher, userDN string) (Groups, error) {
	names := map[string]string{} // DN → name
	var g Groups
	search := func(filter string) ([]*ldap.Entry, error) {
		res, err := s.SearchWithPaging(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, int(c.QueryTimeout.Seconds()), false, filter,
			[]string{c.GroupNameAttribute}, nil), 500)
		if err != nil {
			return nil, err
		}
		return res.Entries, nil
	}
	switch c.Nested {
	case "in_chain":
		es, err := search(fmt.Sprintf("(&%s(%s:%s:=%s))", c.GroupFilter, c.MemberAttribute, inChainOID,
			ldap.EscapeFilter(userDN)))
		if err != nil {
			return Groups{}, err
		}
		for _, e := range es {
			names[e.DN] = e.GetAttributeValue(c.GroupNameAttribute)
		}
	default:
		depth := 1
		if c.Nested == "recursive" {
			depth = c.MaxDepth
		}
		visited := map[string]bool{strings.ToLower(userDN): true}
		frontier := []string{userDN}
		for level := 0; level < depth && len(frontier) > 0; level++ {
			var next []string
			for start := 0; start < len(frontier); start += walkBatch {
				batch := frontier[start:min(start+walkBatch, len(frontier))]
				es, err := search(memberOfAny(c, batch))
				if err != nil {
					return Groups{}, err
				}
				for _, e := range es {
					k := strings.ToLower(e.DN)
					if visited[k] {
						g.Loops++
						continue
					}
					visited[k] = true
					names[e.DN] = e.GetAttributeValue(c.GroupNameAttribute)
					next = append(next, e.DN)
				}
			}
			frontier = next
		}
		g.Truncated = c.Nested == "recursive" && len(frontier) > 0
	}
	var uniq []string
	for dn, name := range names {
		g.DNs = append(g.DNs, dn)
		if name != "" {
			uniq = append(uniq, name)
		}
	}
	slices.Sort(g.DNs)
	var err error
	g.Names, g.Ambiguous, g.Unfound, err = c.uniqueNames(s, uniq)
	return g, err
}

func memberOfAny(c Config, dns []string) string {
	if len(dns) == 1 {
		return fmt.Sprintf("(&%s(%s=%s))", c.GroupFilter, c.MemberAttribute, ldap.EscapeFilter(dns[0]))
	}
	var b strings.Builder
	for _, d := range dns {
		fmt.Fprintf(&b, "(%s=%s)", c.MemberAttribute, ldap.EscapeFilter(d))
	}
	return fmt.Sprintf("(&%s(|%s))", c.GroupFilter, b.String())
}

// uniqueNames splits names into those exactly one group under
// groups_base_dn has, those two or more share (Ruling 7), and those whose
// search found no group at all (a group renamed between the two searches,
// or a group_name_attribute that does not match as written): the last two
// are dropped and reported, never silently (pre-flight M-9). Compared
// lower-cased; returned as the directory spells them, sorted.
func (c Config) uniqueNames(s Searcher, names []string) (unique, ambiguous, unfound []string, err error) {
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		res, err := s.Search(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
			int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(%s=%s))", c.GroupFilter, c.GroupNameAttribute,
				ldap.EscapeFilter(n)), []string{"dn"}, nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded), err == nil && len(res.Entries) > 1:
			ambiguous = append(ambiguous, n)
		case err != nil:
			return nil, nil, nil, err
		case len(res.Entries) == 1:
			unique = append(unique, n)
		default:
			unfound = append(unfound, n)
		}
	}
	slices.Sort(unique)
	slices.Sort(ambiguous)
	slices.Sort(unfound)
	return unique, ambiguous, unfound, nil
}

// membersOf is every user DN under groupDN, transitively under the nested
// mode, at most limit: what pre-warm enumerates (Ruling 20). in_chain asks
// for limit+1 and stops there, so a huge group is never paged in whole
// (pre-flight M-8).
func (c Config) membersOf(s Searcher, groupDN string, limit int) ([]string, bool, error) {
	if c.Nested == "in_chain" {
		res, err := s.SearchWithPaging(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			limit+1, int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(memberOf:%s:=%s))", c.UserFilter, inChainOID,
				ldap.EscapeFilter(groupDN)), []string{"dn"}, nil), 500)
		truncated := ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
		if err != nil && !truncated {
			return nil, false, err
		}
		var out []string
		if res != nil {
			for _, e := range res.Entries {
				out = append(out, e.DN)
			}
		}
		if len(out) > limit {
			out, truncated = out[:limit], true
		}
		return out, truncated, nil
	}
	depth := 1
	if c.Nested == "recursive" {
		depth = c.MaxDepth
	}
	// A member outside groups_base_dn is never a group the walk follows
	// (groupsOf searches only under it), so it is a user without a search;
	// inside, isGroup's answer is kept for the call (pre-flight M-8).
	groupsBase, _ := ldap.ParseDN(c.GroupsBaseDN)
	kind := map[string]bool{}
	classify := func(dn string) (bool, error) {
		if d, err := ldap.ParseDN(dn); err == nil && groupsBase != nil && !groupsBase.AncestorOfFold(d) {
			return false, nil
		}
		k := strings.ToLower(dn)
		if g, ok := kind[k]; ok {
			return g, nil
		}
		g, err := c.isGroup(s, dn)
		if err == nil {
			kind[k] = g
		}
		return g, err
	}
	visited := map[string]bool{strings.ToLower(groupDN): true}
	frontier, users := []string{groupDN}, []string{}
	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string
		for _, g := range frontier {
			res, err := s.Search(ldap.NewSearchRequest(g, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
				int(c.QueryTimeout.Seconds()), false, "(objectClass=*)", []string{c.MemberAttribute}, nil))
			if err != nil {
				return nil, false, err
			}
			for _, e := range res.Entries {
				for _, m := range e.GetAttributeValues(c.MemberAttribute) {
					if visited[strings.ToLower(m)] {
						continue
					}
					visited[strings.ToLower(m)] = true
					isGroup, err := classify(m)
					if err != nil {
						return nil, false, err
					}
					if isGroup {
						next = append(next, m)
					} else if len(users) < limit {
						users = append(users, m)
					} else {
						return users, true, nil
					}
				}
			}
		}
		frontier = next
	}
	return users, false, nil
}

func (c Config) isGroup(s Searcher, dn string) (bool, error) {
	res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(c.QueryTimeout.Seconds()), false, c.GroupFilter, []string{"dn"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false, nil
	}
	return err == nil && len(res.Entries) == 1, err
}
```

The `fakeDir`'s filters in the test match `memberOfAny`'s output exactly. With `GroupFilter`
`(objectClass=group)` and one DN, the filter is `(&(objectClass=group)(member=<dn>))`.
`ldap.EscapeFilter` leaves `=` and `,` alone, so the test's literal DNs match as written.

Add the two metrics (`port49_directory_walks_truncated_total` counter,
`port49_directory_group_names_ambiguous` gauge). Task 10's resolver moves them; this task
only adds and registers them.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/directory/ -race -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/directory internal/daemon/metrics/metrics.go
git commit -m "feat(directory): nested groups by configuration, loop-safe and depth-capped, names that must be unique" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: The resolver: map, verify, grace from the store, and pre-warm

**Files:**
- Create: `internal/directory/resolver.go`, `internal/directory/resolver_test.go`,
  `internal/directory/prewarm.go`, `internal/directory/prewarm_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`DirectoryLookups`, `DirectoryPrewarmPrincipals`,
  `DirectoryPrewarmLastSuccess`)

**Interfaces:**
- Consumes: `Pool.Do` (Task 6); `Mapping.Lookup`, `KeysOf`, `oneEntry`, `identityOf`,
  `usernameUnique`, `principalUnique` (Task 8); `groupsOf`, `membersOf` (Task 9);
  `store.Membership`, `PutMembership`, `RefuseMapKeys`, `GetMembership`, `MembershipByKey`,
  `store.ErrNotFound` (Task 5).
- Produces:

```go
type Source string
const (Fresh Source = "fresh"; Grace Source = "grace")
var ErrNotUser = errors.New("directory: not a user: principal")
func IsUser(principal string) bool
type Answer struct {
	store.Membership
	Source Source
}
type Resolver struct {
	Cfg      Config
	Pool     *Pool
	Store    store.Store
	Now      func() time.Time
	M        *metrics.Metrics
	Say      func(format string, args ...any)
	// Declared is the usernames policy subjects declare, by username, the
	// subject's name the value; a derived one equal to any is
	// ErrUsernameTaken (Ruling 3), fresh or from grace. Nil declares none.
	Declared func() map[string]string
	// StoreTimeout bounds the resolver's own store reads and writes (the
	// grace read, a refusal); 10s when zero.
	StoreTimeout time.Duration
}
func (r *Resolver) Map(ctx context.Context, leaf *x509.Certificate) (Answer, error)
func (r *Resolver) Verify(ctx context.Context, principal string) (Answer, error)
func (r *Resolver) Current(ctx context.Context, principal string) (Answer, error)
func (r *Resolver) Stored(ctx context.Context, principal string) (store.Membership, bool, error)
func (r *Resolver) TTL() time.Duration
func (r *Resolver) Prewarm(ctx context.Context, groups []string) (PrewarmReport, error)
type PrewarmReport struct{ Groups, Principals, Failed int; Capped bool }
```

- [ ] **Step 1: The failing tests**

Create `internal/directory/resolver_test.go`:

```go
package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

type world struct {
	clk *fakeClock
	srv *fakeServers
	dir *fakeDir
	st  store.Store
	say *lines
	r   *Resolver
}

const dc01 = "ldaps://dc-01"

// newWorld is one directory server holding alice (in netops-oncall,
// directly) and a resolver over a memory store, mapping by san_email.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{clk: newClock(), srv: newFakeServers(dc01), say: &lines{}}
	w.dir = w.srv.dirs[dc01]
	cfg := adCfg()
	cfg.Servers = []Server{{URI: dc01, Priority: 100}}
	cfg.Nested, cfg.Grace, cfg.QueryTimeout = "direct", 4*time.Hour, time.Second
	cfg.FailureThreshold, cfg.ProbeInterval, cfg.HealthInterval, cfg.HealthTimeout = 3, time.Minute, 30*time.Second, time.Second
	cfg.Mapping = Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	cfg.Bind.Mechanism = "simple"
	m := metrics.New(prometheus.NewRegistry())
	w.st = memory.New(w.clk.Now)
	w.r = &Resolver{Cfg: cfg, Pool: NewPool(cfg, w.srv.dial, noCheck, w.clk.Now, m, w.say.say), Store: w.st,
		Now: w.clk.Now, M: m, Say: w.say.say}
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}})
	w.dir.on("(&(objectClass=person)(mail=alice@corp.example.com))", a)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
	w.dir.on("(userPrincipalName=alice@corp.example.com)", a) // principalUnique
	w.dir.on("(sAMAccountName=alice)", a)                      // usernameUnique
	w.dir.on(memberFilter(alice), grp(gOnCall, "netops-oncall"))
	w.dir.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"))
	return w
}

// down takes dc-01 away: every connection to it closed, every dial refused.
func (w *world) down() {
	w.srv.setDown(dc01, true)
	w.srv.closeAll(dc01)
}

func aliceCert(t *testing.T) *x509.Certificate { return leaf(t, nil) }

const alicePrincipal = "user:alice@corp.example.com"

// A fresh mapping is written to the store, by principal and by key.
func TestMapVerifiesAndStores(t *testing.T) {
	w := newWorld(t)
	a, err := w.r.Map(context.Background(), aliceCert(t))
	if err != nil || a.Source != Fresh || a.Principal != alicePrincipal || a.Username != "alice" ||
		!slices.Equal(a.GroupNames, []string{"netops-oncall"}) || !a.VerifiedAt.Equal(w.clk.Now()) {
		t.Fatalf("%+v %v", a, err)
	}
	l, _ := w.r.Cfg.Mapping.Lookup(aliceCert(t), w.r.Cfg.UserFilter)
	if m, err := w.st.MembershipByKey(context.Background(), l.Key); err != nil || m.Principal != a.Principal {
		t.Fatalf("by key: %+v %v", m, err)
	}
}

// With no server answering, a bind and a mint read the store within
// grace, and refuse past it (Ruling 10); a restart loses nothing, as the
// store is the cache (Review Focus 4).
func TestGraceReadsTheStoreAfterARestart(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	restarted := &Resolver{Cfg: w.r.Cfg, Pool: NewPool(w.r.Cfg, w.srv.dial, noCheck, w.clk.Now, w.r.M, w.say.say),
		Store: w.st, Now: w.clk.Now, M: w.r.M, Say: w.say.say}
	w.clk.Add(3 * time.Hour)
	a, err := restarted.Map(context.Background(), aliceCert(t))
	if err != nil || a.Source != Grace || a.Principal != alicePrincipal {
		t.Fatalf("within grace: %+v %v", a, err)
	}
	if c, err := restarted.Current(context.Background(), a.Principal); err != nil || c.Source != Grace {
		t.Fatalf("a mint within grace: %+v %v", c, err)
	}
	w.clk.Add(time.Hour + time.Minute)
	_, err = restarted.Current(context.Background(), a.Principal)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "past directory.grace") {
		t.Fatalf("past grace: %v", err)
	}
}

// A principal the directory refused before an outage is refused through
// it (pre-flight C-1): the refusal is stored, by principal and by key, and
// grace never overrules it. Without it, a user deleted at T and refused at
// T+5m would mint from grace when the DCs drop at T+10m.
func TestARefusedPrincipalIsNotServedFromGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(5 * time.Minute)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))") // deleted
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("verify after the deletion: %v", err)
	}
	w.clk.Add(5 * time.Minute)
	w.down()
	if a, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind in the outage: %+v %v, want ErrUnavailable", a, err)
	}
	if a, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a mint in the outage: %+v %v, want ErrUnavailable", a, err)
	}
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); !m.Refused {
		t.Fatalf("the refusal was not stored: %+v", m)
	}
}

// A bind refused by the key the certificate searched with (no entry maps)
// is stored by that key, so grace refuses the certificate too.
func TestAnUnmappedCertificateIsRefusedByKey(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(time.Minute)
	w.dir.on("(&(objectClass=person)(mail=alice@corp.example.com))") // mail removed
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
	w.down()
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind in the outage: %v, want ErrUnavailable", err)
	}
}

// A principal claimed by another entry than the one it was verified on is
// identity_unmapped, at a bind and on a re-verification (pre-flight C-2):
// alice's UPN moves off her entry and mallory sets hers to it, and
// mallory's own certificate never becomes user:alice@. The refusal keeps
// alice's pin, so a second try fails the same way.
func TestAPrincipalOnAnotherEntryIsUnmapped(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(time.Minute)
	mallory := entry("CN=Mallory,OU=Staff,DC=corp", map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"mallory"}, "mail": {"mallory@corp.example.com"}})
	w.dir.on("(&(objectClass=person)(mail=mallory@corp.example.com))", mallory)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", mallory)
	w.dir.on("(userPrincipalName=alice@corp.example.com)", mallory) // alice's own entry no longer holds it
	w.dir.on("(sAMAccountName=mallory)", mallory)
	mcert := leaf(t, func(c *x509.Certificate) { c.EmailAddresses = []string{"mallory@corp.example.com"} })
	for i := 0; i < 2; i++ {
		a, err := w.r.Map(context.Background(), mcert)
		if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "CN=Mallory") {
			t.Fatalf("mallory's bind %d: %+v %v", i, a, err)
		}
		if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("re-verifying alice %d: %v", i, err)
		}
	}
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); m.EntryID != "dn:"+strings.ToLower(alice) {
		t.Fatalf("the refusal dropped alice's pin: %+v", m)
	}
}

// An entry deleted and re-created (a rehire, a restore) keeps its DN and
// values and gets a new objectGUID: it is refused while the old pin's
// record lives, each refusal renewing it, and the line says once an hour
// how to end it. Once the record is forgotten (DeleteMembership, what
// `port49 directory forget` calls) the next bind pins the new entry
// (Ruling 3's escape).
func TestARecreatedEntryIsRefusedUntilForgotten(t *testing.T) {
	w := newWorld(t)
	seed := func(guid string) {
		a := entry(alice, map[string][]string{"objectGUID": {guid}, "userPrincipalName": {"alice@corp.example.com"},
			"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}})
		for _, f := range []string{"(&(objectClass=person)(mail=alice@corp.example.com))",
			"(&(objectClass=person)(userPrincipalName=alice@corp.example.com))",
			"(userPrincipalName=alice@corp.example.com)", "(sAMAccountName=alice)"} {
			w.dir.on(f, a)
		}
	}
	seed("\x0a\x1b")
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	seed("\x9f\x8e")
	way := "port49 directory forget " + alicePrincipal
	for i := 0; i < 2; i++ {
		w.clk.Add(time.Minute)
		if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnmapped) ||
			!strings.Contains(err.Error(), "guid:0a1b") || !strings.Contains(err.Error(), way) {
			t.Fatalf("the re-created entry's bind %d: %v", i, err)
		}
		if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("re-verifying alice %d: %v", i, err)
		}
	}
	if n := w.say.count(way); n != 1 {
		t.Fatalf("the line naming the way out was said %d times, want once in the hour", n)
	}
	old, err := w.st.DeleteMembership(context.Background(), alicePrincipal)
	if err != nil || old.EntryID != "guid:0a1b" || !old.Refused {
		t.Fatalf("forget: %+v %v, want the refusal pinned to the old entry", old, err)
	}
	w.clk.Add(time.Minute)
	if a, err := w.r.Map(context.Background(), aliceCert(t)); err != nil || a.Source != Fresh ||
		a.Principal != alicePrincipal {
		t.Fatalf("after forget: %+v %v", a, err)
	}
	if m, err := w.st.GetMembership(context.Background(), alicePrincipal); err != nil || m.EntryID != "guid:9f8e" {
		t.Fatalf("after forget, the pin: %+v %v, want the new entry's", m, err)
	}
}

// Two entries holding one principal value are both refused (pre-flight
// C-2), at a bind as on a re-verification.
func TestAPrincipalTwoEntriesHoldIsRefusedAtBind(t *testing.T) {
	w := newWorld(t)
	mallory := entry("CN=Mallory,OU=Staff,DC=corp", map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"mallory"}})
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"}, "sAMAccountName": {"alice"}})
	w.dir.on("(userPrincipalName=alice@corp.example.com)", a, mallory)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("%v", err)
	}
}

// A rotated bind password is the server not answering (pre-flight I-2):
// a request in it is served from grace.
func TestABindRefusalFailsOverAndReachesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.srv.setRefuse(dc01, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	w.srv.closeAll(dc01) // the held connection drops; the next dial is refused
	for i := 0; i < 2; i++ {
		if a, err := w.r.Current(context.Background(), alicePrincipal); err != nil || a.Source != Grace {
			t.Fatalf("request %d: %+v %v, want grace", i, a, err)
		}
	}
	if !w.say.has("refused the bind (simple)") {
		t.Fatalf("%v", w.say.l)
	}
}

// A server slower than query_timeout, asked under a caller deadline
// shorter still, reaches grace: the directory call is bounded by
// query_timeout alone and the grace read has its own budget (pre-flight
// I-8), so a slow DC is never blamed on the store.
func TestASlowServerReachesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.dir.mu.Lock()
	w.dir.delay = 3 * time.Second
	w.dir.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if a, err := w.r.Current(ctx, alicePrincipal); err != nil || a.Source != Grace {
		t.Fatalf("%+v %v, want grace", a, err)
	}
}

// Verify never answers from grace: the scheduled refresh stamps only what
// a server said (Ruling 12).
func TestVerifyNeverServesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// A principal whose entry is gone or renamed is ErrUnmapped on Verify,
// so the scheduled pass revokes (Ruling 12).
func TestVerifyAGoneEntryIsUnmapped(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Verify(context.Background(), "user:bob@corp.example.com"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
}

// A machine principal is never searched for, and never a refusal: the
// directory holds no entry for it (pre-flight I-10).
func TestAMachinePrincipalIsNeverSearched(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{"app:deploy", "spiffe://corp/ns/x", "system:serviceaccount:ns:sa"} {
		_, err := w.r.Verify(context.Background(), p)
		if err == nil || errors.Is(err, ErrUnmapped) || !errors.Is(err, ErrNotUser) {
			t.Fatalf("%s: %v, want ErrNotUser", p, err)
		}
	}
	if len(w.dir.calls) != 0 {
		t.Fatalf("%d searches for machine principals", len(w.dir.calls))
	}
}

// A derived username a policy subject declares collides (Ruling 3), on a
// fresh answer and on a grace one (pre-flight M-11): a declaration made
// in a policy reload during an outage still refuses the stored membership.
func TestADeclaredUsernameCollides(t *testing.T) {
	declared := func() map[string]string { return map[string]string{"alice": "svc_alice"} }
	w := newWorld(t)
	w.r.Declared = declared
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUsernameTaken) ||
		!strings.Contains(err.Error(), "svc_alice") {
		t.Fatalf("fresh: %v", err)
	}
	w = newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	w.r.Declared = declared
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("grace: %v", err)
	}
}

// An earlier verification never overwrites a later one, so a replica's
// slow answer cannot undo a removal (Ruling 10).
func TestAStaleVerificationDoesNotWin(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(-time.Minute)
	w.dir.on(memberFilter(alice)) // no groups any more, but verified "earlier"
	a, err := w.r.Verify(context.Background(), alicePrincipal)
	if err != nil || len(a.GroupDNs) != 0 {
		t.Fatalf("the second answer: %+v %v, want no groups (pre-flight M-10)", a, err)
	}
	m, _ := w.st.GetMembership(context.Background(), alicePrincipal)
	if len(m.GroupDNs) != 1 {
		t.Fatalf("an earlier answer replaced the later one: %+v", m)
	}
}
```

Add to `fake_test.go`:

```go
// closeAll closes every connection dialled to uri, as a server going away
// or dropping its clients does.
func (f *fakeServers) closeAll(uri string) {
	f.mu.Lock()
	cs := slices.Clone(f.conns[uri])
	f.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}
```

(with `"slices"` in its imports).

Create `internal/directory/prewarm_test.go`. It asserts that `Prewarm` with `[]string{gOnCall}`
under `direct` reads the group's `member` (base scope, `(objectClass=*)`) and classifies each
member. It verifies alice and writes her membership with her mapping key, so a later `Map`
with the server down answers from grace. It also asserts that a `max_principals` of 1 with
two members stops at one and reports `Capped`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/directory/ -run 'MapVerifies|Grace|Refused|Unmapped|AnotherEntry|RecreatedEntry|TwoEntriesHold|BindRefusal|SlowServer|VerifyNever|VerifyAGone|MachinePrincipal|DeclaredUsername|StaleVerification|Prewarm' -count=1`
Expected: FAIL, undefined `Resolver`.

- [ ] **Step 3: The resolver**

Create `internal/directory/resolver.go`:

```go
package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

type Source string

const (
	Fresh Source = "fresh"
	Grace Source = "grace"
)

// ErrNotUser is a principal the directory holds no entry for: a machine
// principal (spiffe://, system:serviceaccount:, app:). It is never a
// refusal, so nothing revokes on it (pre-flight I-10).
var ErrNotUser = errors.New("directory: not a user: principal")

// IsUser reports whether principal is one the directory resolves: a
// user: principal (design §7). Every other is policy.MemberOf alone.
func IsUser(principal string) bool { return strings.HasPrefix(principal, "user:") }

// Answer is a membership and where it came from.
type Answer struct {
	store.Membership
	Source Source
}

// Resolver is the broker's one door to the directory (plan 7g).
type Resolver struct {
	Cfg      Config
	Pool     *Pool
	Store    store.Store
	Now      func() time.Time
	M        *metrics.Metrics
	Say      func(format string, args ...any)
	Declared func() map[string]string
	// StoreTimeout bounds each store read and write the resolver makes
	// on its own budget (the grace read, a refusal); 10s when zero, as
	// the broker's holdTimeout.
	StoreTimeout time.Duration

	mu   sync.Mutex
	said map[string]time.Time
}

// TTL is a membership record's lease: past grace, so a policy reload
// judges a context by the membership its principal last had (Ruling 10).
func (r *Resolver) TTL() time.Duration { return max(r.Cfg.Grace, 24*time.Hour) }

func (r *Resolver) storeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	d := r.StoreTimeout
	if d == 0 {
		d = 10 * time.Second
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// lookup is one verification: how the entry is found, and what it must
// still be.
type lookup struct {
	find   func(Searcher) (*ldap.Entry, error)
	want   string // the principal the entry must still give; "" at a bind or a pre-warm
	mapKey string // the key a bind searched with: indexed on success, refused on a refusal
	say    string // what names the lookup in a line said once
}

// Map maps a client certificate to its membership at a bind (Ruling 4):
// from a server, written to the store; with no server answering, from the
// store by the certificate's mapping key within grace.
func (r *Resolver) Map(ctx context.Context, leaf *x509.Certificate) (Answer, error) {
	l, err := r.Cfg.Mapping.Lookup(leaf, r.Cfg.UserFilter)
	if err != nil {
		r.count("unmapped")
		return Answer{}, err
	}
	a, err := r.verify(ctx, lookup{find: r.byFilter(l.Filter), mapKey: l.Key, say: l.Filter})
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.MembershipByKey(ctx, l.Key)
	}, err, "this certificate")
}

// Verify reads principal's entry and groups from a server, never from
// grace: the scheduled refresh and an explicit re-check (Ruling 12). The
// entry must be the one the principal is pinned to (verify's pin check).
func (r *Resolver) Verify(ctx context.Context, principal string) (Answer, error) {
	if !IsUser(principal) {
		return Answer{}, fmt.Errorf("%w: %s", ErrNotUser, printsafe.Line(principal, 200))
	}
	v := strings.TrimPrefix(principal, "user:")
	filter := fmt.Sprintf("(&%s(%s=%s))", r.Cfg.UserFilter, r.Cfg.PrincipalAttribute, ldap.EscapeFilter(v))
	return r.verify(ctx, lookup{find: r.byFilter(filter), want: principal, say: filter})
}

// byFilter finds the one entry filter matches under base_dn.
func (r *Resolver) byFilter(filter string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) { return r.Cfg.oneEntry(s, filter, r.Cfg.entryAttrs()) }
}

// byDN reads the entry at dn, if it is a user (pre-warm: a group's member).
func (r *Resolver) byDN(dn string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) {
		res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
			int(r.Cfg.QueryTimeout.Seconds()), false, r.Cfg.UserFilter, r.Cfg.entryAttrs(), nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			return nil, fmt.Errorf("%w: no entry %s", ErrUnmapped, printsafe.Line(dn, 200))
		case err != nil:
			return nil, err
		case len(res.Entries) != 1:
			return nil, fmt.Errorf("%w: %s is not a user", ErrUnmapped, printsafe.Line(dn, 200))
		}
		return res.Entries[0], nil
	}
}

// Current is the membership a request uses: Verify, else the store's
// within grace (Ruling 10).
func (r *Resolver) Current(ctx context.Context, principal string) (Answer, error) {
	a, err := r.Verify(ctx, principal)
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.GetMembership(ctx, principal)
	}, err, principal)
}

// Stored is the membership the store holds, whatever its age, refused or
// not: what a policy refresh judges by (Ruling 12). false with none.
func (r *Resolver) Stored(ctx context.Context, principal string) (store.Membership, bool, error) {
	m, err := r.Store.GetMembership(ctx, principal)
	if errors.Is(err, store.ErrNotFound) {
		return store.Membership{}, false, nil
	}
	return m, err == nil, err
}

// verify finds the entry, derives its identity, checks that its principal
// and username are its alone and reads its groups, on the pool; then
// checks the entry is the one the principal is pinned to, and writes the
// store. The
// pool call is bounded by query_timeout alone, never by the caller's
// shorter deadline (pre-flight I-8), so a slow DC reaches grace. A
// refusal (unmapped, ambiguous, collision) is written too (pre-flight
// C-1): by the principal asked for, by the principal the entry gave when
// it is that principal's own (its value or username held twice), and by
// the key a bind searched with.
func (r *Resolver) verify(ctx context.Context, q lookup) (Answer, error) {
	var id Identity
	var g Groups
	var keys []string
	refuse := ""
	srv, err := r.Pool.Do(context.WithoutCancel(ctx), func(s Searcher) error {
		e, err := q.find(s)
		if err != nil {
			return err
		}
		if id, err = r.Cfg.identityOf(e); err != nil {
			return err
		}
		if q.want != "" && id.Principal != q.want {
			return fmt.Errorf("%w: the entry now gives %s", ErrUnmapped, id.Principal)
		}
		if err := r.Cfg.principalUnique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		if err := r.Cfg.usernameUnique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		keys = r.Cfg.Mapping.KeysOf(e)
		g, err = r.Cfg.groupsOf(s, id.DN)
		return err
	})
	if err == nil {
		// The pin (Ruling 3; pre-flight C-2): a principal the store holds
		// for another entry is refused, at a bind as on a re-verification.
		// No refusal is written for the principal here at a bind: it is
		// another person's, and its record (with its pin) stands. The line
		// is said once an hour per principal, naming the way out.
		if err = r.pinned(ctx, id); errors.Is(err, ErrUnmapped) {
			r.sayOnce("pin:"+id.Principal, time.Hour, "%s", printsafe.Line(err.Error(), 900))
		}
	}
	if err == nil {
		if who, ok := r.declared()[id.Username]; ok {
			refuse = id.Principal
			err = fmt.Errorf("%w: the directory derives username %q for %s, which subject %q declares",
				ErrUsernameTaken, id.Username, id.Principal, who)
		}
	}
	switch {
	case errors.Is(err, ErrUnavailable):
		r.sayOnce("unavailable", time.Hour, "directory: no server answered (%s); serving memberships verified within "+
			"%s (directory.grace)", printsafe.Line(err.Error(), 300), r.Cfg.Grace)
		return Answer{}, err
	case errors.Is(err, ErrAmbiguous):
		r.count("ambiguous")
		r.sayOnce("ambiguous:"+q.say, time.Hour, "directory: identity_ambiguous: %s; refusing it: two people "+
			"matching one certificate is an impersonation path (design §7)", printsafe.Line(err.Error(), 400))
		r.refuse(ctx, q, refuse, id)
		return Answer{}, err
	case errors.Is(err, ErrUsernameTaken):
		r.count("collision")
		r.refuse(ctx, q, refuse, id)
		return Answer{}, err
	case errors.Is(err, ErrUnmapped):
		r.count("unmapped")
		r.refuse(ctx, q, "", id)
		return Answer{}, err
	case err != nil:
		return Answer{}, err
	}
	if g.Truncated {
		r.M.DirectoryWalksTruncated.Inc()
		r.sayOnce("truncated:"+id.DN, time.Hour, "directory: %s's group walk reached max_depth (%d); the groups "+
			"found are used and the deeper ones are not", printsafe.Line(id.DN, 200), r.Cfg.MaxDepth)
	}
	if g.Loops > 0 {
		r.sayOnce("loop:"+id.DN, time.Hour, "directory: %s's group walk met a loop %d time(s); it ended at the "+
			"revisit", printsafe.Line(id.DN, 200), g.Loops)
	}
	if len(g.Ambiguous) > 0 {
		r.sayOnce("names:"+strings.Join(g.Ambiguous, ","), time.Hour, "directory: group name(s) %s are shared by "+
			"two or more groups under %s; a subject naming one matches no one (use its DN)",
			strings.Join(g.Ambiguous, ", "), r.Cfg.GroupsBaseDN)
	}
	if len(g.Unfound) > 0 {
		r.sayOnce("unfound:"+strings.Join(g.Unfound, ","), time.Hour, "directory: group name(s) %s matched no group "+
			"under %s by %s when checked for uniqueness; a subject naming one matches no one until it does",
			strings.Join(g.Unfound, ", "), r.Cfg.GroupsBaseDN, r.Cfg.GroupNameAttribute)
	}
	if q.mapKey != "" && !slices.Contains(keys, q.mapKey) {
		keys = append(keys, q.mapKey) // the key the bind searched with is indexed too (pre-flight M-2)
		slices.Sort(keys)
	}
	m := store.Membership{Principal: id.Principal, DN: id.DN, EntryID: id.EntryID, Username: id.Username,
		GroupDNs: g.DNs, GroupNames: g.Names, MapKeys: keys, VerifiedAt: r.Now(), Server: srv.URI, Site: srv.Site}
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	if err := r.Store.PutMembership(sctx, m, r.TTL()); err != nil {
		return Answer{}, err
	}
	r.count("fresh")
	return Answer{Membership: m, Source: Fresh}, nil
}

// pinned is ErrUnmapped when the store holds id.Principal pinned to
// another entry (Ruling 3): a principal_attribute value moved between
// entries never carries the principal with it. A refused record keeps its
// pin and is checked the same way.
func (r *Resolver) pinned(ctx context.Context, id Identity) error {
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	m, err := r.Store.GetMembership(sctx, id.Principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case m.EntryID == "" || m.EntryID == id.EntryID:
		return nil
	}
	// The line names the way out (Ruling 3's escape): an entry deleted and
	// re-created reads exactly like another person's, and only the operator
	// can tell them apart.
	return fmt.Errorf("%w: %s is pinned to entry %s and is now claimed by %s (%s); a %s value moved "+
		"between entries never carries a principal with it (Ruling 3); if this is the same person's entry "+
		"re-created (a rehire, a restore), confirm that and run `port49 directory forget %s` against the "+
		"broker's admin_socket", ErrUnmapped, id.Principal, printsafe.Line(m.EntryID, 120),
		printsafe.Line(id.DN, 200), printsafe.Line(id.EntryID, 120), r.Cfg.PrincipalAttribute, id.Principal)
}

// refuse stores the directory's "no" (pre-flight C-1) for q.want, for
// also (a principal the entry gave whose value or username another entry
// holds), and for q.mapKey, so grace never answers yes in an outage that
// follows. Each principal's refusal keeps the pin its record held, or the
// refused entry's own id when none was held, so a refusal never frees the
// principal for the next claimant. A failed write is said; the refusal
// itself stands either way.
func (r *Resolver) refuse(ctx context.Context, q lookup, also string, id Identity) {
	now := r.Now()
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	ps := []string{q.want}
	if also != q.want {
		ps = append(ps, also)
	}
	for _, p := range ps {
		if p == "" {
			continue
		}
		pin := ""
		if held, err := r.Store.GetMembership(sctx, p); err == nil {
			pin = held.EntryID
		} else if p == id.Principal {
			pin = id.EntryID
		}
		if err := r.Store.PutMembership(sctx, store.Membership{Principal: p, EntryID: pin, Refused: true,
			VerifiedAt: now}, r.TTL()); err != nil {
			r.sayOnce("refuse:"+p, time.Hour, "directory: %s: storing the directory's refusal failed (%v); grace "+
				"may serve its older membership in an outage until the store takes the write", p, err)
		}
	}
	if q.mapKey != "" {
		if err := r.Store.RefuseMapKeys(sctx, []string{q.mapKey}, now, r.TTL()); err != nil {
			r.sayOnce("refusekey:"+q.mapKey, time.Hour, "directory: storing a certificate's refusal failed (%v)", err)
		}
	}
}

// grace answers from a stored membership verified within grace, read on
// its own budget, or ErrUnavailable saying why not. A refused record is
// never served (pre-flight C-1), and a declared username still collides
// (pre-flight M-11).
func (r *Resolver) grace(ctx context.Context, read func(context.Context) (store.Membership, error), cause error,
	who string) (Answer, error) {
	sctx, cancel := r.storeCtx(ctx)
	defer cancel()
	m, gerr := read(sctx)
	switch {
	case errors.Is(gerr, store.ErrNotFound):
		r.count("unavailable")
		return Answer{}, fmt.Errorf("%w: no membership is stored for %s (%v)", ErrUnavailable, who, cause)
	case gerr != nil:
		return Answer{}, gerr
	case m.Refused:
		r.count("unavailable")
		return Answer{}, fmt.Errorf("%w: the directory refused %s at %s, before it stopped answering; grace never "+
			"overrules a refusal", ErrUnavailable, m.Principal, m.VerifiedAt.UTC().Format(time.RFC3339))
	}
	age := r.Now().Sub(m.VerifiedAt)
	if r.Cfg.Grace == 0 || age > r.Cfg.Grace {
		r.count("unavailable")
		r.sayOnce("past:"+m.Principal, time.Hour, "directory: %s: no server answered and the membership stored was "+
			"verified %s ago, past directory.grace (%s); refused directory_unavailable", m.Principal,
			age.Round(time.Minute), r.Cfg.Grace)
		return Answer{}, fmt.Errorf("%w: the membership stored for %s was verified %s ago, past directory.grace (%s)",
			ErrUnavailable, m.Principal, age.Round(time.Minute), r.Cfg.Grace)
	}
	if subj, ok := r.declared()[m.Username]; ok {
		r.count("collision")
		return Answer{}, fmt.Errorf("%w: the stored membership gives username %q for %s, which subject %q declares",
			ErrUsernameTaken, m.Username, m.Principal, subj)
	}
	r.count("grace")
	r.sayOnce("grace:"+m.Principal, time.Hour, "directory: %s minted from a membership verified %s ago (grace)",
		m.Principal, age.Round(time.Minute))
	return Answer{Membership: m, Source: Grace}, nil
}

func (r *Resolver) declared() map[string]string {
	if r.Declared == nil {
		return nil
	}
	return r.Declared()
}

func (r *Resolver) count(outcome string) { r.M.DirectoryLookups.WithLabelValues(outcome).Inc() }

// sayOnce says a line at most once per every, by key.
func (r *Resolver) sayOnce(key string, every time.Duration, format string, args ...any) {
	r.mu.Lock()
	if r.said == nil {
		r.said = map[string]time.Time{}
	}
	now := r.Now()
	if last, ok := r.said[key]; ok && now.Sub(last) < every {
		r.mu.Unlock()
		return
	}
	r.said[key] = now
	r.mu.Unlock()
	r.Say(format, args...)
}
```

`sayOnce`'s map is bounded by the population: one key per principal, filter and DN, hourly.
That is the same bound as `Broker.said` (7c).

A user whose entry moves OU keeps their principal, since the pin is `objectGUID` or
`entryUUID`. On a directory that returns neither, the pin is the DN, and a move is
`identity_unmapped` until the record lapses (`max(grace, 24h)` after the last verification or
refusal). A re-created entry for the same person (a new id) is refused the same way: fail
closed, said with both ids.

- [ ] **Step 4: Pre-warm**

Create `internal/directory/prewarm.go`:

```go
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// PrewarmReport is one pre-warm pass.
type PrewarmReport struct {
	Groups, Principals, Failed int
	Capped                     bool
}

// Prewarm verifies every member of groups, transitively under the nested
// mode, at most prewarm.max_principals, and writes each membership with
// its mapping keys, so an operator who never logged in can log in within
// grace in an outage (design §10; Ruling 20). groups are the policy's
// `group:` values: a DN, or a name resolved to its one group under
// groups_base_dn (a shared name is skipped and said, as it matches no one).
func (r *Resolver) Prewarm(ctx context.Context, groups []string) (PrewarmReport, error) {
	var rep PrewarmReport
	var dns []string
	_, err := r.Pool.Do(ctx, func(s Searcher) error {
		for _, g := range groups {
			if isDN(g) {
				dns = append(dns, g)
				continue
			}
			res, err := s.Search(ldap.NewSearchRequest(r.Cfg.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				2, int(r.Cfg.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(%s=%s))", r.Cfg.GroupFilter,
					r.Cfg.GroupNameAttribute, ldap.EscapeFilter(g)), []string{"dn"}, nil))
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
				return err
			}
			if res == nil || len(res.Entries) != 1 {
				continue // none, or shared: it matches no one (Ruling 7)
			}
			dns = append(dns, res.Entries[0].DN)
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.Groups = len(dns)
	var users []string
	for _, g := range dns {
		var members []string
		var capped bool
		if _, err := r.Pool.Do(ctx, func(s Searcher) error {
			var err error
			members, capped, err = r.Cfg.membersOf(s, g, r.Cfg.PrewarmMax-len(users))
			return err
		}); err != nil {
			return rep, err
		}
		users = append(users, members...)
		if capped || len(users) >= r.Cfg.PrewarmMax {
			rep.Capped = true
			break
		}
	}
	slices.Sort(users)
	users = slices.Compact(users)
	for _, dn := range users {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if _, err := r.verify(ctx, lookup{find: r.byDN(dn), say: dn}); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return rep, err
			}
			rep.Failed++
			continue
		}
		rep.Principals++
	}
	r.M.DirectoryPrewarmPrincipals.Set(float64(rep.Principals))
	r.M.DirectoryPrewarmLastSuccess.Set(float64(r.Now().Unix()))
	return rep, nil
}

// isDN is Ruling 7's test, shared with the policy's group match: a value
// holding "=" that ldap.ParseDN accepts is a DN; anything else is a name
// (pre-flight M-9).
func isDN(g string) bool {
	if !strings.Contains(g, "=") {
		return false
	}
	_, err := ldap.ParseDN(g)
	return err == nil
}
```

`byDN` reads a member by its DN at base scope with `user_filter`, so a member that is
neither a user nor readable is counted `Failed` and skipped. It works the same on OpenLDAP,
which has no `distinguishedName` attribute, and on AD.

- [ ] **Step 5: The metrics**

Add `DirectoryLookups *prometheus.CounterVec` (`port49_directory_lookups_total{outcome}`),
`DirectoryPrewarmPrincipals prometheus.Gauge` and `DirectoryPrewarmLastSuccess prometheus.Gauge`,
registered beside Task 6's.

- [ ] **Step 6: Run them to verify they pass**

Run: `go test ./internal/directory/ -race -count=1 && go vet ./internal/directory/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/directory internal/daemon/metrics/metrics.go
git commit -m "feat(directory): the resolver: map at bind, verify, grace from the store, pre-warm" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: The policy resolves a member: every matching subject composes, and the diff gates a group

**Files:**
- Modify: `internal/policy/load.go:37-67` (`Env`), `:159-169` (`Subject`), `:1231-1250`
  (`buildSubjects`), `:1398-1412` (`checkMinters`), `:1679-1695` (`SubjectOf`, `HasRight`)
- Modify: `internal/policy/scope.go:106-180` (`composition`, `compose`)
- Modify: `internal/policy/resolve.go:20-60` (`Resolution`, a new error), `:95-160`
  (`Resolve`, `resolveNow`, `resolved`), `:704-` (`checkDeviceAt` split into `jointCheck`)
- Modify: `internal/policy/explain.go:64-` (`ExplainMember`)
- Modify: `internal/policy/diff.go:459-520` (`principals`: the group gate)
- Modify: `cmd/port49/policy.go:814-834` (`blobSource`)
- Create: `internal/policy/member.go`, `internal/policy/member_test.go`
- Test: `internal/policy/diff_test.go`, `internal/policy/load_test.go`

**Interfaces:**
- Consumes: `Policy.byID`, `subs`, `grants`, `compose`, `resolved`, `quarantined`,
  `admitted`, `checkDeviceAt` as they are.
- Produces:

```go
type DirectoryMode int
const (DirectoryUnknown DirectoryMode = iota; DirectoryOn; DirectoryOff)
// Env gains: Directory DirectoryMode

// Member is a principal as the broker resolved it: with a directory, its
// username and groups from there (plan 7g).
type Member struct {
	Principal  string
	Directory  bool     // the username and groups below are the directory's
	Username   string
	GroupDNs   []string
	GroupNames []string // the names verified unique (Ruling 7)
}
func MemberOf(principal string) Member // identity only: no directory
var ErrCompositionRefused = errors.New("policy: the principal's subjects compose to a reply a joint check refuses")
func (p *Policy) SubjectsOf(m Member) []string
func (p *Policy) ResolveMember(m Member, d admission.Device, now time.Time) (Resolution, error)
func (p *Policy) ResolveSubjects(names []string, username string, d admission.Device, now time.Time) (Resolution, error)
func (p *Policy) HasRightOf(m Member, right string) bool
func (p *Policy) ExplainMember(m Member, device, line string, now time.Time) (Explanation, error)
func (p *Policy) GroupValues() []string          // every group subject's group:, sorted, once each
func (p *Policy) GroupSubjects() []string        // their names, sorted
func (p *Policy) DeclaredUsernames() map[string]string // username → subject
// Resolution gains: Subjects []string (with several; Subject is then "")
func (p *Policy) jointCheck(res Resolution, d admission.Device) string
```

- [ ] **Step 1: The failing tests**

Create `internal/policy/member_test.go`. It loads a policy through the package's test loader
(the helper `resolve_test.go` uses to load YAML text against a small inventory; read it and
use it). The policy text:

```yaml
levels: [readonly, operator, admin]
scopes: [{name: all_devices, match: {}}, {name: leaf, match: {name: "/^leaf-/"}}]
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: ops, privilege: operator, permit: ["clear counters"]}
subjects:
  - {name: netops_ro, group: netops-ro, enable: auto, token_ttl: 15m}
  - {name: netops_oncall, group: "CN=netops-oncall,OU=G,DC=corp", enable: token, token_ttl: 5m,
     api: [revoke_others]}
  - {name: alice_direct, identity: ["user:alice@corp.example.com"], token_ttl: 10m}
grants:
  - {subject: netops_ro, scope: all_devices, roles: [ro]}
  - {subject: netops_oncall, scope: leaf, roles: [ops]}
  - {subject: alice_direct, scope: leaf, roles: [ro]}
```

and asserts:

```go
// A member in a named group, a DN-named group and an identity subject
// matches all three; on a leaf every grant composes, with the least
// token_ttl and the most demanding enable among those granting there
// (Ruling 5).
func TestEverySubjectComposes(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	m := Member{Principal: "user:alice@corp.example.com", Directory: true, Username: "alice",
		GroupDNs: []string{"cn=NetOps-OnCall,ou=G,dc=corp"}, GroupNames: []string{"NetOps-RO"}}
	if got := p.SubjectsOf(m); !slices.Equal(got, []string{"alice_direct", "netops_oncall", "netops_ro"}) {
		t.Fatalf("subjects %v", got)
	}
	res, err := p.ResolveMember(m, device(t, p, "leaf-01"), now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Subjects, []string{"alice_direct", "netops_oncall", "netops_ro"}) || res.Subject != "" ||
		!slices.Equal(res.Roles, []string{"ops", "ro"}) || res.Level != "operator" || res.Username != "alice" ||
		res.TokenTTL != 5*time.Minute || res.Enable != "token" {
		t.Fatalf("%+v", res)
	}
	// On a spine only netops_ro grants: one subject, its own fields.
	res, err = p.ResolveMember(m, device(t, p, "spine-01"), now)
	if err != nil || res.Subject != "netops_ro" || res.Subjects != nil || res.Enable != "auto" || res.TokenTTL != 15*time.Minute {
		t.Fatalf("%+v %v", res, err)
	}
}

// A group name the directory did not verify unique is not in GroupNames,
// so a name subject does not match; with no groups, only the identity
// subject does (Ruling 7; fail closed).
func TestOnlyVerifiedNamesMatch(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	m := Member{Principal: "user:bob@corp.example.com", Directory: true, Username: "bob"}
	if got := p.SubjectsOf(m); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if _, err := p.ResolveMember(m, device(t, p, "leaf-01"), now); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("%v", err)
	}
}

// Rights through a group (7c's carry; Ruling 13).
func TestARightHeldThroughAGroup(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	in := Member{Principal: "user:carol@corp.example.com", Directory: true, Username: "carol",
		GroupDNs: []string{"CN=netops-oncall,OU=G,DC=corp"}}
	if !p.HasRightOf(in, RightRevokeOthers) || p.HasRightOf(Member{Principal: in.Principal, Directory: true}, RightRevokeOthers) {
		t.Fatal("revoke_others through netops_oncall")
	}
}

// Two subjects whose union lands above a ceiling neither alone exceeds is
// composition_refused, for that member on that device alone (Ruling 5).
func TestACompositionAJointCheckRefusesIsRefused(t *testing.T) {
	p := ceilingPolicy(t) // netops_ro: ro capped at readonly; netops_ops: ops, no ceiling: the union caps ops at readonly
	m := Member{Principal: "user:dan@corp.example.com", Directory: true, Username: "dan",
		GroupNames: []string{"netops-ro", "netops-ops"}}
	_, err := p.ResolveMember(m, device(t, p, "leaf-01"), now)
	if !errors.Is(err, ErrCompositionRefused) || !strings.Contains(err.Error(), "max_privilege") {
		t.Fatalf("%v", err)
	}
	if _, err := p.ResolveMember(Member{Principal: m.Principal, Directory: true, Username: "dan",
		GroupNames: []string{"netops-ops"}}, device(t, p, "leaf-01"), now); err != nil {
		t.Fatalf("one subject alone: %v", err)
	}
}

// With a directory, a human identity subject declares no username; without
// one it must; offline, either loads (Ruling 16).
func TestAHumanUsernameAndTheDirectory(t *testing.T) {
	with := "subjects: [{name: a, identity: [\"user:a@x.com\"], username: a, token_ttl: 5m}]\n" + minimalGrant
	without := "subjects: [{name: a, identity: [\"user:a@x.com\"], token_ttl: 5m}]\n" + minimalGrant
	if _, err := loadText(t, with, DirectoryOn); err == nil || !strings.Contains(err.Error(), "the directory supplies human usernames") {
		t.Fatalf("on: %v", err)
	}
	if _, err := loadText(t, without, DirectoryOff); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("off: %v", err)
	}
	for _, text := range []string{with, without} {
		if _, err := loadText(t, text, DirectoryUnknown); err != nil {
			t.Fatalf("offline: %v", err)
		}
	}
}
```

`memberPolicy`, `ceilingPolicy`, `loadText`, `device`, `now` and `minimalGrant` are small
helpers this file defines:
- `loadText(t, body, mode)` is `load_test.go`'s `mustParse` with an environment:
  `e := env(); e.Directory = mode; return Parse([]byte(body), e)`;
- `device(t, p, name)` is `p.Device(name)`, failing the test when absent;
- the inventory `env()` gives must hold a `leaf-01` and a `spine-01`. Add `spine-01` to it if
  absent; the existing tests ignore an extra device. `ceilingPolicy` declares two
group subjects:
- `netops_ro`, with `max_privilege: readonly` on its grant;
- `netops_ops`, granting `ops` (operator) with no ceiling.

Composed, the ceiling (readonly, the only one stated) caps a level of operator.
`checkDeviceAt`'s first check names "max_privilege".

Append to `internal/policy/diff_test.go`:

```go
// A changed group: fails the gate until a passing session test names the
// subject; a new group subject is gated too (Ruling 15).
func TestAChangedGroupIsGated(t *testing.T) {
	before := loadDiff(t, `subjects: [{name: oncall, group: netops-oncall, token_ttl: 5m}]`+grantOnCall)
	after := loadDiff(t, `subjects: [{name: oncall, group: netops-admins, token_ttl: 5m}]`+grantOnCall)
	d := Compare(before, after, now)
	if d.UnacknowledgedPrincipals() != 1 {
		t.Fatalf("%+v", d.Subjects)
	}
	tested := loadDiff(t, `subjects: [{name: oncall, group: netops-admins, token_ttl: 5m}]`+grantOnCall+
		"\ntests: [{subject: oncall, device: leaf-01, level: readonly}]")
	if d := Compare(before, tested, now); d.UnacknowledgedPrincipals() != 0 {
		t.Fatalf("a session test naming the subject acknowledges it: %+v", d.Subjects)
	}
}
```

(`loadDiff`, `grantOnCall` and `now` follow `diff_test.go`'s existing helpers; use theirs.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/policy/ -run 'EverySubject|OnlyVerified|RightHeld|CompositionA|HumanUsername|ChangedGroup' -count=1`
Expected: FAIL, undefined `Member`, `DirectoryOn`, `ResolveMember`.

- [ ] **Step 3: The member, the composition**

Create `internal/policy/member.go`:

```go
package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/admission"
)

// DirectoryMode is whether the process loading a policy resolves humans
// through a directory (plan 7g, Ruling 16): its broker's, on or off; an
// offline tool or the inventory service does not know.
type DirectoryMode int

const (
	DirectoryUnknown DirectoryMode = iota
	DirectoryOn
	DirectoryOff
)

// Member is a principal as the broker resolved it.
type Member struct {
	Principal  string
	Directory  bool
	Username   string
	GroupDNs   []string
	GroupNames []string
}

// MemberOf is a principal with no directory: identity subjects alone.
func MemberOf(principal string) Member { return Member{Principal: principal} }

// ErrCompositionRefused is composition_refused (spec §5.7): the principal's
// subjects compose on the device to a reply a joint check refuses.
var ErrCompositionRefused = errors.New("policy: the principal's subjects compose to a reply a joint check refuses")

// subjectsOf is every subject m matches, by name: the identity subject
// listing it, and each group subject whose group m is in (spec §2;
// decision 38).
func (p *Policy) subjectsOf(m Member) []*Subject {
	var out []*Subject
	if name, ok := p.byID[m.Principal]; ok {
		out = append(out, p.subs[name])
	}
	if m.Directory {
		for _, name := range sortedKeys(p.subs) {
			if sub := p.subs[name]; sub.Group != "" && sub.matches(m) {
				out = append(out, sub)
			}
		}
	}
	slices.SortFunc(out, func(a, b *Subject) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// matches reports whether a group subject's group is one of m's: by DN,
// compared as DNs, or by a name m's directory verified unique.
func (s *Subject) matches(m Member) bool {
	if s.groupDN != nil {
		for _, dn := range m.GroupDNs {
			if d, err := ldap.ParseDN(dn); err == nil && d.EqualFold(s.groupDN) {
				return true
			}
		}
		return false
	}
	return slices.ContainsFunc(m.GroupNames, func(n string) bool { return strings.EqualFold(n, s.Group) })
}

// SubjectsOf is the names of every subject m matches, sorted.
func (p *Policy) SubjectsOf(m Member) []string {
	var out []string
	for _, s := range p.subjectsOf(m) {
		out = append(out, s.Name)
	}
	return out
}

// HasRightOf reports whether any subject m matches declares right
// (Ruling 13).
func (p *Policy) HasRightOf(m Member, right string) bool {
	return slices.ContainsFunc(p.subjectsOf(m), func(s *Subject) bool { return slices.Contains(s.API, right) })
}

// ResolveMember is spec §5.1 for m on d at now: every matching subject's
// grants compose (Ruling 5). One identity subject and no directory is
// Resolve exactly as before plan 7g.
func (p *Policy) ResolveMember(m Member, d admission.Device, now time.Time) (Resolution, error) {
	subs := p.subjectsOf(m)
	if len(subs) == 0 {
		return Resolution{}, ErrNoGrants
	}
	if len(subs) == 1 && !m.Directory {
		return p.resolveNow(subs[0], d, now)
	}
	return p.resolveAll(subs, m.Username, d, now, true)
}

// ResolveSubjects is ResolveMember for subjects named directly, as a
// record names them: replay recompiles a blob from it with no directory.
func (p *Policy) ResolveSubjects(names []string, username string, d admission.Device, now time.Time) (Resolution, error) {
	var subs []*Subject
	for _, n := range names {
		s, ok := p.subs[n]
		if !ok {
			return Resolution{}, fmt.Errorf("policy: subject %q is not declared", n)
		}
		subs = append(subs, s)
	}
	return p.resolveAll(subs, username, d, now, false)
}

func (p *Policy) resolveAll(subs []*Subject, username string, d admission.Device, now time.Time,
	check bool) (Resolution, error) {
	c := p.composeAll(subs, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	if err := p.quarantined(d, now); err != nil {
		return Resolution{}, err
	}
	if r, ok := p.admitted[d.Name]; p.AdmissionAssessed() && (!ok || r.Refused != "") {
		if !ok {
			r.Refused = "is not in the inventory admission assessed"
		}
		return Resolution{}, fmt.Errorf("%w: %s", ErrDeviceRefused, r.Refused)
	}
	granting := c.granting(subs)
	merged := &Subject{Name: granting[0].Name, Domain: granting[0].Domain, Username: username}
	if username == "" {
		for _, s := range granting {
			if s.Username != "" {
				merged.Username = s.Username
			}
		}
	}
	merged.Enable, merged.TokenTTL = strongestEnable(granting), leastTTL(granting)
	res, err := p.resolved(merged, d, c)
	if err != nil {
		return res, err
	}
	if len(granting) > 1 {
		res.Subject = ""
		for _, s := range granting {
			res.Subjects = append(res.Subjects, s.Name)
		}
		if check {
			if cause := p.jointCheck(res, d); cause != "" {
				return Resolution{}, fmt.Errorf("%w: subjects %s on %s: %s", ErrCompositionRefused,
					strings.Join(res.Subjects, ", "), d.Name, cause)
			}
		}
	}
	return res, nil
}

// strongestEnable is the mechanism demanding the most proof among those
// the subjects offer: token, then auto, then none (Ruling 5).
func strongestEnable(subs []*Subject) string {
	best := "none"
	for _, s := range subs {
		switch {
		case s.Enable == "token":
			return "token"
		case s.Enable == "auto":
			best = "auto"
		}
	}
	return best
}

func leastTTL(subs []*Subject) time.Duration {
	var least time.Duration
	for _, s := range subs {
		if s.TokenTTL > 0 && (least == 0 || s.TokenTTL < least) {
			least = s.TokenTTL
		}
	}
	return least
}

// GroupValues is every group subject's group:, once each, sorted: the
// population pre-warm enumerates (Ruling 20).
func (p *Policy) GroupValues() []string {
	var out []string
	for _, s := range p.subs {
		if s.Group != "" {
			out = append(out, s.Group)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// GroupSubjects is every group subject's name, sorted.
func (p *Policy) GroupSubjects() []string {
	var out []string
	for _, name := range sortedKeys(p.subs) {
		if p.subs[name].Group != "" {
			out = append(out, name)
		}
	}
	return out
}

// DeclaredUsernames is every username a subject declares, by username.
func (p *Policy) DeclaredUsernames() map[string]string {
	out := map[string]string{}
	for name, s := range p.subs {
		if s.Username != "" {
			out[s.Username] = name
		}
	}
	return out
}
```

In `scope.go`:
- Rename `compose(sub, d, now)` to `composeAll(subs []*Subject, d, now)`, which takes grants
  whose `Subject` is any of `subs`' names. `c.subject` becomes `subs[0]` (every subject a
  human principal matches is in the `humans` domain, so attached roles read the same
  domain).
- Keep `compose(sub, …)` as a one-line wrapper, `composeAll([]*Subject{sub}, …)`, for every
  existing caller.
- Add `(c composition) granting(subs []*Subject) []*Subject`: the subjects in `subs`, in
  order, with at least one grant in `c.grants`.

In `resolve.go`:
- Add `Subjects []string` to `Resolution`, after `Subject`, commented "every subject that
  composed, when more than one did; Subject is then empty (spec §5.7, policy.subjects)".
- `Resolve(principal, …)` becomes `return p.ResolveMember(MemberOf(principal), d, now)`.
- Split `checkDeviceAt` at its `resolve`: the body after `if err != nil { return
  err.Error() }` moves, unchanged, into `func (p *Policy) jointCheck(res Resolution, d
  admission.Device) string`, and `checkDeviceAt` calls it.

In `load.go`:
- `Env` gains `Directory DirectoryMode` with the comment of Ruling 16.
- `Subject` gains `groupDN *ldap.DN // a group: given as a DN, parsed at load`.
- `buildSubjects`' group case parses a `group:` holding `=` with `ldap.ParseDN`, refusing one
  that does not parse: `subject %q: group %q holds = but is not a DN`.
- After the identity loop, a `user:` identity subject with `Username != ""` under
  `env.Directory == DirectoryOn` is refused: `subject %q: the directory supplies human
  usernames (spec §2; decision 38); remove username`. `buildSubjects` needs `env`: read how
  `Load` threads `env` to the builders, and pass it the same way.
- `checkMinters` requires `username:` of an identity subject only when its domain is
  `machines`, or it is `humans` and `env.Directory == DirectoryOff`. Its message stays
  "username is required".
- `SubjectOf` keeps its signature and comment's first line. Its second line becomes "A
  group subject is matched through a Member (SubjectsOf)."
- `HasRight(principal, right)` becomes `return p.HasRightOf(MemberOf(principal), right)`.

In `explain.go`, `ExplainMember(m Member, device, line string, now time.Time)` is `Explain`'s
principal path with `ResolveMember(m, …)` in place of `ResolveSubject(subject, …)`. For a
command line, it decides with the resolved blob (`engine.Decide` on `res.Blob`, as `Decide`
does inside). `Explain(subject, principal, …)`'s principal branch calls
`ExplainMember(MemberOf(principal), …)`. A refused composition sets `e.MintError =
"composition_refused"`.

In `diff.go`'s `principals`:
- record `subjectTested[r.Test.Subject] = true` for a passing session test naming a subject
  (and not `onlyAPI`);
- a new subject with a group is compared against `&Subject{Username: is.Username}`, so its
  group counts as changed;
- `Gated` adds `|| was.Group != is.Group`;
- `Acknowledged` adds `&& (was.Group == is.Group || subjectTested[name])`;
- the `SubjectChange` comment's "a group change … is reported, since a group subject mints
  for no one until plan 7" becomes "a group change is gated, and acknowledged by a passing
  session test naming the subject (decision 38)".

In `cmd/port49/policy.go`'s `blobSource`, resolve with `p.ResolveSubjects(subjects,
rec.Session.Username, d, at)`, where `subjects` is `rec.Policy.Subjects` or
`[]string{rec.Policy.Subject}`. Fall back to `p.Resolve(rec.Principal, d, at)` only when the
record names neither (a record from before 7g).

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/policy/ ./cmd/port49/ ./internal/broker/ -count=1`
Expected: PASS. Every existing test that resolves an identity subject passes unchanged: that
path is `resolveNow` as before.

- [ ] **Step 5: Commit**

```bash
git add internal/policy cmd/port49
git commit -m "feat(policy): resolve a member: every matching subject composes, a refused composition, rights through groups, the group gate" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: The broker maps at bind and pins the principal to the connection

**Files:**
- Modify: `internal/broker/identity.go:22-94` (`Identity`, `principalOf`): split out
  `CertIdentity`
- Modify: `internal/broker/listen.go:100-110` (`Listener` fields), `:149-158` (`trackedConn`),
  `:276-330` (`handshake`), `:392-415` (`bind`: the legacy principal's mark), `:643-650`
  (`acceptedAt` beside a new `mappedOf`)
- Modify: `internal/broker/server.go:85-91` (`VerifyConnection`), `:93` (`ConnContext`)
- Modify: `internal/broker/broker.go:60-80` (`Broker.Directory`), `:199-237` (`heldConn`),
  `:415-463` (`authenticate`), `:514-529` (`revocation`: further principals)
- Create: `internal/broker/member.go`, `internal/broker/member_test.go`,
  `internal/directory/static.go`

**Interfaces:**
- Consumes: `directory.Resolver.Map`, `Current`, `directory.Answer`, `directory.ErrUnmapped`,
  `ErrAmbiguous`, `ErrUsernameTaken`, `ErrUnavailable` (Task 10); `BindRefusal` (7b).
- Produces:

```go
// Broker gains
Directory *directory.Resolver // nil: no directory; the email-SAN principal stands

func CertIdentity(cs *tls.ConnectionState, now time.Time) (store.Credential, *x509.Certificate, error)
// BindMap is Listener.Map: the certificate mapped once, at bind (Ruling 4).
func (b *Broker) BindMap(ctx context.Context, cs tls.ConnectionState, cred store.Credential) (directory.Answer, *BindRefusal)
// Listener gains
Map func(ctx context.Context, cs tls.ConnectionState, cred store.Credential) (directory.Answer, *BindRefusal)
// heldConn gains: principal string; answer *directory.Answer
func mappedOf(c net.Conn) *directory.Answer
// directoryRefusal is the API's answer for a resolver error.
func directoryRefusal(err error) *BindRefusal
// legacyPrincipal is the principal the certificate had before a directory:
// "user:" + its one email SAN, or "" (pre-flight I-16).
func legacyPrincipal(leaf *x509.Certificate) string
func (l *Listener) markedOf(certKey, legacy string) *store.Revocation
// bind gains legacy, a further principal whose mark refuses
func (l *Listener) bind(c *trackedConn, principal, legacy, certKey string, refused bool) (*store.Revocation, bool)
// revocation gains further principals, each read when non-empty
func (b *Broker) revocation(ctx context.Context, principal string, cred store.Credential, also ...string) (store.Revocation, bool, error)

// internal/directory (static.go)
func ForTestsStaticResolver(st store.Store, answers map[string]Answer, err error) *Resolver
```

- [ ] **Step 1: The failing tests**

Create `internal/broker/member_test.go`. Build the broker's test fixture (the one
`identity_api_test.go` uses: a `Broker` over memory, a test PKI client certificate). Set
`b.Directory` to a `directory.Resolver` whose `Pool` dials the in-package fake of Task 6.
That fake is in `directory`'s `_test` files, so add a small exported test double in a new
non-test file, `internal/directory/static.go`. Its name says what it is (pre-flight M-14):
nothing in production may call it, and Task 16's wiring test asserts no non-test file outside
`internal/directory` names it (`grep -rn ForTestsStaticResolver --include='*.go' | grep -v _test.go`
finds only its definition).

```go
// ForTestsStaticResolver is a Resolver for the tests of the packages that
// call one, and never for production: it answers without a directory.
// Map, Verify and Current answer from answers by principal (Map reads the
// principal as "user:" and the leaf's one email SAN), or err when it is
// set; Stored and grace read st as a real resolver does. It never dials.
// Calls counts the answers it gave, so a test asserts it was not asked.
func ForTestsStaticResolver(st store.Store, answers map[string]Answer, err error) *Resolver {
	return &Resolver{Store: st, Now: time.Now, M: metrics.New(prometheus.NewRegistry()),
		Say: func(string, ...any) {}, static: func(principal string) (Answer, error) {
			if err != nil {
				return Answer{}, err
			}
			a, ok := answers[principal]
			if !ok {
				return Answer{}, fmt.Errorf("%w: no entry for %s", ErrUnmapped, principal)
			}
			return a, nil
		}}
}
```

`Resolver` gains the unexported field `static func(principal string) (Answer, error)` and an
exported `Calls atomic.Int64` the static path increments. `Map`, `Verify` and `Current`
answer from it first when it is set. A test changes an answer between calls by mutating the
map, guarded by the test's own mutex. Then:

```go
// With a directory, the principal is the mapping's, pinned at bind, and
// every request on the connection reads it (Ruling 4).
func TestThePrincipalIsPinnedAtBind(t *testing.T)

// Each resolver refusal is answered as the agent can act on it (Ruling 4):
// 401 identity_unmapped, identity_ambiguous and username_collision, each
// closing the connection; 503 directory_unavailable with Retry-After 30,
// which the agent retries.
func TestBindRefusalsReadAsTheAgentNeeds(t *testing.T) {
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		directory.ErrUnmapped:      {401, "identity_unmapped"},
		directory.ErrAmbiguous:     {401, "identity_ambiguous"},
		directory.ErrUsernameTaken: {401, "username_collision"},
		directory.ErrUnavailable:   {503, "directory_unavailable"},
	} {
		ref := directoryRefusal(fmt.Errorf("%w: detail", err))
		if ref.Status != want.status || ref.Error != want.code || (want.status == 503) != (ref.RetryAfter == 30) {
			t.Errorf("%v: %+v", err, ref)
		}
	}
}

// Without a directory, nothing changes: the email SAN is the principal.
func TestNoDirectoryKeepsTheEmailPrincipal(t *testing.T)

// A certificate with no email SAN passes the handshake when a directory
// maps it (VerifyConnection checks the chain, not the mapping).
func TestACertificateWithoutAnEmailSANBindsWithADirectory(t *testing.T)

// A certificate marked by its key, with every directory server down, is
// answered 401 credential_revoked, never 503 directory_unavailable, and
// the resolver is never asked (pre-flight I-4; listen.go:294-297's
// invariant): the static resolver's err is directory.ErrUnavailable and
// its Calls stays 0.
func TestAMarkedCertificateIsRevokedBeforeTheDirectoryIsAsked(t *testing.T)

// A mark made by principal before a directory was configured (the
// certificate's email-SAN principal) still refuses the certificate once
// the directory maps it to another principal (pre-flight I-16): 401
// credential_revoked at the bind, and on a request whose held connection
// bound before the mark.
func TestAMarkOnTheLegacyPrincipalStillHolds(t *testing.T)
```

Write the bodies against the listener tests' helpers (`listen_test.go` dials a `Listener`
with a client certificate and reads the HTTP answer). `TestThePrincipalIsPinnedAtBind` maps
the certificate to `user:alice@corp.example.com` and asserts `GET /v1/identity` on that
connection answers it. It then changes the static resolver's answer and asserts the same
connection still answers alice: pinned, with no re-map per request.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'PinnedAtBind|BindRefusals|EmailPrincipal|WithoutAnEmailSAN' -count=1`
Expected: FAIL, undefined `directoryRefusal`, `Broker.Directory`.

- [ ] **Step 3: Split the identity, map at bind**

In `identity.go`, `CertIdentity` is `Identity`'s body up to and including the `clientAuth`
check, returning the credential and the leaf. `Identity` becomes `CertIdentity`, then
`principalOf(leaf)` as before: the no-directory path, unchanged.

Create `internal/broker/member.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// directoryRefusal is a resolver error as the API answers it (Ruling 4).
func directoryRefusal(err error) *BindRefusal {
	switch {
	case errors.Is(err, directory.ErrUnavailable):
		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.DirectoryUnavailable,
			Error: string(decision.DirectoryUnavailable), RetryAfter: 30,
			Detail: "no directory server answered and no membership verified within the grace window is held; " +
				"the agent retries"}
	case errors.Is(err, directory.ErrAmbiguous):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityAmbiguous,
			Error: string(decision.IdentityAmbiguous), Detail: "this certificate maps to more than one directory entry; tell the operator"}
	case errors.Is(err, directory.ErrUsernameTaken):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.UsernameCollision,
			Error: string(decision.UsernameCollision), Detail: "your directory username is held by another; tell the operator"}
	case errors.Is(err, directory.ErrUnmapped):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityUnmapped,
			Error: string(decision.IdentityUnmapped), Detail: "this certificate maps to no usable directory entry; tell the operator"}
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.StoreUnavailable,
			Error: string(decision.StoreUnavailable), RetryAfter: 30, Detail: "the broker's store did not answer; the agent retries"}
	}
	return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.DirectoryUnavailable,
		Error: string(decision.DirectoryUnavailable), RetryAfter: 30, Detail: "the directory lookup failed; the agent retries"}
}

// BindMap is Listener.Map (Ruling 4): the connection's certificate mapped
// once, by the resolver, bounded by the directory's query timeout. The
// line for a refusal is the resolver's; the record is RefusedAtBind's.
func (b *Broker) BindMap(ctx context.Context, cs tls.ConnectionState, _ store.Credential) (directory.Answer, *BindRefusal) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return directory.Answer{}, directoryRefusal(directory.ErrUnmapped)
	}
	a, err := b.Directory.Map(ctx, cs.VerifiedChains[0][0])
	if err != nil {
		return directory.Answer{}, directoryRefusal(err)
	}
	return a, nil
}

// member is the policy's view of a directory answer.
func member(a directory.Answer) policy.Member {
	return policy.Member{Principal: a.Principal, Directory: true, Username: a.Username, GroupDNs: a.GroupDNs,
		GroupNames: a.GroupNames}
}

// mappedOf is the answer the listener pinned to c at bind, nil without one.
func mappedOf(c net.Conn) *directory.Answer {
	if tc, ok := c.(*tls.Conn); ok {
		if t, ok := tc.NetConn().(*trackedConn); ok && t.mapped != nil {
			a := *t.mapped
			return &a
		}
	}
	return nil
}
```

In `listen.go`:
- `trackedConn` gains `mapped *directory.Answer`;
- `Listener` gains `Map`, with a comment mirroring `Status`'s;
- `bind` gains `legacy`, checked as a principal mark beside `principal` and the certificate
  key when non-empty (every existing caller passes `""`);
- `markedOf(certKey, legacy)` reads `l.marked` under `l.mu` for the certificate key's mark,
  then the legacy principal's, and returns the first, or nil;
- in `handshake`, under a directory, the bind runs in Ruling 4's order (pre-flight I-4): the
  certificate's own marks, then `Status`'s refusal, then `Map`, then `bind`'s principal mark.

```go
		var principal, legacy string
		var cred store.Credential
		var err error
		if l.Map != nil {
			var leaf *x509.Certificate
			cred, leaf, err = CertIdentity(&cs, l.now())
			if err == nil {
				legacy = legacyPrincipal(leaf)
			}
		} else {
			principal, cred, err = Identity(&cs, l.now())
		}
		if err != nil {
			l.refuse(c, tc, "identity_refused", err)
			return
		}
		certKey := store.CertKey(cred.Issuer, cred.Serial)
		var ref *BindRefusal
		if l.Status != nil {
			ref = l.Status(cs, cmp.Or(principal, legacy), cred)
		}
		if l.Map != nil {
			// The marks the certificate itself answers to (its key, and the
			// principal its email SAN gave before a directory: pre-flight
			// I-16) are decided before the directory is asked, so a revoked
			// certificate is answered credential_revoked and never a
			// directory_unavailable the agent keeps its session on
			// (pre-flight I-4; the invariant above).
			if rv := l.markedOf(certKey, legacy); rv != nil {
				if ref != nil && ref.queue != nil {
					ref.queue()
				}
				l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
				l.answerRefused(tc, http.StatusUnauthorized, revokedError(*rv), 0, legacy, cred,
					decision.CredentialRevoked)
				return
			}
			if ref == nil {
				mctx, cancel := context.WithTimeout(context.Background(), l.lim.MapTimeout)
				a, mref := l.Map(mctx, cs, cred)
				cancel()
				if mref != nil {
					l.m.BrokerConnectionEvents.WithLabelValues("identity_refused").Inc()
					l.answerRefused(tc, mref.Status, api.Error{Error: mref.Error, Detail: mref.Detail},
						mref.RetryAfter, "", cred, mref.Reason)
					return
				}
				principal, c.mapped = a.Principal, &a
			}
		}
		rv, ok := l.bind(c, principal, legacy, certKey, ref != nil)
```

and the rest of the block (queueing `ref`, the `switch` on `ok`, `rv` and `ref`) is unchanged.
`listen.go` gains the imports `cmp` and `crypto/x509`.
With `Status` refusing under a directory, `principal` is empty and `bind` decides on the
certificate's marks, as before. `legacyPrincipal` is `principalOf(leaf)`'s answer, or `""`
when it errs.

`ListenerLimits` gains `MapTimeout time.Duration` (port49d sets the directory's
`query_timeout` plus 1s; a zero is `HandshakeTimeout`). The `"identity_refused"` label is
one the connection-events counter already counts (it is the event `refuse` uses above).
`answerRefused` records through `Refused` with an empty principal, as a chain refusal does.

In `server.go`:
- `VerifyConnection` calls `CertIdentity` when `b.Directory != nil`, else `Identity`, so a
  certificate with no email SAN passes the handshake under a directory.
- `ConnContext` becomes
  `withHeldConn(ctx, acceptedAt(c, b.Now), mappedOf(c))`.

In `broker.go`:
- `heldConn` gains `answer *directory.Answer`, and `withHeldConn(ctx, at, a)` stores it. Every
  existing caller of `withHeldConn(ctx, at)`, tests included, passes `nil`.
- `authenticate` reads the principal as follows:

```go
	var principal string
	var cred store.Credential
	var err error
	if b.Directory != nil {
		cred, _, err = CertIdentity(r.TLS, now)
		if err == nil {
			principal, err = b.pinnedPrincipal(r)
		}
	} else {
		principal, cred, err = Identity(r.TLS, now)
	}
```

where `pinnedPrincipal(r)` is the `heldConn`'s answer's principal. For a request with no
held connection (a handler driven without `Server`, as the tests do), it maps now through
`b.BindMap` and returns that refusal's error. A mapping refusal in `authenticate` is
answered with `answerRefusal(w, r, directoryRefusal(err))` and recorded under the event with
its reason, as `certRefusal` is.

Under a directory, `authenticate` keeps Ruling 4's order too: the session age; then
`b.revocation(ctx, "", cred, legacy)` (the certificate's key and its legacy principal) and
`certRefusal`, both before `pinnedPrincipal`, so a request with no held connection never maps
a revoked certificate; then `pinnedPrincipal`; then `b.revocation(ctx, principal, cred)` for
the mapped principal. `revocation` gains `also ...string`, read as principal marks after
`principal`, and skips an empty principal. Without a directory every line of `authenticate`
is unchanged.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/broker/ ./internal/directory/ -race -count=1`
Expected: PASS: the new tests, and every existing listener and identity test (no
directory: `Identity` unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/broker internal/directory
git commit -m "feat(broker): map the certificate at bind and pin the principal to the held connection" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: The broker mints, explains, identifies and revokes through the membership

**Files:**
- Modify: `internal/broker/broker.go:253-405` (`tokens`), `:733-880` (`mintOne`)
- Modify: `internal/broker/identity_api.go`, `explain_api.go:55-140`, `revoke_api.go:90-110`,
  `revoke.go:230-240`
- Modify: `internal/broker/member.go` (`memberFor`)
- Test: `internal/broker/member_test.go`, `internal/broker/broker_test.go`
- The pin's escape (Steps 6–10):
  - Create: `internal/broker/forget.go` (+ `forget_test.go`), `cmd/port49/directory.go`
    (+ `directory_linux_test.go`).
  - Modify: `internal/decision/reasons.go` (after `EventInventoryChange`) and `log.go`
    (`Record`, after `Change`).
  - Modify: `internal/daemon/admin/admin.go` (`Server`, `handle`, `connTimeout`, `answer`)
    and `admin_test.go`.
  - Modify: `internal/port49d/revocations.go:529` (beside `adminRevoke`),
    `brokerd.go:535`, `main.go:1135-1141`.
  - Modify: `cmd/port49/main.go` (usage, `run`'s switch).

**Interfaces:**
- Consumes: Task 5's `DeleteMembership`; Task 12's pinned answer; `directory.Resolver.Current`; `policy.ResolveMember`,
  `HasRightOf`, `ExplainMember`, `SubjectsOf`, `ErrCompositionRefused` (Task 11);
  `token.Subject.VerifiedAt` (Task 3); `decision.Directory`, `Policy.Subjects` (Task 2).
- Produces:

```go
// memberFor is the membership a request uses (Ruling 10): Current for the
// pinned principal, fresh or grace; no directory, or a machine principal,
// is MemberOf(principal).
func (b *Broker) memberFor(ctx context.Context, principal string) (policy.Member, *directory.Answer, error)
// memberBudget is the deadline memberFor is given: query_timeout plus
// holdTimeout under a directory (pre-flight I-8), holdTimeout without.
func (b *Broker) memberBudget() time.Duration
func directoryAuth(a *directory.Answer) *decision.Directory

// Forget is `port49 directory forget` (Ruling 3's escape): it deletes
// principal's membership record, pin included, and writes a
// directory_forget record naming origin. It never asks the directory.
func (b *Broker) Forget(ctx context.Context, principal, origin string) (string, error)

// decision
const EventDirectoryForget = "directory_forget"
type Forget struct {
	EntryID    string `json:"entry_id,omitempty"`
	DN         string `json:"dn,omitempty"`
	VerifiedAt string `json:"verified_at"`
	Refused    bool   `json:"refused,omitempty"`
	Origin     string `json:"origin"`
}
// Record gains: Forget *Forget `json:"forget,omitempty"`

// admin
// Server gains:
Forget func(ctx context.Context, principal string, uid uint32) (string, error)
// op "directory_forget", naming Request.Principal

// port49d
func adminForget(brk *broker.Broker) func(context.Context, string, uint32) (string, error)

// cmd/port49
func directoryCmd(args []string, stdout, stderr io.Writer) int
```

- [ ] **Step 1: The failing tests**

Append to `internal/broker/member_test.go`:

```go
// A group member mints on a device the group's grant selects, and the
// token carries the membership's verification time (Rulings 5, 11).
func TestAGroupMemberMints(t *testing.T)

// Past grace the whole request is refused 503 directory_unavailable with
// Retry-After, nothing minted, one mint deny record (Review Focus 4).
func TestAMintPastGraceIsRefused(t *testing.T)

// A grace mint mints, its record says source grace and verified_at, and
// the token's VerifiedAt is that instant, not now (Ruling 11).
func TestAGraceMintCarriesItsVerification(t *testing.T)

// Two subjects whose composition a joint check refuses: that device is
// denied composition_refused, the rest of the batch minted (Ruling 5).
func TestARefusedCompositionDeniesThatDeviceAlone(t *testing.T)

// revoke_others held through a group lets a member revoke another
// principal; without the group it is api_right_missing (Ruling 13).
func TestRevokeOthersThroughAGroup(t *testing.T)

// /v1/identity answers the subjects, groups, username, verified_at and
// source.
func TestIdentityAnswersTheMembership(t *testing.T)

// POST /v1/revoke {mine: true} works with the directory unavailable and
// nothing stored: revoking oneself never asks the directory (pre-flight
// I-9). The static resolver's err is directory.ErrUnavailable and its
// Calls stays 0 across the request.
func TestRevokeMineNeedsNoDirectory(t *testing.T)

// A machine principal (an app: identity subject) mints under a directory
// without the directory being asked (pre-flight I-10).
func TestAMachinePrincipalMintsWithoutTheDirectory(t *testing.T)
```

Each body drives the handler through the fixture of Task 12, with
`directory.ForTestsStaticResolver` answering per principal. A policy loaded with
`policy.Env{Directory: policy.DirectoryOn}` holds one group subject and grant. Assert as
follows:
- **The token's `VerifiedAt`.** `Candidates` on the minted key reads it.
- **The record.** It carries `policy.subjects` or `policy.subject` and
  `auth.directory.source`; parse the JSON lines the fixture's log buffer holds.
- **The past-grace answer.** Read `Retry-After: 30`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'GroupMemberMints|PastGrace|GraceMint|RefusedComposition|RevokeOthersThrough|IdentityAnswers' -count=1`
Expected: FAIL.

- [ ] **Step 3: The membership per request**

In `member.go`:

```go
// memberFor is the membership one request resolves with. A request on a
// held connection reads the pinned principal's membership again (fresh, or
// grace): group membership is resolved at mint time (design §7), not at
// bind. The answer is the pinned one only when no server answers and the
// store holds nothing newer.
func (b *Broker) memberFor(ctx context.Context, principal string) (policy.Member, *directory.Answer, error) {
	if b.Directory == nil || !directory.IsUser(principal) {
		// A machine principal has no directory entry (pre-flight I-10).
		return policy.MemberOf(principal), nil, nil
	}
	a, err := b.Directory.Current(ctx, principal)
	if err != nil {
		return policy.Member{}, nil, err
	}
	return member(a), &a, nil
}

// memberBudget is memberFor's deadline: the directory's own query_timeout
// plus a store read's holdTimeout, so a DC slower than holdTimeout still
// reaches grace and is never answered store_unavailable (pre-flight I-8).
func (b *Broker) memberBudget() time.Duration {
	if b.Directory == nil {
		return holdTimeout
	}
	return b.Directory.Cfg.QueryTimeout + holdTimeout
}

// directoryAuth is auth.directory for a record (spec §5.7).
func directoryAuth(a *directory.Answer) *decision.Directory {
	if a == nil {
		return nil
	}
	return &decision.Directory{Source: string(a.Source), VerifiedAt: decision.FormatTime(a.VerifiedAt),
		Server: a.Server, Site: a.Site}
}
```

In `broker.go`'s `tokens`, after `authenticate` and before `Reserve`, resolve the membership
once for the whole batch:

```go
	dctx, dcancel := context.WithTimeout(r.Context(), b.memberBudget())
	m, answer, err := b.memberFor(dctx, principal)
	dcancel()
	if err != nil {
		ref := directoryRefusal(err)
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: ref.Reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
		b.answerRefusal(w, r, ref)
		return
	}
```

`resp.Subject` takes `pol.SubjectsOf(m)`'s one name, or none with several. `api.MintResponse`
gains ``Subjects []string `json:"subjects,omitempty"` `` for several. Thread `m` and `answer`
into `mintOne` in place of the bare `principal` string, as one parameter `m policy.Member`
(`m.Principal` is the principal) plus `answer *directory.Answer`.

In `mintOne`:
- `pol.Resolve(principal, dev, now)` becomes `pol.ResolveMember(m, dev, b.Now())`;
- a new case before `err != nil` denies a refused composition:

```go
	case errors.Is(err, policy.ErrCompositionRefused):
		// The principal's subjects compose here to a reply a joint check
		// refuses: this device alone, never a quarantine (Ruling 5).
		b.logf("broker: %v", err)
		return deny(decision.CompositionRefused, dev.Platform), nil
```

- `deny`'s record and the minter's `Policy` carry `Subjects: res.Subjects`;
- `Auth.Directory` is `directoryAuth(answer)` on every record;
- the minted `token.Subject` gets `VerifiedAt: verifiedAt(answer)`, the answer's
  `VerifiedAt`, zero without a directory;
- the policy's `MintCheck(res, principal, name)` keeps the principal string.

In `identity_api.go`, resolve `m, answer, err := b.memberFor(…)` as `tokens` does (a refusal
answered the same way). Then:
- `out.Subject` is the one name, and `out.Subjects` the several;
- `out.Username`, `out.GroupDNs` and `out.Groups` (the verified names) come from the answer;
- `out.VerifiedAt` and `out.Source` come from the answer;
- grants are gathered over every subject in `pol.SubjectsOf(m)`;
- `out.API` is the union of their rights.

In `explain_api.go`:
- `pol.HasRight(caller, …)` becomes `pol.HasRightOf(callerMember, …)`, where `callerMember`
  comes from `memberFor(ctx, caller)`;
- `explanationIn` takes a `policy.Member` and calls `pol.ExplainMember`;
- explaining another principal under `explain_others` resolves *their* membership through
  `memberFor(ctx, about)`, so the explanation answers as their mint would. A refusal there is
  the record's reason and the API's answer, as for a mint.

In `revoke_api.go:98`, `mayOthers := pol.HasRight(caller, policy.RightRevokeOthers)` becomes a
function evaluated only in the two branches that act on someone else, the `case mayOthers:`
of a key request (after `case req.Mine:`) and the `if !mayOthers` before revoking another
principal:

```go
	// mayOthers asks the directory only when the request names another
	// principal or a key: a caller revoking themselves never waits on the
	// directory, and can always end their own sessions (pre-flight I-9).
	mayOthers := func() (bool, *BindRefusal) {
		ctx, cancel := context.WithTimeout(r.Context(), b.memberBudget())
		defer cancel()
		m, _, err := b.memberFor(ctx, caller)
		if err != nil {
			return false, directoryRefusal(err)
		}
		return pol.HasRightOf(m, policy.RightRevokeOthers), nil
	}
```

The key branch becomes `default:` with `ok, ref := mayOthers()` inside it: a refusal is
answered with `b.answerRefusal(w, r, ref)`, `ok` revokes the key, and neither refuses the right
as today. The principal branch's `if !mayOthers` becomes the same call after the
`target == caller` case, so `mine` and a caller naming themselves never call it. In `revoke.go:237`, `SubjectOf(key)` names the subject on
the revoke record. With a directory, it reads `SubjectsOf(memberFor(key))` from the stored
membership (`Directory.Stored`) and never queries a server, since a revocation must not wait
on the directory. With none stored, it names none.

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/broker/... -race -count=1`
Expected: PASS: the new tests and every existing broker test (no directory: `memberFor` is
`MemberOf`, and `ResolveMember` of one identity subject is `resolveNow`).

- [ ] **Step 5: Commit**

```bash
git add internal/broker
git commit -m "feat(broker): mint, explain, identify and revoke through the directory membership, grace and composition_refused" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

- [ ] **Step 6: The failing tests for the pin's escape (Ruling 3)**

Create `internal/broker/forget_test.go`:

```go
package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
)

// port49 directory forget deletes the principal's membership, pin
// included, writes one directory_forget record naming the old entry and
// who asked, and says what it removed. A second forget finds nothing and
// writes nothing. It never asks the directory (Ruling 3's escape).
func TestForgetRemovesThePinAndIsRecorded(t *testing.T) {
	f := newFixture(t, 8)
	r := directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	f.b.Directory = r
	ctx := context.Background()
	verified := f.b.Now().Add(-time.Hour)
	if err := f.st.PutMembership(ctx, store.Membership{Principal: alice, DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b", Refused: true, VerifiedAt: verified}, time.Hour); err != nil {
		t.Fatal(err)
	}
	text, err := f.b.Forget(ctx, alice, "admin_socket uid 0")
	if err != nil || !strings.Contains(text, "guid:0a1b") || !strings.Contains(text, "CN=Alice,OU=Staff,DC=corp") {
		t.Fatalf("%q %v", text, err)
	}
	if _, err := f.st.GetMembership(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the record outlived the forget: %v", err)
	}
	forgetsIn := func() []map[string]any {
		var out []map[string]any
		for _, rec := range f.records(t) {
			if rec["event"] == "directory_forget" {
				out = append(out, rec)
			}
		}
		return out
	}
	forgets := forgetsIn()
	if len(forgets) != 1 {
		t.Fatalf("%d directory_forget records, want 1", len(forgets))
	}
	body, _ := forgets[0]["forget"].(map[string]any)
	if forgets[0]["principal"] != alice || forgets[0]["verdict"] != nil || body["entry_id"] != "guid:0a1b" ||
		body["dn"] != "CN=Alice,OU=Staff,DC=corp" || body["refused"] != true || body["origin"] != "admin_socket uid 0" {
		t.Fatalf("%v", forgets[0])
	}
	if text, err := f.b.Forget(ctx, alice, "admin_socket uid 0"); err != nil || !strings.Contains(text, "no membership is held") {
		t.Fatalf("a second forget: %q %v", text, err)
	}
	if n := len(forgetsIn()); n != 1 {
		t.Fatalf("%d directory_forget records after a forget of nothing, want the one", n)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("forget asked the directory %d times", n)
	}
}

// Forget refuses what holds no membership: no directory configured, and a
// principal that is not user: (pre-flight I-10's machine principals).
func TestForgetRefusesWhatHoldsNoMembership(t *testing.T) {
	f := newFixture(t, 8)
	if _, err := f.b.Forget(context.Background(), alice, "admin_socket uid 0"); err == nil ||
		!strings.Contains(err.Error(), "no broker.directory") {
		t.Fatalf("without a directory: %v", err)
	}
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, nil)
	if _, err := f.b.Forget(context.Background(), "app:ci-runner", "admin_socket uid 0"); err == nil ||
		!strings.Contains(err.Error(), "not a user: principal") {
		t.Fatalf("a machine principal: %v", err)
	}
}
```

`r.Calls` is the static resolver's `atomic.Int64` count of answers given (Task 12), as
`TestRevokeMineNeedsNoDirectory` reads it.

In `internal/daemon/admin/admin_test.go`:
- update `TestAnswerRefusesAnUnknownOpAndAnUnheldDevice`'s expected line to
  `"unknown op; the ops are keys_diagnose, revoke, revocations and directory_forget"`;
- extend `TestConnTimeoutCoversTheOpsWorstCase` with
  `s.connTimeout("directory_forget") == ListWait`;
- add:

```go
// directory_forget reaches the broker with the caller's uid; with no
// broker it names where it is answered; a request naming no principal is
// refused before the broker is asked (plan 7g, Ruling 3's escape).
func TestDirectoryForgetReachesTheBroker(t *testing.T) {
	ctx := context.Background()
	var gotP string
	var gotUID uint32
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		Forget: func(_ context.Context, principal string, uid uint32) (string, error) {
			gotP, gotUID = principal, uid
			return "forgot it", nil
		}}
	if r := s.answer(ctx, Request{Op: "directory_forget", Principal: "user:alice@example.com"}, 1000); r.Text != "forgot it" ||
		gotP != "user:alice@example.com" || gotUID != 1000 {
		t.Fatalf("%+v %q %d", r, gotP, gotUID)
	}
	if r := s.answer(ctx, Request{Op: "directory_forget"}, 0); !strings.Contains(r.Error, "names a principal") {
		t.Fatalf("%+v", r)
	}
	beside := &Server{Held: &keyring.Held{}, Now: time.Now, RevokeElsewhere: "port49-broker's admin socket"}
	if r := beside.answer(ctx, Request{Op: "directory_forget", Principal: "user:a@b"}, 0); !strings.Contains(r.Error,
		"port49-broker's admin socket") || !strings.Contains(r.Error, "port49 directory forget --socket") {
		t.Fatalf("%+v", r)
	}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	if r := none.answer(ctx, Request{Op: "directory_forget", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "runs no broker") {
		t.Fatalf("%+v", r)
	}
}
```

Create `cmd/port49/directory_linux_test.go` (`//go:build linux`, as `revoke_linux_test.go`):

```go
// port49 directory forget sends one directory_forget op naming the
// principal and prints the answer; a refusal exits 1 on stderr; a missing
// or extra argument is a usage error (plan 7g, Ruling 3's escape).
func TestDirectoryForgetAsksTheAdminSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49-broker.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var got []string
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Forget: func(_ context.Context, principal string, _ uint32) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, principal)
			if principal == "app:ci" {
				return "", errors.New("broker: \"app:ci\" is not a user: principal")
			}
			return "forgot " + principal, nil
		}}
	go srv.Serve(ctx, ln)

	var out, errb bytes.Buffer
	if code := run([]string{"directory", "forget", "--socket", socket, "user:alice@example.com"}, &out, &errb); code != 0 ||
		strings.TrimSpace(out.String()) != "forgot user:alice@example.com" {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"directory", "forget", "--socket", socket, "app:ci"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "not a user: principal") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	for _, args := range [][]string{{"directory", "forget", "--socket", socket}, {"directory", "forget", "--socket",
		socket, "user:a@b", "user:c@d"}, {"directory"}, {"directory", "remember", "user:a@b"}} {
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("the broker was asked %d times, want 2: %v", len(got), got)
	}
}
```

with the imports it needs (`bytes`, `context`, `errors`, `path/filepath`, `strings`, `sync`,
`testing`, `time`, `admin`, `keyring`).

- [ ] **Step 7: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'Forget' -count=1; go test ./internal/daemon/admin/ ./cmd/port49/ -run 'Forget|UnknownOp|ConnTimeout' -count=1`
Expected: FAIL, undefined `Forget`, `directoryCmd`; the unknown-op line differs.

- [ ] **Step 8: The record, the broker's op, the socket and the command**

In `internal/decision/reasons.go`, after `EventInventoryChange`:

```go
// EventDirectoryForget is not a decision: an operator removed a
// principal's directory membership, and with it the entry the principal
// was pinned to (spec §5.7; plan 7g, Ruling 3's escape).
const EventDirectoryForget = "directory_forget"
```

In `log.go`, `Record` gains, after `Change`:

```go
	// Forget is the directory_forget record's body (spec §5.7).
	Forget *Forget `json:"forget,omitempty"`
```

and, beside `Revocation`:

```go
// Forget is what a directory_forget record says: the entry the principal
// was pinned to, its last verification or refusal, and who asked. It names
// no group and no mapping value.
type Forget struct {
	EntryID    string `json:"entry_id,omitempty"`
	DN         string `json:"dn,omitempty"`
	VerifiedAt string `json:"verified_at"`
	Refused    bool   `json:"refused,omitempty"`
	Origin     string `json:"origin"`
}
```

If `reasons_test.go` or the log's schema test lists the events, add `directory_forget` to it.

Create `internal/broker/forget.go`:

```go
package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// Forget is `port49 directory forget` (Ruling 3's escape). An entry
// deleted and re-created, a rehire or a directory restore, has a new
// objectGUID or entryUUID, and is refused identity_unmapped while its
// principal's record lives: max(directory.grace, 24h) after the last
// verification or refusal, and every refusal renews it. Forget deletes the
// record, pin included, so the principal's next verification pins the
// entry the directory gives it then. It writes one directory_forget record
// naming origin and the entry the principal was pinned to. It never asks
// the directory and grants nothing; whether the new entry is the same
// person is the operator's to confirm before running it.
//
// A broker verifying the principal as this runs may write a refusal
// pinned to the old entry after the delete, from a read made before it;
// the next bind then reads the same refusal line, and running this again
// ends it.
func (b *Broker) Forget(ctx context.Context, principal, origin string) (string, error) {
	if b.Directory == nil {
		return "", errors.New("broker: no broker.directory is configured, so no membership is held to forget")
	}
	if !directory.IsUser(principal) {
		return "", fmt.Errorf("broker: %q is not a user: principal; only a directory principal has a membership",
			printsafe.Line(principal, 200))
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	m, err := b.Store.DeleteMembership(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Sprintf("no membership is held for %s, so nothing pins it; its next verification pins the "+
			"entry the directory gives it then", principal), nil
	case err != nil:
		return "", fmt.Errorf("broker: forgetting %s failed (%w); the record may or may not be gone: run it again",
			principal, err)
	}
	entry := m.EntryID
	if entry == "" {
		entry = "unknown (the record did not open)"
	}
	b.emit(decision.Record{TS: b.Now(), Event: decision.EventDirectoryForget, Principal: principal,
		Forget: &decision.Forget{EntryID: m.EntryID, DN: m.DN, VerifiedAt: decision.FormatTime(m.VerifiedAt),
			Refused: m.Refused, Origin: origin}})
	b.say("directory: %s forgot %s, pinned to entry %s (%s)", origin, principal,
		printsafe.Line(entry, 120), printsafe.Line(m.DN, 200))
	return fmt.Sprintf("forgot %s: it was pinned to entry %s (%s), last verified %s; its next verification "+
		"pins the entry the directory gives it then", principal, printsafe.Line(entry, 120),
		printsafe.Line(m.DN, 200), decision.FormatTime(m.VerifiedAt)), nil
}
```

`b.say` (`broker.go:1041`) is `Say`, which both processes set (`brokerd.go:373`,
`main.go:919`), so the line reads as "What the operator sees" has it (`port49-broker:
directory: admin_socket uid 0 forgot …`, or `port49d: …` on the memory store), its quoted
values redacted as every broker line's are.

In `internal/daemon/admin/admin.go`:
- the package comment's op list adds "and directory_forget (plan 7g), which deletes a
  principal's directory membership and its pin";
- `Server` gains, after `Revocations`:

```go
	// Forget answers `port49 directory forget` (plan 7g, Ruling 3's
	// escape): it deletes a principal's directory membership, pin
	// included. Nil when this process runs no broker.
	Forget func(ctx context.Context, principal string, uid uint32) (string, error)
```

- `handle` holds a `directory_forget` connection open as a list's: its condition becomes
  `req.Op == "revoke" || req.Op == "revocations" || req.Op == "directory_forget"`;
- `connTimeout` answers `s.opTimeout() + answerMargin` for any op but `revoke`;
- `answer` gains, before the final return, whose list becomes "keys_diagnose, revoke,
  revocations and directory_forget":

```go
	case "directory_forget":
		if s.Forget == nil {
			if s.RevokeElsewhere != "" {
				return Response{Error: "port49d runs no broker; directory forget is " + s.RevokeElsewhere +
					": run port49 directory forget --socket <that path>"}
			}
			return Response{Error: "this process runs no broker, so it holds no directory membership"}
		}
		if req.Principal == "" {
			return Response{Error: "directory_forget names a principal"}
		}
		ctx, cancel := context.WithTimeout(ctx, s.opTimeout())
		defer cancel()
		text, err := s.Forget(ctx, req.Principal, uid)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Text: text}
```

In `internal/port49d/revocations.go`, after `adminRevocations`:

```go
// adminForget is the admin socket's directory_forget (plan 7g, Ruling 3's
// escape), its origin the caller's uid as a revocation's is.
func adminForget(brk *broker.Broker) func(context.Context, string, uint32) (string, error) {
	return func(ctx context.Context, principal string, uid uint32) (string, error) {
		return brk.Forget(ctx, principal, fmt.Sprintf("admin_socket uid %d", uid))
	}
}
```

Wire it beside `Revoke` in both processes:
- `brokerd.go:535`: `asrv := &admin.Server{Revoke: adminRevoke(brk), Revocations: …,
  Forget: adminForget(brk), …}`, and the start line becomes `admin socket on %s (port49
  revoke, port49 directory forget)`;
- `main.go:1140`: `srv.Revoke, srv.Revocations, srv.Forget = adminRevoke(brk),
  adminRevocations(brk.Store), adminForget(brk)`.

`Forget` refuses without a directory itself, so the wiring is unconditional.

Create `cmd/port49/directory.go`:

```go
package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// directoryCmd is `port49 directory forget` (plan 7g, Ruling 3's escape):
// it asks the broker, over its admin socket, to forget a principal's
// directory membership and the entry the principal is pinned to, so its
// next verification pins the entry the directory gives it then. It is for
// an entry deleted and re-created: confirm the new entry is the same
// person first.
func directoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "forget" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("port49 directory forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "the admin_socket of the process running the broker")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	resp, err := askAdmin(*socket, admin.Request{Op: "directory_forget", Principal: fs.Arg(0)}, listWait)
	if err != nil {
		fmt.Fprintln(stderr, "port49 directory forget:", err, "(a forget that was not answered may have run: "+
			"the broker's log names each, event directory_forget; running it again is safe)")
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 directory forget:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	return 0
}
```

The default socket is `port49 revoke`'s, for the same reason (7e OR-1): one process holds
both on the memory store; beside `port49-broker`, port49d's answer names the broker's socket.

In `cmd/port49/main.go`, add `case "directory": return directoryCmd(args[1:], stdout, stderr)`
to `run`, and to `usage`, after the `revoke` lines:

```
  port49 directory forget [--socket PATH] PRINCIPAL
                (forget a principal's directory membership and the entry it is pinned to: for an
                entry deleted and re-created, once you have confirmed it is the same person)
```

- [ ] **Step 9: Run them to verify they pass**

Run: `go test ./internal/broker/ ./internal/daemon/admin/ ./internal/decision/ ./internal/port49d/ ./cmd/port49/ -race -count=1 && go vet ./...`
Expected: PASS: the new tests, and every existing test (the unknown-op line updated).

- [ ] **Step 10: Commit**

```bash
git add internal/broker/forget.go internal/broker/forget_test.go internal/decision internal/daemon/admin \
  internal/port49d/revocations.go internal/port49d/brokerd.go internal/port49d/main.go cmd/port49
git commit -m "feat(broker): port49 directory forget, the pin's escape for an entry re-created" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: The refresh judges a member: the stored membership on a policy pass, and a session refresh verifies

Tasks 14 and 15 are committed on one branch in order, and the build and `make test` are green
after each commit: Task 14 adds the judge with every caller passing a stamp of zero, and Task
15 adds the pass that passes one (pre-flight I-12).

**Files:**
- Modify: `internal/broker/refresh.go:55-85` (`RefreshReport`: `Unverified`,
  `UnverifiedPrincipals`, `OldestUnverified`), `:320-360` (`mintedBy`), `:375-` (`supersedeTokens`),
  `:478-` (`refreshContexts`, `refreshContext`), `:901-998` (`decideRefresh`), `:999-`
  (`count`), `:1017-1023` (`resolveFor`, `mintedFor`)
- Modify: `internal/broker/sessionrefresh.go:220-320` (`RefreshSession`), the `/v1/refresh`
  handler that calls it, `internal/broker/reindex.go:123`
- Test: `internal/broker/refresh_test.go` (and `:1013`'s `mintedFor` stand-in),
  `internal/broker/sessionrefresh_test.go`

**Interfaces:**
- Consumes: `policy.Member`, `MemberOf`, `ResolveMember`, `ErrCompositionRefused` (Task 11);
  `directory.Resolver.Stored`, `Current`, `IsUser`, `ErrUnavailable` (Task 10);
  `store.ContextPolicy.RefreshedAt`, `StampRefreshed` (Task 3); `store.MembershipPrincipals`
  (Task 5); `b.memberFor` (Task 13).
- Produces:

```go
// storedMember is the membership a policy pass judges principal by: the
// store's, if it is unrefused and verified within directory.grace; else
// no groups (Ruling 12; pre-flight I-14). A machine principal is MemberOf.
func (b *Broker) storedMember(ctx context.Context, principal string) (policy.Member, error)
var resolveFor = (*policy.Policy).ResolveMember
var mintedFor = mintedBy
func (b *Broker) decideRefresh(cur *policy.Policy, now time.Time, m policy.Member, ref store.ContextRef,
	c store.Context) refreshStep
func mintedBy(p *policy.Policy, m policy.Member, d admission.Device, at time.Time, def time.Duration) (minted, bool)
// passJudge is how a pass learns each principal's member, and under which
// policy it judges it.
type passJudge struct {
	// member is principal's member and the stamp's time; a zero time stamps nothing.
	member func(ctx context.Context, principal string) (policy.Member, time.Time, error)
	// hold, when set, is the policy each principal is judged under: taken
	// after member answers, released once that principal's contexts are
	// written (pre-flight I-11). Unset, cur judges every principal.
	hold func() (*policy.Policy, func())
}
func (b *Broker) refreshContexts(ctx context.Context, cur *policy.Policy, priors []Prior, now time.Time,
	rep *RefreshReport, sameSource bool, judge passJudge) error
func (b *Broker) refreshContext(ctx context.Context, cur *policy.Policy, priors []Prior, now time.Time,
	m policy.Member, ref store.ContextRef, rep *RefreshReport, quarantined map[string]bool,
	sameSource bool, stamp time.Time) (outcome string, err error)
// RefreshReport gains
Unverified           int       // contexts left unstamped: the directory did not answer for their principal
UnverifiedPrincipals int
OldestUnverified     time.Time // the least refreshed_at among them
Narrowed             []string  // principals a pass revoked or narrowed a context of, for token supersession
// RefreshSession takes the member its handler resolved
func (b *Broker) RefreshSession(ctx context.Context, m policy.Member, answer *directory.Answer,
	cred store.Credential, at time.Time) (SessionRefreshReport, error)
```

- [ ] **Step 1: The failing tests**

Append to `internal/broker/refresh_test.go`:

```go
// A policy reload judges a group member by the stored membership: a grant
// withdrawn from their group revokes their context with no server asked
// (Ruling 12), and refreshed_at is not touched.
func TestAReloadJudgesTheStoredMembership(t *testing.T)

// A principal with no stored membership, a refused one, or one verified
// longer ago than directory.grace, is judged with no groups: a reload that
// adds a grant to their group writes nothing into their context
// (pre-flight I-14), and a context held only through a group is revoked.
func TestAnAbsentRefusedOrOldMembershipIsNoGroups(t *testing.T)

// A context whose subjects' composition a joint check now refuses is
// revoked composition_refused.
func TestARefusedCompositionRevokesOnRefresh(t *testing.T)

// A machine principal (app:) is judged as MemberOf under a directory, and
// keeps its context (pre-flight I-10).
func TestAMachinePrincipalIsJudgedWithoutTheDirectory(t *testing.T)

// A reload that withdraws a group's grant supersedes its members' unspent
// tokens, though no identity subject names them (pre-flight I-13).
func TestAReloadSupersedesAGroupMembersTokens(t *testing.T)
```

Update `TestASettlePassComparesNoPolicyWithItself` (`refresh_test.go:1013`): its `mintedFor`
stand-in takes `m policy.Member` and calls `was(p, m, d, at, def)`.

Append to `internal/broker/sessionrefresh_test.go`:

```go
// A session refresh with a directory verifies the membership (fresh, or
// grace) and writes refreshed_at as the membership's verification, never
// later; a refresh past grace is refused directory_unavailable and extends
// nothing.
func TestASessionRefreshVerifiesTheMembership(t *testing.T)
```

Write them on the fixtures those files already use, with a `directory.ForTestsStaticResolver` and
a memory store holding the memberships (`PutMembership`).

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'ReloadJudgesTheStored|AbsentRefusedOrOld|RefusedCompositionRevokes|MachinePrincipalIsJudged|SupersedesAGroupMember|SessionRefreshVerifies' -count=1`
Expected: FAIL.

- [ ] **Step 3: The pass judges a member**

In `refresh.go`:
- `resolveFor` becomes `(*policy.Policy).ResolveMember`.
- `decideRefresh` takes `m policy.Member`. It names `rec.Principal = m.Principal`. Its
  subject is `cur.SubjectsOf(m)`: one goes in `Subject`, several in `Subjects`.
- Its switch gains a case, before `err != nil`, that revokes a refused composition:

```go
	case errors.Is(err, policy.ErrCompositionRefused):
		b.logf("broker: refresh: %v; revoking the context (ctx_id %s)", err, c.CtxID)
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.CompositionRefused
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
```

- `RefreshReport` gains the four fields of Interfaces, and `count` passes `unverified` to
  `port49_context_refreshes_total` (spec §5.1.3's new outcome).
- `refreshContexts` gains `judge passJudge`. Per principal, after `ContextsByPrincipal`:

```go
		m, stamp, jerr := judge.member(ctx, principal)
		switch {
		case errors.Is(jerr, directory.ErrUnavailable):
			// The directory did not answer for this principal: its contexts
			// are left as they are and unstamped, and context_stale takes
			// over at the ceiling (Ruling 12). Task 15 says the line.
			rep.UnverifiedPrincipals++
			for _, ref := range refs {
				b.count(rep, "unverified")
				rep.Unverified++
				if c, err := b.Store.GetContext(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username}); err == nil &&
					(rep.OldestUnverified.IsZero() || c.RefreshedAt.Before(rep.OldestUnverified)) {
					rep.OldestUnverified = c.RefreshedAt
				}
			}
			continue
		case errors.Is(jerr, directory.ErrUnmapped), errors.Is(jerr, directory.ErrAmbiguous),
			errors.Is(jerr, directory.ErrUsernameTaken):
			// The directory answered no: every context of the principal is
			// revoked under that reason, and its tokens superseded.
			for _, ref := range refs {
				if err := b.revokeFor(ctx, principal, ref, refusalReason(jerr), now, rep); err != nil {
					return err
				}
			}
			rep.Narrowed = append(rep.Narrowed, principal)
			continue
		case jerr != nil:
			return jerr
		}
		pol, release := cur, func() {}
		if judge.hold != nil {
			pol, release = judge.hold()
		}
		for _, ref := range refs {
			// refreshContext(ctx, pol, priors, now, m, ref, rep, quarantined, sameSource, stamp) …
		}
		release()
```

  `revokeFor` is `refreshContext`'s revoke step for one context with a fixed reason (read
  the context, write `RevokedAt` compared on `PolicyRev`, one `refresh` deny record);
  lift it from `refreshContext`'s revoke branch rather than duplicating the write.
  `refusalReason` maps the three errors to `decision.IdentityUnmapped`, `IdentityAmbiguous`
  and `UsernameCollision`. `refreshContext` appends `m.Principal` to `rep.Narrowed` whenever
  its step revokes or narrows a context.
- `refreshContext` takes `m` and `stamp` in place of the principal string, passes `m` to
  `decideRefresh`, and when `stamp` is non-zero:
  - an `"unchanged"` step is stamped with `StampRefreshed(ctx, k, c.PolicyRev, stamp)`,
    retried on `ErrConflict` as `SetContextPolicy` is;
  - an `"updated"` step's `ContextPolicy` carries `RefreshedAt: stamp`.
- The policy reload's pass (`Refresh`, `RefreshAtStart`) passes
  `passJudge{member: b.storedJudge}`, no hold: its `cur` is the reload's own policy.
- `reindex.go:123` passes `b.storedMember`'s member for `c.Principal` and a zero stamp.

```go
// storedJudge is a policy pass's member: the stored membership, no stamp.
func (b *Broker) storedJudge(ctx context.Context, principal string) (policy.Member, time.Time, error) {
	m, err := b.storedMember(ctx, principal)
	return m, time.Time{}, err
}

func (b *Broker) storedMember(ctx context.Context, principal string) (policy.Member, error) {
	if b.Directory == nil || !directory.IsUser(principal) {
		return policy.MemberOf(principal), nil // a machine principal has no entry (pre-flight I-10)
	}
	sm, ok, err := b.Directory.Stored(ctx, principal)
	switch {
	case err != nil:
		return policy.Member{}, err
	case !ok, sm.Refused, b.Now().Sub(sm.VerifiedAt) > b.Directory.Cfg.Grace:
		// None stored, the directory's refusal, or a membership older than
		// grace: no groups, which can only narrow. A reload during a long
		// outage never widens a context on a membership nobody has verified
		// for longer than grace (pre-flight I-14).
		return policy.Member{Principal: principal, Directory: true}, nil
	}
	return policy.Member{Principal: principal, Directory: true, Username: sm.Username, GroupDNs: sm.GroupDNs,
		GroupNames: sm.GroupNames}, nil
}
```

- With no username stored, a context's username differs from the resolution's empty one, so
  `decideRefresh`'s username check revokes it. That is the same fail-closed answer, and the
  test asserts it.
- `mintedBy` takes `m policy.Member` and resolves with `p.ResolveMember(m, d, at)`;
  `policy.MintCheck(res, m.Principal, d.Name)` keeps the principal string.
- `supersedeTokens` builds each principal's member through `b.storedMember`, cached by
  principal for the pass. Its principal set is `pr.Policy.Principals()` (identity-declared)
  together with `b.Store.MembershipPrincipals(ctx)` once per pass, de-duplicated and sorted,
  so a group member's unspent tokens are superseded when a reload withdraws the group's grant
  (pre-flight I-13). Without a directory the second set is not read.

In `sessionrefresh.go` (`/v1/refresh`, a fresh authentication):
- the handler resolves `m, answer, err := b.memberFor(ctx, principal)` under
  `b.memberBudget()`, before `RefreshSession` takes its `Hold`, so no directory query runs
  under a held policy;
- a refusal answers as `tokens` does and extends nothing;
- `RefreshSession` takes `m` and `answer`, and passes `m` and a zero stamp to `refreshContext`
  (the session refresh writes `RefreshedAt` through its own `RefreshContext`, below);
- `pol.Resolve(principal, dev, at)` becomes `pol.ResolveMember(m, dev, at)`;
- `RefreshedAt` is `refreshedAt(answer, at)`, the answer's `VerifiedAt` when it is before
  `at`, else `at`. A session refresh must not reset the staleness clock past the directory's
  last answer either (Ruling 11).

- [ ] **Step 4: Run them to verify they pass**

Run: `go test ./internal/broker/... ./internal/port49d/ -race -count=1`
Expected: PASS. The port49d end-to-end tests run the reload's pass with no directory, which is
`MemberOf` and unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/broker
git commit -m "feat(broker): the refresh judges a member by its stored membership; a session refresh verifies it" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 15: The scheduled refresh stamps `refreshed_at`, and the staleness ceiling takes its default

Tasks 14 and 15 are the one change the roadmap asks for (plan 2's hand-off): the ceiling's
default lands in the same task as the pass that keeps contexts under it.

**Files:**
- Create: `internal/broker/scheduled.go`, `internal/broker/scheduled_test.go`
- Modify: `internal/config/config.go:116-153` (`SessionConfig`), `:479-486` (`sessionYAML`),
  `:815-835` (the default), `:2244-2260` (the checks), the one-process checks beside them
- Modify: `internal/daemon/metrics/metrics.go` (`DirectoryRefreshLastComplete`)
- Modify: `tests/lab/port49d-lab.yaml` (`staleness_ceiling: 0s`, commented)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `refreshContexts` with `passJudge`, `RefreshReport.Unverified*`, `Narrowed`
  (Task 14); `directory.Resolver.Verify`, `directory.IsUser`; `b.Policy.Hold`
  (`internal/policy/live.go:42`); `b.sayOnce` (`internal/broker/certcheck.go:303`);
  `store.TokensByPrincipal`, `DeleteTokens`.
- Produces:

```go
// RefreshDirectory is the scheduled pass (spec §5.1.3; Ruling 12).
func (b *Broker) RefreshDirectory(ctx context.Context) (RefreshReport, error)
// config
const DefaultStalenessCeiling = 4 * time.Hour
// config.Config gains: StalenessOff bool // the ceiling was set to 0s explicitly, for the start line
```

- [ ] **Step 1: The failing tests**

Create `internal/broker/scheduled_test.go`:

```go
// The scheduled pass verifies each active principal, stamps every context
// it judged with the verification time, changed or not, and writes a
// record only for a change (spec §5.1.3).
func TestTheScheduledPassStamps(t *testing.T)

// A directory that does not answer leaves every context unstamped and
// unrevoked, counted unverified (Ruling 12; spec §14 "Directory").
func TestAnOutageStampsNothingAndRevokesNothing(t *testing.T)

// An entry gone revokes identity_unmapped; two entries identity_ambiguous;
// a username taken username_collision; and each principal's unspent
// tokens are superseded (pre-flight I-13).
func TestAGoneOrAmbiguousEntryRevokes(t *testing.T)

// Without a directory the pass judges on the policy and stamps its own
// instant: the ceiling bounds a broker outage (Ruling 12).
func TestWithoutADirectoryThePassStampsItsInstant(t *testing.T)

// A machine principal's context under a directory is judged as MemberOf,
// stamped with the pass's instant, and never revoked identity_unmapped
// (pre-flight I-10).
func TestAMachinePrincipalIsStampedAndKept(t *testing.T)

// A removal from a group reaches the live context at the next pass:
// revoked no_grants_matched, the next command denied credential_revoked.
func TestARemovalReachesTheSessionAtTheNextPass(t *testing.T)

// A reload that lands while the pass is verifying a principal is the
// policy that principal is judged and written under: the pass never
// writes a superseded policy over a reload's (pre-flight I-11). The
// static resolver's answer for the principal swaps the policy (b.Policy.Swap)
// before returning.
func TestAReloadDuringThePassIsThePolicyItWrites(t *testing.T)
```

Each runs `b.RefreshDirectory(ctx)` over a memory store holding contexts written as a login
writes them (`store.Context{Principal, Username, BlobHash, AuthTime, RefreshedAt}`), with
`directory.ForTestsStaticResolver`'s per-principal answers or error. It asserts `RefreshedAt` read
back, `RevokedAt`, the records in the fixture's log, and the report's counts.

Append to `internal/config/config_test.go`:

```go
// session.staleness_ceiling defaults to 4h now that the scheduled refresh
// stamps refreshed_at (plan 2's hand-off; OR-1); 0s is off and said.
func TestTheStalenessCeilingDefault(t *testing.T) {
	c := loadWith(t, "") // no session: block
	if c.Session.StalenessCeiling != DefaultStalenessCeiling || c.StalenessOff {
		t.Fatalf("%v %v", c.Session.StalenessCeiling, c.StalenessOff)
	}
	c = loadWith(t, "session: {staleness_ceiling: 0s}")
	if c.Session.StalenessCeiling != 0 || !c.StalenessOff {
		t.Fatalf("explicit 0s: %v %v", c.Session.StalenessCeiling, c.StalenessOff)
	}
}

// In one process, the refresh must fit the ceiling twice, and grace must
// not outlive it (Ruling 14).
func TestOneProcessChecksRefreshAndGraceAgainstTheCeiling(t *testing.T) {
	for _, c := range []struct{ yaml, want string }{
		{"session: {staleness_ceiling: 8m}\nbroker: {refresh_interval: 5m}",
			"broker.refresh_interval 5m0s: above half session.staleness_ceiling (8m0s); a context would go stale between two passes"},
		{"session: {staleness_ceiling: 1h}\nbroker: {directory: {grace: 2h}}",
			"broker.directory.grace 2h0m0s: above session.staleness_ceiling (1h0m0s), a grace mint would be stale at its first command"},
	} {
		if _, err := loadErr(t, c.yaml); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
}

// port49-broker's load shares the schema but never applies the ceiling, so
// the one-process checks never refuse a split deployment's broker file
// (pre-flight I-15): grace 8h loads there.
func TestTheBrokersLoadSkipsTheOneProcessChecks(t *testing.T) {
	if _, err := loadBrokerErr(t, "broker: {directory: {grace: 8h}}"); err != nil {
		t.Fatalf("port49-broker.yaml with grace 8h: %v", err)
	}
}
```

(`loadWith`, `loadErr`: the file's helpers that write a port49d.yaml with a broker block and
load it; `loadBrokerErr` the same through `LoadBroker`. Use the existing ones, adding the keys
to their base config. The directory cases need Task 4's directory fixture merged into the
YAML.)

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ ./internal/config/ -run 'ScheduledPass|AnOutageStamps|GoneOrAmbiguous|WithoutADirectoryThePass|MachinePrincipalIsStamped|RemovalReaches|ReloadDuringThePass|StalenessCeilingDefault|OneProcessChecks|BrokersLoadSkips' -count=1`
Expected: FAIL.

- [ ] **Step 3: The pass**

Create `internal/broker/scheduled.go`:

```go
package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
)

// RefreshDirectory is the scheduled refresh (spec §5.1.3; plan 7g Ruling
// 12): every principal in active_principals verified against the
// directory, from a server and never from grace, its contexts judged on
// that membership and stamped with its verification time. A principal the
// directory does not answer for is left and unstamped; its contexts
// deny context_stale past session.staleness_ceiling. A machine principal,
// and every principal without a directory, is judged on the policy alone
// and stamped with the pass's instant.
//
// Each principal is verified first, with no policy held, then judged and
// written under b.Policy.Hold, so a reload between two principals is the
// policy the next is judged by, and a reload never waits on a directory
// query (pre-flight I-11). Records go to a held log flushed after each
// release, as RefreshSession's do (plan 7e, Ruling 10).
//
// It writes contexts, so it is the runner's alone, as the policy pass's
// context half is (plan 7e, Ruling 6).
func (b *Broker) RefreshDirectory(ctx context.Context) (RefreshReport, error) {
	var rep RefreshReport
	rep.At = b.Now()
	judge := passJudge{
		member: func(ctx context.Context, principal string) (policy.Member, time.Time, error) {
			if b.Directory == nil || !directory.IsUser(principal) {
				return policy.MemberOf(principal), rep.At, nil
			}
			a, err := b.Directory.Verify(ctx, principal)
			if err != nil {
				return policy.Member{}, time.Time{}, err
			}
			return member(a), a.VerifiedAt, nil
		},
		hold: func() (*policy.Policy, func()) {
			buf := newHeldLog()
			rep.log = buf
			pol, release := b.Policy.Hold()
			return pol, func() {
				release()
				rep.log = nil
				buf.Flush(b.Log, b.blobLanded)
			}
		},
	}
	err := b.refreshContexts(ctx, b.Policy.Load(), nil, rep.At, &rep, false, judge)
	if err != nil && !errors.Is(err, ErrPrincipalUnvisited) && !errors.Is(err, ErrLeftUnderUnheldKey) {
		return rep, fmt.Errorf("the scheduled refresh: %w", err)
	}
	if serr := b.supersedeNarrowed(ctx, &rep); serr != nil && err == nil {
		err = serr
	}
	if rep.UnverifiedPrincipals == 0 && err == nil {
		b.Metrics.DirectoryRefreshLastComplete.Set(float64(rep.At.Unix()))
	}
	if rep.UnverifiedPrincipals > 0 {
		b.sayOnce("refresh-unverified", time.Hour, "broker: refresh: the directory did not answer for %d principals; "+
			"their %d contexts keep their last verification (oldest %s ago) and deny context_stale past port49d's "+
			"session.staleness_ceiling", rep.UnverifiedPrincipals, rep.Unverified,
			rep.At.Sub(rep.OldestUnverified).Round(time.Minute))
	}
	return rep, err
}

// supersedeNarrowed deletes the unspent tokens of every principal the pass
// revoked or changed a context of (pre-flight I-13): a token minted on the
// membership the pass just withdrew must not be redeemable after it. A
// key is cleared whole, as supersedeTokens clears one.
func (b *Broker) supersedeNarrowed(ctx context.Context, rep *RefreshReport) error {
	slices.Sort(rep.Narrowed)
	for _, principal := range slices.Compact(rep.Narrowed) {
		keys, err := b.Store.TokensByPrincipal(ctx, principal)
		if err != nil {
			return err
		}
		for _, k := range keys {
			toks, err := b.Store.Candidates(ctx, k)
			if err != nil {
				return err
			}
			if err := b.Store.DeleteTokens(ctx, k); err != nil {
				return err
			}
			b.supersede(ctx, k, b.Now())
			if len(toks) > 0 {
				rep.TokenKeys++
				b.Metrics.TokensSuperseded.Inc()
			}
		}
	}
	return nil
}
```

`rep.log` is the held-log field `RefreshSession` already sets on its report
(`sessionrefresh.go:241`); read how `refreshContext` writes through it and follow that. The
`unverified` counting is Task 14's (the `directory.ErrUnavailable` branch of
`refreshContexts`).

- [ ] **Step 4: The ceiling's default**

In `config.go`:
- `const DefaultStalenessCeiling = 4 * time.Hour`, beside `DefaultMaxSessionAge`.
- `SessionConfig.StalenessCeiling`'s comment becomes "denies a context whose `refreshed_at`
  is older than this, `context_stale`. Default 4h (plan 7g; OR-1): the broker's scheduled
  refresh stamps `refreshed_at` every `broker.refresh_interval`. An explicit `0s` turns it
  off, which every start says." Its tag becomes `yaml:"-"`: the YAML key is read through
  `sessionYAML` alone, since `SessionConfig` is inlined there and two fields may not share
  the `staleness_ceiling` key (pre-flight M-12).
- `sessionYAML` gains `StalenessCeiling *time.Duration \`yaml:"staleness_ceiling"\``, the way
  it already tells `ceiling_warning`'s explicit 0 from absent, and the load resolves:
  - absent → `DefaultStalenessCeiling`;
  - `0s` → 0 and `c.StalenessOff = true`.
- The two existing checks stay (negative refused; positive under 1m refused). Their advice
  "omit the key to disable the check" (`config.go:2253` and `:2257`) becomes "set it to 0s to
  disable the check": omitting it now takes the 4h default (pre-flight M-12). The comment
  above them ("its zero … is the default") is rewritten the same way.
- The two one-process refusals the test names run only for port49d's load with a broker in
  the process, `role == RoleDaemon && c.Broker != nil`, and a positive ceiling (pre-flight
  I-15). port49-broker's load (`RoleBroker`) shares the schema but never applies the
  ceiling, so a split deployment's broker file is compared by neither:
  - `RefreshInterval > StalenessCeiling/2`;
  - `Directory != nil && Directory.Grace > StalenessCeiling`.

Remove the comment at `:824` ("staleness_ceiling has no default"), which is now false.

Run the whole suite after this step. A test that builds a `Config`, starts a daemon over
contexts older than 4h and expects no staleness check now sees one. Fix each by setting what
it asserts (`StalenessCeiling: 0`), never by weakening the check.

In `tests/lab/port49d-lab.yaml`, under `session:`, add:

```yaml
  # The lab's seeded contexts are judged by no broker, so nothing stamps
  # refreshed_at; the 4h default would deny a long run's seeds context_stale.
  staleness_ceiling: 0s
```

- [ ] **Step 5: Run them to verify they pass**

Run: `make test && make vet`
Expected: PASS, the labpcap audit included.

- [ ] **Step 6: Commit**

```bash
git add internal/broker internal/config internal/daemon/metrics/metrics.go tests/lab/port49d-lab.yaml
git commit -m "feat(broker): the scheduled refresh stamps refreshed_at, and session.staleness_ceiling defaults to 4h" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 16: port49-broker and port49d run the directory: the resolver, the pool's checks, the pass, pre-warm

**Files:**
- Create: `internal/port49d/directory.go`, `internal/port49d/directory_test.go`
- Modify: `internal/port49d/main.go:232-291` (`buildBroker`, `buildBrokerAnchor`), `:1103-1115`
  (the listener), `:1225-1242` (beside the reloader)
- Modify: `internal/port49d/brokerd.go:100-180` (`openBroker`), `:498-510` (the listener)
- Modify: `internal/port49d/runner.go:167-203` (`duties`)
- Modify: `internal/port49d/reload.go:322` (the policy's `Env.Directory` at each `bundle.Parse`:
  `:633`, `:865`, `:1107`)
- Modify: `deploy/compose/config/port49-broker.yaml`, `deploy/compose/README.md`

**Interfaces:**
- Consumes: everything above.
- Produces:

```go
// openDirectory builds the resolver from cfg.Broker.Directory, or nil.
func openDirectory(cfg config.Config, st store.Store, live *policy.Live, m *metrics.Metrics,
	say func(string, ...any)) (*directory.Resolver, error)
func announceDirectory(w io.Writer, proc string, cfg config.Config, pol *policy.Policy)
// scheduled runs RefreshDirectory every interval until ctx ends.
func scheduled(ctx context.Context, brk *broker.Broker, every time.Duration, say func(string, ...any))
// prewarm runs Prewarm every interval, the first 30s in; nil r or a zero
// interval returns at once.
func prewarm(ctx context.Context, r *directory.Resolver, live *policy.Live, every time.Duration, say func(string, ...any))
// prewarmInterval is broker.directory.prewarm.interval, 0 without a directory.
func prewarmInterval(cfg config.Config) time.Duration
func policyEnv(cfg config.Config) policy.Env // KeyRefs and Directory
```

- [ ] **Step 1: The failing tests**

Create `internal/port49d/directory_test.go`:

```go
// The start says the pool, the bind (never its secret), the mapping, the
// nested mode, grace, pre-warm and the refresh (What the operator sees).
func TestTheDirectoryStartLines(t *testing.T)

// A simple bind is said as the weakest, naming the env var, never its value.
func TestASimpleBindIsSaidAsTheWeakest(t *testing.T)

// Group subjects with no directory: said, by name (Ruling 17).
func TestGroupSubjectsWithoutADirectoryAreSaid(t *testing.T)

// The scheduled loop runs RefreshDirectory every interval and stops with
// ctx; a pass error is said and the next pass runs on schedule.
func TestTheScheduledLoop(t *testing.T)

// A grace mint's session, end to end on port49d with a broker inside and
// the memory store: the context's refreshed_at is the membership's
// verification, and its command is denied context_stale once the ceiling
// passes from then, not from the login (Review Focus 5).
func TestAGraceMintsSessionGoesStaleFromItsVerification(t *testing.T)

// /readyz stays ready with every directory server down and every breaker
// open: readiness never follows the directory (design §10, §12; pre-flight
// M-15). port49-broker's /readyz, over a resolver whose pool dials a
// refusing fake, after enough health checks to open each breaker.
func TestReadinessNeverFollowsTheDirectory(t *testing.T)

// The runner's duties start and stop cleanly with no directory: the
// pre-warm goroutine returns at once and wg.Wait does not hang
// (pre-flight M-13).
func TestTheDutiesRunWithoutADirectory(t *testing.T)

// A bind credential that does not load (an unreadable keytab, a missing
// password variable) stops the start, naming the key, never the secret
// (pre-flight M-3).
func TestABindCredentialThatDoesNotLoadStopsTheStart(t *testing.T)
```

`TestAGraceMintsSessionGoesStaleFromItsVerification` uses the port49d end-to-end harness the
reload tests use (`reload_test.go`'s daemon with a broker block and a fake clock). It
injects a `directory.ForTestsStaticResolver` through a test hook, `openDirectoryHook` (a package
variable defaulting to `openDirectory`), answering alice from grace verified 3h50m ago. It
then:
- mints and logs in over the in-process TACACS+ client;
- advances the clock 11 minutes;
- asserts the next command is denied `context_stale` with the ceiling at its 4h default.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/port49d/ -run 'DirectoryStartLines|SimpleBindIsSaid|GroupSubjectsWithout|ScheduledLoop|GraceMintsSession|ReadinessNever|DutiesRunWithout|BindCredentialThatDoesNot' -count=1`
Expected: FAIL.

- [ ] **Step 3: Building and running it**

Create `internal/port49d/directory.go`:

```go
package port49d

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

var openDirectoryHook = openDirectory

// openDirectory builds the resolver from broker.directory: the bind's
// credentials read once, the pool over a dialer that binds each
// connection, the policy's declared usernames read live.
func openDirectory(cfg config.Config, st store.Store, live *policy.Live, m *metrics.Metrics,
	say func(string, ...any)) (*directory.Resolver, error) {
	d := cfg.Broker.Directory
	if d == nil {
		return nil, nil
	}
	cr, err := directory.LoadCredentials(d.Bind, os.Getenv)
	if err != nil {
		// The error names the key (keytab_file, tls_cert_file,
		// password_env), never the secret; the start stops on it, as on a
		// config refusal (pre-flight M-3).
		return nil, fmt.Errorf("config: %w", err)
	}
	dial, err := directory.NewDialer(*d, cr)
	if err != nil {
		return nil, err
	}
	pool := directory.NewPool(*d, dial, directory.RootDSE, time.Now, m, say)
	return &directory.Resolver{Cfg: *d, Pool: pool, Store: st, Now: time.Now, M: m, Say: say,
		Declared: func() map[string]string { return live.Load().DeclaredUsernames() }}, nil
}

// policyEnv is the policy's environment in this process: the key refs, and
// whether its broker resolves humans through a directory (Ruling 16).
func policyEnv(cfg config.Config) policy.Env {
	env := policy.Env{KeyRefs: cfg.KeyRefs()}
	switch {
	case cfg.Broker == nil:
	case cfg.Broker.Directory != nil:
		env.Directory = policy.DirectoryOn
	default:
		env.Directory = policy.DirectoryOff
	}
	return env
}

// announceDirectory is the start's directory lines (What the operator sees).
func announceDirectory(w io.Writer, proc string, cfg config.Config, pol *policy.Policy) {
	d := cfg.Broker.Directory
	if d == nil {
		if gs := pol.GroupSubjects(); len(gs) > 0 {
			fmt.Fprintf(w, "%s: policy: %d group subjects (%s) mint for no one: no broker.directory is configured\n",
				proc, len(gs), strings.Join(gs, ", "))
		}
		return
	}
	var servers []string
	for _, s := range d.Servers {
		servers = append(servers, fmt.Sprintf("%s %s %d", s.URI, cmp.Or(s.Site, "-"), s.Priority))
	}
	site := "none: servers rank by priority alone (set broker.directory.site or PORT49_SITE)"
	if d.Site != "" {
		site = d.Site + " (" + d.SiteFrom + ")"
	}
	fmt.Fprintf(w, "%s: directory: %d servers (%s); this broker's site is %s; bind %s as %s\n", proc,
		len(d.Servers), strings.Join(servers, ", "), site, d.Bind.Mechanism, bindWho(d.Bind))
	if d.Bind.Mechanism == "simple" {
		fmt.Fprintf(w, "%s: directory: bind simple as %s: the weakest of the three (design §10); a password in %s\n",
			proc, d.Bind.BindDN, d.Bind.PasswordEnv)
	}
	strength := "weak, pinned to " + strings.Join(d.Mapping.Issuers, "; ")
	if d.Mapping.Kind.Strong() {
		strength = "strong"
	}
	fmt.Fprintf(w, "%s: directory: certificates map by %s (%s) through %s; principal from %s, username from %s; "+
		"nested groups %s under %s\n", proc, d.Mapping.Kind, strength, d.Mapping.Attribute, d.PrincipalAttribute,
		d.UsernameAttribute, d.Nested, d.GroupsBaseDN)
	fmt.Fprintf(w, "%s: directory: %s and %s must be writable only by directory administrators: two entries "+
		"holding one value are both refused (identity_ambiguous, username_collision) until it is fixed\n", proc,
		d.PrincipalAttribute, d.UsernameAttribute)
	fmt.Fprintf(w, "%s: directory: grace %s; pre-warm %s; the scheduled refresh every %s stamps refreshed_at "+
		"(port49d's session.staleness_ceiling denies a session past it)\n", proc, d.Grace,
		every(d.PrewarmInterval), cfg.Broker.RefreshInterval)
}

func bindWho(b directory.Bind) string {
	switch b.Mechanism {
	case "gssapi":
		return b.Principal
	case "simple":
		return b.BindDN
	}
	return "the certificate in " + b.TLSCertFile
}

func every(d time.Duration) string {
	if d == 0 {
		return "off"
	}
	return "every " + d.String()
}

// scheduled runs the scheduled refresh every interval until ctx ends. A
// pass that stops is said; the next runs on schedule.
func scheduled(ctx context.Context, brk *broker.Broker, interval time.Duration, say func(string, ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := brk.RefreshDirectory(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			say("refresh: the scheduled refresh stopped (%s so far): %v; the next runs in %s", summary(rep), err, interval)
		case rep.Updated+rep.Revoked+rep.Failed > 0:
			say("refresh: scheduled: %s", summary(rep))
		}
	}
}

// prewarmInterval is broker.directory.prewarm.interval, 0 (off) without a
// directory, so a caller never dereferences a nil directory (pre-flight
// M-13).
func prewarmInterval(cfg config.Config) time.Duration {
	if cfg.Broker == nil || cfg.Broker.Directory == nil {
		return 0
	}
	return cfg.Broker.Directory.PrewarmInterval
}

// prewarm runs pre-warm every interval, the first 30s after the start.
func prewarm(ctx context.Context, r *directory.Resolver, live *policy.Live, interval time.Duration,
	say func(string, ...any)) {
	if r == nil || interval == 0 {
		return
	}
	wait := 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = interval
		rep, err := r.Prewarm(ctx, live.Load().GroupValues())
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			say("directory: pre-warm stopped: %v; the next runs in %s", err, interval)
		default:
			capped := ""
			if rep.Capped {
				capped = fmt.Sprintf("; capped at prewarm.max_principals (%d)", r.Cfg.PrewarmMax)
			}
			say("directory: pre-warm: %d groups, %d principals verified, %d skipped%s", rep.Groups,
				rep.Principals, rep.Failed, capped)
		}
	}
}
```

(`summary` is `reload.go:1295`'s. The package has no `or`, which is `internal/config`'s, so the
file uses `cmp.Or`.)

The wiring:
- **Both builders** (`main.go`'s `buildBroker`/`buildBrokerAnchor`, and `brokerd.go`'s
  `openBroker`) set `brk.Directory, err = openDirectoryHook(cfg, st, brk.Policy, m, sayf)`,
  where `st` is the broker's sealed store. Then:
  - `announceDirectory(stderr, procOf(cfg), cfg, pol)`;
  - each listener sets `bl.Map = brk.BindMap` when `brk.Directory != nil`, and
    `lim.MapTimeout = d.QueryTimeout + time.Second`;
  - a goroutine runs `brk.Directory.Pool.Run(ctx)`, the health checks, on every process with
    a directory: each replica selects for its own queries.
- **port49-broker.** `runner.duties` (`runner.go:181`) gains two goroutines, `wg.Add(6)`
  becoming `wg.Add(8)`, both started unconditionally so the count always matches:
  `scheduled(ctx, r.brk, r.cfg.Broker.RefreshInterval, sayf)` and
  `prewarm(ctx, r.brk.Directory, r.brk.Policy, prewarmInterval(r.cfg), sayf)`. Without a
  directory `prewarm` returns at once and its `wg.Done` runs; nothing dereferences
  `r.cfg.Broker.Directory` (pre-flight M-13). Both are the runner's alone.
- **A credential that does not load** stops the start: `openDirectory`'s error is returned by
  `buildBroker` and `openBroker` as a config error is, and the process exits non-zero naming
  the key (`broker.directory.bind.keytab_file …`). `LoadCredentials` reads the keytab, the
  EXTERNAL certificate and key, and the password variable once, here (pre-flight M-3).
- **Readiness** is unchanged: neither builder adds a directory or breaker condition to
  `/readyz` (`brokerd.go:252-260`). The test pins it.
- **port49d with a broker inside** (`main.go:1225`, the memory store's single process) starts
  the same two goroutines beside `r.run(ctx, hup)`, with `prewarmInterval(cfg)` as above.
- **The reloader's three `bundle.Parse` calls** take `policyEnv(r.cfg)` in place of
  `policy.Env{KeyRefs: r.cfg.KeyRefs()}`. So does `startPolicy`'s, wherever port49d and
  port49-broker load the policy (`loadPolicy`, `parseBundle`).

The compose example's `deploy/compose/config/port49-broker.yaml` gains a commented
`directory:` block showing an `issuer_serial` mapping, `in_chain`, a GSSAPI bind and two
servers in one site. It ships commented out: the trial has no directory, as 7f ships
`context_cache` commented. `deploy/compose/README.md` gains a "Directory" section:
- what each key does;
- that `PORT49_SITE` is set per broker container;
- that the keytab goes in the broker's configuration volume, 0600, owned by 65532.

- [ ] **Step 4: Run them to verify they pass**

Run: `make test && make vet && make compose-smoke`
Expected: PASS. The smoke test runs the compose stack with no directory, and the 4h ceiling
does not touch its sessions.

- [ ] **Step 5: Commit**

```bash
git add internal/port49d deploy/compose
git commit -m "feat(port49d): run the directory: the resolver, health checks, the scheduled refresh and pre-warm on the runner" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 17: (lab, on beehive) L42 and L43 on OpenLDAP and Samba AD

**Files:**
- Create: `tests/lab/directory/openldap/Dockerfile`, `tests/lab/directory/openldap/config.ldif`,
  `tests/lab/directory/openldap/seed.ldif`, `tests/lab/directory/openldap/entrypoint.sh`
- Create: `tests/lab/directory/samba/Dockerfile`, `tests/lab/directory/samba/entrypoint.sh`,
  `tests/lab/directory/samba/seed.sh`
- Create: `tests/lab/directory/compose.yaml`
- Create: `tests/lab/directory_test.go` (`//go:build lab`: bringing the two up, the PKI, the
  evidence writer), `tests/lab/l42_test.go`, `tests/lab/l43_test.go`
- Create: `tests/lab/results/L42-openldap.md`, `L42-samba_ad.md`, `L43-openldap.md`,
  `L43-samba_ad.md`; `tests/lab/evidence/L42-*.json`, `L43-*.json`
- Modify: `tests/lab/README.md` ("Directories"), `Makefile` (`lab-directory`)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` §15 (L42, L43 Status; L44 untouched),
  §13 decision 38 (the L42 and L43 provisional marks, if they close; the L44 marks stay)

**Interfaces:**
- Consumes: `directory.NewDialer`, `LoadCredentials`, `Config`, `Pool`, `Resolver`,
  `Mapping.Lookup`, `ADIssuerSerial`, `groupsOf` through `Resolver.Verify` (Tasks 6–10);
  `internal/testpki` for the directories' server certificates and the broker's client
  certificate.
- Produces: the four results notes and their evidence; L42 and L43 closed on OpenLDAP and
  Samba AD, the platforms they name, or narrowed with what was measured. L44 (Windows Server
  AD) stays open: nothing here measures a Windows DC.

**The users CA** that issues the lab's client certificates for these runs has a subject with
`DC=` RDNs (`CN=lab-users-CA,DC=corp,DC=example,DC=com`), built in `directory_test.go` with
`x509.CreateCertificate` over a `RawSubject`, as Task 8's `issuingCA` does. So `issuer_serial`
and the issuer pin meet `DC=` on real directories (pre-flight I-1).

**The fixture** (both directories, the same shape):

| Entry | Where | Membership |
|---|---|---|
| `alice` | `OU=Staff` | `g-leaf` |
| `carol` | `OU=Staff` | `netops-oncall` |
| `dave` | `OU=Staff` | `g-loop-a` |
| `bob` | `OU=Staff` | none |
| `eve`, `eve2` | `OU=Staff`, `OU=Contractors` | none; the same `mail` (`eve@corp.example.com`), for the ambiguity check |
| `g-leaf` | `OU=G` | member of `g-mid` |
| `g-mid` | `OU=G` | member of `netops-oncall` |
| `netops-oncall` | `OU=G` | — |
| `g-loop-a`, `g-loop-b` | `OU=G` | each a member of the other |
| `netops-oncall` (a second) | `OU=Users-Can-Create` | — (the shared-name check) |
| `port49` | `OU=Svc` | the broker's account: read-only |

- [ ] **Step 1: The OpenLDAP image**

`tests/lab/directory/openldap/Dockerfile`:

```dockerfile
# OpenLDAP for plan 7g's lab (L42, L43): Debian's slapd, configured by
# cn=config LDIF at first start, with the memberof overlay, TLS from the
# lab PKI, and EXTERNAL mapping the broker's certificate to its account.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      slapd ldap-utils ca-certificates && rm -rf /var/lib/apt/lists/*
COPY config.ldif seed.ldif entrypoint.sh /lab/
RUN chmod 0755 /lab/entrypoint.sh
EXPOSE 389 636
ENTRYPOINT ["/lab/entrypoint.sh"]
```

`entrypoint.sh` does the following:
- it replaces `/etc/ldap/slapd.d` with `slapadd -n0 -F /etc/ldap/slapd.d -l /lab/config.ldif`
  and loads `seed.ldif` with `slapadd -n1`;
- it copies `/pki/server.pem`, `server-key.pem` and `ca.pem` (mounted read-only) to slapd's
  own paths, owned by `openldap`;
- it runs `slapd -d 256 -h "ldap:/// ldaps:///" -u openldap -g openldap`.

`config.ldif` holds the following, in the standard `cn=config` form `slapd.conf(5)`'s LDIF
conversion produces:
- the `mdb` database for `DC=corp,DC=example,DC=com`;
- `olcTLSCertificateFile`, `olcTLSCertificateKeyFile` and `olcTLSCACertificateFile`, with
  `olcTLSVerifyClient: try`;
- `olcAuthzRegexp: "^cn=port49-broker,o=port49 lab$" "cn=port49,ou=Svc,dc=corp,dc=example,dc=com"`,
  matching the subject the broker's lab client certificate carries;
- `olcSecurity: tls=1`, which refuses a simple bind over plain LDAP;
- the `memberof` overlay (`olcMemberOfRefInt: TRUE`), and an ACL giving `cn=port49`
  read-only access to everything.

`seed.ldif` is the fixture, with `objectClass: inetOrgPerson` users (`uid`, `mail`, `cn`)
and `objectClass: groupOfNames` groups (`member`). `port49`'s `userPassword` is the lab's
simple-bind password, which `tests/lab/labcreds` already holds for break-glass. Reuse that
reader and never write the password in the LDIF: the entrypoint substitutes it from
`LAB_LDAP_PASSWORD`.

- [ ] **Step 2: The Samba AD image**

`tests/lab/directory/samba/Dockerfile`:

```dockerfile
# Samba 4 as an Active Directory DC for plan 7g's lab: Debian's samba,
# provisioned at first start, the fixture made with samba-tool, and the
# broker's keytab exported for GSSAPI.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba krb5-user winbind ldb-tools ca-certificates && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh seed.sh /lab/
RUN chmod 0755 /lab/entrypoint.sh /lab/seed.sh
EXPOSE 88/tcp 88/udp 389 636
ENTRYPOINT ["/lab/entrypoint.sh"]
```

`entrypoint.sh`:
- On first start (no `/var/lib/samba/private/sam.ldb`), it provisions:

  ```sh
  samba-tool domain provision --realm=CORP.EXAMPLE.COM --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$LAB_ADMIN_PASSWORD"
  ```

  It sets `tls certfile`, `tls keyfile` and `tls cafile` in `smb.conf` to the mounted lab
  PKI, and `ldap server require strong auth = yes`. Then it runs `seed.sh`.
- It then runs `samba -i`.

`seed.sh`:
- creates the fixture with `samba-tool ou create`, `user create --userou`, `group add
  --groupou` and `group addmembers`; a group added to a group is how AD nests;
- sets `alice`'s `mail`;
- sets `alice`'s `altSecurityIdentities` to the `X509:<I>…<SR>…` string of the lab's alice
  client certificate. Task 17's test computes it with `directory.ADIssuerSerial` and passes it
  in `LAB_ALICE_ALTSECID`, so the test checks port49's form against what Samba matches.
- creates `port49` with a random password, and exports its keytab to the mounted
  `/out/port49.keytab` (`samba-tool domain exportkeytab --principal=port49@CORP.EXAMPLE.COM`),
  chmod 0600.

`tests/lab/directory/compose.yaml` runs both on a network of their own (`172.30.42.0/24`).
It publishes OpenLDAP on `127.0.0.1:10389`/`10636`, and Samba on `127.0.0.1:20389`/`20636`
and `20088` (Kerberos, TCP and UDP). It mounts `tests/lab/logs/directory/pki` read-only and
`tests/lab/logs/directory/out`. The lab test writes the `krb5.conf` that points
`CORP.EXAMPLE.COM`'s KDC at `127.0.0.1:20088`.

- [ ] **Step 3: The harness**

`tests/lab/directory_test.go` (`//go:build lab`):
- **`startDirectories(t)`:**
  - writes the PKI with `internal/testpki`: a CA, a server certificate for `localhost` and
    the two containers' names, the broker's client certificate (`CN=port49-broker,O=port49
    lab`), and alice's client certificate (her email SAN, and a SID extension built as Task
    8's test builds it, from her `objectSid`, which `seed.sh` prints and the test reads back);
  - runs `sg docker -c 'docker compose -f tests/lab/directory/compose.yaml up -d --build'`;
  - waits for each LDAPS port to answer a root DSE read (up to 3 minutes for Samba's
    provision);
  - registers `t.Cleanup` to bring both down and keep their logs in `tests/lab/logs/directory/`.
- **`dockerCmd(args...)`** wraps `sg docker -c` with argument quoting.
- **`evidence(t, name)`** appends one JSON line per search to `tests/lab/evidence/<name>.json`:
  base, scope, filter, the DNs returned, the result code and the duration. No password, no
  keytab, no ticket. The evidence is what a reader can follow, since LDAPS captures are
  encrypted.
  - **How it records.** A `directory.Client` wrapper, `recording`, logs each
    `SearchContext` and passes it on. It wraps the dialer: the lab's `directory.Dialer`
    returns it around the real connection `NewDialer` gave.

- [ ] **Step 4: L42**

`tests/lab/l42_test.go`:

```go
//go:build lab

package lab

const l42Claim = "For alice (alice ∈ g-leaf ∈ g-mid ∈ netops-oncall), carol (∈ netops-oncall directly) and " +
	"dave (∈ g-loop-a, g-loop-a ∈ g-loop-b ∈ g-loop-a): which groups each nested mode returns on each directory; " +
	"whether member:1.2.840.113556.1.4.1941:= answers, errors or is refused, on the loop too, and how long it " +
	"takes; whether the user entry's memberOf lists only direct groups; and whether a directory that does not " +
	"implement the matching rule refuses the filter or answers it empty (policy engine spec §15 L42)."

func TestL42NestedGroups(t *testing.T) {
	d := startDirectories(t)
	for _, dir := range d.all() { // openldap, samba_ad
		t.Run(dir.name, func(t *testing.T) {
			var obs strings.Builder
			obs.WriteString("| user | mode | groups returned | result | time |\n|---|---|---|---|---|\n")
			for _, mode := range []directory.Nested{"in_chain", "recursive", "direct"} {
				for _, user := range []string{"alice", "carol", "dave"} {
					start := time.Now()
					a, err := dir.resolver(t, mode).Verify(context.Background(), dir.principal(user))
					fmt.Fprintf(&obs, "| %s | %s | %s | %s | %s |\n", user, mode,
						strings.Join(a.GroupNames, ", "), errOrOK(err), time.Since(start).Round(time.Millisecond))
				}
			}
			fmt.Fprintf(&obs, "\nmemberOf on alice's entry: %s\n", strings.Join(dir.memberOf(t, "alice"), ", "))
			writeResult(t, "L42", dir.name, l42Claim, dir.version(t), obs.String(), "tests/lab/evidence/L42-"+dir.name+".json")
		})
	}
}
```

`writeResult` is defined in `directory_test.go`. It writes
`tests/lab/results/<row>-<platform>.md` with `os.WriteFile`, as `l29_midnight_test.go:175`
writes its note, in the house shape: platform, image version, claim, observation, capture
pointer. `dir.version` reads `slapd -VV` or `samba --version` through `docker exec`. The
test asserts nothing about what in_chain returns on OpenLDAP. That is the measurement:
- if OpenLDAP refuses the filter, the note says so;
- if it answers it empty, the note says so, which is the fail-closed shape;
- if it answers it in full, the note says that.

The test does assert what port49 itself guarantees, on both directories:
- `recursive` returns `g-leaf`, `g-mid` and `netops-oncall` for alice;
- `direct` returns `g-leaf` alone;
- dave's walk ends, with `g-loop-a` and `g-loop-b`.

- [ ] **Step 5: L43**

`tests/lab/l43_test.go`. For each directory, each mechanism is dialled and bound through
`directory.NewDialer`, and the outcome recorded:
- **EXTERNAL:** the broker's client certificate.
- **GSSAPI:** Samba only, with the exported keytab and the written `krb5.conf`.
- **simple over LDAPS:** `port49`'s password.
- **simple over plain LDAP**, built by hand with `ldap.DialURL("ldap://…")` and `Bind`, since
  port49 refuses it at load. The note records what the directory says.

Each outcome is the LDAP result code and go-ldap's error, never a secret. The test asserts
port49's side only:
- every refusal is said with the mechanism and the code;
- a refusal does not open the pool's breaker as a fault when it is invalid credentials
  (result 49), and a query against a directory refusing the bind returns
  `directory.ErrUnavailable`, so grace would apply (pre-flight I-2).

Then, on each directory, it checks the mapping end to end through `Resolver.Map`:
- alice's certificate under `san_email` (pinned to the lab CA) maps to her;
- under `issuer_serial` (Samba, the `altSecurityIdentities` the seed wrote) maps to her;
- under `sid` (Samba) maps to her;
- eve's certificate under `san_email` is `identity_ambiguous`, naming both DNs;
- on Samba with `principal_attribute: mail`, `samba-tool user edit` gives `bob` alice's `mail`;
  alice's certificate under `issuer_serial` is then `identity_ambiguous` naming both DNs, and
  so is a `Verify` of `user:alice@corp.example.com`; the `mail` is then restored (pre-flight
  C-2: a self-editable attribute refuses both people and makes neither the other);
- a group subject named `netops-oncall` matches no one, because two groups share the name,
  and the DN form matches carol.

These are port49's guarantees and are asserted. They go in the note under "Mapping".

- [ ] **Step 6: Run it**

On beehive, from a pinned worktree at the branch's head, with the watchdog armed:

```bash
df -h /var/lib/docker
sg docker -c 'docker compose version'
go test -tags lab ./tests/lab/ -run 'TestL42|TestL43' -count=1 -v -timeout 30m 2>&1 | tee tests/lab/logs/l42-l43.log
```

Expected: both tests pass, and the four notes and four evidence files are written. Read each
note before closing anything.

- [ ] **Step 7: Close or narrow, and commit**

A row closes only when every platform in its Platforms cell has a note with no INVALID cell
(CLAUDE.md lab rule 3). L42 and L43 name OpenLDAP and Samba AD, and nothing else, so each
closes on those two notes:

```
closed — measured <date>; tests/lab/results/L42-openldap.md, L42-samba_ad.md
```

A row with one of its two platforms measured stays open: change only the text after `open —`
to name what was measured. L44 is not touched: its platform is Windows Server AD, and no note
here measures one. In decision 38:
- "provisional on L42" leaves the nested-modes bullet if L42 closed; its "on Windows Server
  AD, on L44" stays;
- "provisional on L43" leaves the bind bullet if L43 closed; its "on Windows Server AD, on
  L44" stays;
- the mapping bullet's `issuer_serial` and `sid` stay "provisional on L44 (Windows Server
  AD)". A Samba result never removes an L44 mark (CLAUDE.md lab rule 2).

If a result contradicts the plan, the doc is wrong. Fix the doc, cite the note, and say so in
the commit. For example: OpenLDAP may answer `in_chain` in full (a dynlist-backed `memberOf`),
or Samba may refuse EXTERNAL. Then fix the spec's and the design's words, and the config
comment that recommends a mode per directory.

```bash
git add tests/lab docs/design/2026-08-23-policy-engine-spec.md Makefile
git commit -m "docs: close lab register entries L42 and L43 (nested groups, bind mechanisms) on OpenLDAP and Samba AD" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 18: (lab, on beehive) A directory login end to end on the compose stack

Not a register row: what the device does with each answer is measured already (L4, L35,
L41). This is the plan's own end-to-end check on real images:
- a login granted through a nested group;
- a removal reaching the open session;
- an outage served from grace until the ceiling, and resumed when the directory returns.

**Files:**
- Create: `tests/lab/directory_e2e_test.go` (`//go:build lab`)
- Create: `tests/lab/compose/directory.yaml` (a compose overlay: the OpenLDAP service of Task
  17 on the compose project's network; the broker's `directory:` block; `refresh_interval:
  1m`; port49d's `staleness_ceiling: 3m`; `grace: 3m`)
- Create: `tests/lab/results/directory-e2e-arista_eos.md`,
  `directory-e2e-juniper_vjunos-router.md`

**Interfaces:**
- Consumes: `l.startCompose(t)` (7f), `eachPlatform`, `l.sshCLI`, `l.errLinesSince`, Task
  17's `startDirectories` PKI and images, the agent's `port49 login`/`port49 token` as 7f's
  L41 test drives them.
- Produces: two results notes.

- [ ] **Step 1: The overlay**

`tests/lab/compose/directory.yaml` adds the `openldap` service and gives `port49-broker` the
directory:
- `servers: [{uri: ldaps://openldap:636, priority: 100, site: lab}]` and `site: lab`;
- `bind: {mechanism: external, …}`;
- `certificate_mapping: {kind: san_email, allow_weak: true, issuers: [<the lab users CA's DN>]}`;
- `nested_groups: recursive`, `principal_attribute: mail`, `username_attribute: uid`;
- `grace: 3m`, `prewarm: {interval: 5m}`;
- `refresh_interval: 1m`.

It sets port49d's `session.staleness_ceiling: 3m`. Under it, the lab policy holds:
- `{name: netops_oncall, group: netops-oncall, token_ttl: 15m}`, granted `network_admin` on
  `all_devices`;
- bob as an identity subject, as 7f's trial has him, with no `username:` (the directory
  supplies it).

- [ ] **Step 2: The test**

`TestDirectoryEndToEnd`, under `eachPlatform`, for `arista_eos` and
`juniper_vjunos-router` only (skip others). Each step records its observation in the note's
table:

1. **Nested grant.**
   - `port49 login` with alice's certificate, then `port49 token` for the device.
   - The broker's decision log has `mint permit grants_matched`, `policy.subject:
     netops_oncall`, `auth.directory.source: fresh`.
   - SSH as `alice` with the token, and `show version`. vEOS: permitted. Junos: the session
     opens.
2. **A removal.**
   - `ldapmodify` inside the `openldap` container (`dockerCmd("compose", "exec", …)`)
     deletes `g-leaf` from `g-mid`'s `member`.
   - Within `refresh_interval` + 30s, the broker writes `refresh deny no_grants_matched` for
     alice's `ctx_id`.
   - vEOS: the session's next `show version` is denied, and port49d's record says
     `credential_revoked`.
   - Junos: the refresh record carries `session.unreached: true`, and the session runs on
     (decision 21). Record it.
   - Put the membership back.
3. **An outage, inside grace.**
   - Log alice in again and SSH, then stop the `openldap` container.
   - `port49 token` for a second token within 3m: it is minted, with the broker's grace line
     and `auth.directory.source: grace` on the record.
   - The open session's commands keep being permitted until the ceiling.
   - Past 3m from the last verification, vEOS's next command is denied `context_stale`, and
     the device prints port49's `server_msg` (L2's display).
4. **The directory returns.**
   - Start the container.
   - Within `refresh_interval` + 30s, the scheduled pass stamps alice's context: no record,
     and the broker's metric `port49_directory_refresh_last_complete_timestamp_seconds`
     moves.
   - The same session's next command is permitted: the context was retained and resumed.
5. **A broker restart in an outage.**
   - Stop the `openldap` container, then `docker compose restart port49-broker`.
   - `port49 login` and `port49 token` for alice within grace succeed from the store.
   - Bob's mint is refused `directory_unavailable`: he has never logged in, so no membership
     is stored for him. Pre-warm does not change that: it enumerates the members of the
     groups a policy names, and bob is in none (he is an identity subject), so pre-warm never
     verifies or stores him, whatever its timing (pre-flight M-16). Assert his
     `mb/` record is absent before stopping the container.

- [ ] **Step 3: Run it**

```bash
go test -tags lab ./tests/lab/ -run TestDirectoryEndToEnd -count=1 -v -timeout 60m 2>&1 | tee tests/lab/logs/directory-e2e.log
```

Expected: PASS on both images, two notes written. Copy any raw captures to `main`'s
`tests/lab/captures/` before removing the worktree.

- [ ] **Step 4: Commit**

```bash
git add tests/lab
git commit -m "test(lab): a directory login end to end on the compose stack: nested grant, removal, grace, ceiling, resume" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 19: Plan 7g as built

**Files:**
- Modify: `docs/superpowers/plans/README.md`: the status line, and a "Plan 7g — As built"
  section after "Plan 7f — As built"

- [ ] **Step 1: Write the section**

It follows 7f's shape:
- **The run.** Executed on `feature/the-directory` (base, ledger path), each task reviewed;
  what differs from the plan's text, task by task.
- **The rulings, as made.** OR-1 to OR-3 with Ryan's answers. Rulings made during execution.
- **Operator notes, as built.** This plan's "Operator-facing notes", corrected to what was
  built.
- **Interfaces 7g added.**
- **Carried, for later plans:**
  - **7h:** OIDC principals resolve groups through `Resolver.Verify` (`user:` + the claim the
    deployment names), and `/v1/logout`.
  - **8:** the workload verifier calls `Resolver.Map` for a workload certificate's directory
    entry, where decision 16 allows one.
  - **12:** the directory alerts, and the systemd and Kubernetes shapes' keytab and
    `PORT49_SITE`:
    - `port49_directory_refresh_last_complete_timestamp_seconds` older than 3 ×
      `refresh_interval`;
    - any increase of `port49_directory_lookups_total{outcome="ambiguous"}`;
    - `port49_directory_server_up == 0`;
    - `port49_directory_group_names_ambiguous > 0`.
  - **Unassigned:** L44, Windows Server AD (OR-3): open until the SER8 box measures it;
    decision 38's L44 marks stay until then.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 7g as built" \
  -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Operator-facing notes (for the pull request body)

- **Upgrading: the staleness ceiling is on.** `session.staleness_ceiling` defaults to 4h.
  - **What it does.** The broker's runner re-verifies every live principal every
    `broker.refresh_interval` (5m) and stamps `refreshed_at`. A session whose principal has
    not been verified for 4h (the directory or every broker unreachable that long) is denied
    `context_stale` at its next command, and resumes at the next pass after they return.
  - **The opt-out.** `staleness_ceiling: 0s` turns it off, said at every start.
  - **Upgrade order.** Upgrade every broker before port49d. A new port49d (4h default) beside
    an old broker that never stamps `refreshed_at` denies every session 4h after its login.
    If the order cannot be kept, set `staleness_ceiling: 0s` on port49d until the brokers are
    new, then remove it.
  - **At 3am, at the ceiling.** Live sessions are denied `context_stale` by a reachable
    port49d, so break-glass does not help on them. The escapes: set
    `session.staleness_ceiling: 0s` and restart port49d, or stop port49d so devices fall back
    to break-glass (L4). Alert at half the ceiling, `time() -
    port49_directory_refresh_last_complete_timestamp_seconds > ceiling / 2`, to get two hours'
    warning at the default.
  - **A grace mint near the ceiling** opens a session whose `refreshed_at` is the membership's
    verification, so it can go `context_stale` minutes after it opens. That is the ceiling
    counting from the last time the directory vouched for the person, as designed.
- **Upgrading: principals change with a directory.** With `broker.directory` set:
  - a human principal is `user:` + the entry's `principal_attribute`, no longer the email
    SAN;
  - a `user:` identity subject declares no `username:` (the broker refuses one at load).
  - Revocation marks by principal made before the change still apply: the broker checks a
    certificate against the principal its email SAN gave as well as the mapped one, so turning
    a directory on never lifts a revocation. Marks made from now on name the mapped principal.
- **Directory hygiene, required.** `principal_attribute` and `username_attribute` must be
  writable only by directory administrators (on OpenLDAP, remove `by self write` on `mail`).
  port49 refuses both people when two entries hold one value (`identity_ambiguous`,
  `username_collision`), so a self-edit can lock a colleague out until it is fixed, but can
  never make one person another. A principal is pinned to the entry it was verified on, by
  `objectGUID` or `entryUUID`: another entry later given the same value is refused
  `identity_unmapped` for as long as the principal's record lives (`max(grace, 24h)` after its
  last verification). An OU move keeps the pin; on a directory that returns neither id, the
  pin is the DN and a moved user is refused until the record lapses. A person whose entry is
  deleted and re-created is refused the same way.
- **New: `port49 directory forget <principal>`, the pin's way out.** A rehire, or an entry
  restored without its tombstone, has a new `objectGUID`/`entryUUID`. It is refused
  `identity_unmapped`, and each refusal renews the record. The broker's line names the
  command. Once you have confirmed the new entry is the same person, run it on the broker's
  admin socket (`--socket <its admin_socket>`; the broker's uid or root). It deletes the
  principal's membership, pin included, and writes a `directory_forget` record naming your
  uid and the old entry id. The next bind pins the new entry. It grants nothing and needs no
  directory; if a bind is still refused naming the old entry, run it again.
- **New: `broker.directory`.**
  - **Servers:** `servers` (`uri`, `priority`, `site`, `start_tls`), `site` or `site_env`
    (default `PORT49_SITE`), `ca_file`.
  - **`bind`:** `external` with `tls_cert_file`/`tls_key_file`; `gssapi` with
    `keytab_file`/`principal`/`krb5_conf`; or `simple` with `bind_dn`/`password_env`.
  - **Where to search:** `base_dn`, `groups_base_dn`, `user_filter`, `group_filter`.
  - **Attributes:** `principal_attribute`, `username_attribute`, `group_name_attribute`,
    `member_attribute`.
  - **`certificate_mapping`:** `kind`, `attribute`, `allow_weak`, `issuers`.
  - **Nesting:** `nested_groups` (required: `in_chain`, `recursive` or `direct`), and
    `max_depth`.
  - **Timing:** `query_timeout`, `health_check`, `circuit_breaker`, `failback`.
  - **Outages:** `grace`, `prewarm`.
- **New: `broker.refresh_interval`** (5m).
- **New reason codes:** `identity_unmapped`, `identity_ambiguous` (alert on it),
  `directory_unavailable`, `composition_refused`. New record fields: `policy.subjects`,
  `auth.directory`.
- **New metrics:** Ruling 19. Alert on:
  - `port49_directory_lookups_total{outcome="ambiguous"}` increasing;
  - `time() - port49_directory_refresh_last_complete_timestamp_seconds > 3 × refresh_interval`;
  - `port49_directory_server_up == 0` for a while;
  - `port49_directory_group_names_ambiguous > 0`.
- **The diff:** a changed `group:` now fails `port49 policy diff` until a session test names
  the subject.
- **Group subjects mint** for their members (nested per `nested_groups`). A member of several
  subjects holds the union of their grants, the least `token_ttl` and the most demanding
  `enable`. A combination a joint check refuses is `composition_refused` on that device.
- **`/v1/identity`** answers the subjects, groups, username, and the membership's
  `verified_at` and source.
- **A directory outage.**
  - **Logins.** New logins and mints continue from the membership verified within
    `directory.grace` (4h), held in the store, so a broker restart keeps them. A person the
    directory refused before the outage (deleted, ambiguous, a username taken) stays refused
    through it.
  - **Live sessions** continue until the ceiling.
  - **Revocation.** `port49 revoke` works throughout and needs no directory; revoking your
    own sessions never asks it.
  - **A rotated bind password or an expired bind certificate** is treated as the directory
    not answering: queries fail over, grace serves, and the broker says the refusal hourly per
    server with the result code. Fix the credential; it is not a down server.
  - **Every breaker open.** Queries are refused at once until the next probe, up to
    `circuit_breaker.probe_interval` plus `health_check.interval` (90s at the defaults) after
    the DCs return. Grace serves meanwhile.
  - **Readiness** never follows the directory: a broker with every DC down stays ready.
- **Lab:** L42 and L43 measured on OpenLDAP and Samba AD. L44, Windows Server AD (`in_chain`,
  EXTERNAL, GSSAPI, `altSecurityIdentities`, strong-mapping enforcement), is open until
  measured: the AD-only mechanisms are measured on Samba alone.

## Self-review against the spec

- **Design §7, the mapping:** configurable kinds, Rulings 1–2, Task 8; ambiguity fails
  closed, Task 8 and L43's eve; weak needs opt-in and a pin, Task 4's refusal and Task 8's
  check. ✓
- **Design §10.**
  - Group membership only, from the directory, never a credential: Ruling 10 and "What this
    plan does not do". ✓
  - Three binds, TLS-only, read-only: Task 7, L43. ✓
  - Nested by configuration: Task 9, L42. ✓
  - Pre-warm's population: Ruling 20, Task 10. ✓
  - The pool: priority, health, breaker, sticky, failback, sites, consistency events,
    locality from the environment (Task 6). ✓
  - Replication lag, no quorum: "What this plan does not do". ✓
- **Design §12, "Directory unavailable".** Credential-only new sessions become "within grace"
  (Task 1 edits the cell); new device login within grace (Task 13); active login to the
  ceiling (Task 15). ✓
- **Spec §2.**
  - Group subjects: Tasks 11, 13.
  - The human x509 principal from the mapping: Task 12.
  - The directory's username: Task 8.
  - Usernames unique across subjects, the later claimant refused: Ruling 3, Tasks 8, 10.
  - `remote`/`p49-*` from a directory refused: Task 8.
  - Rights through a group: Task 13. ✓
- **Spec §5.1.3.** The scheduled refresh through `active_principals` (Task 15); a policy
  pass never stamps (Task 14). ✓
- **Spec §5.7.** Four reasons added to the table first (Task 1), then the constants (Task 2).
  ✓
- **Spec §12.** The group gate: Task 11. ✓
- **The carries table:** each row's task exists. ✓
- **Placeholder scan.** No "TBD", "TODO" or "similar to Task N". Each code step shows its
  code. Where a step names an existing helper by role ("the file's test loader"), it says
  which file to read for its name. Those helpers' names were not verified here and exist in
  the files named.
- **Types.** These names match across tasks:
  - `directory.Answer`, `Source`, `Resolver.Map/Verify/Current/Stored`, `IsUser`,
    `ErrNotUser`, `Client`, `ForTestsStaticResolver`;
  - `store.Membership` (with `Refused`), `MapKey`, `RefuseMapKeys`, `MembershipPrincipals`,
    `DeleteMembership`,
    `StampRefreshed`, `ContextPolicy.RefreshedAt`, `Token.VerifiedAt`;
  - `policy.Member`, `ResolveMember`, `HasRightOf`, `SubjectsOf`, `ErrCompositionRefused`;
  - `broker.BindMap`, `memberFor`, `storedMember`, `passJudge`, `RefreshDirectory`, `Forget`;
  - `decision.EventDirectoryForget`, `decision.Forget`, `admin.Server.Forget`, `adminForget`,
    `directoryCmd`.

  `Listener.Map`'s signature in Task 12 returns `(directory.Answer, *BindRefusal)`, as
  `BindMap` does. ✓
- **Review Focus:** each of the seven has its test named in its owning task (Tasks 3, 6, 8,
  9, 10, 13, 16). ✓
- **Pre-flight (2026-10-05, READY WITH FIXES, 2C/17I/17M):** every finding is applied in the
  task it names; the per-finding table is
  `.superpowers/sdd/2026-10-05-07g-the-directory/planfix-report.md`.
  - **C-1:** a refusal is stored (`Membership.Refused`, `RefuseMapKeys`) and grace never
    serves it (Rulings 10, 12; Tasks 5, 10, 14). ✓
  - **C-2:** a principal must be one entry's alone (`principalUnique`), and is pinned to its
    entry's immutable id at every verification, a bind included; a refusal keeps the pin
    (Ruling 3; Tasks 5, 8, 10, 16, 17). ✓
  - **The pin's escape (controller, after pre-flight):** an entry deleted and re-created is
    refused until `port49 directory forget <principal>`, on the broker's admin socket, deletes
    the record and writes `directory_forget` naming the uid and the old entry id. The refusal
    line names the command (Ruling 3; Tasks 1, 5, 10, 13; `TestARecreatedEntryIsRefusedUntilForgotten`,
    `TestForgetRemovesThePinAndIsRecorded`, `TestDirectoryForgetReachesTheBroker`,
    `TestDirectoryForgetAsksTheAdminSocket`, `MembershipForgetRemovesThePin`). ✓
  - **I-17 / OR-3:** L44 opens for Windows Server AD and stays open; L42 and L43 close on the
    platforms they name (Tasks 1, 17). ✓
