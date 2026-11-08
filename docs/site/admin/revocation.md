---
title: Revoking access
description: Revoking a person, a certificate or a session, closing what revocation cannot reach, and setting up the CRL and OCSP checks that mark certificates for you.
---

# Revoking access

[Revocation](../concepts/revocation.md) explains what happens, in order, and what it cannot do. This page is
the runbook: the commands, what each one needs, how to read the answer, and the broker settings that check
your CA's revocation lists.

## What you need

`port49 revoke` talks to the broker through your own agent, so run `port49 login` first. It needs your subject
to declare the right in the policy's [`api:` list](roles-and-grants.md#api-rights):

- `revoke_others` to revoke another principal, a certificate, a `(device, username)` key or an OIDC session,
  and to list what is in force;
- `lift_revocations` to lift a revocation, and to list.

Every write but `--mine` also asks for a press of your security key, bound to that one request. Without the
right the call is refused before any key press, and the refusal is logged. Your own sessions, with
`port49 revoke --mine`, need neither a right nor a touch.

## Revoking

| You want to stop | Run | Leaves a standing mark |
|---|---|---|
| a person or workload, everywhere | `port49 revoke --principal user:alice@example.com` | yes |
| one certificate | `port49 revoke --cert alice.pem` | yes |
| whoever holds one device login | `port49 revoke --device leaf1 --username alice` | no |
| one OIDC session | `port49 revoke --sid <sid> --sid-issuer <issuer>` | no |
| your own sessions | `port49 revoke --mine` | no |

On a terminal, `--principal` asks `revoke <principal> everywhere? ... [y/N]` first. `--yes` skips the question, and
a script with no terminal is not asked. The answer begins with a `target:` line naming the policy subject the
principal belongs to. If it says `no subject in the policy in force names it`, check the spelling: the mark is
written anyway, so a typo of a real colleague's address is a revocation of nobody. The broker spells a certificate's
principal `user:<lower-case email>`, a workload's is its SPIFFE ID verbatim, and a service account's is
`system:serviceaccount:<namespace>:<name>`.

`port49 revoke --list` shows what is in force, each with its origin (`api <who>` for an operator,
`crl <name>` or `ocsp <responder>` for a CA's revocation). A `--mine`, `--device` or `--sid` revocation leaves no
mark, so it is not listed; the decision log's `revoke` record names each, with `revocation.by` of `self`, `key`
or a logout.

A revocation does **not expire**. The agent reconnects with the same key on its own, so only a lift undoes it.

### `--cert` over `--cert-serial`

Name a certificate by file:

```sh
port49 revoke --cert alice.pem
```

`port49 revoke` reads the issuer and serial out of the file, and prints them before anything is sent, so you see
whose certificate it is:

```text
port49 revoke: alice.pem: subject "CN=alice,O=Example", issuer "CN=Example Issuing CA,O=Example", serial 0x2a
```

The file must hold one certificate, PEM or DER. One that holds a private key, more than one certificate (a chain
would revoke the CA's serial and say it did) or more than 1 MiB is refused. The command never prints a key or a
block.

The by-hand form is `--cert-issuer DN --cert-serial HEX`, both required, and it is the one to avoid. The broker
compares the issuer as Go prints it (RFC 2253, `CN=Example Issuing CA,O=Example`), so a differently spelled issuer
matches nothing, and the report says so (`nothing was found under this certificate; ... use --cert FILE`). The
serial is **hexadecimal**: colons, a `0x` and leading zeros are dropped and a leading `-` is kept. A serial of
digits alone is read as hex, though `openssl` prints a small serial in decimal first (`4096 (0x1000)`). The
report warns when that may have happened: revoke again with `--cert FILE`, then lift the wrong one. `--cert`
sends the serial as explicit hex and cannot make that mistake. Use `--cert-serial` only when you have no file,
for instance a serial copied from your CA's issuance log.

A certificate revocation closes that certificate's held connections, deletes unspent tokens and marks its live
contexts. It leaves the principal's **other** certificates working, except that unspent tokens are deleted by
`(device, username)`, so they lose theirs on those devices and can mint again. A workload renews its certificate
under a new serial the mark does not name, so for a workload revoke the principal too, and revoke the
certificate at your CA so it cannot renew.

### A stolen laptop

Revoke in this order:

1. `port49 revoke --principal user:alice@example.com` now. It stops every mint, closes the person's held
   connections and refuses the agent's next request.
2. **Close the device sessions.** TACACS+ cannot disconnect a device's session, so a revocation takes effect at the
   *next authorization request*. A platform that asks port49 only at login never asks again, so the revocation
   reaches a context nobody reads. The report names those sessions:

    ```text
    not reached, on a platform that never asks port49 about a command (close these on the device): leaf1 (alice), srx2 (alice)
    ```

    Close each on the device with the device's own tools, and see
    [Junos](devices/juniper-junos.md) for what it does on its own.
3. When your CA has issued the person a new certificate, revoke the **old** one by `--cert` (or revoke it at the
   CA, below) and lift the principal.

Close a stranger's session too. `--mine` and `--device`/`--username` leave no mark, so the owner's next login on
that device re-admits every session still open there under that username. The report says so.

### Exit codes

| Exit | Meaning |
|---|---|
| 0 | done; `--list` printed |
| 1 | nothing was revoked, or it is unknown. Refused or unreachable: no agent, the right missing, the touch refused or not given, a declined confirmation (`nothing was revoked`), an unreadable or refused `--cert` file, or a broker refusal that says nothing was done. **Unknown whether it ran:** the broker did not answer (`the broker did not answer ...`), it answered with no revocation named (`the broker's answer named no revocation; it may be in force`), it answered `503 revocation_unconfirmed` (`the broker could not confirm it: ...`), or a revoke got `503 store_unavailable` (`the broker says: ...`). The first two say to run `port49 revoke --list` and look at the decision log before you retry; for the last two, read the broker's words |
| 2 | the flags are wrong: no target, two targets, or a flag that does not go with the form |
| 3 | the revocation **is in force** but incomplete, or not saved to the revocations file, or a lift step did not finish: run the same command again, which repeats every step |

Exit 1 is two different things, so read the line. A refusal that says nothing was done means nothing happened;
`it may be in force` means it may have. Two broker answers look like refusals and are not:

- `the broker could not confirm it` (`503 revocation_unconfirmed`): the revocation may have gone through, and so
  may a lift made meanwhile. Run `port49 revoke --list` to see what is in force, then repeat the command if the
  mark is not what you wanted.
- `the broker says: ...` on a revoke that got `503 store_unavailable`: the mark went nowhere but that one broker's
  own process, so the credential is revoked on that broker and not, yet, on the others. Do what the broker's words
  say to make the mark everywhere, and run the revoke again once the store is back.

Exit 3 is never a failure to revoke: the mark stands and refuses every new mint, but
until a run finishes, unspent tokens may still log in (up to their TTL) and unmarked contexts keep authorizing.
`port49 revoke --lift` takes the same codes; an answer with no text exits 1 with `it may have run`.

## Lifting

```sh
port49 revoke --lift --principal user:alice@example.com
port49 revoke --lift --cert alice.pem
```

A lift needs `lift_revocations` and a touch. It restores nothing: contexts the revocation marked stay revoked until
a login with a token minted after the lift joins them. `--lift --principal` on a principal that is not revoked
answers `no such revocation is in force`.

**Lifting a mark a CA made.** A mark whose origin is `crl <name>` or `ocsp <responder>` was written because the
CA revoked the certificate. The person is told the certificate was revoked at its CA and to request a new
one; no lift is offered. You can still run `--lift --cert`, but it is no fix: the next connection checks the CA
again and is refused, or, with the list gone stale, answered `certificate_status_unavailable`, or admitted under
`on_unavailable: allow`. Lift such a mark only after the CA has unrevoked the certificate, and expect it to be
marked again if the CA's list still names it. A `certificateHold` entry is never marked.

## Where marks are kept

A standing mark is in the session store and is read by every broker. How it survives a restart depends on the
shape:

- **A broker on etcd** (the normal split) keeps each mark in the store, and each broker keeps a copy in
  `broker.state_dir`, which is what puts a mark back after a store restore. Back that directory up and follow
  [Backup and restore](../operate/backup-and-restore.md); it also covers `port49-broker revoke --offline` for
  revoking with every broker down.
- **A single-process port49d on the memory store** also writes every mark to `broker.revocations_file`. port49d
  never creates that file, so run `port49d init-revocations` once at install, as port49d's user
  (see [Install](../operate/install/index.md#the-memory-store-trial-port49d-init-revocations)); a missing file refuses
  every start.

When a revocation was made but the file could not be written, the report says `NOT saved to
broker.revocations_file`, `port49 revoke` exits 3, and `port49_revocations_file_failed` is 1. Run the revoke again
once the disk is fixed, and see [Revocations file failed](../operate/troubleshooting/index.md#revocations-file-failed).

## Checking your CA's revocation lists

A revocation made at your CA reaches port49 only if the broker is told where to look. `certificate_status` is
**required** wherever a client certificate verifier is configured, in the broker block and in the `tls_listener`
block for devices on RFC 9887 TLS; leaving it out refuses the config, so skipping the check is always a choice you
wrote down. The device side is on [TLS](../operate/tls.md#revocation). The broker side, which covers the
certificates people and workloads sign in with, looks like this:

```yaml
broker:
  certificate_status:
    crls:
      - name: corp_ca
        url: http://crl.example.com/corp-ca.crl
        issuer_file: /etc/port49/corp-ca.pem
    # ocsp: {use_aia: true}
    refresh_interval: 10m
    on_unavailable: refuse
```

To check nothing, write it out:

```yaml
broker:
  certificate_status:
    disabled: true
```

`disabled: true` takes no other key, and port49d says so at every start: `certificate status checking is disabled
(broker.certificate_status.disabled): a certificate revoked at its CA keeps minting until `port49 revoke --cert``.
With it, only `port49 revoke` ends a certificate.

Otherwise name at least one `crls` entry or an `ocsp` block. A CRL is a `file` or an `http(s)` `url` (exactly one), a
unique `name` (lowercase letters, digits and `_`), and an `issuer_file`. The lists are fetched or re-read every
`refresh_interval` (10 minutes by default, 1 minute to 24 hours). An OCSP block takes a fixed `responder` or
`use_aia: true`, and `hash: sha1` for a responder that knows no SHA-256 CertID. All keys are in the
[port49d reference](../reference/config/port49d.md).

### `issuer_file` rules

`issuer_file` is **required** on every CRL, and it is the CA certificate that signs that list. A list is trusted
for the issuer it names, so port49d checks the file at start and refuses to start, naming the source, unless:

- it holds exactly **one** PEM block, a certificate, and nothing else;
- it is a **CA** certificate, since only a CA signs a list;
- it is the trust anchor (`client_ca_file`, or the x509 trust anchor of a workload verifier) or a certificate that
  anchor signed, since a list for an issuer the broker does not already trust would vouch for certificates
  it never trusted.

A list is then used only if it verifies against that certificate: signed by it, with an issuer name encoded exactly
as the certificate's subject is, an authority key identifier that matches, not dated in the future and not signed
with a weak algorithm. A delta CRL, a list with a critical extension port49 does not understand, or one scoped in a
way its certificates do not name is refused, and counted at `port49_crl_loads_total{outcome="refused"}`; the log
says why.

**An intermediate CA needs the root's list too.** Name the root's CRL (`issuer_file` is your `client_ca_file`
anchor), or every certificate under the intermediate is refused: port49d checks each CA in the chain, and nothing
else says whether the intermediate itself was revoked. An OCSP responder the root signs for covers it as well. At
start port49d says which CA nothing covers, as `certificates issued by <CA> will be refused ...: nothing covers
<CA> itself; name the root CA's CRL`, and never refuses to start over it. That is the `on_unavailable: refuse`
line; under `allow` it reads `certificates issued by <CA> will be admitted with their revocation status unchecked
(on_unavailable: allow): nothing covers <CA> itself; name the root CA's CRL`, and those certificates are let in.

Each verified list is kept as `crl-<name>.der` in `broker.state_dir` (beside `broker.revocations_file` for a
single-process port49d), so a restart during a publisher outage keeps serving it until its next update. Back these
up with the rest of the state.

### `on_unavailable: refuse`

When a certificate's status cannot be established, because a CRL is past its next update or an OCSP responder is
down, `on_unavailable` decides:

- `refuse` (the default): the broker answers `503 certificate_status_unavailable` with `Retry-After: 60`, the
  reason `trust_domain_unresolved`. The agent is told to try again, and nothing is minted for that certificate
  until the status is known.
- `allow`: the connection is admitted and the broker says so (`admitting a certificate whose revocation status
  cannot be established`). It keeps logins working through an outage, and lets a certificate revoked during the
  outage in until the list returns. It is the reviewed escape, not a setting to leave on.

An uncovered status, with no CRL or OCSP source for that issuer, follows the same setting. Under `refuse` it is
refused too, and it holds until a source covers it, so retrying does not help; add the CRL. **Under `allow`, a
certificate from an issuer nothing covers is admitted with its revocation status unchecked**, like any other
unavailable status: that is a fail-open case, and the start line quoted under the `issuer_file` rules is the warning.

What the broker refuses and what it marks:

- A certificate a CRL or OCSP lists as revoked, or one under a revoked issuing CA, is refused with
  `credential_revoked` at login and at every mint.
- If the certificate holds anything (a connection, a device session, an unspent token), port49d also marks it as
  `port49 revoke --cert` would, with origin `crl <name>` or `ocsp <responder>`, so its live contexts are
  revoked and its tokens deleted. A revoked issuing CA is refused and not marked.
- Freshness follows the broker's clock, so an NTP step forward can make a fresh list stale. Keep time
  synchronized on every broker host.

Watch `port49_crl_next_update_timestamp_seconds` (an hour before a list passes its next update, at
`time() - port49_crl_next_update_timestamp_seconds > -3600`), `port49_cert_status_unavailable_total` and
`port49_crl_loads_total`; they carry a `component` label of `broker` or `tls_listener`. They are in the
[metrics reference](../reference/metrics.md), and the TLS alerts on the
[alerts reference](../reference/alerts.md#port49_crl_next_update_passed).
