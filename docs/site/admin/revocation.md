---
title: Revoking access
description: Revoke a person, a certificate or a session, close what revocation cannot reach, and lift a revocation.
---

# Revoking access

[Revocation](../concepts/revocation.md) explains what happens, in order, and what it cannot do. This page is the
runbook: the commands, what each one needs and how to read the answer. Checking your CA's revocation lists is on
[Client certificate sign-in](sign-in/x509.md).

## What you need

`port49 revoke` talks to the broker through your own agent, so run `port49 login` first. It needs your subject to
declare the right in the policy's [`api:` list](roles-and-grants.md#api-rights): `revoke_others` to revoke another
principal, a certificate, a `(device, username)` key or an OIDC session, and `lift_revocations` to lift one. Either lets
you list what is in force. [Admin access](admin-access.md) sets up the rights and the attestation roots.

Every write but `--mine` also asks for a press of your security key, bound to that one request. Without the right the
call is refused before any key press, and the refusal is logged. Your own sessions, with `port49 revoke --mine`, need
neither a right nor a touch.

## Revoking

| You want to stop | Run | Leaves a standing mark |
|---|---|---|
| a person or workload, everywhere | `port49 revoke --principal user:alice@example.com` | yes |
| one certificate | `port49 revoke --cert alice.pem` | yes |
| whoever holds one device login | `port49 revoke --device leaf1 --username alice` | no |
| one OIDC session | `port49 revoke --sid <sid> --sid-issuer <issuer>` | no |
| your own sessions | `port49 revoke --mine` | no |

On a terminal, `--principal` asks `revoke <principal> everywhere? ... [y/N]` first. `--yes` skips the question, and
a script with no terminal is not asked.

The answer begins with a `target:` line naming the policy subject the principal belongs to. If it says
`no subject in the policy in force names it`, check the spelling. The mark is written anyway, so a typo of a real
colleague's address is a revocation of nobody. The broker spells principals this way:

- a certificate's principal: `user:<lower-case email>`;
- a workload's: its SPIFFE ID, verbatim;
- a service account's: `system:serviceaccount:<namespace>:<name>`.

`port49 revoke --list` shows what is in force, each with its origin (`api <who>` for an operator, `crl <name>` or
`ocsp <responder>` for a CA's revocation). A `--mine`, `--device` or `--sid` revocation leaves no mark, so it is not
listed. The decision log's `revoke` record names each, with `revocation.by` of `self`, `key` or a logout.

A revocation does not expire. The agent reconnects with the same key on its own, so only a lift undoes it.

### `--cert` over `--cert-serial`

Name a certificate by file:

```sh
port49 revoke --cert alice.pem
```

`port49 revoke` reads the issuer and serial out of the file and prints them before anything is sent, so you see whose
certificate it is:

```text
port49 revoke: alice.pem: subject "CN=alice,O=Example", issuer "CN=Example Issuing CA,O=Example", serial 0x2a
```

The file must hold one certificate, PEM or DER. One that holds a private key, more than one certificate (a chain
would revoke the CA's serial and say it did) or more than 1 MiB is refused. The command never prints a key or a block.

The by-hand form is `--cert-issuer DN --cert-serial HEX`, both required. Use `--cert-serial` only when you have no
file, for instance a serial copied from your CA's issuance log. Two things go wrong with it:

- The issuer must be spelled as Go prints it (RFC 2253, `CN=Example Issuing CA,O=Example`). A differently spelled
  issuer matches nothing, and the report says so (`nothing was found under this certificate; ... use --cert FILE`).
- The serial is hexadecimal. Colons, a `0x` and leading zeros are dropped and a leading `-` is kept. A serial of digits
  alone is read as hex, though `openssl` prints a small serial in decimal first (`4096 (0x1000)`). The report warns
  when that may have happened: revoke again with `--cert FILE`, then lift the wrong one.

`--cert` sends the serial as explicit hex and cannot make that mistake.

A certificate revocation closes that certificate's held connections, deletes unspent tokens and marks its live
contexts. It leaves the principal's other certificates working, with one exception: unspent tokens are deleted by
`(device, username)`, so the other certificates lose theirs on those devices and can mint again.

A workload renews its certificate under a new serial the mark does not name. For a workload, revoke the principal too,
and revoke the certificate at your CA so it cannot renew.

### A stolen laptop

Revoke in this order:

1. `port49 revoke --principal user:alice@example.com` now. It stops every mint, closes the person's held connections
   and refuses the agent's next request.
2. Close the device sessions. TACACS+ cannot disconnect a device's session, so a revocation takes effect at the
   next authorization request. A platform that asks port49 only at login never asks again, so the revocation reaches a
   context nobody reads. The report names those sessions:

    ```text
    not reached, on a platform that never asks port49 about a command (close these on the device): leaf1 (alice), srx2 (alice)
    ```

    Close each on the device with the device's own tools. [Junos](devices/juniper-junos.md) says what it does on its own.
3. When your CA has issued the person a new certificate, revoke the old one by `--cert` (or revoke it at the CA, see
   [Client certificate sign-in](sign-in/x509.md)) and lift the principal.

Close a stranger's session too. `--mine` and `--device`/`--username` leave no mark, so the owner's next login on that
device re-admits every session still open there under that username. The report says so.

### Exit codes

| Exit | Meaning |
|---|---|
| 0 | done; `--list` printed |
| 1 | nothing was revoked, or it is unknown. Refused or unreachable: no agent, the right missing, the touch refused or not given, a declined confirmation (`nothing was revoked`), an unreadable or refused `--cert` file, or a broker refusal that says nothing was done. **Unknown whether it ran:** the broker did not answer (`the broker did not answer ...`), it answered with no revocation named (`the broker's answer named no revocation; it may be in force`), it answered `503 revocation_unconfirmed` (`the broker could not confirm it: ...`), or a revoke got `503 store_unavailable` (`the broker says: ...`). The first two say to run `port49 revoke --list` and look at the decision log before you retry; for the last two, read the broker's words |
| 2 | the flags are wrong: no target, two targets, or a flag that does not go with the form |
| 3 | the revocation **is in force** but incomplete, or not saved to the revocations file, or a lift step did not finish: run the same command again, which repeats every step |

Exit 1 is two different things, so read the line. A refusal that says nothing was done means nothing happened; `it may
be in force` means it may have. Two broker answers look like refusals and are not:

- `the broker could not confirm it` (`503 revocation_unconfirmed`): the revocation may have gone through, and so may a
  lift made meanwhile. Run `port49 revoke --list` to see what is in force, then repeat the command if the mark is not
  what you wanted.
- `the broker says: ...` on a revoke that got `503 store_unavailable`: the mark went nowhere but that one broker's own
  process, so the credential is revoked on that broker and not, yet, on the others. Do what the broker's words say to
  make the mark everywhere, and run the revoke again once the store is back.

Exit 3 is never a failure to revoke: the mark stands and refuses every new mint, but until a run finishes, unspent
tokens may still log in (up to their TTL) and unmarked contexts keep authorizing. `port49 revoke --lift` takes the same
codes. An answer with no text exits 1 with `it may have run`.

## Lifting

```sh
port49 revoke --lift --principal user:alice@example.com
port49 revoke --lift --cert alice.pem
```

A lift needs `lift_revocations` and a touch. It restores nothing: contexts the revocation marked stay revoked until a
login with a token minted after the lift joins them. `--lift --principal` on a principal that is not revoked answers
`no such revocation is in force`.

A mark whose origin is `crl <name>` or `ocsp <responder>` was written because the CA revoked the certificate. The
person is told the certificate was revoked at its CA and to request a new one, and no lift is offered. You can still run
`--lift --cert`, but it is no fix: the next connection checks the CA again and is refused, or, with the list gone
stale, answered `certificate_status_unavailable`, or admitted under `on_unavailable: allow`. Lift such a mark only
after the CA has unrevoked the certificate, and expect it to be marked again if the CA's list still names it. A
`certificateHold` entry is never marked.

## Where marks are kept

A standing mark is in the session store and is read by every broker. How it survives a restart depends on the
deployment:

- A broker on etcd (the normal split) keeps each mark in the store, and each broker keeps a copy in
  `broker.state_dir`, which is what puts a mark back after a store restore. Back that directory up and follow
  [Backup and restore](../operate/backup-and-restore.md). It also covers `port49-broker revoke --offline` for revoking
  with every broker down.
- A single-process port49d on the memory store also writes every mark to `broker.revocations_file`. port49d never
  creates that file, so run `port49d init-revocations` once at install, as port49d's user (see
  [Install](../operate/install/index.md#the-memory-store-trial-port49d-init-revocations)). A missing file refuses
  every start.

When a revocation was made but the file could not be written, the report says `NOT saved to
broker.revocations_file`, `port49 revoke` exits 3, and `port49_revocations_file_failed` is 1. Run the revoke again once
the disk is fixed, and see [Revocations file failed](../operate/troubleshooting/index.md#revocations-file-failed).
