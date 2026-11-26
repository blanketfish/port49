---
title: Revoking access
description: Revoke a person, a certificate or a session, close what revocation cannot reach, lift a revocation, and revoke with every broker down.
---

# Revoking access

[Revocation](../concepts/revocation.md) explains what happens and what it cannot do. Below are the commands and how to
read the answer. Checking your CA's revocation lists is on [Client certificate sign-in](sign-in/x509.md).

## What you need

`port49 revoke` talks to the broker through your own agent, so run `port49 login` first. Your subject must declare the
right in the policy's [`api:` list](roles-and-grants.md#api-rights): `revoke_others` to revoke another principal, a
certificate, a `(device, username)` key or an OIDC session, and `lift_revocations` to lift one. Either lets you list
what is in force. [Admin access](admin-access.md) sets up the rights and the attestation roots.

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

On a terminal, `--principal` asks `revoke <principal> everywhere? ... [y/N]` first; `--yes` skips it, and a script with
no terminal is not asked. The answer begins with a `target:` line naming the policy subject the principal belongs to.
If it says `no subject in the policy in force names it`, check the spelling: the mark is written anyway, so a typo of
a colleague's address revokes nobody. The broker spells principals this way:

- a certificate's principal: `user:<lower-case email>`;
- a workload's: its SPIFFE ID, verbatim;
- a service account's: `system:serviceaccount:<namespace>:<name>`.

`port49 revoke --list` shows what is in force, with each origin (`api <who>` for an operator, `crl <name>` or
`ocsp <responder>` for a CA's revocation). A `--mine`, `--device` or `--sid` revocation leaves no mark, so it is not
listed; the decision log's `revoke` record names each, with `revocation.by` of `self`, `key` or a logout. A revocation does not expire, and the agent reconnects with the same key on its own, so only a lift undoes it.
Exit codes, and how to read exit 1 and 3: [Client commands](../reference/client-commands.md#port49-revoke).

### Name a certificate by file

```sh
port49 revoke --cert alice.pem
```

It reads the issuer and serial out of the file and prints them before anything is sent:

```text
port49 revoke: alice.pem: subject "CN=alice,O=Example", issuer "CN=Example Issuing CA,O=Example", serial 0x2a
```

The file must hold one certificate, PEM or DER. A file with a private key, more than one certificate (a chain would
revoke the CA's serial and say it did) or more than 1 MiB is refused. The by-hand form is `--cert-issuer DN
--cert-serial HEX`, both required, for when you have no file. The issuer must be spelled as Go prints it (RFC 2253); a
different spelling matches nothing, and the report says so. The serial is hexadecimal: colons, a `0x` and leading zeros
are dropped, and digits alone are read as hex, though `openssl` prints a small serial in decimal first
(`4096 (0x1000)`). The report warns when that may have happened: revoke again with `--cert FILE`, which sends the serial as explicit hex, then lift the
wrong one.

A certificate revocation closes that certificate's held connections, deletes unspent tokens and marks its live
contexts. The principal's other certificates keep working, except that unspent tokens are deleted by `(device,
username)`, so they lose theirs on those devices and can mint again. A workload renews under a new serial the mark does
not name, so revoke the workload's principal too, and the certificate at your CA so it cannot renew.

### A stolen laptop

1. `port49 revoke --principal user:alice@example.com` now. It stops every mint, closes the person's held connections
   and refuses the agent's next request.
2. Close the device sessions. TACACS+ cannot disconnect a device's session, so a revocation takes effect at the next
   authorization request. A platform that asks port49 only at login never asks again. The report names those sessions:

    ```text
    not reached, on a platform that never asks port49 about a command (close these on the device): leaf1 (alice), srx2 (alice)
    ```

    Close each with the device's own tools. [Junos](devices/juniper-junos.md) says what it does on its own.
3. When your CA has issued the person a new certificate, revoke the old one by `--cert` (or at the CA) and lift the
   principal.

Close a stranger's session too: `--mine` and `--device`/`--username` leave no mark, so the owner's next login on that
device re-admits every session still open there under that username.

## Lifting

```sh
port49 revoke --lift --principal user:alice@example.com
port49 revoke --lift --cert alice.pem
```

A lift needs `lift_revocations` and a touch. It restores nothing: contexts the revocation marked stay revoked until a
login with a token minted after the lift joins them. On a principal that is not revoked it answers
`no such revocation is in force`.

A mark whose origin is `crl <name>` or `ocsp <responder>` was written because the CA revoked the certificate. The
person is told to request a new one, and no lift is offered. `--lift --cert` is no fix: the next connection checks the
CA again and is refused, or, with the list stale, answered `certificate_status_unavailable`, or admitted under
`on_unavailable: allow`. Lift such a mark only after the CA has unrevoked the certificate. A `certificateHold` entry is
never marked.

## Where marks are kept

A standing mark is in the session store and is read by every broker.

- A broker on etcd (the normal split) keeps each mark in the store and a copy in `broker.state_dir`, which puts a mark
  back after a store restore. Back that directory up ([Backup and restore](../operate/backup-and-restore.md)).
- A single-process port49d on the memory store also writes every mark to `broker.revocations_file`. port49d never
  creates it, so run `port49d init-revocations` once at install, as port49d's user (see
  [Install](../operate/install/index.md#the-memory-store-trial-port49d-init-revocations)); it refuses when the file
  exists, and a missing file refuses every start.

When the file could not be written, the report says `NOT saved to broker.revocations_file`, `port49 revoke` exits 3 and
`port49_revocations_file_failed` is 1. Revoke again once the disk is fixed
([Revocations file failed](../operate/troubleshooting/index.md#revocations-file-failed)).

## Break-glass

!!! warning
    Offline revocation stops issuance fleet-wide while the brokers are down. Use it only when no admin can reach a
    running broker.

Run it with the broker stopped, as the broker's own user. As root it refuses, revokes nothing and names the `sudo -u`
line to use, because the files it writes belong to that user.

=== "systemd"

    ```sh
    systemctl stop port49-broker              # on every broker host
    sudo -u port49-broker port49-broker revoke --offline --principal user:bob@example.com
    systemctl start port49-broker
    ```

    `port49-broker revoke --offline --list` shows the marks. It writes `broker.state_dir`. A port49d that runs its
    broker in process has `port49d revoke --offline`, which writes `broker.revocations_file`.

=== "Containers"

    ```sh
    docker compose stop port49-broker
    docker compose run --rm --no-deps port49-broker revoke --offline --principal user:bob@example.com
    docker compose run --rm --no-deps port49-broker revoke --offline --list
    docker compose start port49-broker
    ```

    `--lift` instead of the principal's revoke lifts it. `port49 store status --metrics 127.0.0.1:9050` reads the
    broker's stores on the metrics port.

=== "Helm"

    Admin commands (`port49 revoke`, `port49 directory ...`) are calls to the broker API and need a security-key press
    from an admin whose key chains to `broker.attestationRootsConfigMap` (a ConfigMap holding
    `attestation-roots.pem`). Without it every admin call is refused 503. Run them from a workstation that can reach
    the `<release>-broker` Service. When no broker is reachable:

    ```sh
    scripts/revoke-offline.sh <ns> <release> -- --principal <name> [--lift|--list]
    ```

    It scales the brokers to 0, runs `port49-broker revoke --offline` against broker-0's volume, and scales back on
    every exit. The chart is on etcd, which keeps the marks (with a copy in `broker.state_dir`), so it has no
    `init-revocations` step.
