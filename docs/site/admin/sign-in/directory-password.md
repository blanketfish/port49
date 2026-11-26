---
title: Directory password sign-in
description: Let people sign in with a directory password and an authenticator code when there is no identity provider and no PKI.
---

# Directory password sign-in

For a site with no identity provider and no PKI. A person signs in with their directory password and a time-based
code from an authenticator app, and the broker issues the same short-lived certificate as the other backends
([Identities](../../concepts/identities.md)).

## Set it up

1. Turn on `broker.directory` ([The directory](../directory.md)).

2. Add the verifier and turn on issuance. `principal_domains` must not overlap an `oidc` verifier's: a password beside
   a provider that enforces stronger sign-in is a downgrade an attacker would pick, so the config refuses it.

    ```yaml
    broker:
      identity:
        humans:
          - type: directory_password
            second_factor: totp
            principal_domains: ["example.com"]
        issuance: {}
    ```

3. Create the enrollment store once, before the broker's first start. The broker never creates it, because a store
   that went missing must not reopen enrollment for everyone.

    === "systemd"

        ```sh
        sudo -u port49-broker port49-broker init-enrollments
        ```

    === "Containers"

        ```sh
        docker compose run --rm port49-broker init-enrollments
        ```

    === "Helm"

        Apply `examples/init-enrollments-job.yaml` once per new deployment, after adapting its names to your values:

        ```sh
        kubectl -n <ns> apply -f examples/init-enrollments-job.yaml
        kubectl -n <ns> wait --for=condition=complete job/port49-init-enrollments --timeout=300s
        ```

    A broker that is already running finds the new store within 30 seconds. Until then its sign-ins answer
    `enrollment_store_lost`. To check, read `port49_directory_enrollment_store_ok` on the broker's metrics port: it is
    1 when the store opened.

4. Open an enrollment window (below), then sign in from a test account. To check, run:

    ```sh
    port49 login --directory
    ```

    It asks for the directory name, the password and the code. A person with no authenticator leaves the code empty,
    and the broker starts an enrollment that shows the authenticator's secret on the terminal. Success prints
    `port49: logged in to <broker>; the session ends at <time>`.

## Why the order is fixed

The broker checks the code first and consumes its step. Then it makes one bind as the person's own entry. Then it
issues the certificate. A password spray therefore never reaches the directory for someone with a code, and port49
cannot lock an account. Service accounts and workload entries are refused.

Limits are 5 failures per person and 50 per source in 15 minutes (`rate_limits`). Over them the answer is
`429 sign_in_throttled`, and `port49 directory unlock <principal>` clears one person's count at 3am.

## Enrolling the authenticator

A person with no authenticator enrolls at a sign-in whose password is right, only while a window is open for them:

| Window | Opens when | Default |
|---|---|---|
| `enrollment.open_until` | a date you set, for the whole fleet (a rollout) | none |
| `enrollment.new_entries_for` | after the entry's creation (`whenCreated` or `createTimestamp`) | 336h |
| `enrollment.reopen_for` | after `port49 directory reset-second-factor <principal>` | 24h |

`port49 directory reset-second-factor --all` opens the reopen window for everyone. Outside every window the answer is
403 `enrollment_closed`. An entry with no creation time counts as outside its `new_entries_for` window, so a directory
that does not supply one fails closed.

!!! warning "A window weakens the second factor"
    Inside a window, the directory password alone lets the first caller enroll their own authenticator. If the
    password is stolen, the thief enrolls first and the real person later finds a second factor they never set up.
    Every enrollment is an `enroll` record you can alert on. Keep windows short, and close `open_until` when a rollout
    ends.

## The enrollment store

The enrollments live in a sealed file in `broker.state_dir`, or in etcd. A missing or unreadable store refuses password
sign-in with 503 `enrollment_store_lost`, and every other path keeps serving. Restore it from backup with
`port49 directory import`, or run `reset-second-factor --all`. `port49-broker export-enrollments` writes a copy
([Backup and restore](../../operate/backup-and-restore.md)).

The operator commands are `port49 directory forget`, `unlock` and `reset-second-factor`, run through your agent.
