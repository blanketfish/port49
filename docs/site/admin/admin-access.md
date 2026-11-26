---
title: Admin access
description: Set up who may run port49 revoke and port49 directory commands, how attestation roots are loaded, and how many admins to keep.
---

# Admin access

You run `port49 revoke` and `port49 directory ...` on your own workstation, through your agent. Nothing is run on the
server host. Each admin-level write needs the right in the policy and a press of your security key, once per operation,
so an exposed certificate or token alone authorizes nothing admin-level.

The broker needs three things: the attestation roots, the right in the policy, and a session key on each admin's
security key.

## Set it up

1. Give the broker Yubico's PIV attestation roots as a PEM file. It checks each admin's key against them. There is
   nothing to enroll per key.

    === "systemd"

        Name the file from the `identity:` block, which replaces `client_ca_file`:

        ```yaml
        broker:
          identity:
            humans:
              - {type: x509, trust_anchor_file: /etc/port49/broker/client-ca.pem}
            per_login_mfa:
              hardware_key_touch: {attestation_roots_file: /etc/port49/broker/attestation-roots.pem}
        ```

        After you change the roots file, run `sudo systemctl reload port49-broker`.

    === "Containers"

        Put the PEM roots in `PORT49_COMPOSE_LOCAL/broker/attestation-roots.pem`. `setup` copies it to
        `/etc/port49/broker/attestation-roots.pem`, the path the broker config's
        `broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file` names. After you change the file, run:

        ```sh
        docker compose up -d
        docker compose kill -s HUP port49-broker
        ```

        The broker re-reads the roots file at SIGHUP. A file it cannot use keeps the roots in force and logs one line
        saying so.

    === "Helm"

        Put `attestation-roots.pem` in a ConfigMap and name it with `broker.attestationRootsConfigMap`. Without it, every
        admin call is refused 503.

2. Grant the right in the policy, on subjects that name the admins by `identity:`:

    ```yaml
    subjects:
      - {name: oncall_a, identity: ["user:a@example.com"], api: [revoke_others, lift_revocations]}
      - {name: oncall_b, identity: ["user:b@example.com"], api: [revoke_others, lift_revocations]}
    ```

    The rights are listed under [`api:` rights](roles-and-grants.md#api-rights).

3. Each admin logs in with a session key on their security key, which is `key: pkcs11:...` in their client config
   ([Hardware keys](../use/hardware-keys.md)):

    ```sh
    port49 login
    ```

4. To check, run `port49 identity`, which lists your `api:` rights, then ask for something harmless that needs a touch:

    ```sh
    port49 identity
    port49 revoke --lift --principal user:nobody@example.com
    ```

    The second command asks for a touch. When the roots and the right are in place, the broker answers
    `no such revocation is in force`, and nothing changed. `port49 revoke --list` also shows what is in force and
    needs the right but no touch.

## How many admins

Several admins can share one directory group: a `group:` subject can hold the `api:` right. Also name at least two by
`identity:`, as above, because a group's rights resolve through the directory, which may be down when you need them.

## When an admin call is refused

The words each refusal prints and the fix are in the
[3am index](../operate/troubleshooting/index.md). The ones that depend on the deployment, such as an attestation that
does not chain or a store that is down, are on the troubleshoot page for
[systemd](../operate/systemd/troubleshoot.md), [containers](../operate/containers/troubleshoot.md) or
[Helm](../operate/helm/troubleshoot.md). With every broker down, use the
[break-glass revoke](revocation.md).
