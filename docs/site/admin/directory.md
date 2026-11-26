---
title: The directory
description: Connect port49 to an LDAP directory for groups, certificate mapping and password sign-in, and set the bind, the site and group nesting.
---

# The directory

A directory supplies the people behind `group:` subjects and the `username_attribute` a device login uses. It is also
where [directory password sign-in](sign-in/directory-password.md) checks passwords. It is off until you configure
`broker.directory`. Every key is in the [port49d reference](../reference/config/port49d.md).

## Connect it

1. Describe the directory in the broker config. `deploy/compose/config/port49-broker.yaml`
   has a commented `broker.directory:` block to start from. A minimal Active Directory block with a Kerberos bind looks like this:

    ```yaml
    broker:
      directory:
        servers:
          - {uri: "ldaps://dc1.example.com", site: hq, priority: 10}
        ca_file: /etc/port49/directory/ca.pem
        bind:
          mechanism: gssapi
          principal: svc-port49@EXAMPLE.COM
          keytab_file: /etc/port49/directory/svc-port49.keytab
          krb5_conf: /etc/port49/directory/krb5.conf
        base_dn: dc=example,dc=com
        nested_groups: in_chain
    ```

    The broker prefers servers in its own site, then the highest `priority`, then file order. A plain `ldap://` server
    needs `start_tls: true`.

2. Give the broker its site, and place the bind's files if it needs any.

    === "systemd"

        Put the keytab at `/etc/port49/directory/svc-port49.keytab` (0600, owned by `port49-broker`) with the `krb5.conf`
        beside it. Set the site with `sudo systemctl edit port49-broker`:

        ```ini
        [Service]
        Environment=PORT49_SITE=hq
        ```

    === "Containers"

        Put the keytab and `krb5.conf` in the broker's configuration volume (`broker-etc`, under `/etc/port49/`), the
        keytab mode 0600 and owned by uid 65532. Set `PORT49_SITE` in the broker service's `environment:`. It is not a
        secret, and replicas in different sites set different values.

    === "Helm"

        Set `broker.site` (the same for every replica of a release) and, for a Kerberos bind, `broker.directory.keytabSecret`:
        a Secret holding the keytab and `krb5.conf`, mounted at `/etc/port49/directory`.

3. Restart the broker. To check, read `port49_directory_server_up` on the broker's metrics port. It is 1 for each server
   whose breaker is closed. A keytab that cannot be read, or holds no key for the principal, stops the start and the log
   names the key.

A directory outage never makes `/readyz` fail. A session on a stored membership goes on within `grace` (4h by
default), and past `session.staleness_ceiling` (4h by default) a command is denied `context_stale`. See
[Troubleshooting](../operate/troubleshooting/index.md) for what a stale cache looks like.

## Bind

`bind.mechanism` is one of three:

- `gssapi` uses a Kerberos keytab (`principal`, `keytab_file`, `krb5_conf`). It is only a way to bind to the
  directory. port49 has no Kerberos sign-in for people.
- `external` binds with a TLS client certificate (`tls_cert_file`, `tls_key_file`).
- `simple` binds with `bind_dn` and `password_secret_ref`. It is the weakest. Name the password as `file:/path`, read
  when the directory opens and never printed. Use a file, not `env:NAME`, which a container's `docker inspect` shows.

| Directory | Use | Notes |
|---|---|---|
| OpenLDAP | `external`, mapped by `olcAuthzRegexp`, with `nested_groups: recursive` | `in_chain` answers empty there, which fails closed |
| Samba AD | `simple` or `gssapi` | SASL EXTERNAL is refused (LDAP result 1), which port49 counts as a server fault: every breaker opens and `port49_directory_server_up` drops to 0. `gssapi` needs `ldap server require strong auth = allow_sasl_over_tls`. `in_chain` works |
| Windows AD | `external` over `ldap://` with `start_tls: true` | `ldaps://` gets result 7. Result 49 means the certificate is unmapped or that DC's KDC is down. `gssapi` is refused under `LdapEnforceChannelBinding = 2` |

The Windows row is measured on Windows Server 2025 only
([L44](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L44-windows_ad.md)). Older Windows Server
releases are unmeasured. OpenLDAP and Samba are in
[L42](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L42-openldap.md) and
[L43](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L43-samba_ad.md).

## Who a person is

`principal_attribute` and `username_attribute` must be writable only by directory administrators, and need a
case-insensitive matching rule. Whoever can write them chooses who a person is.

A principal is pinned to the entry's immutable id (`entryUUID` or `objectGUID`). A rename is followed. Two entries
claiming one principal are refused `identity_ambiguous`, and a username that two entries claim `username_collision`.
`port49 directory forget <principal>` releases a pin.

`nested_groups` is `in_chain` (Active Directory's chain matching), `recursive` or `direct`. `prewarm` looks up group
members ahead of a person's first login. `broker.refresh_interval` (5m by default) re-verifies every live principal.

## Certificate mapping

`certificate_mapping` says how a client certificate finds its entry. `issuer_serial` and `sid` are strong. The others
need `allow_weak: true` and `issuers`.

With `external` on Windows AD, the directory finds a person's entry from the certificate through
`altSecurityIdentities`, so each entry holds the string for its certificate. port49 computes the same string Windows
does:

```text
X509:<I>DC=com,DC=corp,CN="corp, ""east"" CA"<SR>11AC0000000012
```

That is the value for an issuer `DC=com, DC=corp, CN=corp, "east" CA`. `<I>` is the issuer's RDNs, most significant
first, and `<SR>` the serial's bytes reversed in upper-case hex. A value is quoted as Windows' CertNameToStr quotes it:
if it is empty, contains any of `,+="<>#;` or a newline, or has leading or trailing white space, with an inner `"`
doubled. A backslash and a slash are not quoted. A comma, a plus, an inner quote and a leading space were measured.
An empty value, trailing white space, `=`, `<`, `>`, `#`, `;`, a newline and white space other than a plain space are
unmeasured, so a certificate whose issuer holds one is a case to test.

A multi-valued relative distinguished name in the issuer has no one string, so port49 does not guess one. The mapping
is empty and the certificate is refused `identity_unmapped`, which fails closed.

`identity_unmapped` is also the answer when no entry holds the string. The broker's detail reads
`directory: identity_unmapped: no entry under <BaseDN>`. For a certificate from a CA that
`broker.directory.certificate_mapping.issuers` does not pin it reads `the certificate's issuer "<issuer>" is not one
broker.directory.certificate_mapping.issuers pins`, and for a certificate with several UPN SANs `the certificate
carries <n> UPN SANs; exactly one maps`. It does not print the value it searched for. Compute the string as above from
the certificate's issuer and serial, or read it from the entry that should hold it.
