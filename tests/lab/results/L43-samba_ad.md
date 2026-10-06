# L43 — samba_ad

- **Date measured:** 2026-10-05
- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** Samba Version 4.17.12-Debian; image `port49lab/samba:bookworm` (port49lab/samba@sha256:966cf1153e0f3ebe30eb7e869ac2648488fe98ceb2bc481a6f64ff42c8ae53ff), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `1deabaa1e3590bc90e0eb5367131447a76f1b14a`, `go test -tags lab ./tests/lab/ -run 'TestL42|TestL43'`
- **Capture:** `tests/lab/evidence/L43-samba_ad.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is LDAPS, so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.

## Claim

Which bind mechanisms each directory accepts from port49-broker, and how each refusal reads: SASL EXTERNAL over LDAPS with a client certificate (OpenLDAP mapping it by `olcAuthzRegexp`); GSSAPI with a keytab and no SASL security layer, over LDAPS (Samba AD's KDC); simple bind over LDAPS; and a simple bind over plain LDAP to a directory configured to require TLS (policy engine spec §15 L43). Samba's GSSAPI and plain-LDAP cells are measured under `ldap server require strong auth = yes` and again under the setting that permits SASL over TLS.

## Observation

### How this directory was configured

- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again under the setting that permits SASL over TLS, each row naming the value in force.
- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).
- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.
- `port49` is an ordinary domain user with its default rights.

### Bind

| mechanism | outcome | LDAP result | time |
|---|---|---|---|
| SASL EXTERNAL over LDAPS, the broker's certificate | refused: `LDAP Result Code 1 "Operations Error": bind external as CN=port49-broker,O=port49 lab: LDAP result 1` | 1 | 4ms |
| simple bind over LDAPS | accepted; a search for alice found 1 entry | 0 | 41ms |
| GSSAPI over LDAPS, keytab, no SASL security layer (`ldap server require strong auth = yes`) | refused: `LDAP Result Code 8 "Strong Auth Required": bind gssapi as port49@CORP.EXAMPLE.COM: LDAP result 8` | 8 | 67ms |
| simple bind over plain LDAP, built by hand (`ldap server require strong auth = yes`) | refused: `LDAP Result Code 8 "Strong Auth Required": BindSimple: Transport encryption required.` | 8 | 35ms |
| GSSAPI over LDAPS, keytab, no SASL security layer (`ldap server require strong auth = allow_sasl_over_tls`, after a restart) | accepted; a search for alice found 1 entry | 0 | 80ms |
| simple bind over LDAPS (`ldap server require strong auth = allow_sasl_over_tls`, after a restart) | accepted; a search for alice found 1 entry | 0 | 42ms |
| simple bind over plain LDAP, built by hand (`ldap server require strong auth = allow_sasl_over_tls`, after a restart) | refused: `LDAP Result Code 8 "Strong Auth Required": BindSimple: Transport encryption required.` | 8 | 37ms |

Whether the directory's LDAPS asked the client for a certificate (what EXTERNAL needs): the server sent a CertificateRequest listing 1 acceptable CA name(s). A Samba refusal of EXTERNAL says nothing about a Windows DC (L44).

### A refused bind through the pool (a wrong password)

| check | observed |
|---|---|
| `Resolver.Verify` | `directory: no server answered (the last: localhost:20636: LDAP Result Code 49 "Invalid Credentials": bind simple as CN=port49,OU=Svc,DC=corp,DC=example,DC=com: LDAP result 49)` |
| `Resolver.Map`, nothing stored | `directory: no server answered: no membership is stored for this certificate (directory: no server answered (the last: a directory server refused the bind; no server is bound until the hold-off ends))` |
| counters | queries{refused}=1, queries{fault}=0, server_up=1 |
| lines the pool said | 4, none holding a password |

### Also asserted: port49's mapping guarantees (not part of L43's claim)

These are port49's own guarantees on a real directory and close nothing in the register. The `issuer_serial` and `sid` rows compare port49's `X509:<I>...<SR>...` form and its SID extension with what port49 itself wrote or built: they show the value survives filter escaping and a string-form `objectSid` matches, not that a DC accepts it (L44).

| check | observed |
|---|---|
| alice's certificate under `san_email`, issuer pinned to `CN=lab-users-CA,DC=corp,DC=example,DC=com` | ok as `user:alice@corp.example.com`, username `alice`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| alice's certificate under `issuer_serial`, the `altSecurityIdentities` the seed wrote from `directory.ADIssuerSerial` | ok as `user:alice@corp.example.com`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| alice's certificate under `sid`, the extension holding her `objectSid` | ok as `user:alice@corp.example.com`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| eve's certificate under `san_email` (`eve` and `eve2` hold one `mail`) | `directory: identity_ambiguous: 2 or more entries (CN=eve2,OU=Contractors,DC=corp,DC=example,DC=com; CN=eve,OU=Staff,DC=corp,DC=example,DC=com)` |
| `principal_attribute: mail`; `samba-tool`-equivalent edit gives bob alice's `mail`; alice's certificate under `issuer_serial` | `directory: identity_ambiguous: mail "alice@corp.example.com" is held by CN=alice,OU=Staff,DC=corp,DC=example,DC=com and by CN=bob,OU=Staff,DC=corp,DC=example,DC=com: two people under one principal is ...` |
| the same, `Verify` of `user:alice@corp.example.com` | `directory: identity_ambiguous: 2 or more entries (CN=bob,OU=Staff,DC=corp,DC=example,DC=com; CN=alice,OU=Staff,DC=corp,DC=example,DC=com)` |
| bob's `mail` restored, alice's certificate again | ok |
| `netops-oncall` named by two groups (`OU=G` and `OU=Users-Can-Create`), groups base the whole domain, carol (direct member of the first) | names `(none)`; DNs `CN=netops-oncall,OU=G,DC=corp,DC=example,DC=com`; the line said: `directory: selected localhost:20636 (no site, priority 100) directory: group name(s) netops-oncall are shared by two or more groups under DC=corp,DC=example,DC=com; a subject naming one matches no one (use its DN)` |

