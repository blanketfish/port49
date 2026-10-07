# L43 — openldap

- **Date measured:** 2026-10-07
- **Platform:** openldap, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** @(#) $OpenLDAP: slapd 2.5.13+dfsg-5 (Feb  8 2023 01:56:12) $; image `port49lab/openldap:bookworm` (port49lab/openldap@sha256:e5ee1f178c6d1e471dd5614547c1e258ee56840644f2b36846fef00e18f86660), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `e3db1d3808e6faec0d54817e03260af6167b0125`, `go test -tags lab ./tests/lab/ -run 'TestL42|TestL43'`
- **Capture:** `tests/lab/evidence/L43-openldap.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is LDAPS, so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.

## Claim

Which bind mechanisms each directory accepts from port49-broker, and how each refusal reads: SASL EXTERNAL over LDAPS with a client certificate (OpenLDAP mapping it by `olcAuthzRegexp`); GSSAPI with a keytab and no SASL security layer, over LDAPS (Samba AD's KDC); simple bind over LDAPS; and a simple bind over plain LDAP to a directory configured to require TLS (policy engine spec §15 L43). Samba's GSSAPI and plain-LDAP cells are measured under `ldap server require strong auth = yes` and again under the setting that permits SASL over TLS.

## Observation

### How this directory was configured

- `olcSecurity: tls=1` (every operation must be under TLS), set after the seed was loaded over ldapi.
- `olcTLSVerifyClient: try`: a client certificate is requested and verified when presented.
- `olcAuthzRegexp: "^cn=port49-broker,o=port49 lab$" -> cn=port49,ou=Svc,dc=corp,dc=example,dc=com`.
- The `memberof` overlay with `olcMemberOfRefInt: TRUE`; the seed was loaded with `ldapadd` so the overlay ran.
- `cn=port49` has read access to everything; anonymous has none beyond the root DSE and authentication.

### Bind

| mechanism | outcome | LDAP result | time |
|---|---|---|---|
| SASL EXTERNAL over LDAPS, the broker's certificate | accepted; a search for alice found 1 entry | 0 | 2ms |
| simple bind over LDAPS | accepted; a search for alice found 1 entry | 0 | 1ms |
| GSSAPI | not run: the OpenLDAP container has no KDC | n/a | n/a |
| simple bind over plain LDAP, built by hand | refused: `LDAP Result Code 13 "Confidentiality Required": TLS confidentiality required` | 13 | 0s |

Whether the directory's LDAPS asked the client for a certificate (what EXTERNAL needs): the server sent a CertificateRequest listing 1 acceptable CA name(s).

### A refused bind through the pool (a wrong password)

| check | observed |
|---|---|
| `Resolver.Verify` | `directory: no server answered (the last: localhost:10636: LDAP Result Code 49 "Invalid Credentials": bind simple as cn=port49,ou=Svc,dc=corp,dc=example,dc=com: LDAP result 49)` |
| `Resolver.Map`, nothing stored | `directory: no server answered: no membership is stored for this certificate (directory: no server answered (the last: a directory server refused the bind; no server is bound until the hold-off ends))` |
| counters | queries{refused}=1, queries{fault}=0, server_up=1 |
| lines the pool said | 4, none holding a password |

### Also asserted: port49's mapping guarantees (not part of L43's claim)

These are port49's own guarantees on a real directory and close nothing in the register. The `issuer_serial` and `sid` rows compare port49's `X509:<I>...<SR>...` form and its SID extension with what port49 itself wrote or built: they show the value survives filter escaping and a string-form `objectSid` matches, not that a DC accepts it (L44).

| check | observed |
|---|---|
| alice's certificate under `san_email`, issuer pinned to `CN=lab-users-CA,DC=corp,DC=example,DC=com` | ok as `user:alice@corp.example.com`, username `alice`, DN `uid=alice,ou=Staff,dc=corp,dc=example,dc=com` |
| `issuer_serial` and `sid` | not run: OpenLDAP has no `altSecurityIdentities` or `objectSid` |
| eve's certificate under `san_email` (`eve` and `eve2` hold one `mail`) | `directory: identity_ambiguous: 2 or more entries (uid=eve,ou=Staff,dc=corp,dc=example,dc=com; uid=eve2,ou=Contractors,dc=corp,dc=example,dc=com)` |
| `netops-oncall` named by two groups (`OU=G` and `OU=Users-Can-Create`), groups base the whole domain, carol (direct member of the first) | names `(none)`; DNs `cn=netops-oncall,ou=G,dc=corp,dc=example,dc=com`; the line said: `directory: selected localhost:10636 (no site, priority 100) directory: group name(s) netops-oncall are shared by two or more groups under dc=corp,dc=example,dc=com; a subject naming one matches no one (use its DN)` |

