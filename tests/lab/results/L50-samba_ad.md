# L50 — samba_ad

- **Date measured:** 2026-10-09
- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** Samba Version 4.17.12-Debian; image `port49lab/samba:bookworm` (port49lab/samba@sha256:0949e58a2edf897e7df6cabb051735cfa02033ffbbf47dcfa0cc99f7740ebc70), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `e70e75f64dac6a97d16218674fd5ace0df2cda66`, `go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$'`
- **Capture:** `tests/lab/evidence/L50-samba_ad.json`: one JSON line per mark: each write (attribute, writer, ACL, the LDAP result code), the security descriptors read back after every ACL change and every re-seed, and the audit-log lines found. There are no search or bind lines; the wire is LDAPS, so a pcap would be encrypted.
- **Credentials:** none appear here or in the evidence. The writers' shared password is generated for each run; it is never printed or logged, and reaches the container only as an argument of `l50-seed.sh`.

## Claim

Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, 40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of Account Operators, a delegated OU administrator ("create, delete and manage user accounts" on the OU) and an ordinary domain user can write it, under the default ACLs and under a candidate ACL plan 8b's docs might prescribe once this row closes (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change auditing turned on (policy engine spec §15 L50).

## Observation

### How this directory was configured

- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again under the setting that permits SASL over TLS, each row naming the value in force.
- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).
- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.
- `port49` is an ordinary domain user with its default rights.

### The OU's and the target's security descriptors before the default cells

The container is fresh each run, so this is the default: `samba-tool dsacl get --objectdn=OU=Workloads,DC=corp,DC=example,DC=com`, then the same for `CN=svc-oxidized-01` in it.

```
descriptor for OU=Workloads,DC=corp,DC=example,DC=com:
O:DAG:DAD:AI(A;CIIO;GA;;;S-1-5-21-794377702-766097350-1101223200-1118)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-794377702-766097350-1101223200-1118)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;ED)(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)
descriptor for CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com:
O:DAG:DAD:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77b5b886-944a-11d1-aebd-0000f80367c1;;PS)(OA;;RPWP;e45795b2-9455-11d1-aebd-0000f80367c1;;PS)(OA;;RPWP;e45795b3-9455-11d1-aebd-0000f80367c1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77b5b886-944a-11d1-aebd-0000f80367c1;;AU)(OA;;RP;e45795b3-9455-11d1-aebd-0000f80367c1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(A;ID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-794377702-766097350-1101223200-1118)(A;CIIOID;GA;;;S-1-5-21-794377702-766097350-1101223200-1118)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:AI(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)

```

### How the prescribed deny was set and cleared on Samba

`acl set` writes three ACEs (`OD;CI;WP;<the attribute's schemaIDGUID>;<user class>;` for SELF `PS`, Account Operators `AO` and l50-ouadmin) with `samba-tool dsacl set`. Samba 4.17's `samba-tool` has no `dsacl delete`, so `acl clear` **re-seeds the OU**: it deletes `OU=Workloads` and its subtree and seeds it again, which also **recreates the target `svc-oxidized-01` with a new SID**. Every prescribed attribute therefore ran against a fresh OU and a fresh target. After every set and every re-seed the harness reads both descriptors back, stops if the set did not leave exactly three deny ACEs on the OU or the re-seed left any, and keeps the descriptors in the evidence (`l50 samba: after acl ...` marks). What it found:

- after `acl set uid`: the OU holds 3 deny ACE(s), the target 3 (inherited)
- after `acl clear uid`: the OU holds 0 deny ACE(s), the target 0 (inherited)
- after `acl set description`: the OU holds 3 deny ACE(s), the target 3 (inherited)
- after `acl clear description`: the OU holds 0 deny ACE(s), the target 0 (inherited)
- after `acl set wWWHomePage`: the OU holds 3 deny ACE(s), the target 3 (inherited)
- after `acl clear wWWHomePage`: the OU holds 0 deny ACE(s), the target 0 (inherited)
- after `acl set url`: the OU holds 3 deny ACE(s), the target 3 (inherited)
- after `acl clear url`: the OU holds 0 deny ACE(s), the target 0 (inherited)

The deny ACEs after `acl set uid`:

```
OU:
(OD;CI;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-794377702-766097350-1101223200-1118)
(OD;CI;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;AO)
(OD;CI;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;PS)
target:
(OD;CIID;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-794377702-766097350-1101223200-1118)
(OD;CIID;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;AO)
(OD;CIID;WP;0bb0fca0-1e89-429f-901a-1413894d9f59;bf967aba-0de6-11d0-a285-00aa003049e2;PS)
```

### The delegated administrator against the prescribed deny on `uid`

- (b) `l50-made`, created by l50-ouadmin, has owner and group `O:S-1-5-21-794377702-766097350-1101223200-1118`.
- (a) The target's owner and group before the ACE: `O:DA`.
- l50-ouadmin (adds an allow ACE for itself on the target): `accepted`
- (a) The target's descriptor now holds an explicit allow for l50-ouadmin: true.
- l50-ouadmin (takes ownership of the target): `accepted`
- (c) The target's owner and group after l50-ouadmin took ownership: `O:S-1-5-21-794377702-766097350-1101223200-1118`.
- l50-ouadmin (after taking ownership, adds an allow ACE for itself): `accepted`

The re-seed that followed undid the ACE and the entry.

### The audit

One accepted write (`uid` by l50-acctop) and one refused (`uid` by svc-oxidized-01) are made twice; the container's log (`docker compose logs`, since the probe) is searched for a `dsdbChange` record naming the target.

- **As installed: not in the log.** No `dsdbChange` record named the target. "As installed" is `log level = 1` (`tests/lab/directory/samba/entrypoint.sh:30`, written into `smb.conf`), with no `dsdb_json_audit` or `dsdb_audit` class set.
- **After `smbcontrol all debug "dsdb_json_audit:5 dsdb_audit:5"`: in the log** (2 `dsdbChange` record(s); `smbcontrol samba debug` reaches only the root process, not the LDAP workers):

  - `samba-1 | {"timestamp": "2026-10-09T06:19:15.307456+0000", "type": "dsdbChange", "dsdbChange": {"version": {"major": 1, "minor": 0}, "statusCode": 0, "status": "Success", "operation": "Modify", "remoteAddress": "ipv4:172.30.42.1:43944", "performedAsSystem": false, "userSid": "S-1-5-21-794377702-766097350-1101223200-1117", "dn": "CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com", "transactionId": "ca049e4b-ca13-4375-8adf-cd0acc947a98", "sessionId": "acbf93a0-8589-48b1-bd85-6937216ebee1", "attributes": {"uid": {"actions": [{"action": "replace", "values": [{"value": "spiffe://corp.exampl...`
  - `samba-1 | {"timestamp": "2026-10-09T06:19:15.354767+0000", "type": "dsdbChange", "dsdbChange": {"version": {"major": 1, "minor": 0}, "statusCode": 50, "status": "insufficient access rights", "operation": "Modify", "remoteAddress": "ipv4:172.30.42.1:43954", "performedAsSystem": false, "userSid": "S-1-5-21-794377702-766097350-1101223200-1126", "dn": "CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com", "transactionId": "daecdb07-69eb-4325-9299-9675da4c938e", "sessionId": "bed3aecc-dded-405f-962c-75c3ff800ba8", "attributes": {"uid": {"actions": [{"action": "replace", "values": [{"value": "...`


### The matrix

| attribute | writer | ACL | written | reads back | refusal |
|---|---|---|---|---|---|
| `uid` | svc-oxidized-01 | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-acctop | default | true | true | - |
| `uid` | l50-ouadmin | default | true | true | - |
| `uid` | l50-user | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | svc-oxidized-01 | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-acctop | default | true | true | - |
| `description` | l50-ouadmin | default | true | true | - |
| `description` | l50-user | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | svc-oxidized-01 | default | true | true | - |
| `wWWHomePage` | l50-acctop | default | true | true | - |
| `wWWHomePage` | l50-ouadmin | default | true | true | - |
| `wWWHomePage` | l50-user | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | svc-oxidized-01 | default | true | true | - |
| `url` | l50-acctop | default | true | true | - |
| `url` | l50-ouadmin | default | true | true | - |
| `url` | l50-user | default | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | svc-oxidized-01 | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-acctop | prescribed | true | true | - |
| `uid` | l50-ouadmin | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-user | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | svc-oxidized-01 | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-acctop | prescribed | true | true | - |
| `description` | l50-ouadmin | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-user | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | svc-oxidized-01 | prescribed | true | true | - |
| `wWWHomePage` | l50-acctop | prescribed | true | true | - |
| `wWWHomePage` | l50-ouadmin | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | l50-user | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | svc-oxidized-01 | prescribed | true | true | - |
| `url` | l50-acctop | prescribed | true | true | - |
| `url` | l50-ouadmin | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | l50-user | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-ouadmin (creates l50-made in the OU) | prescribed | true | false | - |
| `uid` | l50-ouadmin (writes l50-made, which it created) | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=l50-made,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-ouadmin (adds an allow ACE for itself on the target) | prescribed | true | false | - |
| `uid` | l50-ouadmin (writes the target after that ACE) | prescribed | true | true | - |
| `uid` | l50-ouadmin (takes ownership of the target) | prescribed | true | false | - |
| `uid` | l50-ouadmin (writes the target after taking ownership, no ACE) | prescribed | false | false | LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-ouadmin (after taking ownership, adds an allow ACE for itself) | prescribed | true | false | - |
| `uid` | l50-ouadmin (writes the target after taking ownership and that ACE) | prescribed | true | true | - |

The rows whose writer is `l50-ouadmin` with a parenthesis are the delegated administrator trying to get around the prescribed deny on `uid`. A row that names a step (adds an ACE, creates an entry, takes ownership) is the step itself: `written` is whether the directory accepted it, and `reads back` is `false` as nothing is read. A row that names a write is the write of `uid` that followed it. Every ACE, entry and ownership change those rows made was undone afterwards.

### Who could write what

- under the default ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the default ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-ouadmin could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-user could write: none
- under the prescribed ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the prescribed ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the prescribed ACL, l50-ouadmin could write: none
- under the prescribed ACL, l50-user could write: none


