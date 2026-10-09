# L50 — samba_ad

- **Date measured:** 2026-10-09
- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** Samba Version 4.17.12-Debian; image `port49lab/samba:bookworm` (port49lab/samba@sha256:89da2ab5ffb7cb058f2103736ff7a1ff9bd63289974ab0c6658e189b0ad8622d), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `025d115067beb73e626b3ff3e50e4d96ab33bf53`, `go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$'`
- **Capture:** `tests/lab/evidence/L50-samba_ad.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is LDAPS, so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.

## Claim

Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, 40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of Account Operators, a delegated OU administrator ("create, delete and manage user accounts" on the OU) and an ordinary domain user can write it, under the default ACLs and under a candidate ACL plan 8b's docs might prescribe once this row closes (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change auditing turned on (policy engine spec §15 L50).

## Observation

### How this directory was configured

- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again under the setting that permits SASL over TLS, each row naming the value in force.
- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).
- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.
- `port49` is an ordinary domain user with its default rights.

### The OU's security descriptor before the default cells

The container is fresh each run, so this is the default: `samba-tool dsacl get --objectdn=OU=Workloads,DC=corp,DC=example,DC=com`

```
descriptor for OU=Workloads,DC=corp,DC=example,DC=com:
O:DAG:DAD:AI(A;CIIO;GA;;;S-1-5-21-556814435-4026451668-2265281451-1118)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-556814435-4026451668-2265281451-1118)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;ED)(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)

```

### The audit

One accepted write (`uid` by l50-acctop) and one refused (`uid` by svc-oxidized-01) are made twice; the container's log (`docker compose logs`, since the probe) is searched for a `dsdbChange` record naming the target.

- **As installed: not in the log.** No `dsdbChange` record named the target.
- **After `smbcontrol all debug "dsdb_json_audit:5 dsdb_audit:5"`: in the log** (2 `dsdbChange` record(s); `smbcontrol samba debug` reaches only the root process, not the LDAP workers):

  - `samba-1 | {"timestamp": "2026-10-09T05:33:13.253568+0000", "type": "dsdbChange", "dsdbChange": {"version": {"major": 1, "minor": 0}, "statusCode": 0, "status": "Success", "operation": "Modify", "remoteAddress": "ipv4:172.30.42.1:56648", "performedAsSystem": false, "userSid": "S-1-5-21-556814435-4026451668-2265281451-1117", "dn": "CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com", "transactionId": "7ad802da-5e86-4007-8e13-eea799a90e9d", "sessionId": "a80c700f-5cc9-4a1d-a77f-cbd45dcbed78", "attributes": {"uid": {"actions": [{"action": "replace", "values": [{"value": "spiffe://corp.examp...`
  - `samba-1 | {"timestamp": "2026-10-09T05:33:13.305592+0000", "type": "dsdbChange", "dsdbChange": {"version": {"major": 1, "minor": 0}, "statusCode": 50, "status": "insufficient access rights", "operation": "Modify", "remoteAddress": "ipv4:172.30.42.1:56650", "performedAsSystem": false, "userSid": "S-1-5-21-556814435-4026451668-2265281451-1123", "dn": "CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com", "transactionId": "e2056963-e4cf-4ebd-8469-ffb7d1289477", "sessionId": "dce1e234-bbd8-4583-b88a-2948d8519497", "attributes": {"uid": {"actions": [{"action": "replace", "values": [{"value": ...`


### The matrix

| attribute | writer | ACL | written | reads back | refusal |
|---|---|---|---|---|---|
| `uid` | svc-oxidized-01 | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-acctop | default | true | true | - |
| `uid` | l50-ouadmin | default | true | true | - |
| `uid` | l50-user | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | svc-oxidized-01 | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-acctop | default | true | true | - |
| `description` | l50-ouadmin | default | true | true | - |
| `description` | l50-user | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | svc-oxidized-01 | default | true | true | - |
| `wWWHomePage` | l50-acctop | default | true | true | - |
| `wWWHomePage` | l50-ouadmin | default | true | true | - |
| `wWWHomePage` | l50-user | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | svc-oxidized-01 | default | true | true | - |
| `url` | l50-acctop | default | true | true | - |
| `url` | l50-ouadmin | default | true | true | - |
| `url` | l50-user | default | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | svc-oxidized-01 | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-acctop | prescribed | true | true | - |
| `uid` | l50-ouadmin | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `uid` | l50-user | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | svc-oxidized-01 | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-acctop | prescribed | true | true | - |
| `description` | l50-ouadmin | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `description` | l50-user | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | svc-oxidized-01 | prescribed | true | true | - |
| `wWWHomePage` | l50-acctop | prescribed | true | true | - |
| `wWWHomePage` | l50-ouadmin | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `wWWHomePage` | l50-user | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | svc-oxidized-01 | prescribed | true | true | - |
| `url` | l50-acctop | prescribed | true | true | - |
| `url` | l50-ouadmin | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |
| `url` | l50-user | prescribed | false | false | LDAP result 50: LDAP Result Code 50 "Insufficient Access Rights": 00002098: Object CN=svc-oxidized-01,OU=Workloads,DC=corp,DC=example,DC=com has no write property access |

### Who could write what

- under the default ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the default ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-ouadmin could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-user could write: none
- under the prescribed ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the prescribed ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the prescribed ACL, l50-ouadmin could write: none
- under the prescribed ACL, l50-user could write: none


