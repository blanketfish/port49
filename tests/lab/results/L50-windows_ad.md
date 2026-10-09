# L50 — windows_ad

- **Date measured:** 2026-10-09
- **Platform:** windows_ad, Windows Server 2025 Standard Evaluation as a KVM VM in `dockurr/windows`, on `tests/lab/directory/windows/compose.yaml` (no network device)
- **Image version:** Microsoft Windows Server 2025 Standard Evaluation (ServerStandardEval), build 26100.32230; ISO `26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso` (SHA-256 `7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51`); image `dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea`
- **Run:** commit `025d115067beb73e626b3ff3e50e4d96ab33bf53`, `go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$'`
- **Capture:** `tests/lab/evidence/L50-windows_ad.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is TLS (LDAPS or StartTLS), so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The Administrator, DSRM and port49 passwords are generated for each run, held only in 0600 files under `tests/lab/logs/windows`, and reach the VM on an SSH session's stdin, never on a host command line; the one command line that carries one is `ktpass`'s own, inside the VM, which is destroyed at the end of the run. Alice's is made on the DC and never leaves it. The keytab and every private key stay on the host that ran it, 0600, and are removed at the end of the run.

## Claim

Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, 40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of Account Operators, a delegated OU administrator ("create, delete and manage user accounts" on the OU) and an ordinary domain user can write it, under the default ACLs and under a candidate ACL plan 8b's docs might prescribe once this row closes (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change auditing turned on (policy engine spec §15 L50).

## Observation

### The OU's security descriptor before the default cells

The DC is built by this run (not reused): the install's defaults. The seed removed 0 prescribed deny(s) of an earlier run from `OU=Workloads,DC=corp,DC=example,DC=com` before the default cells, and the SDDL after that is:

```
O:DAG:DAD:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1102731772-3194105932-4183108488-1118)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1102731772-3194105932-4183108488-1118)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;KA)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-1102731772-3194105932-4183108488-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1102731772-3194105932-4183108488-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)
```

### The audit settings as found, before this run changed any

The DC is built by this run (not reused): the install's defaults.

- `auditpol` Directory Service Changes: `System audit policy Category/Subcategory Setting DS Access Directory Service Changes No Auditing`
- `auditpol` Directory Service Access: `System audit policy Category/Subcategory Setting DS Access Directory Service Access Success`
- SACL on the OU: `S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)`

### The OU's security descriptor after the prescribed cells

After every `acl clear`, so it is the seed's again:

```
O:DAG:DAD:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1102731772-3194105932-4183108488-1118)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1102731772-3194105932-4183108488-1118)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;KA)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-1102731772-3194105932-4183108488-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1102731772-3194105932-4183108488-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)
```

### The audit

One accepted write (`uid` by l50-acctop) and one refused (`uid` by svc-oxidized-01) are made twice, each pair followed, 30 seconds later (the DC logs a 5136 several seconds after the write), by a read of the Security log's 5136 (attribute modified) and 4662 (an access) events since before the pair. Each event is assigned to a write by its `Account Name`. The DC's events are in the evidence, each cut at 600 characters.

- **As installed** (the settings above): 0 event(s) read in all. Accepted write, `uid` by l50-acctop: 0 5136 event(s) naming the target's DN and the attribute, 0 4662 event(s) by that account (a 4662 names the object by GUID, not DN). Refused write, `uid` by svc-oxidized-01: 0 5136 event(s) naming the target's DN and the attribute, 0 4662 event(s) by that account (a 4662 names the object by GUID, not DN).
- **With directory-change auditing on** (`audit.ps1 on`: success and failure for Directory Service Changes and Access, and a success-and-failure SACL for Everyone's writes on the OU, inherited): 4 event(s) read in all. Accepted write, `uid` by l50-acctop: 2 5136 event(s) naming the target's DN and the attribute, 1 4662 event(s) by that account (a 4662 names the object by GUID, not DN). Refused write, `uid` by svc-oxidized-01: 0 5136 event(s) naming the target's DN and the attribute, 1 4662 event(s) by that account (a 4662 names the object by GUID, not DN).


### The matrix

| attribute | writer | ACL | written | reads back | refusal |
|---|---|---|---|---|---|
| `uid` | svc-oxidized-01 | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `uid` | l50-acctop | default | true | true | - |
| `uid` | l50-ouadmin | default | true | true | - |
| `uid` | l50-user | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `description` | svc-oxidized-01 | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `description` | l50-acctop | default | true | true | - |
| `description` | l50-ouadmin | default | true | true | - |
| `description` | l50-user | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `wWWHomePage` | svc-oxidized-01 | default | true | true | - |
| `wWWHomePage` | l50-acctop | default | true | true | - |
| `wWWHomePage` | l50-ouadmin | default | true | true | - |
| `wWWHomePage` | l50-user | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `url` | svc-oxidized-01 | default | true | true | - |
| `url` | l50-acctop | default | true | true | - |
| `url` | l50-ouadmin | default | true | true | - |
| `url` | l50-user | default | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `uid` | svc-oxidized-01 | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `uid` | l50-acctop | prescribed | true | true | - |
| `uid` | l50-ouadmin | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `uid` | l50-user | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `description` | svc-oxidized-01 | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `description` | l50-acctop | prescribed | true | true | - |
| `description` | l50-ouadmin | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `description` | l50-user | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `wWWHomePage` | svc-oxidized-01 | prescribed | true | true | - |
| `wWWHomePage` | l50-acctop | prescribed | true | true | - |
| `wWWHomePage` | l50-ouadmin | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `wWWHomePage` | l50-user | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `url` | svc-oxidized-01 | prescribed | true | true | - |
| `url` | l50-acctop | prescribed | true | true | - |
| `url` | l50-ouadmin | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |
| `url` | l50-user | prescribed | false | false | Microsoft.ActiveDirectory.Management.ADException: Insufficient access rights to perform the operation |

### Who could write what

- under the default ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the default ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-ouadmin could write: `uid`, `description`, `wWWHomePage`, `url`
- under the default ACL, l50-user could write: none
- under the prescribed ACL, svc-oxidized-01 could write: `wWWHomePage`, `url`
- under the prescribed ACL, l50-acctop could write: `uid`, `description`, `wWWHomePage`, `url`
- under the prescribed ACL, l50-ouadmin could write: none
- under the prescribed ACL, l50-user could write: none


