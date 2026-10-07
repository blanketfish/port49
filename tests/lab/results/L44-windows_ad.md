# L44 — windows_ad

- **Date measured:** 2026-10-07
- **Platform:** windows_ad, Windows Server 2025 Standard Evaluation as a KVM VM in `dockurr/windows`, on `tests/lab/directory/windows/compose.yaml` (no network device)
- **Image version:** Microsoft Windows Server 2025 Standard Evaluation (ServerStandardEval), build 26100.32230; ISO `26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso` (SHA-256 `7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51`); image `dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea`
- **Run:** commit `ad1e4a91253d0b244749651f0d6dcd12527a07a3`, `PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$'`
- **Capture:** `tests/lab/evidence/L44-windows_ad.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is TLS (LDAPS or StartTLS), so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The Administrator, DSRM and port49 passwords are generated for each run, held only in 0600 files under `tests/lab/logs/windows`, and reach the VM on an SSH session's stdin, never on a host command line; the one command line that carries one is `ktpass`'s own, inside the VM, which is destroyed at the end of the run. Alice's is made on the DC and never leaves it. The keytab and every private key stay on the host that ran it, 0600, and are removed at the end of the run.

## Claim

The Active Directory claims on a Windows DC: on L42's fixture and its loop, which groups `member:1.2.840.113556.1.4.1941:=<user DN>` returns and how the loop is answered; SASL EXTERNAL over LDAPS with a client certificate (measured over StartTLS; [MS-ADTS] 5.1.1.2, with what LDAPS answers it); GSSAPI with a keytab and no SASL security layer against the Windows KDC; whether `altSecurityIdentities` values written in port49's `X509:<I>{issuer}<SR>{serial}` form (issuer from the raw DER, `DC=` included) match the certificate the DC itself maps; whether the SID extension's value equals `objectSid`; and how KB5014754's strong-mapping enforcement treats each (policy engine spec §15 L44). Also measured, for two questions plan 7g carried: whether the DC advertises the AD capability 1.2.840.113556.1.4.800, and the LDAP result an EXTERNAL bind it refuses carries.

## Observation

### How this directory was configured

- Windows Server 2025 Standard Evaluation, installed unattended by `dockurr/windows` from the pinned ISO into a KVM VM (6 GB, 4 vCPUs), and promoted to the first DC of a new forest `corp.example.com` by `Install-ADDSForest` with this build's defaults.
- Set up only over OpenSSH (installed by Windows, started by `oem/install.bat`) as the domain's Administrator. The Windows firewall is off and Windows Update disabled, so the build measured is the ISO's. Ports are published on 127.0.0.1 only.
- L42's fixture, made by `scripts/seed.ps1` with global security groups; the second `netops-oncall` is renamed in, as on Samba.
- SASL EXTERNAL is measured over StartTLS on `ldap://dc1.corp.example.com:30389`, port49's own `start_tls` connection. [MS-ADTS] 5.1.1.2: on the LDAPS port the DC authenticates the connection as the client certificate's identity at the handshake and rejects an EXTERNAL bind there; over StartTLS it maps the certificate when an EXTERNAL bind follows. One LDAPS EXTERNAL row is kept as an observation, with what the run read of that connection: its result code, and WhoAmI with no bind.
- LDAPS serves a certificate from the lab CA (`localhost`, `dc1.corp.example.com`, 127.0.0.1), placed in the NTDS service's own store; the lab CA is in the DC's Root store.
- The URIs name the DC, `dc1.corp.example.com`, which the test process alone resolves to 127.0.0.1, so port49's GSSAPI bind asks for `ldap/dc1.corp.example.com`, an SPN the DC keeps itself. `ldap/localhost`, added to `DC1$` as on Samba, left the account within minutes twice, with no 4742 event naming who removed it. The client `krb5.conf` reaches the KDC at 127.0.0.1:30088 over TCP.
- `port49` is an ordinary domain user, AES only; its keytab is made with `ktpass` (AES256-SHA1, `-mapuser CORP\port49`), which also sets its UPN. `ktpass` takes the password on its own command line inside the VM, the one place a secret is on a command line.
- AD CS: an enterprise root CA `corp-L44-CA` on the DC, `OfflineRouter` published for requests whose subject the harness supplies, and the DC's `KerberosAuthentication` certificate enrolled for PKINIT. The lab users CA and six quirk CAs, each CN holding one character (a comma, a backslash, a slash, a plus, an inner quote, a leading space), are in the DC's Root store and in NTAuth; a quirk CA that failed to publish makes its rows INVALID.
- Each KB5014754 block starts with a control, `control-ski`: alice's AD CS certificate under the strong `X509:<SKI>` mapping, which no part of the claim is about. A block whose control got no TGT is INVALID.
- Each `LdapEnforceChannelBinding` change reboots the DC, and the next cell waits for LDAPS. Restarting NTDS after setting 2 instead was followed, once, in an earlier run on its own fresh DC, by `lsass.exe` crashing (an access violation in `ntdsai.dll` 15 seconds after NTDS came back) and Windows restarting the VM; whether the restart or the binds under 2 that followed set it off was not separated. The DC's boot is read before and after the cells under 2, and a change makes them INVALID.
- The KDC is stopped for one EXTERNAL cell (OR-1) and started again by a task the stop registered; the next cell repeats the mapped bind to show the DC recovered.
- Alice's `User` certificate is requested as alice over WinRM with CredSSP, under a session configuration only she may use; all of it is removed after, and her password for it is made on the DC, used once and replaced. `enroll_as` first registers `WSMAN/DC1` and `WSMAN/dc1.corp.example.com` on `DC1$` (this build's WinRM had registered none, and without them CredSSP refuses the DC as a target); they stay on the lab DC.
- During the KB5014754 table only, `UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = 1` on the KDC: the harness's own CAs publish no CRL, and revocation is no part of the claim. Removed after.
- LDAP interface diagnostics at level 2 (`16 LDAP Interface Events`), so the DC logs bind and channel-binding events.
- PKINIT's client is MIT Kerberos (`kinit` from Fedora 43's `krb5-workstation` and `krb5-pkinit`, the versions its image recorded are in the facts table) on the project network, with `pkinit_kdc_hostname`, as MIT documents for an Active Directory KDC. MIT 1.22 or later is required: Windows Server 2025's KDC answers FFDH PKINIT without MS-PKCA's `paChecksum2` with KDC error 79 ("Checksum must be included"), and MIT added the field in 1.22 (krb5 commit 310793b); MIT 1.20 (Debian stable's, measured on an earlier L44 DC of this build) failed every cell with it; 1.21 lacks the commit.

### Running it again

- From a worktree pinned at the commit under test: `PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$' -count=1 -v -timeout 240m`. It needs `/dev/kvm`, Docker with Compose v2.24.4+, 6 GB of RAM and 66 GiB free; a fresh run takes 1.5 to 2.5 hours. Windows Setup can be watched at `http://127.0.0.1:8006`.
- The evaluation ISO is cached in `PORT49_LAB_ISO_DIR` (default `~/.cache/port49-lab/iso`), checked by size and SHA-256 on every run, and never committed or redistributed.
- `PORT49_LAB_WINDOWS_KEEP` leaves the DC and its secrets up; `PORT49_LAB_WINDOWS_REUSE` runs on a kept DC. Both are for developing the harness: a note from a reused DC says so and never closes L44.
- Under `tests/lab/logs/windows`, `windows.env`, `secrets.json`, `port49.keytab`, `broker-adcs-key.pem` and `pkinit/*-key.pem` hold secrets: never print them. The run removes them unless `PORT49_LAB_WINDOWS_KEEP` is set.
- Never print the project's resolved compose file or inspect its containers: both show the Administrator's password from the environment.

### The DC, as the run found it

| fact | value |
|---|---|
| build | Microsoft Windows Server 2025 Standard Evaluation 24H2 (ServerStandardEval), 26100.32230 |
| updates | KB5066131, KB5073379, KB5072725 |
| domain and forest modes | Windows2025Domain, Windows2025Forest |
| `StrongCertificateBindingEnforcement` as installed | absent |
| `CertificateBackdatingCompensation` | absent |
| Schannel `CertificateMappingMethods` | absent |
| NTDS LDAP settings in the registry | `ldapserverintegrity` = 1 |
| account lockout threshold | 0 |
| PKINIT client (MIT Kerberos 1.22+, Fedora 43), as installed in its image | krb5-workstation 1.22.2-4.fc43, krb5-pkinit 1.22.2-4.fc43, krb5-libs 1.22.2-4.fc43 |

### Nested groups: L42's fixture

| user | mode | groups returned | result | time |
|---|---|---|---|---|
| alice | in_chain | g-leaf, g-mid, netops-oncall | ok | 6ms |
| carol | in_chain | netops-oncall | ok | 5ms |
| dave | in_chain | g-loop-a, g-loop-b | ok | 5ms |
| alice | recursive | g-leaf, g-mid, netops-oncall | ok | 6ms |
| carol | recursive | netops-oncall | ok | 5ms |
| dave | recursive | g-loop-a, g-loop-b | ok | 5ms |
| alice | direct | g-leaf | ok | 5ms |
| carol | direct | netops-oncall | ok | 5ms |
| dave | direct | g-loop-a | ok | 14ms |

memberOf on alice's entry: CN=g-leaf,OU=G,DC=corp,DC=example,DC=com

### The AD capability (plan 7g's carried question a)

| directory | advertises `1.2.840.113556.1.4.800` | `in_chain` (L42) | supportedCapabilities |
|---|---|---|---|
| windows_ad | true | the table above | 1.2.840.113556.1.4.1670, 1.2.840.113556.1.4.1791, 1.2.840.113556.1.4.1935, 1.2.840.113556.1.4.2080, 1.2.840.113556.1.4.2237, 1.2.840.113556.1.4.800 |
| openldap | false | answers empty, no error (`L42-openldap.md`) |  |
| samba_ad | true | answers in full (`L42-samba_ad.md`) | 1.2.840.113556.1.4.1670, 1.2.840.113556.1.4.1791, 1.2.840.113556.1.4.1935, 1.2.840.113556.1.4.2080, 1.2.840.113556.1.4.800 |

### Binds

| mechanism | outcome | LDAP result | time |
|---|---|---|---|
| simple bind over LDAPS | accepted; a search for alice found 1 entry | 0 | 4ms |
| simple bind over plain LDAP, built by hand (an observation of this build's default) | refused: `LDAP Result Code 8 "Strong Auth Required": 00002028: LdapErr: DSID-0C09035C, comment: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection, data 0, v65f4` | 8 | 2ms |
| GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` absent (this build's default) | accepted; a search for alice found 1 entry | 0 | 6ms |
| SASL EXTERNAL over StartTLS, the broker's AD CS certificate, `altSecurityIdentities` on port49 in port49's form | accepted; WhoAmI `u:CORP\port49`; a search for alice found 1 entry | 0 | 8ms |
| SASL EXTERNAL over LDAPS, the same mapped certificate (a documented observation; [MS-ADTS] 5.1.1.2 says EXTERNAL is rejected there) | refused: `LDAP Result Code 7 "Auth Method Not Supported": bind external as CN=port49-broker: LDAP result 7` | 7 | 8ms |
| LDAPS with the mapped certificate and no bind, an observation: WhoAmI is `u:CORP\port49` | — | — | — |
| SASL EXTERNAL over StartTLS, the same certificate, no `altSecurityIdentities` on port49 (carried question b) | refused: `LDAP Result Code 49 "Invalid Credentials": bind external as CN=port49-broker: LDAP result 49` | 49 | 6ms |
| SASL EXTERNAL over StartTLS, a certificate from the lab directory CA (in the DC's Root store, not in NTAuth), unmapped (carried question b) | refused: `LDAP Result Code 49 "Invalid Credentials": bind external as CN=port49-broker,O=port49 lab: LDAP result 49` | 49 | 4ms |
| GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` 2 (port49 sends no channel binding token) | refused: `LDAP Result Code 49 "Invalid Credentials": bind gssapi as port49@CORP.EXAMPLE.COM: LDAP result 49` | 49 | 8ms |
| SASL EXTERNAL over StartTLS, mapped, `LdapEnforceChannelBinding` 2 | accepted; WhoAmI `u:CORP\port49`; a search for alice found 1 entry | 0 | 7ms |
| simple bind over LDAPS, `LdapEnforceChannelBinding` 2 | accepted; a search for alice found 1 entry | 0 | 5ms |

Whether the DC's LDAPS asked the client for a certificate (what EXTERNAL needs): the server sent a CertificateRequest listing 0 acceptable CA name(s).

### A refused bind through the pool (a wrong password)

| check | observed |
|---|---|
| `Resolver.Verify` | `directory: no server answered (the last: dc1.corp.example.com:30636: LDAP Result Code 49 "Invalid Credentials": bind simple as CN=port49,OU=Svc,DC=corp,DC=example,DC=com: LDAP result 49)` |
| `Resolver.Map`, nothing stored | `directory: no server answered: no membership is stored for this certificate (directory: no server answered (the last: a directory server refused the bind; no server is bound until the hold-off ends))` |
| counters | queries{refused}=1, queries{fault}=0, server_up=1 |
| lines the pool said | 4, none holding a password |

What the DC logged during the binds: KDC 7: The Security Account Manager failed a KDC request in an unexpected way. The error is in the data field. The account name was and lookup type 0x108.; Schannel 36928: Could not retrieve an OCSP response. The Failure Reason is: REASON_OCSP_RESPONSE_RETRIEVAL_ERROR The OCSP Url is: The previous OCSP response contained the follo...; Schannel 36928: Could not retrieve an OCSP response. The Failure Reason is: REASON_OCSP_RESPONSE_RETRIEVAL_ERROR The OCSP Url is: The previous OCSP response contained the follo...; DS 3039: The following client performed an LDAP bind over SSL/TLS and failed the channel binding token validation. Either the client did not pass channel binding tokens ...; DS 2889: The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without requesting signing (integrity verification), or performed a simple bind...

### The SID extension and objectSid

| certificate | SID extension | objectSid | equal |
|---|---|---|---|
| alice's, AD CS `User` template, requested as alice | `S-1-5-21-3624651544-2943056936-309724280-1103` | `S-1-5-21-3624651544-2943056936-309724280-1103` | true |
| a KDC-EKU certificate from the DC's store (`KerberosAuthentication`; not necessarily the one the KDC presents) | `S-1-5-21-3624651544-2943056936-309724280-1001` | `S-1-5-21-3624651544-2943056936-309724280-1001` | true |
| alice's, AD CS `OfflineRouter` (subject from the request) | none: the certificate carries 0 SID extension values; exactly one maps | `S-1-5-21-3624651544-2943056936-309724280-1103` | false |

| port49's mapping on the DC's certificates (asserted: port49's guarantees, not the DC's) | observed |
|---|---|
| `sid`, alice's `User` certificate | ok as `user:alice@corp.example.com` |
| `issuer_serial`, alice's `OfflineRouter` certificate, alice holding port49's form | ok as `user:alice@corp.example.com` |
| `issuer_serial`, the comma CA's certificate, alice holding the quoted form (recorded, not asserted (Task 7a)) | ok |

### Also asserted: port49's mapping guarantees (not part of L43's claim)

These are port49's own guarantees on a real directory and close nothing in the register. The `issuer_serial` and `sid` rows compare port49's `X509:<I>...<SR>...` form and its SID extension with what port49 itself wrote or built: they show the value survives filter escaping and a string-form `objectSid` matches, not that a DC accepts it (L44).

| check | observed |
|---|---|
| alice's certificate under `san_email`, issuer pinned to `CN=lab-users-CA,DC=corp,DC=example,DC=com` | ok as `user:alice@corp.example.com`, username `alice`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| alice's certificate under `issuer_serial`, the `altSecurityIdentities` the seed wrote from `directory.ADIssuerSerial` | ok as `user:alice@corp.example.com`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| alice's certificate under `sid`, the extension holding her `objectSid` | ok as `user:alice@corp.example.com`, DN `CN=alice,OU=Staff,DC=corp,DC=example,DC=com` |
| eve's certificate under `san_email` (`eve` and `eve2` hold one `mail`) | `directory: identity_ambiguous: 2 or more entries (CN=eve,OU=Staff,DC=corp,DC=example,DC=com; CN=eve2,OU=Contractors,DC=corp,DC=example,DC=com)` |
| `principal_attribute: mail`; `Set-ADObject` edit gives bob alice's `mail`; alice's certificate under `issuer_serial` | `directory: identity_ambiguous: mail "alice@corp.example.com" is held by CN=alice,OU=Staff,DC=corp,DC=example,DC=com and by CN=bob,OU=Staff,DC=corp,DC=example,DC=com: two people under one principal is ...` |
| the same, `Verify` of `user:alice@corp.example.com` | `directory: identity_ambiguous: 2 or more entries (CN=alice,OU=Staff,DC=corp,DC=example,DC=com; CN=bob,OU=Staff,DC=corp,DC=example,DC=com)` |
| bob's `mail` restored, alice's certificate again | ok |
| `netops-oncall` named by two groups (`OU=G` and `OU=Users-Can-Create`), groups base the whole domain, carol (direct member of the first) | names `(none)`; DNs `CN=netops-oncall,OU=G,DC=corp,DC=example,DC=com`; the line said: `directory: selected dc1.corp.example.com:30636 (no site, priority 100) directory: group name(s) netops-oncall are shared by two or more groups under DC=corp,DC=example,DC=com; a subject naming one matches no one (use its DN)` |

### KB5014754: what the DC itself maps

Each certificate is offered to the KDC by PKINIT (MIT `kinit`) as `alice@CORP.EXAMPLE.COM`, alice holding exactly the `altSecurityIdentities` the row names; the KDC is restarted after each `StrongCertificateBindingEnforcement` change. The first row of each block is the control. "refused" means the KDC itself refused, for no setup reason, while the control got a TGT; anything else is INVALID (R6), with the reason. The last row of each block is the broker's AD CS certificate by SASL EXTERNAL over StartTLS (on LDAPS it is rejected, [MS-ADTS] 5.1.1.2), port49's form on its account.

| `StrongCertificateBindingEnforcement` | certificate | `altSecurityIdentities` held | outcome | the KDC said | DC events | time |
|---|---|---|---|---|---|---|
| absent | control: AD CS `OfflineRouter`, alice holding the strong `X509:<SKI>` mapping | `X509:<SKI>afac1a9d8e7139e787e6a923909854a31c675f7c` | **TGT issued** | — | (none) | 471ms |
| absent | AD CS `OfflineRouter` (UPN SAN, no SID extension) | (none) | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 453ms |
| absent | the same, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>050000000000D7CF40EDDFFA52170500000031` | **TGT issued** | — | (none) | 438ms |
| absent | the same, alice holding the issuer least significant RDN first | `X509:<I>CN=corp-L44-CA,DC=corp,DC=example,DC=com<SR>050000000000D7CF40EDDFFA52170500000031` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 446ms |
| absent | the same, alice holding the serial in certificate byte order | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>31000000051752FADFED40CFD7000000000005` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 440ms |
| absent | AD CS `User`, requested as alice (SID extension) | (none) | **TGT issued** | — | (none) | 480ms |
| absent | a CA whose CN holds a comma (`lab-users, comma-CA`), alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 461ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 460ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\, comma-CA<SR>745BD75D7F2F5714` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 470ms |
| absent | a CA whose CN holds a backslash (`lab-users\back-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 434ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 448ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\\back-CA<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 455ms |
| absent | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\back-CA<SR>0A390B851B34132C` | **TGT issued** | — | (none) | 446ms |
| absent | a CA whose CN holds a forward slash (`lab-users/slash-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 448ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 434ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 455ms |
| absent | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 468ms |
| absent | a CA whose CN holds a plus sign (`lab-users+plus-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 463ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 445ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 449ms |
| absent | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 475ms |
| absent | a CA whose CN holds an inner quote (`lab-users "q" CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 457ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 443ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users \"q\" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 445ms |
| absent | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users "q" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 449ms |
| absent | a CA whose CN holds a leading space (` lab-users lead-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 466ms |
| absent | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 458ms |
| absent | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=\ lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 437ms |
| absent | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN= lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 438ms |
| absent | the lab users CA, a serial whose top bit is set, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 448ms |
| absent | the same, alice holding the serial with its DER sign byte | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 462ms |
| absent | the broker's AD CS certificate, SASL EXTERNAL over StartTLS | port49's form, on port49 | **bound** as `u:CORP\port49` |  | (none) | 8ms |
| 1 | control: AD CS `OfflineRouter`, alice holding the strong `X509:<SKI>` mapping | `X509:<SKI>afac1a9d8e7139e787e6a923909854a31c675f7c` | **TGT issued** | — | (none) | 455ms |
| 1 | AD CS `OfflineRouter` (UPN SAN, no SID extension) | (none) | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 458ms |
| 1 | the same, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>050000000000D7CF40EDDFFA52170500000031` | **TGT issued** | — | (none) | 471ms |
| 1 | the same, alice holding the issuer least significant RDN first | `X509:<I>CN=corp-L44-CA,DC=corp,DC=example,DC=com<SR>050000000000D7CF40EDDFFA52170500000031` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 459ms |
| 1 | the same, alice holding the serial in certificate byte order | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>31000000051752FADFED40CFD7000000000005` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 469ms |
| 1 | AD CS `User`, requested as alice (SID extension) | (none) | **TGT issued** | — | (none) | 472ms |
| 1 | a CA whose CN holds a comma (`lab-users, comma-CA`), alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 495ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 448ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\, comma-CA<SR>745BD75D7F2F5714` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 439ms |
| 1 | a CA whose CN holds a backslash (`lab-users\back-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 455ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 453ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\\back-CA<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 461ms |
| 1 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\back-CA<SR>0A390B851B34132C` | **TGT issued** | — | (none) | 455ms |
| 1 | a CA whose CN holds a forward slash (`lab-users/slash-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 432ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 482ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 492ms |
| 1 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 446ms |
| 1 | a CA whose CN holds a plus sign (`lab-users+plus-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 485ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 466ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 440ms |
| 1 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 454ms |
| 1 | a CA whose CN holds an inner quote (`lab-users "q" CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 479ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 462ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users \"q\" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 466ms |
| 1 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users "q" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 438ms |
| 1 | a CA whose CN holds a leading space (` lab-users lead-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 480ms |
| 1 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 460ms |
| 1 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=\ lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 444ms |
| 1 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN= lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 452ms |
| 1 | the lab users CA, a serial whose top bit is set, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 454ms |
| 1 | the same, alice holding the serial with its DER sign byte | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 440ms |
| 1 | the broker's AD CS certificate, SASL EXTERNAL over StartTLS | port49's form, on port49 | **bound** as `u:CORP\port49` |  | (none) | 7ms |
| 2 | control: AD CS `OfflineRouter`, alice holding the strong `X509:<SKI>` mapping | `X509:<SKI>afac1a9d8e7139e787e6a923909854a31c675f7c` | **TGT issued** | — | (none) | 456ms |
| 2 | AD CS `OfflineRouter` (UPN SAN, no SID extension) | (none) | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 465ms |
| 2 | the same, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>050000000000D7CF40EDDFFA52170500000031` | **TGT issued** | — | (none) | 450ms |
| 2 | the same, alice holding the issuer least significant RDN first | `X509:<I>CN=corp-L44-CA,DC=corp,DC=example,DC=com<SR>050000000000D7CF40EDDFFA52170500000031` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 461ms |
| 2 | the same, alice holding the serial in certificate byte order | `X509:<I>DC=com,DC=example,DC=corp,CN=corp-L44-CA<SR>31000000051752FADFED40CFD7000000000005` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 457ms |
| 2 | AD CS `User`, requested as alice (SID extension) | (none) | **TGT issued** | — | (none) | 452ms |
| 2 | a CA whose CN holds a comma (`lab-users, comma-CA`), alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 487ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>745BD75D7F2F5714` | **TGT issued** | — | (none) | 491ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\, comma-CA<SR>745BD75D7F2F5714` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 459ms |
| 2 | a CA whose CN holds a backslash (`lab-users\back-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 482ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users\back-CA"<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 464ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\\back-CA<SR>0A390B851B34132C` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 463ms |
| 2 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\back-CA<SR>0A390B851B34132C` | **TGT issued** | — | (none) | 485ms |
| 2 | a CA whose CN holds a forward slash (`lab-users/slash-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 440ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users/slash-CA"<SR>5EF013ADBECFFF3D` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 454ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 461ms |
| 2 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users/slash-CA<SR>5EF013ADBECFFF3D` | **TGT issued** | — | (none) | 474ms |
| 2 | a CA whose CN holds a plus sign (`lab-users+plus-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 449ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users+plus-CA"<SR>092846873D94AA3E` | **TGT issued** | — | (none) | 434ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 437ms |
| 2 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users+plus-CA<SR>092846873D94AA3E` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 471ms |
| 2 | a CA whose CN holds an inner quote (`lab-users "q" CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 463ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users ""q"" CA"<SR>40B750B1B542D824` | **TGT issued** | — | (none) | 485ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users \"q\" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 466ms |
| 2 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users "q" CA<SR>40B750B1B542D824` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 447ms |
| 2 | a CA whose CN holds a leading space (` lab-users lead-CA`), alice holding port49's form (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 437ms |
| 2 | the same, alice holding the value quoted as CertNameToStr quotes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=" lab-users lead-CA"<SR>8A27B222215A4123` | **TGT issued** | — | (none) | 463ms |
| 2 | the same, alice holding the value escaped as RFC 4514 escapes it (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN=\ lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | KDC 39: The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping,... | 473ms |
| 2 | the same, alice holding the value as it is, neither quoted nor escaped (recorded, not asserted (Task 7a)) | `X509:<I>DC=com,DC=example,DC=corp,CN= lab-users lead-CA<SR>8A27B222215A4123` | refused | -1765328318/Certificate mismatch; kinit: Certificate mismatch while getting initial credentials | (none) | 461ms |
| 2 | the lab users CA, a serial whose top bit is set, alice holding port49's form | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 470ms |
| 2 | the same, alice holding the serial with its DER sign byte | `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>C3494C0A13EC21538000` | **TGT issued** | — | (none) | 478ms |
| 2 | the broker's AD CS certificate, SASL EXTERNAL over StartTLS | port49's form, on port49 | **bound** as `u:CORP\port49` |  | (none) | 7ms |

### OR-1: a mapped certificate while the DC's KDC is stopped

| mechanism | outcome | LDAP result | time |
|---|---|---|---|
| SASL EXTERNAL over StartTLS, mapped, the KDC up (e5's control, before) | accepted; WhoAmI `u:CORP\port49`; a search for alice found 1 entry | 0 | 8ms |
| SASL EXTERNAL over StartTLS, mapped, **the DC's KDC stopped** | refused: `LDAP Result Code 49 "Invalid Credentials": bind external as CN=port49-broker: LDAP result 49` | 49 | 6ms |
| SASL EXTERNAL over StartTLS, mapped, the KDC started again (e5's control, after) | accepted; WhoAmI `u:CORP\port49`; a search for alice found 1 entry | 0 | 7ms |

The KDC's outage, on the DC's clock: stopped 2026-10-07T12:12:44.2121883Z, its start task scheduled for 2026-10-07T12:14:13.3996080Z and run at 2026-10-07T12:14:13.0000000Z (the Task Scheduler's trigger is whole seconds, so the run time can precede the scheduled instant by under a second), found running at 2026-10-07T12:14:15.6339818Z (result 0). An SSH logon fails while the KDC is down, so the stop registered that task and nothing called the DC until it had run. e5's bind ended 1.27s after the stop was asked.

