# L42 — samba_ad

- **Date measured:** 2026-10-07
- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** Samba Version 4.17.12-Debian; image `port49lab/samba:bookworm` (port49lab/samba@sha256:2b297ab07e3c0b25c0ff80cca17f6bffb642285b36f20d36bc4cb7b8ecae7f2d), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `e3db1d3808e6faec0d54817e03260af6167b0125`, `go test -tags lab ./tests/lab/ -run 'TestL42|TestL43'`
- **Capture:** `tests/lab/evidence/L42-samba_ad.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is LDAPS, so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.

## Claim

For alice (alice ∈ g-leaf ∈ g-mid ∈ netops-oncall), carol (∈ netops-oncall directly) and dave (∈ g-loop-a, g-loop-a ∈ g-loop-b ∈ g-loop-a): which groups each nested mode returns on each directory; whether member:1.2.840.113556.1.4.1941:= answers, errors or is refused, on the loop too, and how long it takes; whether the user entry's memberOf lists only direct groups; and whether a directory that does not implement the matching rule refuses the filter or answers it empty (policy engine spec §15 L42).

## Observation

### How this directory was configured

- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again under the setting that permits SASL over TLS, each row naming the value in force.
- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).
- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.
- `port49` is an ordinary domain user with its default rights.

| user | mode | groups returned | result | time |
|---|---|---|---|---|
| alice | in_chain | g-leaf, g-mid, netops-oncall | ok | 65ms |
| carol | in_chain | netops-oncall | ok | 43ms |
| dave | in_chain | g-loop-a, g-loop-b | ok | 47ms |
| alice | recursive | g-leaf, g-mid, netops-oncall | ok | 49ms |
| carol | recursive | netops-oncall | ok | 46ms |
| dave | recursive | g-loop-a, g-loop-b | ok | 46ms |
| alice | direct | g-leaf | ok | 46ms |
| carol | direct | netops-oncall | ok | 47ms |
| dave | direct | g-loop-a | ok | 47ms |

memberOf on alice's entry: CN=g-leaf,OU=G,DC=corp,DC=example,DC=com

