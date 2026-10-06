# L42 — openldap

- **Date measured:** 2026-10-05
- **Platform:** openldap, as a container on `tests/lab/directory/compose.yaml` (no network device)
- **Image version:** @(#) $OpenLDAP: slapd 2.5.13+dfsg-5 (Feb  8 2023 01:56:12) $; image `port49lab/openldap:bookworm` (port49lab/openldap@sha256:1b345ecf5fbfd503fee22ebb8be5ca315ce858b2a57605028ae5f0da62c8e548), built on debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
- **Run:** commit `1deabaa1e3590bc90e0eb5367131447a76f1b14a`, `go test -tags lab ./tests/lab/ -run 'TestL42|TestL43'`
- **Capture:** `tests/lab/evidence/L42-openldap.json`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, the LDAP result code and the duration, recorded by the broker's own client (the wire is LDAPS, so a pcap would be encrypted).
- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.

## Claim

For alice (alice ∈ g-leaf ∈ g-mid ∈ netops-oncall), carol (∈ netops-oncall directly) and dave (∈ g-loop-a, g-loop-a ∈ g-loop-b ∈ g-loop-a): which groups each nested mode returns on each directory; whether member:1.2.840.113556.1.4.1941:= answers, errors or is refused, on the loop too, and how long it takes; whether the user entry's memberOf lists only direct groups; and whether a directory that does not implement the matching rule refuses the filter or answers it empty (policy engine spec §15 L42).

## Observation

### How this directory was configured

- `olcSecurity: tls=1` (every operation must be under TLS), set after the seed was loaded over ldapi.
- `olcTLSVerifyClient: try`: a client certificate is requested and verified when presented.
- `olcAuthzRegexp: "^cn=port49-broker,o=port49 lab$" -> cn=port49,ou=Svc,dc=corp,dc=example,dc=com`.
- The `memberof` overlay with `olcMemberOfRefInt: TRUE`; the seed was loaded with `ldapadd` so the overlay ran.
- `cn=port49` has read access to everything; anonymous has none beyond the root DSE and authentication.

| user | mode | groups returned | result | time |
|---|---|---|---|---|
| alice | in_chain | (none) | ok | 3ms |
| carol | in_chain | (none) | ok | 2ms |
| dave | in_chain | (none) | ok | 2ms |
| alice | recursive | g-leaf, g-mid, netops-oncall | ok | 2ms |
| carol | recursive | netops-oncall | ok | 2ms |
| dave | recursive | g-loop-a, g-loop-b | ok | 2ms |
| alice | direct | g-leaf | ok | 2ms |
| carol | direct | netops-oncall | ok | 1ms |
| dave | direct | g-loop-a | ok | 13ms |

memberOf on alice's entry: cn=g-leaf,ou=G,dc=corp,dc=example,dc=com

