---
title: Workloads
description: Giving a cron job or a pod its own identity at the device, with a workload certificate or a Kubernetes token, and grouping workloads in a directory.
---

# Workloads

A workload is a program that logs in to devices without a person: a configuration backup, a compliance check, a
deployment job. It needs an identity of its own so that its access is granted, logged and revoked on its own, not
borrowed from a person's. port49 knows two kinds:

| Identity | Proof | Principal | Use it when |
|---|---|---|---|
| A **workload certificate** | an x509 certificate with a SPIFFE ID in a URI SAN, from a CA you run | `spiffe://<trust domain>/<path>` | the job runs on a host you manage, such as a cron job or a backup server |
| A **Kubernetes service account token** | the pod's projected token, checked against the cluster's published keys | `system:serviceaccount:<namespace>:<name>` | the job runs in a cluster, and you want no CA and no secret at rest |

Either is a peer of the other, and neither is required. The concepts are on [Identities](../concepts/identities.md)
and [Trust domains](../concepts/trust-domains.md); how a workload becomes a subject, and why it gets its own
device login, is on [Roles and grants](roles-and-grants.md#machine_group).

The workload anchor and the people's anchor must be in **unrelated** hierarchies, so that nothing a workload CA signs
can be read as a person.

## Workload certificates and step-ca

The worked example is Oxidized, the configuration backup tool, with [step-ca](https://smallstep.com/docs/step-ca)
as the workload CA. The same shape fits any job on a host: the host holds a certificate valid for a few hours, a
renewal timer replaces it, and the broker verifies it against the CA you name.

Four rules carry the design:

1. **The workload CA is the trust root, and it is yours.** The broker's `broker.identity.machines` entry names the
   CA's certificate (`trust_anchor_file`) and the SPIFFE trust domains it may speak for (`spiffe_trust_domains`).
   Anyone who can get that CA to sign a certificate with a SPIFFE ID inside those domains is that workload.
2. **Give each host its own provisioner**, with the SPIFFE ID fixed in the provisioner's template (`uris`), so a
   host can only ever obtain its own name. A shared provisioner lets any enrolled host ask for another's.
3. **The certificate must name the CA's CRL.** port49 applies step-ca's CRL, which carries a critical issuing
   distribution point, only to a certificate whose CRL distribution points name it exactly. A certificate without
   that name is undecided, and the broker refuses it with **503 `certificate_status_unavailable`** (under
   `broker.certificate_status.on_unavailable: refuse`, the default; `allow` would admit it and say so). The template
   below adds the extension. Replace its URL with the name your CA's CRL carries (`crl.idpURL`
   when set, otherwise `https://<the first of ca.json's dnsNames>/1.0/crl`) and check it with
   `step crl inspect`. This was measured on step-ca ([L48](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L48-step_ca.md)).
4. **For an immediate stop, use `port49 revoke`** ([Revocation](revocation.md)) rather than waiting for the CA's CRL
   to be republished and read.

The provisioner's template, `step-ca-workload.tpl`, is step's default leaf with `clientAuth` alone and the one
addition:

```text
--8<-- "examples/oxidized/step-ca-workload.tpl"
```

The broker side is the verifier below; its keys are in the
[port49d reference](../reference/config/port49d.md). Nothing about the broker's TLS is special: workloads reach it
over the same listener as everyone ([TLS](../operate/tls.md)).

```yaml
broker:
  identity:
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workload-ca.pem
        spiffe_trust_domains: ["example.com"]
```

Enrolling, renewing, the broker policy snippet, what `port49 policy test` says about it and what to do on a bad
day are in the Oxidized guide at the end of this page. Its section 7a covers host keys: they are OpenSSH's job, and
the guide uses `accept-new` and `known_hosts`.

## The workload directory

By default a workload's groups come only from the policy: a subject names the SPIFFE ID in `identity:` and the
grant follows. At fleet scale you may want the other thing, a **directory group of workloads**, so that adding a host
to `cn=ci-runners` grants it what the group has, with no policy edit. That is the `machine_group:` subject:

```yaml
subjects:
  - name: ci_runners
    machine_group: "cn=ci-runners,ou=groups,dc=example,dc=com"
  - name: svc_backup
    identity: ["spiffe://example.com/host/backup-01"]
    username: svc-backup
```

A `machine_group:` subject matches workloads only. It takes no `username:` (the name comes from the entry), and it
never sits beside `group:` or `identity:` in one subject. `port49 policy test` says so when you write one (output
re-run for the policy above, with a third subject, `svc_mapped`, that names a SPIFFE ID and no username):

```text
report: group_subject: subject "ci_runners" is a machine_group: subject: it mints only with broker.identity.machines[].directory configured (a workload certificate's directory mapping), through which the broker matches a workload to the group; explain and policy tests evaluate it by name
report: workload_no_username: subject "svc_mapped" declares no username: it mints only under broker.identity.machines[].directory, where its entry's username_attribute names it
```

### Opting in

The broker finds a workload's entry through a `directory:` block on the machine verifier. It is off until you write
it, and all four keys are required:

```yaml
broker:
  identity:
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workload-ca.pem
        spiffe_trust_domains: ["example.com"]
        directory:
          kind: spiffe_id
          attribute: uid
          allow_weak: true
          issuers: ["CN=Example Workload CA,O=Example"]
```

- `kind: spiffe_id` is the only kind. The entry holds the workload's SPIFFE ID in `attribute`.
- `attribute` has **no default**, and it must not be the attribute `broker.directory` uses for `username_attribute` or
  `principal_attribute`: the config refuses it. Use `uid` or `description`. **Never `wWWHomePage` or `url` on Active
  Directory:** the entry itself can write those whatever the OU's ACL says, so a workload could put another
  workload's SPIFFE ID on itself. This was measured on a service account's entry
  ([L50](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L50-windows_ad.md)), and port49d says it at
  start if you choose one of them.
- `allow_weak: true` acknowledges what the mapping is: a SPIFFE ID is matched by a lookup, not a signature, so it is
  only as strong as who can write `attribute`. It is required, with `issuers`, the RFC 4514 DNs of the CAs whose
  certificates this mapping accepts.

### What it costs

**Every workload this verifier accepts then needs exactly one entry**, those whose subject names them in `identity:`
included. port49d prints it at start:

```text
directory: workload certificates map by spiffe_id (weak, pinned to <issuers>) through <attribute> under <filter>; every workload this verifier accepts must have exactly one entry holding its SPIFFE ID: none is refused identity_unmapped, two or more identity_ambiguous, and while the directory is down past grace it is refused directory_unavailable
```

(Shortened here: the line goes on to name where the username comes from.) In the operator's terms:

| Situation | The workload sees | What to do |
|---|---|---|
| No entry holds its SPIFFE ID | refused `identity_unmapped` | add the entry, or the value to it |
| Two entries hold it | refused `identity_ambiguous` | remove one |
| The directory is down past `grace` | refused `directory_unavailable`, and `port49 workload` exits **75** | restore the directory; pre-warm keeps recently mapped workloads working until then |
| The directory is down longer than `session.staleness_ceiling` | live device sessions deny `context_stale` | the same |

Keep pre-warm on, since it is what lets a mapped workload mint through a short directory outage. A workload whose
entry changed identity (a host rebuilt with a new directory entry, say) is released from its pin with
`port49 directory forget spiffe://example.com/host/backup-01`. It is run through your agent and needs the
`forget_principals` right and a press of your security key.

The workload's login name comes from the subject that lists its SPIFFE ID (`username:`), else from the entry's
`username_attribute`. The entry needs a unique canonical one either way.

### Whoever writes `attribute` chooses the groups

Anyone who can write `attribute` on an entry decides which workload takes that entry's group memberships. So it must
be writable **only by directory administrators**, and you should alert on writes to it: Windows event 5136 or 4662,
and on Samba `dsdb_json_audit` at level 5. port49 prescribes no deny ACL; the measured behaviour is in the
[L50 note for Samba](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L50-samba_ad.md).

**A person's entry is never a workload.** An entry that holds a SPIFFE ID in `attribute` is refused as a person, and
the reverse. Still, writing a SPIFFE ID onto a person's entry takes effect at the next directory refresh, whereas
`port49 revoke --principal user:<email>` is immediate; until the refresh the entry could serve both domains. Only a
directory administrator can open that window, which is the same person who could add the user to any group.
Revoke the person, then fix the entry ([Revocation](revocation.md)).

The directory itself is configured under `broker.directory`; see
[Identity providers](identity-providers.md#the-directory).

## Kubernetes service accounts

Nothing here makes a cluster necessary or preferred: it is the path for a job that already runs in one. The pod's
projected token is the identity, with no CA to run and no secret at rest. The kubelet writes and rotates the token,
and the broker verifies it against the cluster's published keys.

!!! warning "Unmeasured"
    Managed Kubernetes services (GKE, EKS, AKS) are unmeasured: whether their token issuers, discovery and key
    endpoints behave as the kind cluster did is unknown until they are measured (lab register entry L70, open).
    The Kubernetes guide below is measured on kind only; read each claim for the cell that backs it.

## The guides in full

Everything from here to the end of the page is two example READMEs verbatim, the Oxidized one first and the
Kubernetes one after it. Each numbers its own sections from 1, so the second "1." below is the Kubernetes guide's
"What it is". Section headings of the Oxidized guide run from "What runs where" to "What L49 measured, and what it
did not".

--8<-- "examples/oxidized/README.md:8:260"

--8<-- "examples/kubernetes/README.md:16:151"
