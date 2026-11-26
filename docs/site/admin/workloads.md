---
title: Workloads
description: Giving a cron job or a pod its own identity at the device, with a workload certificate or a Kubernetes token, and grouping workloads in a directory.
---

# Workloads

A workload is a program that logs in to devices without a person: a configuration backup, a compliance check, a
deployment job. It has an identity of its own, so its access is granted, logged and revoked apart from any person's.

| Identity | Proof | Principal | Use it when | Guide |
|---|---|---|---|---|
| A **workload certificate** | an x509 certificate with a SPIFFE ID in a URI SAN, from a CA you run | `spiffe://<trust domain>/<path>` | the job runs on a host you manage, such as a cron job or a backup server | [Oxidized and step-ca](workloads-oxidized.md) |
| A **Kubernetes service account token** | the pod's projected token, checked against the cluster's published keys | `system:serviceaccount:<namespace>:<name>` | the job runs in a cluster, and you want no CA and no secret at rest | [Kubernetes service accounts](workloads-kubernetes.md) |

Neither is required. The concepts are on [Identities](../concepts/identities.md) and
[Trust domains](../concepts/trust-domains.md). How a workload becomes a subject, and why it gets its own device login,
is on [Roles and grants](roles-and-grants.md#machine_group). The workload anchor and the people's anchor must be in
unrelated hierarchies, so that nothing a workload CA signs can be read as a person.

## Workload certificates and step-ca

The host holds a certificate valid for a few hours, a renewal timer replaces it, and the broker verifies it against the
CA you name. The guide uses Oxidized with [step-ca](https://smallstep.com/docs/step-ca). Four rules carry the design:

1. **The workload CA is the trust root, and it is yours.** The broker's `broker.identity.machines` entry names the
   CA's certificate (`trust_anchor_file`) and the SPIFFE trust domains it may speak for (`spiffe_trust_domains`).
   Anyone who can get that CA to sign a SPIFFE ID inside those domains is that workload.
2. **Give each host its own provisioner**, with the SPIFFE ID fixed in the provisioner's template (`uris`), so a host
   can only obtain its own name. A shared provisioner lets any enrolled host ask for another's.
3. **The certificate must name the CA's CRL.** port49 applies step-ca's CRL, which carries a critical issuing
   distribution point, only to a certificate whose CRL distribution points name it exactly. Any other certificate is
   undecided and the broker refuses it with **503 `certificate_status_unavailable`** (under
   `broker.certificate_status.on_unavailable: refuse`, the default; `allow` would admit it and say so). The template
   below adds the extension. Replace its URL with the name your CA's CRL carries (`crl.idpURL` when set, otherwise
   `https://<the first of ca.json's dnsNames>/1.0/crl`) and check it with `step crl inspect`. Measured on step-ca
   ([L48](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L48-step_ca.md)).
4. **For an immediate stop, use `port49 revoke`** ([Revocation](revocation.md)) instead of waiting for the CA's CRL to
   be republished and read.

The provisioner's template, `step-ca-workload.tpl`, is step's default leaf with `clientAuth` alone and that one
addition:

```text
--8<-- "examples/oxidized/step-ca-workload.tpl"
```

The broker's verifier is below, with its keys in the [port49d reference](../reference/config/port49d.md). Workloads
reach the broker over the same listener as everyone ([TLS](../operate/tls.md)).

```yaml
broker:
  identity:
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workload-ca.pem
        spiffe_trust_domains: ["example.com"]
```

Enrolling, renewing, the broker policy snippet and the bad-day table are in the [Oxidized guide](workloads-oxidized.md).
Host keys are OpenSSH's job: the guide uses `accept-new` and `known_hosts` (its section 7a).

## The workload directory

By default a workload's groups come only from the policy: a subject names the SPIFFE ID in `identity:`. At fleet
scale you can use a directory group instead, so that adding a host to `cn=ci-runners` grants it what the group has,
with no policy edit. That is the `machine_group:` subject. It matches workloads only, takes no `username:` (the name
comes from the entry) and never sits beside `group:` or `identity:` in one subject.

```yaml
subjects:
  - name: ci_runners
    machine_group: "cn=ci-runners,ou=groups,dc=example,dc=com"
  - name: svc_backup
    identity: ["spiffe://example.com/host/backup-01"]
    username: svc-backup
```

`port49 policy test` reports it (re-run for this policy with a third subject, `svc_mapped`, that names a SPIFFE ID and
no username):

```text
report: group_subject: subject "ci_runners" is a machine_group: subject: it mints only with broker.identity.machines[].directory configured (a workload certificate's directory mapping), through which the broker matches a workload to the group; explain and policy tests evaluate it by name
report: workload_no_username: subject "svc_mapped" declares no username: it mints only under broker.identity.machines[].directory, where its entry's username_attribute names it
```

### Opting in

The broker finds a workload's entry through a `directory:` block on the machine verifier. It is off until you write it,
and all four keys are required:

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
- `attribute` has **no default**, and the config refuses the attribute `broker.directory` uses for `username_attribute`
  or `principal_attribute`. Use `uid` or `description`. **Never `wWWHomePage` or `url` on Active Directory:** the
  entry itself can write those whatever the OU's ACL says, so a workload could put another workload's SPIFFE ID on
  itself ([L50](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L50-windows_ad.md)). port49d says so
  at start if you choose one.
- `allow_weak: true` acknowledges that a SPIFFE ID is matched by a lookup, not a signature, so the mapping is only as
  strong as who can write `attribute`. `issuers` are the RFC 4514 DNs of the CAs whose certificates it accepts.

**Every workload this verifier accepts then needs exactly one entry**, those whose subject names them in `identity:`
included. port49d prints the rule at start:

```text
directory: workload certificates map by spiffe_id (weak, pinned to <issuers>) through <attribute> under <filter>; every workload this verifier accepts must have exactly one entry holding its SPIFFE ID: none is refused identity_unmapped, two or more identity_ambiguous, and while the directory is down past grace it is refused directory_unavailable
```

(The line goes on to name where the username comes from.)

| Situation | The workload sees | What to do |
|---|---|---|
| No entry holds its SPIFFE ID | refused `identity_unmapped` | add the entry, or the value to it |
| Two entries hold it | refused `identity_ambiguous` | remove one |
| The directory is down past `grace` | refused `directory_unavailable`, and `port49 workload` exits **75** | restore the directory; pre-warm keeps recently mapped workloads working until then |
| The directory is down longer than `session.staleness_ceiling` | live device sessions deny `context_stale` | the same |

Keep pre-warm on: it lets a mapped workload mint through a short directory outage. A workload whose entry changed
identity (a host rebuilt with a new directory entry) is released from its pin with
`port49 directory forget spiffe://example.com/host/backup-01`, run through your agent. It needs the `forget_principals`
right and a press of your security key. The login name comes from the subject's `username:`, else from the entry's
`username_attribute`; the entry needs a unique canonical one either way.

### Who can write the attribute

Whoever can write `attribute` on an entry decides which workload takes that entry's group memberships. Make it writable
**only by directory administrators** and alert on writes to it: Windows event 5136 or 4662, and on Samba
`dsdb_json_audit` at level 5. port49 prescribes no deny ACL; the measured behavior is in the
[L50 note for Samba](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L50-samba_ad.md).

**A person's entry is never a workload.** An entry that holds a SPIFFE ID in `attribute` is refused as a person, and the
reverse. One window remains: a SPIFFE ID written onto a person's entry takes effect at the next directory refresh,
while `port49 revoke --principal user:<email>` is immediate, so until then the entry could serve both domains. Only a
directory administrator can open it, the same person who could add the user to any group. If it happens, revoke the
person, then fix the entry ([Revocation](revocation.md)).

The directory itself is configured under `broker.directory`; see [The directory](directory.md).

## Kubernetes service accounts

Nothing here makes a cluster necessary or preferred: it is the path for a job that already runs in one. The pod's
projected token is the identity, with no CA to run and no secret at rest. The kubelet writes and rotates the token, and
the broker verifies it against the cluster's published keys. The steps are in the
[Kubernetes guide](workloads-kubernetes.md).

!!! warning "Unmeasured"
    Managed Kubernetes services (GKE, EKS, AKS) are unmeasured: whether their token issuers, discovery and key
    endpoints behave as the kind cluster did is unknown until they are measured (lab register entry
    [L70](../reference/lab-register.md#l70), open). The Kubernetes guide is measured on kind only.
