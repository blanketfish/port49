# Oxidized with port49 workload certificates

> **Provisional on lab L49** (policy engine spec §15). `port49-oxidized-run`, `config` and the
> `config_backup` role in `policy.yaml` are what the design says Oxidized needs. They stay
> provisional until L49 closes, and are corrected to what it measures.

Oxidized backs up network devices over SSH with a username and password. port49 gives it a
short-lived token per device as that password, so no standing credential exists on the Oxidized
host. Three files fit together:

- `port49-oxidized-run` runs `port49 workload token`, writes Oxidized's `router.db`, and asks
  Oxidized to back each node up now.
- `config` is Oxidized's configuration. It reads `router.db`, and its own interval is set a week
  out so that its schedule tries as few nodes as possible with an expired token. How often it
  still does is what L49 measures.
- `policy.yaml` is the port49 policy: a `config_backup` role that confines the Oxidized host to
  `show` commands where port49 authorizes commands (see §5a).

## 1. What runs where

Oxidized and `port49-oxidized-run` run on one host, under one user. The workload certificate and
its key are that user's files. Cron runs the wrapper once per backup window:

```
17 2 * * *  PORT49_BROKER=https://port49-broker.example.com:8443 PORT49_BROKER_CA=... \
            PORT49_CERT=... PORT49_KEY=... /usr/local/bin/port49-oxidized-run
```

The wrapper's environment is documented at the top of the script. `OXIDIZED_NODES` is a file of
device names, one a line.

## 2. Enrollment, once

Get a certificate whose one URI SAN is the host's SPIFFE ID (for example
`spiffe://corp.example.com/host/oxidized-01`) from your workload CA. step-ca, as L48
measures it, is one such CA; any CA that puts one URI SAN on a client certificate works. Its key
is readable by the Oxidized user alone.

## 3. The workload CA is the trust root

Whoever can get the workload CA to issue a certificate naming a SPIFFE ID *is* that workload to
port49. `spiffe_trust_domains` does not stop one workload impersonating another within a domain.
Restrict each provisioner to the host's own ID: on step-ca, the provisioner's x509 name policy
allows that one URI. L48 measures that it refuses another; this is provisional on L48 until it
closes.

## 4. Renewal

Renewal is your CA's renewer's job (step's `step ca renew --daemon`, or its systemd timer).
port49 needs nothing at a renewal. A late one shows in cron mail and in
`port49_workload_certificates_renewal_late_total`, which each broker replica counts once per
certificate a day. Alert on its increase.

## 5. The broker

```yaml
broker:
  identity:
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workload-ca.pem
        spiffe_trust_domains: [corp.example.com]
```

The anchor is the CA that issues the workload certificates (on step-ca, its intermediate, L48).

- **Its hierarchy.** The workload anchor and the human anchor must be in unrelated hierarchies.
  The start refuses one that signs the other directly. One further down is refused at every
  request whose chain shows it.
- **Its status.** `certificate_status` must cover it: name the CA's CRL in `crls`. An https CRL
  endpoint under a private root needs that root in the broker's trust store (`SSL_CERT_FILE`,
  L48), or sync the CRL to a `file:` source; the deployment shapes are plan 12's. With no source,
  every certificate is refused, and `port49 workload` exits 77, not 75. Turning status checking
  off for everyone is not the fix.

## 5a. What `port49 policy test` says about this snippet

Merged as shipped, `port49 policy test` prints two reports. Neither fails the run, and both are
true.

- **`fallback_exposure` on `arista_eos` and `cisco_nxos`.** `config_backup` is at `admin`, which
  those platforms render as `network-admin`. port49's rules confine the session to the permits in
  `policy.yaml`. But if port49 stops answering while a session is open, and the device's command
  method list falls back to `local`, the device authorizes that session by its role alone. L22
  measured that such a session could change the configuration on vEOS and the N9Kv
  (`tests/lab/results/L22-arista_eos.md`, `L22-cisco_nxos.md`). `admin` is the level spec §2
  gives a backup account so `show running-config` is reachable. Whether a lower level serves
  each Oxidized model is unmeasured (L49). Until it is, the exposure belongs to whoever holds a
  session opened with this run's tokens. Keep `router.db` and the workload key the Oxidized
  user's alone, and keep `PORT49_TTL` to one sweep.
- **`unenforced_rules` on `juniper_junos`.** A policy that pins no `platform_set` renders with
  set 1.0.0. Under 1.0.0, Junos neither asks port49 about a command nor receives the role's rules
  in its session reply, so on Junos the permits above decide nothing: the session gets what the
  device's own login class gives the port49 username. Set 1.1.0 renders them into the session
  reply (spec §8), but the permits here name no Junos command. Which commands Oxidized's `junos`
  model sends, and so which permits a Junos backup needs, is what L49 measures.

## 6. Check before cron

```
port49 workload identity --broker https://port49-broker.example.com:8443 \
  --broker-ca ca.pem --cert w.pem --key w-key.pem
```

prints the SPIFFE ID, the subject and the grants.

## 7. Under cron

Always `--out`, as the wrapper does: cron mails a job's stdout, tokens included. The wrapper gives
`--out` a fresh file each run, so a run that could not write it leaves the last `router.db` alone.
Size `PORT49_TTL` to the whole sweep, since the wrapper queues every node at once. A fleet larger
than one sweep's TTL mints in waves (design §17).

The wrapper never prints a token. If you edit it, do not add `set -x` or an `echo` of one.

## 8. On a bad day

- **Exit 75**: the broker or its store did not answer within the deadline, the output could
  not be written, files could not be made beside `router.db`, another run holds the lock
  (`router.db.lock`), or Oxidized refused a request. The nodes minted before it are queued; with
  none, Oxidized kept its last `router.db` and was not reloaded. Try the next window.
  - **A partial run** replaces `router.db` with the minted nodes alone, so the unminted nodes are
    absent from Oxidized's list until a later run mints them. Their backup history in git is
    untouched.
  - **Oxidized refusing** (each request has a 10 second limit): a failed node prints its name and
    the rest are still queued. A failed reload prints that `router.db` was replaced but Oxidized
    was not reloaded.
- **Exit 77**: nothing was minted and running again will not change it: an expired certificate
  (said before anything connects), a revoked principal, every node denied, or a certificate
  status nothing covers. Oxidized kept its last `router.db`. The stderr line says which.
- **Exit 1**: a node was not permitted, was not minted after a final refusal, or was left out
  because its output line would hold a control character. Its line on stderr says why; the rest
  are queued. A node whose platform has no Oxidized model in the script, or whose name is outside
  `A-Z a-z 0-9 . _ -`, is skipped with a line and exits 1 the same way. A run that has both a
  node of this kind (1) and a failed queue or reload (75) exits 75: 75 takes precedence over 1,
  and the stderr lines name every node either way.
- **To stop the workload**: `port49 revoke --principal spiffe://...`, and revoke the certificate
  at the CA.

The `config` sets `vars: auth_methods` to include `keyboard-interactive`. Arista EOS offers only
`publickey` and `keyboard-interactive` over SSH, and Oxidized's default list does not include the
second, so without this line Oxidized never sends the token to an EOS device. Do not change the
EOS side to suit it.

## 9. Provisional on L49

The REST calls the wrapper makes, the platform-to-model table, the `config` settings (including
`retries: 0` and the interval), and the role's level and permits are not yet measured against
real Oxidized and devices. They are provisional until L49 closes.
