---
title: Troubleshooting
description: Where to start when port49 or a device login is not working.
---

# Troubleshooting

Start from what you were told or what you can see. This index has three parts:

- [A person tells you…](#a-person-tells-you): a report of a login that failed.
- [An alert fired](#an-alert-fired): a family of alerts, with what to do and what not to do.
- [A log line says…](#a-log-line-says): a line in port49's log that you do not recognise.

Each entry gives **You see**, **It means**, **Do this** and **Don't**. Two pages go with it: the
[failure matrix](failure-matrix.md) says what each device does when each part of port49 is down, and
[When it will not start](will-not-start.md) covers a process that refuses to run.

Two commands answer most first questions. `port49 explain --device <device>` asks the broker, through
your agent, what port49 would do for you on that device. `port49 store status` (run on a host that
reaches the metrics port) prints whether each store answers, and exits 3 when the directory store does
not.

## A person tells you… {#a-person-tells-you}

### "I cannot log in to one device"

**You see:** one person, or everyone, fails on one device; the same logins work on other devices.

**It means:** the fault is in what port49 knows about that device or that person's grant on it, not in
port49 as a whole. The decision log record for the attempt carries a [reason](../../reference/reason-codes.md):

- `no_grants_matched`: no grant of theirs selects the device.
- `token_not_found` or `token_spent`: the token expired, was already used, or was minted for another
  device. See [tokens, receipts and contexts](../../concepts/tokens-receipts-contexts.md).
- An `unvalidated` record, and a connection the device sees reset with no reply: no key validated what the
  device sent. Its `unvalidated.diagnosis` says why: `no_known_key_matches` (a wrong key),
  `matches_retired` (a retired key), `unadmitted_source` (the address is not in the inventory),
  `device_quarantined`, `admission_refused` or `transport_mismatch` (the device reached the listener it
  does not speak).

**Do this:** have the person run `port49 explain --device <device>`; it names the grant and the reason.
Look the attempt up in the [decision log](../../reference/decision-log.md) by `device.nas`; for an
`unvalidated` record, by the source address. For a key fault, give the device the current key
(`port49 keys show`).

**Don't:** restart port49d or the broker: a fault confined to one device is not cured by a restart, and
a restart discards what the process holds in memory. Don't widen the policy to "see if it works"; the
reason names what is wrong.

### "I cannot log in to any device"

**You see:** logins fail everywhere, or devices ask for a local password. Alerts that may be firing:
[port49_target_down](../../reference/alerts.md#port49_target_down),
[port49_target_absent](../../reference/alerts.md#port49_target_absent),
[port49_store_health_failures_close](../../reference/alerts.md#port49_store_health_failures_close).

**It means:** one of four things:

- port49d is down or unreachable. The devices find TCP 49 refused and fall to their local method.
- port49d is up and its store is failing. It answers a token login `ERROR` `store_unavailable` and every
  command `FAIL` `store_unavailable`, then closes its listeners after 5.5 seconds at the defaults. After
  the close, devices fall to local.
- The broker is down. No new token can be minted; a token already held still logs in, and an open session
  runs on.
- port49d cannot read `meta/witness` after a restore
  ([port49_redemption_restore_unjudged](../../reference/alerts.md#port49_redemption_restore_unjudged)). It
  refuses every token login until a read answers.

**Do this:** `curl <port49d-host>:9049/readyz` and `port49 store status`; read the first alert that fired;
then the matching row of [a cut region at 3am](../stores.md#a-cut-region-at-3am) or the
[failure matrix](failure-matrix.md#at-3am). Use break-glass (the next entry) while you fix it.

**Don't:** restart port49d in a loop to "wake it": while the store is down it waits with its listener
closed and comes back by itself when the store answers. Don't change the devices' AAA configuration to
get around the outage; the devices already fall to local.

### "Break-glass does not work"

**You see:** a local account is refused on a device while port49 is failing.

**It means:** it depends on the platform, and on how long the device has been failing.

- **An `ERROR` is final on some platforms.** While port49d answers `ERROR` (its store is failing), Cisco
  IOS XE refuses the local account
  ([the IOS XE note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-cisco_iosxe.md)),
  and so does Junos under the reference `authentication-order tacplus`
  ([vJunos-router](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-juniper_vjunos-router.md),
  [vSRX](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-error-juniper_vsrx.md)).
  Cisco IOS XR over TLS does the same
  ([the note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L73-cisco_xrd.md)). The
  local account works again once port49d closes its listener (about 5.5 seconds at the defaults) or is
  stopped. Nokia SR Linux logs the local account in at once
  ([the note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L87-nokia_srlinux.md)).
  The device pages say what each other platform does: [IOS XE](../../admin/devices/cisco-ios-xe.md),
  [IOS XR](../../admin/devices/cisco-ios-xr.md), [Junos](../../admin/devices/juniper-junos.md).
- **A device that failed over keeps answering locally for a while.** After its servers failed, the device
  itself answers for a window and sends port49 nothing: a token login is refused during it, and
  break-glass works. Measured (cells f2 and f3 of the closed reference-configuration row): IOS XE 30 to
  39 seconds over TCP
  ([the IOS XE note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md)),
  and about a minute over TLS on one release, measured once; IOS XR 24 to 46 seconds
  ([the XR note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md)). XR
  also accepts any local account's password in that window, including one port49 denies. Expect the
  window after port49d returns from a stop.
  [`deploy/device-aaa/README.md`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/README.md)
  has the cells and the other notes.

!!! warning "Unmeasured"
    Whether an authentication `ERROR` is final on Cisco IOS XR over plain TCP is not measured (L93,
    open). Plan as if break-glass is refused until port49d closes its listener, and keep a console path.

**Do this:** to get to break-glass at once, stop port49d: the devices then find TCP 49 refused and use
their local method. Otherwise wait for the listener to close, or for the device's window to end. Keep a
console or second path for IOS XE and XR. Test break-glass on each platform before you need it.

**Don't:** don't try to shorten a device's window with `deadtime` on IOS XE: it does not accept the
command. Don't leave local accounts on XR beyond break-glass ones, because of the window above.

### "My session ended early"

**You see:** a person's session ended before they expected: `port49 ssh` exits 255, the agent says the
session ended, or a command is denied `context_stale` or `credential_revoked`.

**It means:** one of the planned ends, which the decision log says apart. The `refresh` or `revoke`
record just before the denial names it:

- the session reached `max_session_age`, or a token ran past `receipt_idle_ttl` or `receipt_max_age`
  (`token_spent`);
- an administrator revoked the person ([revocation](../../concepts/revocation.md));
- an OIDC back-channel logout ended it;
- a policy change withdrew their grant, or the directory no longer maps them;
- `context_stale`: no directory refresh verified them for `session.staleness_ceiling` (4 hours by
  default). [port49_directory_refresh_half_ceiling](../../reference/alerts.md#port49_directory_refresh_half_ceiling)
  pages at half of that.

**Do this:** read that person's last records in the decision log. For a stale context, restore the
directory servers; the person signs in again once a refresh passes.

**Don't:** lift a revocation before reading the `revoke` record: it says who made it and why. Don't set
`session.staleness_ceiling` to `0s` to quiet `context_stale`; that removes the bound on how old a
verification may be.

### "It says the principal was revoked at …"

**You see:** `port49 token` or `port49 ssh` prints `this principal was revoked at <time>; nothing is
minted for it until an operator lifts the revocation (port49 revoke --lift)`. A certificate revoked at
its CA reads `this certificate was revoked at its CA (<origin>) and marked at <time>; nothing is minted
for it; request a new certificate`.

**It means:** a standing revocation mark is in the store, and the person is refused `credential_revoked`
at every mint. The mark does not expire.

**Do this:** `port49 revoke --list` shows the marks in force. If the revocation was a mistake, lift it:
`port49 revoke --principal <principal> --lift`. A certificate the CA revoked is not fixed by a lift: the
person needs a new certificate.

**Don't:** undo a revocation by restoring the store from a snapshot: a restore is the one routine
operation that can admit a revoked person. Don't lift a mark you did not read first.

## An alert fired {#an-alert-fired}

Every alert's `runbook_url` opens its section of the [alerts reference](../../reference/alerts.md), which
gives the expression and why the threshold is what it is. The families below follow the rule file. A
`page` alert means port49 is refusing devices or losing records now; a `ticket` costs nothing yet.

### Scrape and process

Alerts: **page** [port49_target_down](../../reference/alerts.md#port49_target_down) (a target does not
answer its scrape) and [port49_target_absent](../../reference/alerts.md#port49_target_absent) (no port49d
target exists, so every device has lost port49 and falls to local); **ticket**
[port49_broker_target_absent](../../reference/alerts.md#port49_broker_target_absent).

**Do this:** check the process (`systemctl status`, `docker compose ps`, `kubectl get pods`) and
`curl :9049/readyz`. Check that the Prometheus job names are `port49d` and `port49-broker`.

**Don't:** read `port49_target_absent` as "port49d is down" before you check the scrape config: a wrong
job name fires it too. See [monitoring](../monitoring.md#scraping).

### Connections

Alerts: **page** [port49_global_cap_shedding](../../reference/alerts.md#port49_global_cap_shedding);
**ticket** [port49_connections_near_cap](../../reference/alerts.md#port49_connections_near_cap).

**Do this:** raise `limits.max_connections` or add replicas. The shed devices were reset on purpose and tried
their next server.

**Don't:** restart port49d to clear it. A restart resets every open connection and does not change the
cap. See [monitoring](../monitoring.md#shedding).

### Keys and the issuing CA

Alerts: **page** [port49_issuing_ca_missing](../../reference/alerts.md#port49_issuing_ca_missing) and
[port49_key_retirement_within_1d](../../reference/alerts.md#port49_key_retirement_within_1d); **ticket**
[port49_key_secret_files_changed](../../reference/alerts.md#port49_key_secret_files_changed),
[port49_issuing_ca_expiring](../../reference/alerts.md#port49_issuing_ca_expiring),
[port49_key_retirement_within_7d](../../reference/alerts.md#port49_key_retirement_within_7d).

**Do this:** for a retirement, read the decision log for the devices still on the key and move them to the
current one before `retire_after`. For a missing CA, copy it from a broker that holds it. See
[key rotation](../../admin/key-rotation.md).

**Don't:** run `init-issuer` on a second broker (it makes a different CA), and don't run `forget-issuer`
(every certificate the old CA issued stops working). Don't take a `port49_key_version_devices` gauge that
fell after a restart as proof the devices moved: a restart blanks it. Don't restart to "apply" a changed
key file until it holds the key you intend; the process keeps the key it holds until the next start.

### Policy, mint and admin calls

Alerts: **page** [port49_admin_touch_refused](../../reference/alerts.md#port49_admin_touch_refused) (an
admin call was refused its hardware-key touch proof: a stolen token or a broken key) and
[port49_per_login_mfa_refused](../../reference/alerts.md#port49_per_login_mfa_refused) (a run of MFA proofs
did not verify); **ticket**
[port49_policy_fail_closed_compositions](../../reference/alerts.md#port49_policy_fail_closed_compositions),
[port49_policy_file_refused](../../reference/alerts.md#port49_policy_file_refused),
[port49_policy_refresh_pending](../../reference/alerts.md#port49_policy_refresh_pending),
[port49_policy_bundle_mismatch](../../reference/alerts.md#port49_policy_bundle_mismatch),
[port49_broker_mint_gate_closed](../../reference/alerts.md#port49_broker_mint_gate_closed),
[port49_devices_generic_platform](../../reference/alerts.md#port49_devices_generic_platform),
[port49_context_refreshes_failed](../../reference/alerts.md#port49_context_refreshes_failed).

**Do this:** for the two pages, read the `admin_touch` or `per_login_mfa` records for the principal and ask the
person; revoke if it was not them. For a policy ticket, `port49 policy test` names the compositions that
fail closed, and a refused policy file means an older policy is still serving: fix the file or its
directory's mode.

**Don't:** write off a touch refusal as a flaky key. Don't read `port49_policy_file_refused` as "the
change took effect".

### Stores

Alerts: **page** [port49_store_directory_unreachable](../../reference/alerts.md#port49_store_directory_unreachable),
[port49_store_marks_feed_down](../../reference/alerts.md#port49_store_marks_feed_down),
[port49_store_calls_refused](../../reference/alerts.md#port49_store_calls_refused),
[port49_crypt_store_key_unknown](../../reference/alerts.md#port49_crypt_store_key_unknown) and
[port49_store_health_failures_close](../../reference/alerts.md#port49_store_health_failures_close);
**ticket** [port49_store_directory_stale](../../reference/alerts.md#port49_store_directory_stale),
[port49_store_logouts_pending](../../reference/alerts.md#port49_store_logouts_pending),
[port49_store_feed_down](../../reference/alerts.md#port49_store_feed_down),
[port49_store_feed_legs_colocated](../../reference/alerts.md#port49_store_feed_legs_colocated),
[port49_store_circuit_open](../../reference/alerts.md#port49_store_circuit_open),
[port49_contexts_reindexed](../../reference/alerts.md#port49_contexts_reindexed),
[port49_contexts_reindex_failures](../../reference/alerts.md#port49_contexts_reindex_failures),
[port49_store_keyspace_unheld](../../reference/alerts.md#port49_store_keyspace_unheld),
[port49_store_client_cert_expiring](../../reference/alerts.md#port49_store_client_cert_expiring),
[port49_crypt_token_open_failures](../../reference/alerts.md#port49_crypt_token_open_failures),
[port49_store_feed_rescans](../../reference/alerts.md#port49_store_feed_rescans),
[port49_ledger_pending](../../reference/alerts.md#port49_ledger_pending),
[port49_ledger_behind](../../reference/alerts.md#port49_ledger_behind),
[port49_store_health_check_failing](../../reference/alerts.md#port49_store_health_check_failing),
[port49_context_cache_stale](../../reference/alerts.md#port49_context_cache_stale).

**Do this:** run `port49 store status`, then follow [a cut region at 3am](../stores.md#a-cut-region-at-3am).
While a region cannot read the directory, revocations made elsewhere do not reach it: to cut someone off
there now, remove their grants from the policy file that region loads, or stop its port49d. For
`port49_store_health_failures_close` the listeners reopen by themselves once the store answers. For
`port49_crypt_store_key_unknown`, fix the key window (a mis-set `PORT49_ENC_V1`) before anything else.

**Don't:** restart port49d to clear a store alert: a process that restarts in a cut serves from a
snapshot only up to `session.staleness_ceiling`. Don't alert on or probe `/readyz` for store health; it
does not report it. Don't point a new key at an old store: give a new key a new id.

### TLS (RFC 9887)

Alerts: **page** [port49_tls_server_certificate_expired](../../reference/alerts.md#port49_tls_server_certificate_expired);
**ticket** [port49_tls_handshake_failures](../../reference/alerts.md#port49_tls_handshake_failures),
[port49_tls_device_certificate_renewal_late](../../reference/alerts.md#port49_tls_device_certificate_renewal_late),
[port49_tls_server_certificate_renewal_late](../../reference/alerts.md#port49_tls_server_certificate_renewal_late),
[port49_tls_cert_status_unavailable](../../reference/alerts.md#port49_tls_cert_status_unavailable),
[port49_crl_next_update_passed](../../reference/alerts.md#port49_crl_next_update_passed),
[port49_inventory_transport_changed](../../reference/alerts.md#port49_inventory_transport_changed).

**Do this:** replace the listener's certificate; the `outcome` label of the handshake alert says why a
handshake failed. See [TLS](../tls.md).

**Don't:** switch devices to plain TCP as a workaround. A device speaks one transport, and the other
listener declines it.

### Identity providers and restores

Alerts: **page** [port49_redemption_restore_unjudged](../../reference/alerts.md#port49_redemption_restore_unjudged);
**ticket** [port49_store_restore_detected](../../reference/alerts.md#port49_store_restore_detected),
[port49_oidc_keys_stale](../../reference/alerts.md#port49_oidc_keys_stale),
[port49_oidc_logouts_failing](../../reference/alerts.md#port49_oidc_logouts_failing),
[port49_oidc_tokens_unavailable](../../reference/alerts.md#port49_oidc_tokens_unavailable),
[port49_workload_certificates_renewal_late](../../reference/alerts.md#port49_workload_certificates_renewal_late).

**Do this:** for `port49_redemption_restore_unjudged`, fix the store or the daemon role's read of
`meta/witness`; the log line carries the store's own error. Stop port49d only to let devices fall to
break-glass at once. For a detected restore, follow [backup and restore](../backup-and-restore.md).

**Don't:** expect a restart to clear the unjudged page: it clears when a read of `meta/witness` answers.
Don't skip re-issuing the revocations a restore lost.

### Directory and password sign-in

Alerts: **page** [port49_directory_refresh_half_ceiling](../../reference/alerts.md#port49_directory_refresh_half_ceiling),
[port49_directory_enrollment_store_lost](../../reference/alerts.md#port49_directory_enrollment_store_lost)
and [port49_sign_ins_enrollment_store_lost](../../reference/alerts.md#port49_sign_ins_enrollment_store_lost);
**ticket** [port49_directory_refresh_stale](../../reference/alerts.md#port49_directory_refresh_stale),
[port49_directory_lookups_ambiguous](../../reference/alerts.md#port49_directory_lookups_ambiguous),
[port49_directory_server_down](../../reference/alerts.md#port49_directory_server_down),
[port49_directory_group_names_ambiguous](../../reference/alerts.md#port49_directory_group_names_ambiguous),
[port49_sign_ins_throttled](../../reference/alerts.md#port49_sign_ins_throttled).

**Do this:** for the refresh page, restore the directory servers before the ceiling: at it, every live session
is denied `context_stale`. For a lost enrollment store, restore the file or run `port49 directory import`
from the export. See [backup and restore](../backup-and-restore.md).

**Don't:** run `init-enrollments` to fix a lost store on an install that had enrolled people: it makes an
empty store, and everyone enrolls again. Restore the export instead. Don't use the escapes in the alert (`session.staleness_ceiling: 0s`, or stopping port49d) as a
routine fix; each gives up a bound.

### Accounting and the decision log

Alerts: **page** [port49_accounting_spool_drops](../../reference/alerts.md#port49_accounting_spool_drops),
[port49_decision_log_write_failures](../../reference/alerts.md#port49_decision_log_write_failures) and
[port49_accounting_foreign](../../reference/alerts.md#port49_accounting_foreign); **ticket**
[port49_accounting_spool_disk_slow](../../reference/alerts.md#port49_accounting_spool_disk_slow).

**Do this:** for write failures, fix the sink (a full disk, a mode); decisions are not being recorded until you
do. The `stage` label of the spool alert says where records were discarded. For `foreign`, look for
break-glass and console logins: a local login during an outage is expected.

**Don't:** ignore the write-failure page: a decision that is not recorded cannot be reconstructed. Don't
treat `foreign` as a port49 bug before you check the device's local accounts. See
[monitoring](../monitoring.md#accounting-is-delivered-at-least-once).

### Inventory

Alerts, all **ticket**: [port49_inventory_sync_failing](../../reference/alerts.md#port49_inventory_sync_failing),
[port49_inventory_sync_refused](../../reference/alerts.md#port49_inventory_sync_refused),
[port49_inventory_bundle_refused](../../reference/alerts.md#port49_inventory_bundle_refused),
[port49_inventory_mirror_behind](../../reference/alerts.md#port49_inventory_mirror_behind),
[port49_inventory_persist_failed](../../reference/alerts.md#port49_inventory_persist_failed),
[port49_inventory_snapshot_stale](../../reference/alerts.md#port49_inventory_snapshot_stale),
[port49_inventory_policy_mismatch](../../reference/alerts.md#port49_inventory_policy_mismatch),
[port49_inventory_privilege_changes](../../reference/alerts.md#port49_inventory_privilege_changes).

**Do this:** read the inventory service's log. The fleet keeps authenticating on the snapshot in force, and
nothing fails closed. For `port49_inventory_privilege_changes`, the `inventory_change` record names the
device: review it.

**Don't:** restart port49d to refresh the inventory; the bundle in force keeps serving until a good one
arrives.

### etcd

Alerts: **page** [etcd_no_leader](../../reference/alerts.md#etcd_no_leader); **ticket**
[etcd_db_nearly_full](../../reference/alerts.md#etcd_db_nearly_full),
[etcd_disk_slow](../../reference/alerts.md#etcd_disk_slow),
[etcd_leader_changes](../../reference/alerts.md#etcd_leader_changes).

**Do this:** bring back a quorum. A dark member costs up to 12 seconds; a lost quorum stops the store, and
port49d answers `store_unavailable` and then closes its listeners. For a full database, compact and
defragment as etcd's documentation describes, before it reaches its quota. For a slow disk, see
[monitoring](../monitoring.md#the-disk-etcd-and-the-spool-need).

**Don't:** restart every member at once. Don't leave etcd on a disk that cannot hold a WAL fsync p99
under 10 ms.

## A log line says… {#a-log-line-says}

Each **You see** is the line as port49 writes it, with `<…>` for the part that varies.

### Cached directory membership

**You see:** `serving <principal>'s cached directory membership (its pin as this region last read it)`

**It means:** the whole line begins `directory store: not answering:` and ends `a forget made elsewhere
reaches this region when the directory answers`. This region cannot reach the directory store, and port49
answered for that principal from the pin it last read. A forget made in another region has not arrived
here. It is said once per principal per 10 minutes. The table that remembers who was told holds 65,536
principals; past that it drops the oldest, so on a larger fleet the line can repeat for a principal.

**Do this:** restore the link to the directory store (`port49 store status`; the alert
[port49_store_directory_unreachable](../../reference/alerts.md#port49_store_directory_unreachable)). When
it heals, the forget reaches the region by itself. See [stores](../stores.md#forgetting-a-directory-membership).

**Don't:** run `port49 directory forget` in the cut region: it is refused there and changes nothing. Run
it from a region that reaches the directory. Don't size the outage by counting these lines.

### The logout queue is full

**You see:** `the logout queue is full; a pass over the whole logout set follows`

**It means:** the broker's runner received more back-channel logouts from another region than its queue
holds. None is lost: each is in the set the runner follows, and a pass over the whole set reaches them.
The line is said once per pass owed; `port49_broker_logouts_queue_full_total` counts each logout that
found the queue full.

**Do this:** nothing at once. If the counter keeps rising, the runner is behind: look for a store alert.

**Don't:** restart the broker to empty the queue; the pass is what delivers the logouts.

### The session store was restored from a snapshot

**You see:** `the session store was restored from a snapshot`

**It means:** port49d read `meta/witness` and found that the store went back to an earlier moment.
Tokens minted before the restore are refused `token_spent` once and the users mint again. Revocations and
marks made after the snapshot are lost. The full line names the floor revision and says to follow the
restore runbook.

**Do this:** follow [backup and restore](../backup-and-restore.md), from the revocations step. Users run
`port49 token` again.

**Don't:** restart port49d to clear the line, or lift anything, before the runbook says. Don't assume a
revoked person is still revoked until the revocations are re-issued.

### Shedding

**You see:** `shedding: all <N> TACACS+ connection slots (limits.max_connections) are in use`

**It means:** port49d's global connection cap is full and each new connection is reset at accept, so the
device tries its next server. The line is said when shedding begins, then once a minute as
`still shedding: <N> connections reset at Accept in the last minute; <N> of <N> slots in use`.

**Do this:** raise `limits.max_connections` or add replicas. See [monitoring](../monitoring.md#shedding).

**Don't:** treat it as an outage: devices are being sent to their next server on purpose.

### A directory outage past 24 hours

**You see:** `no_grants_matched` (or `identity_unmapped`) for people who held sessions, right after a
broker restart or a policy reload, during or just after a long directory outage.

**It means:** a person's directory membership is stored with a lease of 24 hours from its last
verification (`broker.directory.grace` cannot exceed 24 hours). During an outage nothing refreshes it. Past the lease, a
broker restart or any policy reload finds no membership and revokes every directory session, whatever
`session.staleness_ceiling` is, including `0s`. It fails closed: nobody keeps access they cannot be shown
to hold. Before 24 hours, sessions continue until the ceiling.

**Do this:** bring the directory back before 24 hours. When it is back, the people sign in again.

**Don't:** restart a broker or edit the policy during a directory outage that is approaching 24 hours.
Raising `staleness_ceiling` does not help.

### Revocations file failed

**You see:** `port49_revocations_file_failed` at 1.

**It means:** the last write of `broker.revocations_file` failed (a hung or full disk or mount). The
revocation itself stands in the store and in force, but the file is behind, so a restart would forget a
mark the file does not hold. `port49 revoke` exits 3 for this.

**Do this:** fix the disk or mount the file lives on, then run the revoke again (`port49 revoke` exits 3
and says to). Only a revoke or a lift writes the file, so after a write error, such as a full disk,
nothing retries on its own and the gauge stays at 1 until you do. The revoke lists every mark in force,
rewrites the file with all of them, and the gauge falls to 0. After a hung mount returns, the write that
was in flight finishes the catch-up itself, but run the revoke anyway if the gauge has not fallen.

**Don't:** restart the broker or port49d while it is at 1.

## Related

- [Failure matrix](failure-matrix.md): what each device does when each part is down.
- [When it will not start](will-not-start.md): refusals at start, and which healthcheck to use where.
- [Monitoring](../monitoring.md): scraping, the disk etcd needs, shedding.
- [Backup and restore](../backup-and-restore.md) and [key rotation](../../admin/key-rotation.md).
