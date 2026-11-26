---
title: Troubleshooting
description: Where to start when port49 or a device login is not working.
---

# Troubleshooting

Find your symptom, then follow its link.

| You see | Go to |
|---|---|
| One person cannot log in, or one device fails | [I cannot log in to one device](#i-cannot-log-in-to-one-device) |
| Every login fails, or devices ask for a local password | [I cannot log in to any device](#i-cannot-log-in-to-any-device) |
| A local account is refused on a device | [Device break-glass does not work](#break-glass-does-not-work) |
| A session ended early | [My session ended early](#my-session-ended-early) |
| `port49 revoke`, `port49 directory` or another admin command is refused | [An admin command is refused](#an-admin-command-is-refused) |
| `port49 ssh` sends the device an empty password | [`port49 ssh` sends an empty password](#port49-ssh-sends-an-empty-password) |
| An alert fired | [An alert fired](#an-alert-fired) |
| A line in port49's log you do not recognise | [A log line says](#a-log-line-says) |
| A process will not start | [systemd](../systemd/troubleshoot.md), [containers](../containers/troubleshoot.md) or [Helm](../helm/troubleshoot.md) |
| What each device does when a part of port49 is down | [Failure matrix](failure-matrix.md) |

Three checks answer most first questions. `curl <port49d-host>:9049/readyz` says whether port49d is
serving: after a failing store closes its listener it answers 503 `waiting for the store`. `port49 store status`
(on a host that reaches the metrics port) prints whether each store answers, and exits 3 when one does not. `port49 explain --device <device>` asks the broker, through your agent, what port49 would do for you on that
device.

## A person tells you… {#a-person-tells-you}

### "I cannot log in to one device"

**You see:** one person, or everyone, fails on one device; the same logins work on other devices.

**It means:** the fault is in what port49 knows about that device or that person's grant on it. The decision
log record for the attempt carries a [reason](../../reference/reason-codes.md):

- `no_grants_matched`: no grant of theirs selects the device.
- `token_not_found` or `token_spent`: the token expired, was already used, or was minted for another
  device ([tokens, receipts and contexts](../../concepts/tokens-receipts-contexts.md)).
- An `unvalidated` record, and a connection the device sees reset with no reply: no key validated what the
  device sent. `unvalidated.diagnosis` says why: `no_known_key_matches` (a wrong key), `matches_retired`,
  `unadmitted_source` (the address is not in the inventory, which `unvalidated.source` names; a device whose
  source address changed looks exactly like this), `device_quarantined`, `admission_refused` or
  `transport_mismatch` (the device reached the listener it does not speak).

**Do this:** have the person run `port49 explain --device <device>`; it names the grant and the reason. Look
the attempt up in the decision log by `device.nas`, or by source address for an `unvalidated` record. For a
key fault, give the device the current key (`port49 keys show`).

**Don't:** restart port49d or the broker, which does not cure a fault confined to one device. Don't widen the
policy to "see if it works".

### "I cannot log in to any device"

**You see:** logins fail everywhere, or devices ask for a local password. Alerts that may be firing:
[port49_target_down](../../reference/alerts.md#port49_target_down),
[port49_target_absent](../../reference/alerts.md#port49_target_absent),
[port49_store_health_failures_close](../../reference/alerts.md#port49_store_health_failures_close).

**It means:** one of four things:

- port49d is down or unreachable. The devices find TCP 49 refused and fall to their local method.
- port49d is up and its store is failing. It answers a token login `ERROR` `store_unavailable` and every
  command `FAIL` `store_unavailable`, then closes its listeners after 5.5 seconds at the defaults, and
  devices fall to local.
- The broker is down. No new token can be minted; a token already held still logs in, and an open session
  runs on.
- port49d cannot read `meta/witness` after a restore
  ([port49_redemption_restore_unjudged](../../reference/alerts.md#port49_redemption_restore_unjudged)). It
  refuses every token login until a read answers.

**Do this:** `curl <port49d-host>:9049/readyz` and `port49 store status`; read the first alert that fired;
then the matching row of [a cut region at 3am](../stores.md#a-cut-region-at-3am) or the
[failure matrix](failure-matrix.md#at-3am). Use break-glass while you fix it.

**Don't:** restart port49d in a loop to "wake it": while the store is down it waits with its listener closed
and comes back by itself. Don't change the devices' AAA configuration; they already fall to local.

### "Device break-glass does not work" {#break-glass-does-not-work}

**You see:** a local account is refused on a device while port49 is failing. This is the device's own local
login, not the offline revoke in [Revoking access](../../admin/revocation.md).

**It means:** it depends on the platform, and on how long the device has been failing.

- **An `ERROR` is final on some platforms.** IOS XE, Junos under `authentication-order tacplus` alone, and XR
  over TLS refuse the local account while port49d answers `ERROR` (its store is failing). Local works once port49d
  closes its listener (about 5.5 seconds at the defaults) or is stopped. What each platform does is in the
  [failure matrix](failure-matrix.md) and on its [device page](../../admin/devices/index.md).
- **A device that failed over keeps answering locally for a while.** The device itself answers for a window
  and sends port49 nothing: a token login is refused during it, and break-glass works. Measured: IOS XE 30
  to 39 seconds over TCP
  ([note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_iosxe.md)), about a
  minute over TLS on one release, measured once, and IOS XR 24 to 46 seconds
  ([note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L88-cisco_xrd.md)). XR also
  accepts any local account's password in that window, including one port49 denies. Expect the window after
  port49d returns from a stop. The cells are in
  [`deploy/device-aaa/README.md`](https://github.com/blanketfish/port49/blob/main/deploy/device-aaa/README.md).

!!! warning "Unmeasured"
    Whether an authentication `ERROR` is final on Cisco IOS XR over plain TCP is not measured ([L93](../../reference/lab-register.md#l93),
    open). Plan as if break-glass is refused until port49d closes its listener, and keep a console path.

**Do this:** to get to break-glass at once, stop port49d: the devices then find TCP 49 refused and use their
local method. Otherwise wait for the listener to close, or for the device's window to end. Keep a console or
second path for IOS XE and XR, and test break-glass on each platform before you need it.

**Don't:** try to shorten a device's window with `deadtime` on IOS XE: it does not accept the command. Don't
leave local accounts on XR beyond break-glass ones.

### "My session ended early" {#my-session-ended-early}

**You see:** a person's session ended before they expected: `port49 ssh` exits 255, the agent says the
session ended, or a command is denied `context_stale` or `credential_revoked`.

**It means:** one of the planned ends. The `refresh` or `revoke` record just before the denial names it:

- the session reached `max_session_age`, or a token ran past `receipt_idle_ttl` or `receipt_max_age`
  (`token_spent`);
- an administrator revoked the person ([revocation](../../concepts/revocation.md));
- an OIDC back-channel logout ended it;
- a policy change withdrew their grant, or the directory no longer maps them;
- `context_stale`: no directory refresh verified them for `session.staleness_ceiling` (4 hours by default).
  [port49_directory_refresh_half_ceiling](../../reference/alerts.md#port49_directory_refresh_half_ceiling)
  pages at half of that.

**Do this:** read that person's last records in the decision log. For a stale context, restore the directory
servers; the person signs in again once a refresh passes.

**Don't:** lift a revocation before reading the `revoke` record, which says who made it and why. Don't set
`session.staleness_ceiling` to `0s` to quiet `context_stale`: that removes the bound on how old a
verification may be.

### "It says the principal was revoked at …"

**You see:** `port49 token` or `port49 ssh` prints `this principal was revoked at <time>; nothing is minted
for it until an operator lifts the revocation (port49 revoke --lift)`. A certificate revoked at its CA reads
`this certificate was revoked at its CA (<origin>) and marked at <time>; nothing is minted for it; request a
new certificate`.

**It means:** a standing revocation mark is in the store, and the person is refused `credential_revoked` at
every mint. The mark does not expire.

**Do this:** `port49 revoke --list` shows the marks in force. If the revocation was a mistake, lift it:
`port49 revoke --principal <principal> --lift`. A certificate the CA revoked is not fixed by a lift: the
person needs a new certificate.

**Don't:** undo a revocation by restoring the store from a snapshot: a restore is the one routine operation
that can admit a revoked person. Don't lift a mark you did not read first.

### An admin command is refused

**You see:** `port49 revoke`, `port49 directory ...` or another admin command fails with a status and a
reason.

**It means:** the broker refused the call. A refusal before any key press means your subject lacks the right in
the policy's `api:` list (`revoke_others`, `lift_revocations`): see [Admin access](../../admin/admin-access.md).

The other refusals (the key's attestation does not verify, no attestation roots, no touch in time) have a
different fix for each deployment. The fix is on the troubleshoot page for [systemd](../systemd/troubleshoot.md) or
[containers](../containers/troubleshoot.md), and for no roots on [Helm](../helm/troubleshoot.md). With every broker down, use the
offline revoke in [Revoking access](../../admin/revocation.md).

**Don't:** retry a refused touch in a loop: the alert
[port49_admin_touch_refused](../../reference/alerts.md#port49_admin_touch_refused) pages on a run of them.

### "`port49 ssh` sends an empty password" {#port49-ssh-sends-an-empty-password}

**You see:** `port49 ssh` connects and the device prompts for or accepts nothing: the login fails as though
the password were empty.

**It means:** `ssh` could not run `port49` as its askpass helper, because the binary is setgid or has file
capabilities. Install it with mode `0755`, owned by root: [Install the client](../../use/install-client.md).

**Do this:** check `ls -l $(command -v port49)` for mode `-rwxr-xr-x` and no setgid bit, and
`getcap $(command -v port49)` for no output.

**Don't:** work around it with `sshpass` or a password in a script.

## An alert fired {#an-alert-fired}

Every alert's `runbook_url` opens its section of the [alerts reference](../../reference/alerts.md). A `page`
alert means port49 is refusing devices or losing records now; a `ticket` costs nothing yet. Each family has a
do and a don't in the [alerts reference](../../reference/alerts.md#what-to-do-by-family).

| Family | Page alerts | Ticket alerts | What to do |
|---|---|---|---|
| Scrape and process | [port49_target_down](../../reference/alerts.md#port49_target_down), [port49_target_absent](../../reference/alerts.md#port49_target_absent) | [port49_broker_target_absent](../../reference/alerts.md#port49_broker_target_absent) | [Do and don't](../../reference/alerts.md#scrape-and-process) |
| Connections | [port49_global_cap_shedding](../../reference/alerts.md#port49_global_cap_shedding) | [port49_connections_near_cap](../../reference/alerts.md#port49_connections_near_cap), [port49_unadmitted_source](../../reference/alerts.md#port49_unadmitted_source) | [Do and don't](../../reference/alerts.md#connections), and [Shedding](#shedding) |
| Keys and the issuing CA | [port49_issuing_ca_missing](../../reference/alerts.md#port49_issuing_ca_missing), [port49_key_retirement_within_1d](../../reference/alerts.md#port49_key_retirement_within_1d) | [port49_key_secret_files_changed](../../reference/alerts.md#port49_key_secret_files_changed), [port49_issuing_ca_expiring](../../reference/alerts.md#port49_issuing_ca_expiring), [port49_key_retirement_within_7d](../../reference/alerts.md#port49_key_retirement_within_7d) | [Do and don't](../../reference/alerts.md#keys-and-the-issuing-ca) |
| Policy, mint and admin calls | [port49_admin_touch_refused](../../reference/alerts.md#port49_admin_touch_refused), [port49_per_login_mfa_refused](../../reference/alerts.md#port49_per_login_mfa_refused) | [port49_policy_fail_closed_compositions](../../reference/alerts.md#port49_policy_fail_closed_compositions), [port49_policy_file_refused](../../reference/alerts.md#port49_policy_file_refused), [port49_policy_refresh_pending](../../reference/alerts.md#port49_policy_refresh_pending), [port49_policy_bundle_mismatch](../../reference/alerts.md#port49_policy_bundle_mismatch), [port49_broker_mint_gate_closed](../../reference/alerts.md#port49_broker_mint_gate_closed), [port49_devices_generic_platform](../../reference/alerts.md#port49_devices_generic_platform), [port49_context_refreshes_failed](../../reference/alerts.md#port49_context_refreshes_failed) | [Do and don't](../../reference/alerts.md#policy-mint-and-admin-calls) |
| Stores | [port49_store_directory_unreachable](../../reference/alerts.md#port49_store_directory_unreachable), [port49_store_marks_feed_down](../../reference/alerts.md#port49_store_marks_feed_down), [port49_store_calls_refused](../../reference/alerts.md#port49_store_calls_refused), [port49_crypt_store_key_unknown](../../reference/alerts.md#port49_crypt_store_key_unknown), [port49_store_health_failures_close](../../reference/alerts.md#port49_store_health_failures_close) | [port49_store_directory_stale](../../reference/alerts.md#port49_store_directory_stale), [port49_store_logouts_pending](../../reference/alerts.md#port49_store_logouts_pending), [port49_store_feed_down](../../reference/alerts.md#port49_store_feed_down), [port49_store_feed_legs_colocated](../../reference/alerts.md#port49_store_feed_legs_colocated), [port49_store_circuit_open](../../reference/alerts.md#port49_store_circuit_open), [port49_contexts_reindexed](../../reference/alerts.md#port49_contexts_reindexed), [port49_contexts_reindex_failures](../../reference/alerts.md#port49_contexts_reindex_failures), [port49_store_keyspace_unheld](../../reference/alerts.md#port49_store_keyspace_unheld), [port49_store_client_cert_expiring](../../reference/alerts.md#port49_store_client_cert_expiring), [port49_crypt_token_open_failures](../../reference/alerts.md#port49_crypt_token_open_failures), [port49_directory_pins_unopenable](../../reference/alerts.md#port49_directory_pins_unopenable), [port49_store_feed_rescans](../../reference/alerts.md#port49_store_feed_rescans), [port49_ledger_pending](../../reference/alerts.md#port49_ledger_pending), [port49_ledger_behind](../../reference/alerts.md#port49_ledger_behind), [port49_store_health_check_failing](../../reference/alerts.md#port49_store_health_check_failing), [port49_context_cache_stale](../../reference/alerts.md#port49_context_cache_stale) | [Do and don't](../../reference/alerts.md#stores), and [a cut region at 3am](../stores.md#a-cut-region-at-3am) |
| TLS (RFC 9887) | [port49_tls_server_certificate_expired](../../reference/alerts.md#port49_tls_server_certificate_expired) | [port49_tls_handshake_failures](../../reference/alerts.md#port49_tls_handshake_failures), [port49_tls_device_certificate_renewal_late](../../reference/alerts.md#port49_tls_device_certificate_renewal_late), [port49_tls_server_certificate_renewal_late](../../reference/alerts.md#port49_tls_server_certificate_renewal_late), [port49_tls_cert_status_unavailable](../../reference/alerts.md#port49_tls_cert_status_unavailable), [port49_crl_next_update_passed](../../reference/alerts.md#port49_crl_next_update_passed), [port49_inventory_transport_changed](../../reference/alerts.md#port49_inventory_transport_changed) | [Do and don't](../../reference/alerts.md#tls-rfc-9887), and [what you see at 3am](../tls.md#what-you-see-at-3am) |
| Identity providers and restores | [port49_redemption_restore_unjudged](../../reference/alerts.md#port49_redemption_restore_unjudged) | [port49_store_restore_detected](../../reference/alerts.md#port49_store_restore_detected), [port49_oidc_keys_stale](../../reference/alerts.md#port49_oidc_keys_stale), [port49_oidc_logouts_failing](../../reference/alerts.md#port49_oidc_logouts_failing), [port49_oidc_tokens_unavailable](../../reference/alerts.md#port49_oidc_tokens_unavailable), [port49_workload_certificates_renewal_late](../../reference/alerts.md#port49_workload_certificates_renewal_late) | [Do and don't](../../reference/alerts.md#identity-providers-and-restores) |
| Directory and password sign-in | [port49_directory_refresh_half_ceiling](../../reference/alerts.md#port49_directory_refresh_half_ceiling), [port49_directory_enrollment_store_lost](../../reference/alerts.md#port49_directory_enrollment_store_lost), [port49_sign_ins_enrollment_store_lost](../../reference/alerts.md#port49_sign_ins_enrollment_store_lost) | [port49_directory_refresh_stale](../../reference/alerts.md#port49_directory_refresh_stale), [port49_directory_lookups_ambiguous](../../reference/alerts.md#port49_directory_lookups_ambiguous), [port49_directory_server_down](../../reference/alerts.md#port49_directory_server_down), [port49_directory_group_names_ambiguous](../../reference/alerts.md#port49_directory_group_names_ambiguous), [port49_sign_ins_throttled](../../reference/alerts.md#port49_sign_ins_throttled) | [Do and don't](../../reference/alerts.md#directory-and-password-sign-in) |
| Accounting and the decision log | [port49_accounting_spool_drops](../../reference/alerts.md#port49_accounting_spool_drops), [port49_decision_log_write_failures](../../reference/alerts.md#port49_decision_log_write_failures), [port49_accounting_foreign](../../reference/alerts.md#port49_accounting_foreign) | [port49_accounting_spool_disk_slow](../../reference/alerts.md#port49_accounting_spool_disk_slow) | [Do and don't](../../reference/alerts.md#accounting-and-the-decision-log) |
| Inventory | [port49_inventory_address_moved](../../reference/alerts.md#port49_inventory_address_moved) | [port49_inventory_sync_failing](../../reference/alerts.md#port49_inventory_sync_failing), [port49_inventory_sync_refused](../../reference/alerts.md#port49_inventory_sync_refused), [port49_inventory_bundle_refused](../../reference/alerts.md#port49_inventory_bundle_refused), [port49_inventory_mirror_behind](../../reference/alerts.md#port49_inventory_mirror_behind), [port49_inventory_persist_failed](../../reference/alerts.md#port49_inventory_persist_failed), [port49_inventory_snapshot_stale](../../reference/alerts.md#port49_inventory_snapshot_stale), [port49_inventory_policy_mismatch](../../reference/alerts.md#port49_inventory_policy_mismatch), [port49_inventory_privilege_changes](../../reference/alerts.md#port49_inventory_privilege_changes) | [Do and don't](../../reference/alerts.md#inventory) |
| etcd | [etcd_no_leader](../../reference/alerts.md#etcd_no_leader) | [etcd_db_nearly_full](../../reference/alerts.md#etcd_db_nearly_full), [etcd_disk_slow](../../reference/alerts.md#etcd_disk_slow), [etcd_leader_changes](../../reference/alerts.md#etcd_leader_changes) | [Do and don't](../../reference/alerts.md#etcd) |


## A log line says… {#a-log-line-says}

Each **You see** is the line as port49 writes it, with `<…>` for the part that varies.

### Cached directory membership

**You see:** `serving <principal>'s cached directory membership (its pin as this region last read it)`

**It means:** the whole line begins `directory store: not answering:` and ends `a forget made elsewhere
reaches this region when the directory answers`. This region cannot reach the directory store, and port49
answered for that principal from the pin it last read. A forget made in another region has not arrived here.
It is said once per principal per 10 minutes, so on a fleet past 65,536 principals it can repeat.

**Do this:** restore the link to the directory store (`port49 store status`; the alert
[port49_store_directory_unreachable](../../reference/alerts.md#port49_store_directory_unreachable)). When it
heals, the forget reaches the region by itself ([stores](../stores.md#forgetting-a-directory-membership)).

**Don't:** run `port49 directory forget` in the cut region: it is refused there. Run it from a region that
reaches the directory. Don't size the outage by counting these lines.

### The logout queue is full

**You see:** `the logout queue is full; a pass over the whole logout set follows`

**It means:** the broker's runner received more back-channel logouts from another region than its queue
holds. None is lost: a pass over the whole set reaches them. `port49_broker_logouts_queue_full_total` counts
each logout that found the queue full.

**Do this:** nothing at once. If the counter keeps rising, the runner is behind: look for a store alert.

**Don't:** restart the broker to empty the queue; the pass is what delivers the logouts.

### A logout did not land

**You see:** `a logout token from <issuer> could not be applied: the store did not answer; answered 503 so the provider may retry`

**It means:** an identity provider's back-channel logout reached the broker while its store was down. The
broker answered 503 so the provider may retry. The line ends with the commands to use if it does not, in one
of two forms. The provider's event log shows the 503.

**Do this:** both forms run through your agent and need the `revoke_others` and `lift_revocations` rights
([Revoking access](../../admin/revocation.md)). Form 1 means the logout wrote its record and a later step
failed: if the decision log has a `revoke` record with origin `backchannel_logout` for the principal just
before the line, end its contexts with `port49 revoke --principal <principal>`, then lift it with
`port49 revoke --lift --principal <principal>`, and last check that `port49 revoke --list` shows no mark for
it. Form 2 means nothing was written, so no logout record refuses the held ID token or issued certificate:
revoke the principal the same way, and lift it only after the time the line prints, when that token or
certificate has expired. For a token that names only a `sid`, the line first offers
`port49 revoke --sid <sid> --sid-issuer <issuer>`, which ends that one session and leaves no mark to lift.

**Don't:** lift a Form 2 revocation early: the held token can mint again.

### The session store was restored from a snapshot

**You see:** `the session store was restored from a snapshot`

**It means:** port49d read `meta/witness` and found that the store went back to an earlier moment. Tokens
minted before the restore are refused `token_spent` once and the users mint again. Revocations and marks made
after the snapshot are lost. The full line names the floor revision and says to follow the restore runbook.

**Do this:** follow [backup and restore](../backup-and-restore.md), from the revocations step. Users run
`port49 token` again.

**Don't:** restart port49d to clear the line, or lift anything, before the runbook says. Don't assume a
revoked person is still revoked until the revocations are re-issued.

Other signs of a restore, with what to do:

- `port49_store_restore_detected_timestamp_seconds` above 0 and the alert
  [port49_store_restore_detected](../../reference/alerts.md#port49_store_restore_detected): the same event as a
  metric. Do the same.
- A login fails and `port49_redemption_restored_refused_total` rises: the token is from before the restore. The
  user mints a new one (`port49 token`).
- A broker says `runner: <why>; every unspent token is purged and must be minted again (port49 token)`: the runner
  purged. Nothing to do; every user mints again.
- A broker says `runner: N revocation(s) in broker.state_dir/marks.json were missing from the store ... and are put
  back`: lift again, with `port49 revoke --lift`, any that were lifted on purpose before the snapshot.
- A broker says `broker.state_dir had no marks.json at this start`: it put back nothing. If no broker's
  `state_dir` survived, re-issue every revocation made since the snapshot (step 4 of the runbook).
- `port49_broker_mint_gate_closed` at 1 and `POST /v1/token` answering `503 store_unavailable` with
  `Retry-After: 5`: a broker owes the purge and mints nothing until it is done. Wait. If it stays at 1 for more than
  a minute (ticket [port49_broker_mint_gate_closed](../../reference/alerts.md#port49_broker_mint_gate_closed)),
  check that one broker holds the keyspace and read its stderr for a purge that failed. The next takeover makes a
  cut-short purge again.
- `port49_redemption_restore_unjudged` at 1 and `port49d: store: reading meta/witness, to tell whether the store was
  restored: ...; token redemptions are refused (store_unavailable)`: port49d cannot read `meta/witness`, so it
  refuses every token login (page after 2 minutes:
  [port49_redemption_restore_unjudged](../../reference/alerts.md#port49_redemption_restore_unjudged)). Fix the store,
  or the daemon role's read of `meta/witness`. A device whose authentication `ERROR` is final (IOS XE, and Junos
  under `tacplus` alone) refuses break-glass until the read answers or port49d is stopped. Do not delete
  `restore.json` to clear it.

### A token was minted ahead of this host's clock

**You see:** `clock: a token was minted <N> ahead of this host's clock`, at most once every ten minutes, and
`port49_token_minted_ahead_total` rising; the ticket
[port49_token_clock_skew](../../reference/alerts.md#port49_token_clock_skew) fires on it.

**It means:** the broker that minted the token has a clock `N` ahead of this port49d's, so every token from
that broker lives `N` longer here. The other direction does not show: a broker `N` behind shortens each
token, and past a `token_ttl` its tokens are dead on arrival, so every login with one fails
`token_not_found` with no other sign. If logins from one broker fail `token_not_found` right after the token
was minted, compare the clocks first
([Requirements](../../reference/requirements.md#clocks)).

**Do this:** put every broker host and every port49d host on NTP (`chronyc tracking`, or `timedatectl`) and
confirm they agree to well under the smallest `token_ttl`. Alert on the hosts' own NTP sync, since port49
cannot see a broker that is behind ([Requirements](../../reference/requirements.md#clocks)).

**Don't:** lengthen `token_ttl` to cover the skew: it widens replay for an unspent token and leaves the
clocks wrong for everything else.

### Shedding

**You see:** `shedding: all <N> TACACS+ connection slots (limits.max_connections) are in use`

**It means:** port49d's global connection cap is full and each new connection is reset at accept, so the
device tries its next server. It is said when shedding begins, then once a minute as
`still shedding: <N> connections reset at Accept in the last minute; <N> of <N> slots in use`.

**Do this:** raise `limits.max_connections` or add replicas ([monitoring](../monitoring.md#shedding)). The alerts
are under [Connections](../../reference/alerts.md#connections).

**Don't:** treat it as an outage: devices are being sent to their next server on purpose.

### A directory pin is not re-sealed or does not open {#a-directory-pin-is-not-re-sealed-or-does-not-open}

**You see:** `directory store: <principal>'s pin does not open` and the alert
[port49_directory_pins_unopenable](../../reference/alerts.md#port49_directory_pins_unopenable), on the keyspace
holder (`port49_store_keyspace_held` 1).

**It means:** the broker's scheduled pass could not open a pin, which is a pinned principal's directory entry
sealed under the `encryption:` key. For an unknown key (`ErrUnknownKey`), a key was retired while it still
sealed the pin. Bind, mint and refresh fail for that principal. From the code (not measured), sessions already
open are denied `context_stale` once `session.staleness_ceiling` has passed. Each pass opens the pin again, so
`port49_crypt_open_failures_total{record="membership"}` rises at least once per pass for each such pin. The pass
never deletes or rewrites it, and says the line once an hour for at most 20 principals a pass
(the first 20 in sorted order); the count's line says how many more are not named.

Other lines of the same pass, each once an hour, with no gauge change:

- `directory store: the re-seal sealed N pins under the current key; M are left under encryption.previous`:
  expected during step 2 of a rotation. No action.
- `directory store: the re-seal of pins stopped: <error>; the next pass starts again`: the directory store
  stopped answering or refused the broker's identity.
- `directory store: <principal>'s pin could not be written under the current key (...)`: that pin is counted in
  `port49_directory_pins_sealed_previous`, and the pass goes on.
- `directory store: the re-seal of pins ran out of its <budget> budget after sealing N pins (M did not open); the next pass goes on from there`.

**Do this:** for an unknown key, put the retired key back as `previous` and restart, which deletes nothing and
lets the next pass re-seal the pin. If the line says the record does not match its seal, it was changed outside
port49 and no key helps: run `port49 directory forget <principal>`. If the key is gone, `forget` also frees the
principal, and the person's next sign-in pins them again. Any admin with `forget_principals` whose own pin opens
can run it. Confirm that the person who signs in is the same person
([Stores](../stores.md)). There is no offline forget on `port49-broker`.

**Don't:** remove `encryption.previous` while `port49_directory_pins_sealed_previous` is above 0
([Key rotation](../../admin/key-rotation.md#the-encryption-key)).

### A directory outage past 24 hours

**You see:** `no_grants_matched` (or `identity_unmapped`) for people who held sessions, right after a broker
restart or a policy reload, during or just after a long directory outage.

**It means:** a person's directory membership is stored with a lease of 24 hours from its last verification
(`broker.directory.grace` cannot exceed 24 hours). During an outage nothing refreshes it. Past the lease, a
broker restart or any policy reload finds no membership and revokes every directory session, whatever
`session.staleness_ceiling` is, including `0s`. It fails closed. Before 24 hours, sessions continue until the
ceiling.

**Do this:** bring the directory back before 24 hours. When it is back, the people sign in again.

**Don't:** restart a broker or edit the policy during a directory outage that is approaching 24 hours.
Raising `staleness_ceiling` does not help.

### Revocations file failed

**You see:** `port49_revocations_file_failed` at 1.

**It means:** the last write of `broker.revocations_file` failed (a hung or full disk or mount). The
revocation itself stands in the store and in force, but the file is behind, so a restart would forget a mark
the file does not hold. `port49 revoke` exits 3 for this.

**Do this:** fix the disk or mount the file lives on, then run the revoke again. Only a revoke or a lift
writes the file, so after a write error nothing retries on its own and the gauge stays at 1 until you do. The
revoke rewrites the file with every mark in force, and the gauge falls to 0. After a hung mount returns, the
write in flight finishes the catch-up itself, but run the revoke anyway if the gauge has not fallen.

**Don't:** restart the broker or port49d while it is at 1.
