# port49 alert rules

<!-- --8<-- [start:intro] -->
`port49.rules.yaml` holds one Prometheus alerting rule for each alarm port49 defines. Load it in
one of two ways:

- into Prometheus, with `rule_files:`
- through the Helm chart, with `prometheusRule.enabled: true`. The chart renders the same file as a
  Prometheus Operator `PrometheusRule`. `deploy/helm/port49/files/port49.rules.yaml` is a byte copy,
  because Helm cannot read outside the chart, and `tests/alerts` fails if the two differ.

`make alerts-check` runs `promtool check rules` and `promtool test rules` on it. `go test
./tests/alerts/` checks that every metric an expression names is one port49 registers.

There are two severities; route on the `severity` label.

- `page`: a fault that is refusing devices or losing records now.
- `ticket`: one that costs nothing yet, or that a person fixes in working hours.

**The job names are the rules' parameter.** Three rules read Prometheus's own `up` series for
`job="port49d"` and `job="port49-broker"`: `port49_target_down`, `port49_target_absent` and
`port49_broker_target_absent`. The chart's PodMonitors (rendered with `prometheusRule.enabled`) set
those names. If you scrape another way, give the jobs those names or edit the rules. Without them,
`port49_target_absent` and `port49_broker_target_absent` fire, which is the point of them.

The absent rules are fleet-wide: `absent()` stays quiet while any scrape of that job exists. So use
one Prometheus per port49 fleet, or add a namespace matcher to the two expressions.

No expression names a device, and none groups by one. The series carry no device identity, and the
decision log answers "which devices". The labels used are bounded: `instance`,
`key_ref`, `version`, `server`, `issuer`, `outcome`, `feed`, `pool`, `component`.

<!-- --8<-- [end:intro] -->

## The rules

Each row pairs what an alert covers with the rule that answers it.

**A threshold that follows a setting assumes that setting's default.** The defaults are `close_after`
5, `broker.refresh_interval` 5m, `jwks_max_age` 24h, `expiry_warning_fraction` 0.33 and
`staleness_ceiling` 4h. Edit the rule if you set another. The `hold_ttl` rules are the exception: they
use multiples of the 15s `hold_ttl` default that hold at any allowed setting (10s to 1m), so they need
no edit.

**Edit in the safe direction.** A setting lowered below the default can silence its alarm:

- With `close_after: 3`, the page on `port49_store_health_failures >= 5` never fires.
- With `jwks_max_age: 6h`, the 12h keys rule fires after tokens are already refused.

Recompute each such threshold when you change the setting it follows.

| Statement | Alert | Severity | for | Why this threshold |
|---|---|---|---|---|
| A port49d or broker that is down raises no alarm of its own, because every other rule reads series it no longer exports | `port49_target_down` | page | 2m | `up == 0` for a scrape target of either job; two minutes outlasts a restart's missed scrapes. |
| A port49d target Prometheus is not scraping at all has no `up` series, so `== 0` never matches | `port49_target_absent` | page | 5m | `absent()` of port49d's `up`. Prometheus's pod discovery keeps a target only while its pod exists, so a StatefulSet with every pod Pending or deleted leaves no series for `== 0` to match, and every device has lost port49: a page. Five minutes outlasts a rollout. A mislabelled scrape config shows here too. |
| The same for the broker: no `up` series for `port49-broker` at all | `port49_broker_target_absent` | ticket | 10m | `absent()` of the broker's `up`: no token can be minted, but held tokens still log in. On the memory-store trial, which runs no separate broker, the broker rule fires; drop it there or silence it. |
| Connections reset at accept because the global connection cap is full: `port49_connections_shed_total{reason="global_cap"}` increasing | `port49_global_cap_shedding` | page | none | Any shed connection is a device refused, so any increase pages; five minutes smooths one scrape. |
| A warning before shedding starts: `port49_connections` near the cap | `port49_connections_near_cap` | ticket | 10m | Ten minutes at 80% is a trend, not a burst; the page above covers the cap itself. |
| A key version's secret file that changed or cannot be read: `port49_key_secret_files_changed > 0` for 10m | `port49_key_secret_files_changed` | ticket | 10m | A rotated file is expected for minutes while the rollout restarts; ten minutes is a forgotten restart. |
| A broker set to issue certificates that has no usable issuing CA: `port49_issuing_ca_not_after_timestamp_seconds == 0` while `broker.identity.issuance` is configured | `port49_issuing_ca_missing` | page | 5m | A broker started without its CA says so and keeps serving; five minutes outlasts a rollout and nothing else clears it. |
| The issuing CA expires within 90 days | `port49_issuing_ca_expiring` | ticket | none | Ninety days is a CA rollover's lead time; a CA already at 0 is the page above, not this ticket. |
| A key version that devices still present nears its `retire_after`: the first step of an alarm whose severity rises as the date approaches | `port49_key_retirement_within_7d` | ticket | none | A week is a change window; the series carry no device identity, the log names the devices. |
| The same key version within a day of its `retire_after`, or past it: the alarm's last step | `port49_key_retirement_within_1d` | page | none | A day is the last working shift; a version past retire_after with devices on it is refusing them now. |
| An admin call refused its hardware-key touch proof: `port49_admin_touch_total{outcome="refused"}` | `port49_admin_touch_refused` | page | none | Someone holds an admin credential without the touch; no benign cause repeats. |
| A policy in force that answers some compositions fail-closed: `port49_policy_fail_closed_compositions` > 0 | `port49_policy_fail_closed_compositions` | ticket | none | A standing condition of the policy, not an incident; a ticket the author sees. |
| A policy file on disk that is refused or will not settle, from `port49_policy_reloads_total{outcome}` | `port49_policy_file_refused` | ticket | 5m | An edit in progress is refused for seconds; five minutes is a file that stayed wrong. |
| A policy swap or grant expiry that has not yet reached every live login context: 1 from the change until its settle pass | `port49_policy_refresh_pending` | ticket | 2m | A pass takes seconds; two minutes is a stuck settle pass. |
| A broker serving a policy bundle other than the runner's: `port49_policy_bundle_matches_runner` 0 for longer than twice `broker.policy_watch_interval` | `port49_policy_bundle_mismatch` | ticket | 5m | Five minutes outlasts twice the watch interval and the settle delay at their defaults; raise it if the intervals are raised. |
| A broker that mints nothing: `port49_broker_mint_gate_closed` at 1 for a minute | `port49_broker_mint_gate_closed` | ticket | 1m | The gate is closed from a start until a takeover is seen, so a minute is where a restart ends and a fault begins; a ticket, since other replicas keep minting. |
| A process that cannot read the directory store: `port49_store_directory_reachable == 0` for 1m | `port49_store_directory_unreachable` | page | 1m | A cut region keeps logging devices in on stale marks, so one minute is a real partition. |
| A process whose copy of the directory store is unconfirmed for over a minute: `time() - port49_store_directory_confirmed_timestamp_seconds > 60` | `port49_store_directory_stale` | ticket | 1m | The series exists only under etcd, at 0 until the first confirmation, so a 0 is skipped here: port49_store_directory_unreachable and port49_store_feed_down cover a process that never confirmed. |
| Back-channel logouts accepted but not yet in the directory store: `port49_store_logouts_pending > 0` for 5m | `port49_store_logouts_pending` | ticket | 5m | A cut region holds logouts the others have not seen; five minutes is longer than a blip. |
| The marks feed down, so revocation marks written elsewhere do not arrive: `port49_store_feed_up{feed="marks"} == 0` | `port49_store_marks_feed_down` | page | 1m | Revocation rides this feed; a minute is four times the 15s `hold_ttl` default and the longest `hold_ttl` allows (10s to 1m), so at any setting the feed has been down for a full hold. |
| A store feed other than marks down: `port49_store_feed_up{feed}` 0 for longer than `hold_ttl` | `port49_store_feed_down` | ticket | 1m | A minute is four times the 15s `hold_ttl` default and the longest `hold_ttl` allows (10s to 1m). Every feed but marks, which pages, so a feed added later is covered. |
| Both legs of a feed's watch on one etcd member: `port49_store_feed_legs_colocated` at 1 for 10m | `port49_store_feed_legs_colocated` | ticket | 10m | Both legs of a feed's watch on one member is no redundancy against that member going dark; the move apart is tried from 2 s doubling to 30 s, so ten minutes is a cluster where no other member is reachable for this feed. A client with one etcd endpoint never moves a leg and holds the gauge at 0 (colocation is not a fault there); port49d logs once at start that the feeds share one member. |
| A store pool's circuit open, so its calls fail at once | `port49_store_circuit_open` | ticket | 1m | The rule fires for every `{component, pool}` series, and what an open circuit costs depends on which. On port49d (`component="daemon"`), a `token` or `context` pool open for `hold_ttl` (the 15s `hold_ttl` default) closes the listeners, so a minute is four times that and this ticket follows the close; it does not warn before it. A `bulk` pool never closes them: logins and commands are unaffected and the scans (the refresh, a revocation by principal, a start's purge) fail until a probe succeeds. On port49-broker (`component="broker"`) no circuit closes anything, because its guards never stop; mints, refreshes and revocations through the open pool fail. The component `broker_enrollments` refuses password sign-in and second-factor enrollment through its open pool, and closes nothing. |
| Live login contexts found missing from the index: any increase of `port49_contexts_reindexed_total` | `port49_contexts_reindexed` | ticket | none | No benign path deletes an index record. |
| A login context that could not be re-indexed or judged: any increase of `port49_contexts_reindex_failures_total` | `port49_contexts_reindex_failures` | ticket | none | Each failure leaves a context for the next pass; a mis-set key repeats it. |
| etcd's roles refusing port49's store calls: any increase of `port49_store_calls_total{outcome="refused"}` | `port49_store_calls_refused` | page | none | A refused call is a role or credential fault that retries cannot fix. |
| No broker replica holding the store keyspace: the sum of `port49_store_keyspace_held` over port49-broker's replicas 0 for twice `hold_ttl` | `port49_store_keyspace_unheld` | ticket | 2m | Two minutes is eight times the 15s `hold_ttl` default, and exactly twice the longest `hold_ttl` allows (1m), so it holds at any setting. The series exists only on a process that runs a keyspace runner, so the memory backend, with none, raises nothing. The second arm covers every broker gone (a crashed fleet exports no 0): series seen in the last day and none now, so it fires for a day after the brokers vanish, then stops. |
| A store client certificate within 30 days of expiry | `port49_store_client_cert_expiring` | ticket | none | Thirty days is the stated lead time. |
| port49d started on a store written under a key its encryption window does not hold: `port49_crypt_store_key_unknown` at 1 | `port49_crypt_store_key_unknown` | page | none | Records written under the missing key cannot open; fix the key and start again. |
| A stored token that would not decrypt: any increase of `port49_crypt_open_failures_total{record="token"}` | `port49_crypt_token_open_failures` | ticket | none | The counter is the only witness; the token is dropped from its candidates with no error. |
| A directory pin that opens under neither encryption key: `port49_directory_pins_unopenable` above 0 on the replica holding the keyspace | `port49_directory_pins_unopenable` | ticket | none | One principal is locked out until the key that sealed the pin is back as `encryption.previous` or the pin is forgotten; the pass never deletes it. Gated on `port49_store_keyspace_held == 1`, since a replica that handed over keeps its last value. |
| A feed whose watch was compacted and rescanned the store: any increase of `port49_store_feed_rescans_total` | `port49_store_feed_rescans` | ticket | none | A rescan means a watch fell behind compaction; repeated, the feed is too slow. |
| The runner's ledger record behind: `port49_ledger_pending` above 0 for a minute | `port49_ledger_pending` | ticket | 1m | A write takes a round trip; a minute is a record that cannot be written. |
| The runner's ledger keeper running with its context feed down: `port49_ledger_behind` at 1 | `port49_ledger_behind` | ticket | 1m | One minute rides out a feed reconnect. |
| port49d closing its TACACS+ listeners after its store health checks fail: `port49_store_health_failures >= <close_after>` | `port49_store_health_failures_close` | page | none | 5 is close_after at its default; set it to yours. The gauge is held through the outage, so the page stays up and resolves when the listeners reopen. Not above 0: a defragmenting member fails an occasional check. close_after x interval is shorter than any scrape, so nothing warns first. |
| Store health checks failing often, short of closing the listeners: `increase(port49_store_health_checks_total{outcome="fail"}[10m])` above a threshold the operator picks | `port49_store_health_check_failing` | ticket | none | At the default 1s interval 60 is a tenth of the checks in ten minutes; a defragmenting member measured 4 to 7 of 18. Set your own. |
| Commands answered from login contexts the store did not confirm: any increase of `port49_context_cache_lookups_total{outcome="stale"}` | `port49_context_cache_stale` | ticket | none | Every stale read is a command authorized on unconfirmed state. |
| TLS listener handshakes failing, by outcome: `rate(port49_tls_handshakes_total{outcome!~"ok\|resumed"}[5m])` | `port49_tls_handshake_failures` | ticket | 5m | Scanners cause the odd failure; five minutes of them is a device or a certificate. |
| A device certificate whose renewal is late: `port49_tls_device_certificate_lifetime_left_ratio < 0.33` | `port49_tls_device_certificate_renewal_late` | ticket | none | 0.33 is the default expiry_warning_fraction; a ratio holds for any lifetime, a fixed number of days would fire forever on short-lived certificates. |
| The TLS listener's certificate, its renewal late: `port49_tls_server_certificate_lifetime_left_ratio < 0.33` | `port49_tls_server_certificate_renewal_late` | ticket | none | As for the device certificates. |
| The TLS listener's certificate expired: `port49_tls_server_certificate_lifetime_left_ratio < 0` pages | `port49_tls_server_certificate_expired` | page | none | Below 0 is expired. |
| The TLS listener unable to establish a certificate's revocation status: `increase(port49_cert_status_unavailable_total{component="tls_listener"}[10m]) > 0` while TLS devices are admitted | `port49_tls_cert_status_unavailable` | ticket | none | The series carries only the component; with no TLS devices admitted it does not move. |
| A CRL the TLS listener relies on within an hour of its next update, or past it: `time() - port49_crl_next_update_timestamp_seconds{component="tls_listener"} > -3600` | `port49_crl_next_update_passed` | ticket | none | An hour is time to fix a failed fetch before the list stops serving. |
| A sync that changed a device's transport: `increase(port49_inventory_changes_total{kind="transport_changed"}[1h]) > 0` | `port49_inventory_transport_changed` | ticket | none | A downgrade is silent otherwise. |
| An OIDC provider outage that keeps its keys from being fetched: `time() - port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age / 2 or absent(...)`, with a `for:` of a few minutes | `port49_oidc_keys_stale` | ticket | 5m | Half of jwks_max_age (24h by default): one more failed cycle and every token for that issuer is refused. Set it to yours. Not `or absent()`: the series exists only for configured issuers, so on a deployment with no OIDC it would fire forever. |
| OIDC back-channel logouts not fully applied: logouts `store_error\|partial` | `port49_oidc_logouts_failing` | ticket | none | Each is a logout the store did not take whole. |
| A port49d that cannot tell whether its store was restored: `port49_redemption_restore_unjudged` at 1 | `port49_redemption_restore_unjudged` | page | 2m | The one refusal state the restore floor keeps: port49d cannot read `meta/witness`, so it refuses every token login with an `ERROR`, which IOS XE and Junos under `tacplus` alone treat as final. A failed read clears in seconds; two minutes is a store or a role that stayed wrong. |
| A session store restored from a snapshot: `port49_store_restore_detected_timestamp_seconds` above 0 | `port49_store_restore_detected` | ticket | none | Fires for a day after port49d finds its store restored (the gauge holds the time); the restore runbook on the backup and restore page is the work, and revocations made after the snapshot are lost until it is followed. The 0 of a port49d that never found one is skipped. |
| Bearer tokens refused because their issuer's keys are unavailable: tokens `unavailable` | `port49_oidc_tokens_unavailable` | ticket | none | The identity provider is unreachable and the held keys have expired. |
| Workload certificates presented with their renewal late: `increase(port49_workload_certificates_renewal_late_total[1h]) > 0`, summed over replicas | `port49_workload_certificates_renewal_late` | ticket | none | Each replica counts a certificate once per 24h, so any increase of the sum is a late renewer. |
| No scheduled directory refresh completed for three intervals: `time() - port49_directory_refresh_last_complete_timestamp_seconds > 3 × refresh_interval` | `port49_directory_refresh_stale` | ticket | 15m | 300 is broker.refresh_interval at its default (5m); set 3x yours. The freshest refresh anywhere, so a runner that lost the hold does not alarm on its old value; and only once the newest process with the series is also that old, so a restart does not, but a restart in the middle of an outage does (the gauge reads 0 until a pass completes). 15 minutes covers a failover: the new runner's series sits at 0 until its first pass completes. last_over_time keeps the rule firing for a day after every broker is gone. |
| No directory refresh completed for half the staleness ceiling: `time() - port49_directory_refresh_last_complete_timestamp_seconds > session.staleness_ceiling / 2` | `port49_directory_refresh_half_ceiling` | page | 15m | 7200 is half the default ceiling; set half yours. Same shape and 15m `for:` as port49_directory_refresh_stale. A page: at the ceiling sessions are denied. |
| Directory lookups that match more than one principal: `port49_directory_lookups_total{outcome="ambiguous"}` increasing | `port49_directory_lookups_ambiguous` | ticket | none | Each is a user refused; the directory holds two entries for one name. |
| A directory server down: `port49_directory_server_up == 0` for a while | `port49_directory_server_down` | ticket | 10m | Ten minutes: one server down is a degraded pool, not an outage. |
| Group names that two directory groups share: `port49_directory_group_names_ambiguous > 0` | `port49_directory_group_names_ambiguous` | ticket | 5m | A gauge over the last hour; the grants naming those groups are not given. |
| The broker's password enrollment store lost or never reached: `port49_directory_enrollment_store_ok == 0 or absent()` | `port49_directory_enrollment_store_lost` | page | 2m | The gauge is absent until the store first answers, and a broker that has never reached it is the case to catch. `port49_directory_password_configured` is 1 only on a broker with the verifier, so a broker without one never matches the absent arm. |
| An accounting spool dropping records | `port49_accounting_spool_drops` | page | none | Accounting records are an audit trail; no drop is acceptable. |
| Decision log writes refused: the log must be complete, never sampled | `port49_decision_log_write_failures` | page | none | The log is the audit trail; a refused write counts per attempt. |
| An inventory sync that failed: the service retains the previous bundle and alarms | `port49_inventory_sync_failing` | ticket | 10m | Syncs repeat; ten minutes is several failed ones. |
| An inventory sync that was refused: the service keeps the last good snapshot and alarms | `port49_inventory_sync_refused` | ticket | 5m | A refused sync is a bad source document; five minutes is not a race with its fix. |
| An inventory document port49d refused: the fleet keeps the last good snapshot and alarms | `port49_inventory_bundle_refused` | ticket | 5m | The old bundle serves, so a ticket; five minutes outlasts a rollout. |
| The inventory mirror behind the published bundle | `port49_inventory_mirror_behind` | ticket | 10m | A write is quick; ten minutes behind is a mirror that fails. |
| The inventory document in force not written to the state directory | `port49_inventory_persist_failed` | ticket | 5m | The state directory is full or unwritable. |
| A stale inventory snapshot: `port49_inventory_snapshot_age_seconds` raises an alarm, never a fail-closed | `port49_inventory_snapshot_stale` | ticket | 5m | 86400 is a day; set your sync cadence times a few. The NaN arm (no snapshot yet) is the spec's own expression. Not gated: a process that never watches the inventory reads 0, and one that waits for its first snapshot reads NaN from before its listener opens, which is the case the NaN arm is for. |
| Accounting for sessions port49 never saw begin: the `foreign` series, not rate-limited, because a burst of `foreign` is itself the signal | `port49_accounting_foreign` | page | none | Any foreign record is the detection the spec names for a local login the policy did not see; it pages. |
| Admitted devices served by the generic adapter: `port49_devices_generic_platform`, naming no device | `port49_devices_generic_platform` | ticket | 5m | A standing condition of the inventory, not an incident; the start line names the platforms and counts. |
| An inventory bundle built against a policy other than port49d's: the hash mismatch is logged and alarmed | `port49_inventory_policy_mismatch` | ticket | 5m | Five minutes outlasts a policy rollout reaching both. |
| A login context a policy refresh could not carry onto the policy in force: counted `failed` in `port49_context_refreshes_total` | `port49_context_refreshes_failed` | ticket | none | Each failure is one context left on an older policy or revoked. |
| Source-of-truth edits that move privilege: `port49_inventory_changes_total{kind}` | `port49_inventory_privilege_changes` | ticket | none | Every kind but transport_changed, which has its own alert. A device_added during onboarding raises it too: expected, and it is the only place a new capture target shows. |
| A run of per-login MFA proofs that did not verify: `per_login_mfa_refused`, alerted on its own, because a run of them is someone trying another token or another person's sign-in | `port49_per_login_mfa_refused` | page | none | More than two in ten minutes is a run; a mistyped touch is one. |
| Password sign-ins being throttled: a rise of `throttled` | `port49_sign_ins_throttled` | ticket | none | A throttle needs failures_per_* failed attempts: a guessing run, or one user's stale password on a script. |
| Password sign-ins refused because the enrollment store is lost: any `enrollment_store_lost` | `port49_sign_ins_enrollment_store_lost` | page | none | Any one is an operator or user refused; the gauge alert above covers a store that is lost with no sign-in in flight. |
| An etcd member with no leader: `etcd_server_has_leader == 0` | `etcd_no_leader` | page | 1m | A minute rides out an election. |
| An etcd database nearly at its quota: `etcd_mvcc_db_total_size_in_bytes / etcd_server_quota_backend_bytes > 0.8` | `etcd_db_nearly_full` | ticket | 10m | Defragment or compact before the quota: ten minutes is not a spike. |
| etcd changing leader too often: `increase(etcd_server_leader_changes_seen_total[1h]) > 3` | `etcd_leader_changes` | ticket | none | Occasional changes are rollouts; four in an hour is a fault. |
| An etcd disk too slow, by port49's own threshold: p99 of `etcd_disk_wal_fsync_duration_seconds` over 10 ms, or of `etcd_disk_backend_commit_duration_seconds` over 25 ms | `etcd_disk_slow` | ticket | 10m | etcd's own guidance is a WAL fsync p99 under 10 ms; a drive that stalls can push store calls past the 500 ms call timeout in bursts: on a CT1000P3PSSD8 drive the session etcd logged 7974 to 9244 slow applies in cells d and e (tests/lab/results/load-beehive.md), against 1 and 0 in RAM (tests/lab/results/load-beehive-ram.md) and at most 74 on a GCE pd-ssd (operator-declared; a 44, c 74, d 1, e 0) with a WAL fsync mean of 0.72 to 0.86 ms (tests/lab/results/load-p49-gce-n2s16.us-central1-a.c.port49.internal.md). Ten minutes over a 5m rate is a drive, not a compaction. |
| An accounting spool disk too slow, by port49's own threshold: p99 of `port49_accounting_spool_sync_seconds` over 10 ms for 10m | `port49_accounting_spool_disk_slow` | ticket | 10m | Every accounting ack waits on the spool's fsync; with the session etcd and the spool on a CT1000P3PSSD8 drive, account p99 was 152 ms at 170/s (tests/lab/results/load-beehive.md, cell c, `step_1_account_p99_ms`); with both in RAM the spool's capacity was 1291/s (tests/lab/results/load-beehive-ram.md, cell c), and on a GCE pd-ssd (operator-declared) 2905/s with account p99 3.67 ms at 170/s (tests/lab/results/load-p49-gce-n2s16.us-central1-a.c.port49.internal.md, cell c). |

## Notes

**The `component` label.** `port49_cert_status_checks_total`, `port49_crl_loads_total`,
`port49_crl_next_update_timestamp_seconds` and `port49_cert_status_unavailable_total` carry
`component` (`broker`, `tls_listener`), and the store metrics carry `component` and `pool`. A rule
that divides or compares two such series one-to-one fails to match across components: aggregate with
`sum by (...)` or match with `ignoring(component)`. Every rule here names its component or needs
no match.

**A dark etcd member costs up to 12 s.** gRPC raises a keepalive below 10 s to 10 s, plus a 2 s
timeout, so a dropped link to one member stalls the marks watch (events resume on another member)
and an unhedged call for that long. Reads and the opted-in mark writes are hedged, other writes are
not, so no alert can fire faster than that; the `for:` of the store rules is longer than 12 s
for this reason.

**Nothing warns before the listener closes.** `close_after` x `interval` (5 s at the defaults) is
shorter than any scrape interval, so no alert can fire between the first failed health check and
the close. `port49_store_health_failures_close` pages once the listeners are closed: the gauge is
held by the process, not the run, so the page stays raised through the whole outage and resolves
when the listeners reopen.

**Series that exist only where the thing does.** `port49_store_directory_reachable`,
`port49_store_directory_confirmed_timestamp_seconds`, `port49_store_keyspace_held` and
`port49_directory_refresh_last_complete_timestamp_seconds` are created by the code that starts what
they watch (the etcd store, the keyspace runner, the scheduled refresh), at 0. On the memory backend,
the default, they do not exist, so no alert on `== 0` or on age has a series to fire on. Where a gauge
cannot work that way, a `*_configured` gauge says whether to expect it: `port49_issuing_ca_configured`,
`port49_directory_password_configured`.

**Where the rules differ from the statement they answer.**
- `port49_oidc_keys_stale` drops the statement's `or absent()`: every configured issuer's series is
  created at 0, so an issuer that never fetched already shows `time() - 0`, and the series is absent
  only where OIDC is not configured, where `absent()` would fire forever.
- `port49_directory_enrollment_store_lost` keeps it, as `port49_directory_password_configured == 1
  unless on(instance) port49_directory_enrollment_store_ok`: the gauge is absent until the store
  first answers, and a broker that never reached it is the case to catch.
- `port49_issuing_ca_expiring` also requires the CA gauge above 0, so the page for a missing CA is
  not doubled by a ticket for a CA "expiring" in 1970.
- `port49_store_directory_stale` requires its timestamp above 0 (a process that has not yet confirmed
  is `port49_store_directory_unreachable` and `port49_store_feed_down`).
- `port49_directory_refresh_stale` and `port49_directory_refresh_half_ceiling` take the freshest
  refresh across all runner-capable replicas, so a replica that lost the hold, whose gauge stops
  moving, does not alarm; and they require the newest such process to have been up as long as the
  threshold, so a restart is quiet but a restart in the middle of a directory outage (the gauge reads 0
  until a pass completes) still fires. Both wait 15 minutes (`for:`), which covers a runner failover:
  the new runner's series sits at 0 until its first pass completes. They read `last_over_time(...[1d])`,
  so they keep firing for a day after every broker is gone, when no series is left to read.
- `port49_inventory_snapshot_stale` is the spec's expression with its NaN arm and no gate: a process
  that never watches the inventory reads 0, and one waiting for its first snapshot reads NaN before
  its listener opens, which is the case the NaN arm exists for.
- `port49_store_keyspace_unheld` sums over the processes that run a keyspace runner, and fires for a
  day after the last one disappears (a crashed fleet exports no 0): `count(last_over_time(...[1d]))
  unless count(...)`. A memory-backend install never had the series, so it never fires.
- The key-retirement rules leave out the spec's uptime gate (spec, key rotation: line 5578). That only makes them
  fire more. A restart blanks `port49_key_version_devices` (it counts devices whose latest validated
  connection since start used the version), so a rule that resolves after a restart is not evidence
  the devices have moved: read the decision log.
- `enrolled` sign-ins outside a rollout are not alerted: "outside a rollout" is yours to define.
