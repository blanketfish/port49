# L35-restore — cisco_nxos

- **Date measured:** 2026-10-03
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L35-restore-cisco_nxos.pcap` — 400 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L35-restore-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

A real `etcdutl snapshot restore --bump-revision 1000000000 --mark-compacted` under a running port49d leaves no revision reused; a context written again since the snapshot is denied store_unavailable (the ledger) and revoked by the next refresh pass, and a new login works; `port49d store-roles`' etcdctl lines, run by a real etcdctl, provision the roles port49d starts under (design §12, Backups; spec §13 decision 35; Ruling T13b-a).

## Observation

| step | observed |
|---|---|
| 0. `port49d store-roles`, each line run by etcdctl 3.6.15 as root | `'etcdctl role add port49_daemon': Role port49_daemon created; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/t/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/r/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/rp/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/c/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/x/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/ip/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/is/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/ic/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon readwrite --prefix=true /port49/v1/b/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/rv/': Role port49_daemon updated; 'etcdctl role grant-permission port49_daemon read --prefix=true /port49/v1/meta/': Role port49_daemon updated; 'etcdctl role add port49_broker': Role port49_broker created; 'etcdctl role grant-permission port49_broker readwrite --prefix=true /port49/v1/': Role port49_broker updated; 'etcdctl user add port49-daemon --no-password': User port49-daemon created; 'etcdctl user grant-role port49-daemon port49_daemon': Role port49_daemon is granted to user port49-daemon; 'etcdctl user add port49-broker --no-password': User port49-broker created; 'etcdctl user grant-role port49-broker port49_broker': Role port49_broker is granted to user port49-broker; 'etcdctl user add root --no-password': User root created; 'etcdctl user grant-role root root': Role root is granted to user root; 'etcdctl auth enable': Aut…` |
| 0. the keyspace before port49d's first start | `0 keys under /port49/ (err <nil>)` |
| 0. port49d's start under those roles | `listening (store.etcd.roles: enforced, the default)` |
| 1. session A (before the snapshot), `show version` | `printed its output in 700ms: 'Cisco Nexus Operating System (NX-OS) Software'` |
| 2. session B (after the snapshot), `show version` | `printed its output in 700ms: 'Cisco Nexus Operating System (NX-OS) Software'` |
| 2. revisions | `snapshot at 319; the store at 329 before the restore` |
| 3. the restore | `'etcdutl snapshot restore … --bump-revision 1000000000 --mark-compacted'; the store was gone 8.1s` |
| 3. revisions after the restore | `the store at 1000000319; the next write at 1000000320; a read at 329: {"level":"warn","ts":"2026-10-03T08:00:54.033797Z","logger":"etcd-client","caller":"v3@v3.6.15/retry_interceptor.go:68","msg":"retrying of unary invoker failed","target":"etcd-endpoints://0x14137cf04780/127.0.0.1:41407","peer":"Peer{Addr: '127.0.0.1:41407', LocalAddr: '127.0.0.1:38570', AuthInfo: 'tls'}","method":"/etcdserverpb.KV/Range","attempt":0,"error":"rpc error: code = OutOfRange desc = etcdserver: mvcc: required revision has been compacted"} (err exit status 1)` |
| 4. port49d's lines since the restore | nothing |
| 4. session B's next command | `refused in 100ms: 'Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)'; record deny store_unavailable (B's ctx_id HOCMUXYLXC6J7GFA)` |
| 5. the refresh pass after touching the policy | `port49d: policy reloaded (file changed): sha256:55ea2e42bbad3166ce48402b47748ce497bf4072a1ccf7bafc6f022d1bc6edfc replaces sha256:7dab7395f0b92032bb037eda78b4acf24108412deb1ea390657fdd46e094bb0b (bundle sha256:d009a791fe990be93ece0fafe7eb141b8ac16bdc4da698c73a258e0dbf2750b5); 0 device(s) quarantined now, 0 before / port49d: policy: key_groups are read from the inventory file; move the block into the policy file, where key assignment is reviewed (spec §10) / port49d: policy refresh: 0 live context(s) updated, 0 revoked, 0 unchanged, 0 left on quarantined devices, 1 failed; unspent tokens superseded on 0 (device, username) key(s) / 2026/10/03 08:01:46 broker: refresh: the context for "slice01" on "nx1", indexed under user:alice@slice.port49.test, will not open (crypt: opening context: crypt: not the context this port49d last wrote at its key); revoking it` |
| 5. records since the restore | `event=authorize_command verdict=deny reason=store_unavailable flags= user=slice01 port= event=refresh verdict=deny reason=blob_unavailable flags= user=slice01 port=` |
| 5. session B's next command after the pass | `refused in 100ms: 'Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)'; records [deny store_unavailable]` |
| 6. a new token login after the restore, `show version` | `login err <nil>; printed 'Cisco Nexus Operating System (NX-OS) Software'; redeem [permit token_redeemed], authorize_session [permit context_matched], authorize_command [permit permit_dominates permit permit_dominates]` |

