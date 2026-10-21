# L79 — three simulated regions

- **Date measured:** 2026-10-21
- **Platform:** port49 on the lab host, three simulated regions (network namespaces, tc netem 20ms each way)
- **Image version:** etcd Version: 3.6.15
- **Capture:** tests/lab/evidence/L79-regions/
- **Run:** commit `aa3685b38d3d78082ce116ad6eeec212c53ec895`, `-run TestRegions`

## Claim

spec §15 L79 (decision 51's provisional ruling): whether a directory write sent from region 3 while its link is cut (iptables DROP, so the kernel keeps retransmitting) is delivered after the heal at 20s, inside the retransmission window.

## Observation

| cell | claim | observed | agrees with decision 51 |
|---|---|---|---|
| j | a lift sent from region 3 during the cut, reported "could not be lifted, and stands": whether the mark is deleted after the heal; what port49 store status and the logs say | lift from region 3 exit 1 in 513ms: port49 revoke: broker: the revocation could not be lifted, and stands: store: unavailable: context deadline exceeded; the mark in the directory during the cut: true; the mark was there at the heal and still there for 1m0s; store status in region 3 during the cut (exit 3): directory  etcd    1/3 members  unreachable  cache 2.4s /            timed out / session    etcd    1/1 members  reachable; after the heal: directory  etcd    3/3 members  reachable  cache 0.7s / session    etcd    1/1 members  reachable; broker 3's lines naming alice since the heal: none; port49d 3's lines naming the directory since the heal: port49d: directory store: answering again; the cache was 23.0s old; the mark's revision before the cut 5 and after the heal 5; "are put back" lines in broker 3's log since the heal: 0 | yes |
| k | a revoke sent from region 3 during the cut, reported failed, with the mark lifted in region 1 meanwhile: whether the mark reappears after the heal (expected: it fails closed); what an operator sees | revoke from region 3 exit 1 in 512ms: port49 revoke: broker: the revocation could not be recorded, so nothing else was revoked; this port49-broker denies what it names until a lift on this port49-broker or its restart (store: unavailable: context deadline exceeded); cut access another way: remove the principal's grants from broker.policy_file (live within two watch intervals), or stop every port49d (port49-broker serves no device); the lift in region 1 exit 0; the mark during the cut after the lift: false; the mark was absent at the heal and back after 250ms; store status in region 3 during the cut (exit 3): directory  etcd    ?/? members  unreachable  cache 2.1s /            timed out / session    etcd    1/1 members  reachable; after the heal: directory  etcd    3/3 members  reachable  cache 0.6s / session    etcd    1/1 members  reachable; broker 3's lines naming alice since the heal: port49-broker: runner: a revocation of user:alice@example.com made elsewhere reached 0 token key(s) and 0 context(s) here; port49d 3's lines naming the directory since the heal: port49d: directory store: answering again; the cache was 23.2s old; the directory's revision at the cut 7, after the lift 8, and the mark's after the heal 9; "are put back" lines in broker 3's log since the heal: 0 | yes |
