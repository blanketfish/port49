---
title: Back up with Velero
description: Back up and restore a Helm release of port49 with Velero.
---

# Back up with Velero

A Velero restore that includes `port49-etcd` is a store restore. It was measured on kind with Velero 1.18.4 and its
node agent ([L89-kind.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L89-kind.md)): a backup of
both StatefulSets, a deleted namespace and a restore left both ready with no fence refusal, the issuing CA unchanged,
and a mint and a login working; a restore with the StatefulSets at 0 replicas hung; and the restore order below, with
the pods running and then scaled to 0, completed with `marks.json`, the CA and the spool intact. The runbook below is the repository's own file, so it matches the chart you run.

--8<-- "deploy/helm/port49/examples/velero/README.md:5"
