# Store examples

Complete `port49d.yaml` and `port49-broker.yaml` files at the systemd paths, for the two store
layouts of spec §13 decision 51. The systemd README and the compose README point here; the
Kubernetes form is the chart's `examples/values-multi-region.yaml`. `tests/shapes` loads each file
through `config.Load` and `config.LoadBroker`, so a key renamed in the code fails a test here.

| Directory | Layout |
|---|---|
| `single-site/` | one etcd cluster of three; `stores.session` omitted, so the session store is the directory store |
| `multi-region/` | `stores.directory` stretched one member per region (`call_timeout: 500ms`); `stores.session` an etcd of the region's own. The files are the us region's: each region names its own session endpoints |

Both name every member's URL, never a load balancer or a VIP. Every `secret_ref` is a `file:`.
Replace the `example.com` names and PKI paths; run `port49d store-roles` once per cluster (the
directory's, and each region's session section).

In a multi-region deployment the `encryption:` key is the same material in every region, from
one secret. The README of each shape carries the rotation runbook.

A cut region keeps logging devices in; directory writes and password sign-in are refused there
(L74), and `port49 store status` exits 3.
