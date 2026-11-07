---
title: When it will not start
description: The refusals port49d prints at start, what each means and how to fix it.
status: stub
---

# When it will not start

This page is a stub.

Which probe to use where (this page will expand it): `port49d healthcheck` asks `/healthz`, liveness, and is the one for anything that restarts or holds back on unhealthy. `port49d healthcheck --ready` asks `/readyz`, readiness, and is for routing or display only; compose uses it. `port49-broker healthcheck` and `port49-inventory healthcheck` take the same flags.
