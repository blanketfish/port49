---
title: Install with containers
description: Running port49d, the broker and etcd as containers with Compose.
---

# Install with containers

This is one of three peer shapes (see [Install](index.md)). The Compose stack runs `port49d`,
`port49-broker` and a three-member etcd with client-certificate auth.

Read the [four requirements](index.md#what-every-shape-needs) on the Install page first, then follow the
guide below, which is the deployment's own README.

--8<-- "deploy/compose/README.md:3"
