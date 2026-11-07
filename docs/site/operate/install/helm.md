---
title: Install with Helm
description: Deploying port49 to Kubernetes with the Helm chart.
---

# Install with Helm

This is one of three peer shapes (see [Install](index.md)). The chart runs `port49d` and `port49-broker` as
two StatefulSets, a volume claim per replica, against an etcd you supply. Nothing in port49 requires
Kubernetes. Read the four requirements on the index page first, then follow the guide below, which is
the chart's own README.

--8<-- "deploy/helm/port49/README.md:3"
