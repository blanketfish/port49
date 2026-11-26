---
title: Versions
description: How port49 numbers its releases, what 0.x and 1.0.0 promise, and how to read the version of a running binary.
---

# Versions

port49 uses [Semantic Versioning](https://semver.org/).

| Version | What it means |
|---|---|
| `v0.1.0` | The beta. |
| `0.x` | Configuration may break between releases. Every such change is called out loudly in the release notes. Read them before you upgrade. |
| `1.0.0` | The compatibility promise. Before it, configuration may break between releases, always with a release note; from it, the SemVer rules hold. |

Release tags look like `v0.1.0`, with no pre-release suffix unless it maps to a valid Python (PEP 440)
version, because the Python package is released from the same tag.

## Which version of these docs you are reading

The site keeps one copy of the docs per release line, so a page matches the port49 you run.

| Address | What it is |
|---|---|
| `/latest/` | The newest release. The site root redirects here. Before the first release, it is the same copy as `dev`. |
| `/0.1/`, `/0.2/`, ... | One release line, rebuilt from its highest patch release. |
| `/dev/` | `main`, ahead of any release. It describes behavior no release has yet. |

The version selector in the page header keeps you on the same page when you switch, if it exists there. If
your binary says `port49d 0.1.0`, read `/0.1/`.

## One version across every artifact

A release has one version. The `port49-server` and `port49` packages, the archives, the container image,
the Helm chart and app versions, the Python package and the Ansible collection all carry it, and a check
refuses the release if they differ. A client and a server with the same number are from the same release.

## Read the version of a binary

```sh
port49 --version
port49d --version
port49-broker --version
port49-inventory --version
```

The line is the binary's name and the version, such as `port49d 0.1.0`; `port49 version` prints the same
line. Quote it in a bug report. A release build prints the version without the tag's leading `v`, and the
container image prints the same string as the package. `make build` from source prints `git describe`
without the `v`, marked `-dirty` when the tree has changes, and a plain `go build` prints `dev`.

## Upgrading

Read the release notes for config changes before a `0.x` upgrade. The upgrade steps are on
[systemd](systemd/upgrade.md), [containers](containers/upgrade.md) and [Helm](helm/upgrade.md). After an
upgrade that changes the etcd roles, apply them again by hand: port49 never does it for you (see
[Stores](stores.md)).
