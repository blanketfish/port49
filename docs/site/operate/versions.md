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

Release tags look like `v0.1.0`. A tag carries no pre-release suffix, unless the suffix maps to a valid
Python (PEP 440) version, because the Python package is released from the same tag.

## Which version of these docs you are reading

The site keeps one copy of the docs per release line, so a page matches the port49 you run:

| Address | What it is |
|---|---|
| `/latest/` | The newest release. The site root redirects here, and a link to `/latest/<page>` stays valid across releases. Before the first release, it is the same copy as `dev`. |
| `/0.1/`, `/0.2/`, ... | The docs of one release line, rebuilt from the highest patch release of that line (`v0.1.2` replaces `v0.1.1`). |
| `/dev/` | `main`, ahead of any release. It describes behavior no release has yet. |

The version selector in the page header lists these, and keeps you on the same page when you switch, if
that page exists in the other version. The banner at the top of the page says which one you are reading:
"This site describes port49 v0.1.2." for a release, or that the site describes main, not a release.
If your binary says `port49d 0.1.0` (see below), read `/0.1/`.

## One version across every artifact

A release has one version, and every artifact carries it:

- the `port49-server` and `port49` packages
- the archives
- the container image
- the Helm chart and app versions
- the Python package
- the Ansible collection

They are set to the same number before the tag is pushed, and a check refuses the release if they
differ. So you never have to guess which client goes with which server: the same number means the same
release.

## Read the version of a binary

Every binary prints its own version:

```sh
port49 --version
port49d --version
port49-broker --version
port49-inventory --version
```

The line is the binary's name and the version, such as `port49d 0.1.0`. `port49 version` prints the
same line as `port49 --version`. Quote that line in a bug report.

What the version part says depends on how the binary was built:

- **A release build** prints the version without the tag's leading `v`. The container image prints
  the same string as the package.
- **`make build` from source** prints what `git describe` gives for the checkout, without the `v`. It
  is marked `-dirty` when the tree has changes.
- **A plain `go build`** stamps nothing, and prints the word `dev` in place of the version.

## Upgrading

- **Before a `0.x` upgrade,** read the release notes for config changes.
- **After an upgrade that changes the etcd roles,** apply them again by hand. It is never done for you
  (see [Stores](stores.md)).
