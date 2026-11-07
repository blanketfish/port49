# Packaging

`.goreleaser.yaml` builds the release archives, the `.deb` and `.rpm` packages and `SHA256SUMS`.
`make packages` builds them into `dist/` from a sha256-pinned GoReleaser; it publishes nothing.
`make packages-check` then runs `tests/packages`, which fails (never skips) when `dist/` is empty.

Status: `make packages` has built the snapshot and `make packages-check` passes on the debs and rpms
(2026-10-30). The release workflow itself, signing and publishing have not run.

## The first tag

Before the first tag (the release workflow has never run) do these once. They need the PyPI trusted publisher
and the `galaxy` and `release` environments set up. After the first tag publishes:

- Re-run the workflow's `galaxy` job once. The second publish of the same version must succeed, not fail: the
  job passes only if Galaxy's "already exists" refusal matches the workflow's pattern, whose message text
  after `HTTP Code: 400` was read from ansible-core's source and not yet seen from the real server. If the
  re-run fails with that line, fix the pattern in `.github/workflows/release.yml` to the line it printed.
- Pull the chart and the image by digest and check their attestations: `gh attestation verify
  oci://ghcr.io/blanketfish/charts/port49:<version> --repo blanketfish/port49`.

## Two packages

| Package | Holds | Conflicts with |
|---|---|---|
| `port49-server` | `port49d`, `port49-broker`, `port49-inventory`, a static `port49`, the two units, the sysusers and tmpfiles files, this README's systemd companion and the examples (configs, etcd, snapshot and export units, store blocks) under `/usr/share/doc/port49-server/` | `port49` |
| `port49` | the client `port49` (PKCS#11 through purego), `/etc/port49/config.yaml`, the Ansible collection, and on `.deb` the Python library | `port49-server` |

Both carry `/usr/bin/port49`, so a host has one or the other. A server host that also needs the
client's hardware-key backend uses the client package's binary from the release archive.

## Conffile

`/etc/port49/config.yaml` is a conffile: an upgrade keeps your edits. As shipped it sets nothing
(every key is a commented example), because the broker URL and CA are your configuration
management's to set. `~/.port49/config.yaml` overrides it, and a flag overrides both.

## The Python library on an `.rpm`

An `.rpm` has no version-independent site-packages path, so the `port49` rpm does not carry the
library. After installing it, run `pip install port49==<version>`, the version `port49 --version`
prints (the package exists from the first release, `v0.1.0`; install from the tree before that).

## After install

The server package creates the users and directories and reloads systemd (when it is running), but enables and starts nothing. Removing the package stops and disables both units; an upgrade leaves them running. Configure
`/etc/port49/` first (see `deploy/systemd/README.md`), then `systemctl enable --now port49d`.
