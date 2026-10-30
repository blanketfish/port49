# Packaging

`.goreleaser.yaml` builds the release archives, the `.deb` and `.rpm` packages and `SHA256SUMS`.
`make packages` builds them into `dist/` from a sha256-pinned GoReleaser; it publishes nothing.
`make packages-check` then runs `tests/packages`, which fails (never skips) when `dist/` is empty.

Status: `make packages` has built the snapshot and `make packages-check` passes on the debs and rpms
(2026-10-30). The release workflow itself, signing and publishing have not run.

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
library. Run `pip install port49` after installing it.

## After install

The server package creates the users and directories and reloads systemd (when it is running), but enables and starts nothing. Removing the package stops and disables both units; an upgrade leaves them running. Configure
`/etc/port49/` first (see `deploy/systemd/README.md`), then `systemctl enable --now port49d`.
