---
title: Install the client
description: Install the port49 command-line client on the machine where you sign in, and set up a YubiKey module if you use one.
---

# Install the client

The client runs on the machines where people sign in, not on the server. The Python library and the
Ansible lookup both drive the `port49` command, so install it first.

The release has two builds of `port49`, and both are `/usr/bin/port49`, so no archive and no package holds
both.

| Build | Where you get it | Hardware keys |
|---|---|---|
| Client | the `port49` package and archive, for Linux and macOS (amd64 and arm64) | PKCS#11 keys (a YubiKey or a smartcard), the TPM (Linux) and file keys |
| Static | the `port49-server` package and archive, and the container image | the TPM (Linux) and file keys only |

If your key lives on a YubiKey or a smartcard, run `port49 login` from the client build, which loads the
system's PKCS#11 library at run time. The static build suits a server or a container. It refuses a key
store set to `pkcs11`, and `auto` passes over the key and says so.

## 1. Download a release

Each release on [GitHub Releases](https://github.com/blanketfish/port49/releases) carries the client
archive for each system, `port49_<version>_<os>_<arch>.tar.gz`, and a `SHA256SUMS` file covering every
asset. Download both, check the archive against the sums, then unpack `port49`:

```sh
PORT49_VERSION=0.1.0
base="https://github.com/blanketfish/port49/releases/download/v${PORT49_VERSION}"
curl -fsSLO "${base}/port49_${PORT49_VERSION}_linux_amd64.tar.gz"
curl -fsSLO "${base}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf "port49_${PORT49_VERSION}_linux_amd64.tar.gz" port49
```

To check, the `sha256sum` line prints the archive's name followed by `: OK`. On macOS, use `darwin` in the
archive name and `shasum -a 256 --ignore-missing -c SHA256SUMS`. With the GitHub CLI,
`gh attestation verify port49_${PORT49_VERSION}_linux_amd64.tar.gz --repo blanketfish/port49` also checks
that the release workflow built the archive.

## 2. Install it with mode 0755

Install `port49` with mode `0755`, owned by root, with no setgid bit and no file capabilities. The
packages and the image already do. If you copy the binary by hand, do the same:

```sh
sudo install -m 0755 port49 /usr/local/bin/port49
port49 --version
```

To check, the second command prints `port49` and the release version.

!!! info "Why the mode matters"
    `port49 ssh` tells `ssh` to run `port49` itself as `SSH_ASKPASS`, by the path `/proc/<pid>/exe`. A
    setgid or capability-bearing binary makes that path unexecutable for the `ssh` process, and `ssh` then
    sends the device an empty password, so the login fails.

## 3. Set up PKCS#11 for a YubiKey

Skip this step if your key is a file or in a TPM. A hardware key needs the YubiKey PKCS#11 module,
`libykcs11`. `port49 hwkey setup` and `port49 hwkey status` find it in this order: the `--module` flag,
then the `module-path` of a key already in your config, then a probe of the system paths where a package
installs it.

- On Debian and Ubuntu the `ykcs11` package installs `libykcs11.so` under `/usr/lib/<multiarch>/`, which
  is probed.
- On Fedora and RHEL `yubico-piv-tool` installs `/usr/lib64/libykcs11.so.2`, which is probed.
- On macOS and Homebrew. No path is probed. Install `yubico-piv-tool`, find its `libykcs11.dylib`, and
  pass it:

  ```sh
  port49 hwkey status --module <path-to>/libykcs11.dylib
  ```

  port49 refuses a PKCS#11 module that another user could replace. On macOS it accepts write access held
  by the `admin` group, which owns Homebrew's prefix, but no other group. Once the key is in your config,
  its `module-path` names the module.

If no module is found, the command exits 2. On Linux it says `no libykcs11 found; install yubico-piv-tool or pass --module`. On macOS it says `no libykcs11 is probed on macOS: pass --module PATH, the libykcs11.dylib of your yubico-piv-tool install`. On the static build `port49 hwkey` exits 2 and says it was built without PKCS#11 support, so install the client build.

[Hardware keys](hardware-keys.md) sets the key up.

## The Python library and the Ansible collection

Automation that drives `port49` has two more packages: the [Python library](../automation/python.md) and
the [Ansible collection](../automation/ansible.md).
