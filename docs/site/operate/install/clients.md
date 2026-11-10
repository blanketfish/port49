---
title: Install the clients
description: Installing the port49 command-line client, the Python library and the Ansible lookup.
---

# Install the clients

The clients run on the machines where people and automation sign in, not on the server. There are
three: the `port49` command, the Python library, and the Ansible lookup. The Python library and the
Ansible lookup both drive the `port49` command, so install that first.

## The two `port49` builds

The release has two builds of `port49`. Both are `/usr/bin/port49`, so no archive and no package holds
both.

| Build | Where you get it | Hardware keys |
|---|---|---|
| Client | the `port49` package and archive, for Linux and macOS (amd64 and arm64) | PKCS#11 keys (a YubiKey or a smartcard), the TPM (Linux) and file keys |
| Static | the `port49-server` package and archive, and the container image | the TPM (Linux) and file keys only |

**If your key lives on a YubiKey or a smartcard, run `port49 login` from the client build.** The client
build loads the system's PKCS#11 library at run time, so it needs the system's dynamic loader, which every
desktop Linux and macOS has.

The static build has no such loader dependency, which suits a server or a container. It will not use a
`pkcs11:` key: a key store set to `pkcs11` is refused, and `auto` passes over the key and says so. Nothing
else about it changes.

See [Hardware keys](../hardware-keys.md) for setting a key up.

Check which one you have, and its version:

```sh
port49 --version
```

## PKCS#11 on Linux, macOS and Homebrew

A hardware key needs the YubiKey PKCS#11 module, `libykcs11`. `port49 hwkey setup` and
`port49 hwkey status` find it in this order: the `--module` flag, then the `module-path` of a key already
in your config, then a probe of the system paths where a package installs it.

- **Debian and Ubuntu.** The `ykcs11` package installs `libykcs11.so` under
  `/usr/lib/<multiarch>/`, which is probed.
- **Fedora and RHEL.** `yubico-piv-tool` installs `/usr/lib64/libykcs11.so.2`, which is probed.
- **macOS and Homebrew.** No path is probed. Install `yubico-piv-tool`, find its `libykcs11.dylib`, and pass it:

  ```sh
  port49 hwkey status --module <path-to>/libykcs11.dylib
  ```

  port49 refuses to load a PKCS#11 module that another user could replace. On macOS it accepts write
  access held by the `admin` group, because Homebrew's prefix is group-writable by that group by design,
  but no other group. Once the key is in your config, its `module-path` names the module and you do
  not pass `--module` again.

If no module is found, the command says so and exits with status 2: `no libykcs11 found; install
yubico-piv-tool or pass --module` on Linux, and on macOS `no libykcs11 is probed on macOS: pass
--module PATH, the libykcs11.dylib of your yubico-piv-tool install`.

## The Python library

--8<-- "clients/python/README.md:3"

## The Ansible collection

--8<-- "clients/ansible/ansible_collections/port49/client/README.md:3"
