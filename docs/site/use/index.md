---
title: Sign in
description: How a person installs the port49 client, signs in and connects to a device.
---

# Sign in

You sign in once with `port49 login`, then reach each device with `port49 ssh`, or get a token for your
own tool with `port49 token`. Your admin tells you which method applies to you.

| Method | You sign in with |
|---|---|
| Client certificate | a certificate and key you already hold, in a file, a TPM or a hardware key |
| OIDC | your company's identity provider, in a browser |
| Directory password | your directory name, password and an authenticator code |

| Part | Where it runs |
|---|---|
| The `port49` client | your own machine |
| The agent, started by `port49 login` | your own machine, holding your session |
| The device | unmodified: it asks for a password and you give it a token |

Before you start, install the [client](install-client.md) and get the broker's URL and CA from your admin.
Then run:

```sh
port49 login        # add your method's flags: see Log in
port49 ssh core-sw01
```

[Log in](login.md) covers each method, [Connect to a device](connect.md) covers `port49 ssh` and
`port49 token`, and [Hardware keys](hardware-keys.md) covers a YubiKey. How it all fits together is in
[Concepts](../concepts/index.md).
