---
title: Qualification
description: How a device platform is qualified against port49, how to vet a firmware and add a platform, and how the lab regression run works.
---

# Qualification

A platform is qualified when the lab has run a real firmware image against port49 and the measured behavior
is recorded. Two tiers use that record:

- **The mock tier** (`make qual`) replays each vetted firmware's measured behavior against a real
  in-process port49d. It needs no image, no lab and no special runner, so it runs on every pull request.
- **The lab tier** boots the real image. It is `make lab-qualify`, and `make qual-vet` wraps it for the
  vetting procedure below. It needs the lab, so only a maintainer with the lab runs it.

The commands you will use:

| Command | What it does |
|---|---|
| `make qual` | The mock tier: the device-mock packages, `tests/qual`, and the port49d qualification tests. |
| `make qual-vet P=<selector>` | Vets one firmware in the lab and generates its mock for review. It commits nothing. |
| `make qual-update` | Rewrites the goldens after a deliberate change to port49's decisions. Review the diff. |
| `make qual-fleet` | Linux only: many mock devices, each from its own loopback address, against one port49d. |
| `make qualified-platforms` | Regenerates `docs/qualified-platforms.md` from the profiles, goldens and notes. |

!!! note "Vendor images are never hosted"
    port49 does not host, mirror or redistribute a vendor's device image, and no pull request adds one.
    You obtain an image from the vendor under your own license and keep it on your own lab host. What the
    repository holds is the measured behavior: the notes, the profiles and the goldens.

## The procedures

The rest of this section is the contributor guide from `tests/qual/README.md`, included as it stands.
`engine_gaps` are the behaviors of a device that port49's engine cannot yet express; each one needs Go in
`internal/devicemock` and a test.

--8<-- "tests/qual/README.md:procedures"

## The lab regression run

--8<-- "tests/lab/README.md:regressions"

### Working around the NX-OS boot hang

`make lab-regress` passes `LAB_REGRESS_ARGS` to the runner, whose `-only=` flag takes a comma-separated list
of entry ids and runs just those. Use it to retry an entry whose NX-OS device never booted, instead of rerunning
the whole manifest:

```sh
make lab-regress LAB_REGRESS_ARGS=-only=<entry_id>,<entry_id>
```

`-dry-run` lists the entries and their last measured minutes without running anything. Each deploy logs
`boot:` and `host:` lines; read the hang from them before you raise a timeout.
