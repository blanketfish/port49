# L26c — juniper_srx (operator-reported)

- **Date reported:** 2026-09-25
- **Platform:** SRX-series hardware
- **Image version:** Junos 23.4R2-S8.7
- **Capture:** none. The owner ran these by hand and reported them; no pcap or raw output was
  kept. **This note does not close L26c** (§15 rule 3 needs a capture); it records what the
  hardware showed beside the lab's `L26c-juniper_*.md`.
- **Transport:** SSH, TACACS+ authorization from tac_plus

## Setup

The reply set `local-user-name` to a local template class and sent `user-permissions` and
`deny-commands` as attributes. `show cli authorization` showed the class, the permissions and the
deny list as sent.

## Observation

| # | Reply | Test | Result |
|---|---|---|---|
| 1 | `view view-configuration`, `deny-commands "show configuration security"` | CLI `show configuration`, `show configuration security` | Both run. A deny naming a hierarchy is not enforced (as L26b measured). |
| 2 | `view view-configuration`, a deny naming `show configuration` with a trailing wildcard | CLI `show configuration …` | Runs. |
| 3 | `view view-configuration`, `deny-commands "show configuration"` | CLI `show configuration` | Refused. |
| 4 | same as 3 | `xml-mode netconf`, then `<rpc><get-configuration/></rpc>` | Hello returned; the whole configuration returned, secret values masked. |
| 5 | `view`, `deny-commands "show version"` | CLI `show version` | Refused. |
| 6 | same as 5 | `xml-mode netconf`, then `<rpc><get-software-information/></rpc>` | Refused (permission denied). |
| 7 | `view`, no deny (control for 5 and 6) | the same two | Both run. |
| 8 | denies `(show configuration\|xml-mode)`, `(show configuration\|xml mode netconf)`, `^xml-mode.*`, `.*xml-mode.*`, `xml.*` | CLI `xml-mode netconf` | Enters NETCONF in every case. |

`xml-mode netconf need-trailer` is not a valid command on this release; plain `xml-mode netconf`
works, and the results do not depend on the argument. No configuration statement was found that
controls `xml-mode`.

## What it means for port49

- **A wire deny beneath `view-configuration` is not a boundary.** `<get-configuration/>` is
  authorized by the bit, not by `deny-commands` (row 4). This is the case L26c left open ("whether
  an RPC reaches past a deny beneath `view-configuration`"), and it is what option C assumes.
- A deny does bind an operational RPC mapped to its CLI command (rows 5–7), as L26c saw for a
  `<command>` RPC.
- No deny naming `xml-mode` refuses it (row 8). The lab saw only `^.*$` refuse it, which is why
  the fail-closed and narrow replies send exactly that (`TestTheCatchAllDenyIsExactlyAnchoredDotStar`).
- `^.*$` refusing `xml-mode` was not re-run on this hardware.
