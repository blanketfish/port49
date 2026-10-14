"""port49 and Netmiko: `python3 show_version.py leaf1` (after `port49 login`)."""

import sys

from port49.netmiko import connect

conn = connect(sys.argv[1])
try:
    print(conn.send_command("show version"))
finally:
    conn.disconnect()
