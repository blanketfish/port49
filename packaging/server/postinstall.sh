#!/bin/sh
# Creates the users and directories, and has systemd read the new unit files. It never enables
# or starts a unit: configure first. A failed step fails the install, so it is found here and
# not at the first start. PORT49_PKG_SYSTEMD_RUN is a test hook; the default is systemd's own
# "is this the running init" directory, absent in a container or a chroot.
set -e
run=${PORT49_PKG_SYSTEMD_RUN:-/run/systemd/system}

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers port49.conf
else
    echo "port49-server: systemd-sysusers is not installed: create the users from /usr/lib/sysusers.d/port49.conf yourself" >&2
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create port49.conf
else
    echo "port49-server: systemd-tmpfiles is not installed: create the directories from /usr/lib/tmpfiles.d/port49.conf yourself" >&2
fi
if [ -d "$run" ]; then
    systemctl daemon-reload
fi
exit 0
