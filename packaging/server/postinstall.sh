#!/bin/sh
# Creates the users and directories. It never enables or starts a unit: configure first.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers port49.conf || true
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create port49.conf || true
fi
exit 0
