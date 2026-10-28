#!/bin/sh
# On removal only (deb "remove", rpm 0 left), stops and disables both units, so they do not keep
# running from deleted binaries and leave enable links to removed units. An upgrade (deb
# "upgrade", rpm 1 or more left) does nothing. PORT49_PKG_SYSTEMD_RUN is a test hook.
set -e
case "${1:-}" in
remove | 0) ;;
*) exit 0 ;;
esac
run=${PORT49_PKG_SYSTEMD_RUN:-/run/systemd/system}
if [ -d "$run" ]; then
    systemctl disable --now port49d.service port49-broker.service ||
        echo "port49-server: could not stop the units; stop and disable port49d and port49-broker yourself" >&2
fi
exit 0
