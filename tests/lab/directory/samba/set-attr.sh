#!/bin/sh
# set-attr.sh <dn> <attribute> <value>: replace one attribute of one entry in
# the DC's own database, as `samba-tool user edit` would. The value is not
# printed.
set -eu
dn=$1 attr=$2 value=$3
tmp=$(mktemp)
printf 'dn: %s\nchangetype: modify\nreplace: %s\n%s: %s\n' "$dn" "$attr" "$attr" "$value" > "$tmp"
ldbmodify -H /var/lib/samba/private/sam.ldb "$tmp" >/dev/null
rm -f "$tmp"
