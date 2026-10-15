#!/bin/sh
# The directory fixture (plan 7g, Task 17), the same shape as OpenLDAP's, made
# offline against the DC's own database with samba-tool. Passwords are random
# and are used by nothing but the account that holds them, except port49's.
set -eu
BASE=DC=corp,DC=example,DC=com
DB=/var/lib/samba/private/sam.ldb

# A password that meets the domain's complexity rule, random per account.
pw() { printf 'Aa1!%s' "$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

for ou in Staff Contractors G Users-Can-Create Svc; do
  samba-tool ou create "OU=$ou,$BASE" >/dev/null
done

# user <name> <ou> <mail>
user() {
  samba-tool user create "$1" "$(pw)" --userou="OU=$2" --use-username-as-cn --mail-address="$3" >/dev/null
}
user alice Staff alice@corp.example.com
user carol Staff carol@corp.example.com
user dave Staff dave@corp.example.com
user bob Staff bob@corp.example.com
user eve Staff eve@corp.example.com
user eve2 Contractors eve@corp.example.com
samba-tool user create port49 "$LAB_PORT49_PASSWORD" --userou=OU=Svc --use-username-as-cn >/dev/null

# L67 (plan 9e): the people a sign-in is tried with. alice, carol and dave get
# the run's password (LAB_L67_PASSWORD, never printed), the lockout policy is
# 10 failures in 10 minutes for 10 minutes, and four people are put in the
# state a bind is asked about. Only when LAB_L67 is set: L42 and L43 keep the
# fixture, and the domain's default lockout (none), they were measured on.
if [ -n "${LAB_L67:-}" ]; then
  for u in alice carol dave; do
    samba-tool user setpassword "$u" --newpassword="$LAB_L67_PASSWORD" >/dev/null
  done
  samba-tool domain passwordsettings set --account-lockout-threshold=10 --account-lockout-duration=10 \
    --reset-account-lockout-after=10 >/dev/null
  for u in l67-expired l67-disabled l67-mustchange l67-locked; do
    samba-tool user create "$u" "$LAB_L67_PASSWORD" --userou=OU=Staff --use-username-as-cn \
      --mail-address="$u@corp.example.com" >/dev/null
  done
  samba-tool user disable l67-disabled >/dev/null
  samba-tool user setpassword l67-mustchange --newpassword="$LAB_L67_PASSWORD" --must-change-at-next-login >/dev/null
  # An expired password: pwdLastSet in 2009, far past the domain's maximum age.
  # Samba's password module refuses any pwdLastSet but 0 or -1 unless the write
  # carries its bypass control (measured; local_oid 1.3.6.1.4.1.7165.4.3.12).
  # If the write is refused the fixture still loads and says so; the test reads
  # the state back and records the cell as not measurable.
  if LDB_CONTROLS=local_oid:1.3.6.1.4.1.7165.4.3.12:0 /lab/set-attr.sh "CN=l67-expired,OU=Staff,$BASE" pwdLastSet 128800000000000000 2>/tmp/l67-expired.err; then
    echo "lab: l67 expired password set"
  else
    echo "lab: l67 expired password NOT set: $(tr '\n' ' ' </tmp/l67-expired.err | cut -c1-200)"
  fi
fi

group() { samba-tool group add "$1" --groupou="OU=$2" >/dev/null; }
group g-leaf G
group g-mid G
group netops-oncall G
group g-loop-a G
group g-loop-b G
samba-tool group addmembers g-leaf alice >/dev/null
samba-tool group addmembers g-mid g-leaf >/dev/null
samba-tool group addmembers netops-oncall carol,g-mid >/dev/null
samba-tool group addmembers g-loop-a dave,g-loop-b >/dev/null
samba-tool group addmembers g-loop-b g-loop-a >/dev/null

# The second netops-oncall. sAMAccountName is unique domain-wide in AD, so it
# is made under another name and its CN renamed to the same: two groups with
# one cn, as a user with create rights over an OU could make.
group netops-oncall-uc Users-Can-Create
ldbrename -H "$DB" "CN=netops-oncall-uc,OU=Users-Can-Create,$BASE" "CN=netops-oncall,OU=Users-Can-Create,$BASE" >/dev/null

# Alice's strong mapping, computed by the lab test with directory.ADIssuerSerial
# so that port49's form is what the directory holds.
/lab/set-attr.sh "CN=alice,OU=Staff,$BASE" altSecurityIdentities "$LAB_ALICE_ALTSECID"

# The ldap/localhost SPN: port49 binds GSSAPI to ldap/<the URI's host>, and the
# lab's URI host is localhost, which the test certificate names.
samba-tool spn add ldap/localhost 'DC1$' >/dev/null

rm -f /out/port49.keytab
samba-tool domain exportkeytab /out/port49.keytab --principal=port49@CORP.EXAMPLE.COM >/dev/null
chown "$LAB_UID:$LAB_GID" /out/port49.keytab
chmod 0600 /out/port49.keytab
samba-tool user show alice --attributes=objectSid | grep -i '^objectSid' | sed 's/^/lab: alice /'
echo "lab: samba fixture loaded"
