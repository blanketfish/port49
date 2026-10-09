#!/usr/bin/python3
# l50-dacl.py <password> allow|own <dn> <attribute schemaIDGUID> <trustee SID>
#
# L50 (review I-3): what the delegated administrator l50-ouadmin can do to the
# security descriptor of <dn>, as l50-ouadmin over ldap://localhost.
# - allow: adds an explicit allow of WriteProperty on the attribute for the
#   trustee, as the first ACE of the DACL.
# - own: makes the trustee the owner.
# samba-tool dsacl cannot be used for this: it reads the descriptor with the
# SACL requested, which a delegated admin has no right to read, and stops
# before it changes anything. This reads and writes owner, group and DACL only
# (sd_flags 7, or 1 for the owner).
#
# Prints "accepted" and the new descriptor and exits 0, or "refused" and the
# directory's error and exits 1. The password is never printed.
import re
import sys

import ldb
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

OWNER, GROUP, DACL = 1, 2, 4


def main():
    password, action, dn, guid, trustee = sys.argv[1:6]
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    creds.set_username("l50-ouadmin")
    creds.set_password(password)
    try:
        samdb = SamDB(url="ldap://localhost", credentials=creds, lp=lp)
        domain_sid = security.dom_sid(samdb.get_domain_sid())
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"],
                           controls=["sd_flags:1:%d" % (OWNER | GROUP | DACL)])
        sd = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
        if action == "own":
            flags = OWNER
            sd.owner_sid = security.dom_sid(trustee)
        else:
            flags = DACL
            ace = "(OA;;WP;%s;;%s)" % (guid, trustee)
            sddl = sd.as_sddl(domain_sid)
            # Inherited ACEs are recomputed by the directory; drop them, as
            # samba-tool dsacl does, and put the new ACE first.
            for old in re.findall(r"\(.*?\)", sddl):
                if "ID" in old.split(";")[1]:
                    sddl = sddl.replace(old, "")
            i = sddl.index("(") if "(" in sddl else len(sddl)
            sd = security.descriptor.from_sddl(sddl[:i] + ace + sddl[i:], domain_sid)
        msg = ldb.Message()
        msg.dn = ldb.Dn(samdb, dn)
        msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(sd), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
        samdb.modify(msg, ["sd_flags:1:%d" % flags])
    except ldb.LdbError as e:
        print("refused: ldb error %d: %s" % (e.args[0], e.args[1]))
        return 1
    print("accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
