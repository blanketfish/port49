# MIT Kerberos's kinit with the PKINIT plugin (L44): the client that asks the
# Windows DC's KDC for a TGT with a certificate, so the DC's own mapping
# (KB5014754) is what answers. MIT 1.22 or later: Windows Server 2025's KDC
# refuses FFDH PKINIT without MS-PKCA's paChecksum2 (KDC error 79, "Checksum
# must be included"), which MIT added in 1.22 (commit 310793b). No Debian
# stable release ships 1.22, so Fedora 43, pinned by digest.
FROM fedora:43@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42
RUN dnf -y install --setopt=install_weak_deps=False krb5-workstation krb5-pkinit && dnf clean all
# The packages are not version-pinned; the run records what it got.
RUN rpm -q --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' krb5-workstation krb5-pkinit krb5-libs > /etc/pkinit-versions
