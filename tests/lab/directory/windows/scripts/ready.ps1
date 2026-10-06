# L44: whether AD DS answers after the promotion's reboot.
param()
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$d = Get-ADDomain
@{ domain_dn = $d.DistinguishedName; pdc = $d.PDCEmulator }
