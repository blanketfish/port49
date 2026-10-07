# L44: whether AD DS answers after a reboot, and when this boot began.
param()
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$d = Get-ADDomain
@{ domain_dn = $d.DistinguishedName; pdc = $d.PDCEmulator
   boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
