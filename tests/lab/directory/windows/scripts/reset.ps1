# L44: what every run sets, on a fresh DC or a kept one: port49's password
# (this run's), alice's altSecurityIdentities (port49's form for the run's
# users-CA certificate, as samba/seed.sh writes it), bob's mail, no mapping on
# port49, and LDAP interface diagnostics at 2, so the DC logs its bind events.
param([string]$port49_password, [string]$alice_altsecid)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$p49 = ConvertTo-SecureString $port49_password -AsPlainText -Force
Set-ADAccountPassword port49 -Reset -NewPassword $p49
Set-ADUser alice -Replace @{ altSecurityIdentities = $alice_altsecid }
Set-ADUser bob -EmailAddress 'bob@corp.example.com'
Set-ADUser port49 -Clear altSecurityIdentities
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' `
  -PropertyType DWord -Value 2 -Force | Out-Null
@{ reset = $true }
