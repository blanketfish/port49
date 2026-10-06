# L44: L42's fixture, the shape tests/lab/directory/samba/seed.sh makes: the
# same people, nested groups, loop, shared group name and broker account.
# Passwords are random per account; port49's arrives on stdin.
param([string]$port49_password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = 'DC=corp,DC=example,DC=com'
function New-LabSecret {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ConvertTo-SecureString ('Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')) -AsPlainText -Force
}
foreach ($ou in 'Staff', 'Contractors', 'G', 'Users-Can-Create', 'Svc') {
  New-ADOrganizationalUnit -Name $ou -Path $base -ProtectedFromAccidentalDeletion $false
}
function Add-LabUser([string]$name, [string]$ou, [string]$mail) {
  New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@corp.example.com" -EmailAddress $mail `
    -Path "OU=$ou,$base" -AccountPassword (New-LabSecret) -Enabled $true
}
Add-LabUser alice Staff alice@corp.example.com
Add-LabUser carol Staff carol@corp.example.com
Add-LabUser dave Staff dave@corp.example.com
Add-LabUser bob Staff bob@corp.example.com
Add-LabUser eve Staff eve@corp.example.com
Add-LabUser eve2 Contractors eve@corp.example.com
$p49 = ConvertTo-SecureString $port49_password -AsPlainText -Force
New-ADUser -Name port49 -SamAccountName port49 -Path "OU=Svc,$base" -Enabled $true -PasswordNeverExpires $true `
  -AccountPassword $p49 -KerberosEncryptionType AES128,AES256
function Add-LabGroup([string]$name, [string]$ou) {
  New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path "OU=$ou,$base"
}
'g-leaf', 'g-mid', 'netops-oncall', 'g-loop-a', 'g-loop-b' | ForEach-Object { Add-LabGroup $_ G }
Add-ADGroupMember g-leaf -Members alice
Add-ADGroupMember g-mid -Members g-leaf
Add-ADGroupMember netops-oncall -Members carol, g-mid
Add-ADGroupMember g-loop-a -Members dave, g-loop-b
$loop = 'made'
try { Add-ADGroupMember g-loop-b -Members g-loop-a } catch { $loop = 'refused: ' + $_.Exception.Message }
# The second netops-oncall: sAMAccountName is unique domain-wide, so it is made
# under another and its CN renamed, as samba/seed.sh does.
Add-LabGroup netops-oncall-uc Users-Can-Create
Rename-ADObject "CN=netops-oncall-uc,OU=Users-Can-Create,$base" -NewName netops-oncall
# port49 binds GSSAPI to ldap/<the URI's host>, and the lab's URI host is localhost.
setspn.exe -S ldap/localhost DC1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "setspn ldap/localhost: exit $LASTEXITCODE" }
@{ loop = $loop; alice_created = (Get-ADUser alice -Properties whenCreated).whenCreated.ToUniversalTime().ToString('o') }
