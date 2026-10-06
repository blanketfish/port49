# L44: a certificate for a user from the User template, requested AS that
# user, so the CA builds its subject from the account and writes KB5014754's
# SID extension from it: what an online template issues. The request travels
# over WinRM with CredSSP to this DC, under a session configuration only the
# user may use. The user's password is made here, used once and replaced; it
# never leaves this script. Everything it opens is closed in finally.
param([string]$csr_pem, [string]$user)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
function New-LabPlain {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  'Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}
$fqdn = "$env:COMPUTERNAME.corp.example.com"
# CredSSP delegates only to a target Kerberos can verify, by its WSMAN SPN.
# WinRM registers that SPN itself on a member server; on the L44 DC it had
# not (measured: setspn -L listed no WSMAN/, and CredSSP refused the target as
# not trusted). Registered once, kept: the DC is the lab's.
$spns = (setspn.exe -L $env:COMPUTERNAME | Out-String)
if ($LASTEXITCODE -ne 0) { throw "setspn -L: exit $LASTEXITCODE" }
foreach ($s in "WSMAN/$env:COMPUTERNAME", "WSMAN/$fqdn") {
  if ($spns -notmatch "(?m)^\s*$([regex]::Escape($s))\s*$") {
    setspn.exe -S $s $env:COMPUTERNAME | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "setspn -S ${s}: exit $LASTEXITCODE" }
  }
}
$sid = (Get-ADUser $user).SID.Value
$plain = New-LabPlain
$sec = ConvertTo-SecureString $plain -AsPlainText -Force
Set-ADAccountPassword $user -Reset -NewPassword $sec
$cred = New-Object Management.Automation.PSCredential ("CORP\$user", $sec)
$rootSddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
$name = 'l44enroll'
try {
  $i = $rootSddl.IndexOf('S:')
  $withUser = if ($i -ge 0) { $rootSddl.Insert($i, "(A;;GXGR;;;$sid)") } else { $rootSddl + "(A;;GXGR;;;$sid)" }
  Set-Item WSMan:\localhost\Service\RootSDDL -Value $withUser -Force
  Enable-WSManCredSSP -Role Server -Force | Out-Null
  Enable-WSManCredSSP -Role Client -DelegateComputer $fqdn -Force | Out-Null
  Register-PSSessionConfiguration -Name $name -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GXGR;;;$sid)" `
    -Force -WarningAction SilentlyContinue | Out-Null
  $deadline = (Get-Date).AddMinutes(2)
  while (-not (Test-WSMan -ComputerName $fqdn -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw 'WinRM did not come back' }
    Start-Sleep 3
  }
  $pem = Invoke-Command -ComputerName $fqdn -ConfigurationName $name -Credential $cred -Authentication Credssp `
    -ArgumentList $csr_pem, "$fqdn\corp-L44-CA" -ScriptBlock {
      param($csr, $config)
      $in = Join-Path $env:TEMP 'l44.req'; $out = Join-Path $env:TEMP 'l44.cer'
      Set-Content $in $csr -Encoding ascii
      certreq.exe -submit -q -config $config -attrib 'CertificateTemplate:User' $in $out | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "certreq -submit User: exit $LASTEXITCODE" }
      Get-Content $out -Raw
    }
  @{ cert_pem = "$pem" }
} finally {
  Unregister-PSSessionConfiguration -Name $name -Force -ErrorAction SilentlyContinue
  Disable-WSManCredSSP -Role Client -ErrorAction SilentlyContinue
  Disable-WSManCredSSP -Role Server -ErrorAction SilentlyContinue
  Set-Item WSMan:\localhost\Service\RootSDDL -Value $rootSddl -Force
  Set-ADAccountPassword $user -Reset -NewPassword (ConvertTo-SecureString (New-LabPlain) -AsPlainText -Force)
}
