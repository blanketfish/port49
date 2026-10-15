# L67 (plan 9e): the DC's side of a person's bind and the directory-password
# sign-in. seed: person_password for alice, carol and dave; the lockout policy
# (10 failures in 10 minutes, locked for 10 minutes, as samba/seed.sh sets it);
# and four people each in the state a bind is asked about (an expired, a
# disabled, a must-change and a locked one, which the test locks with failed
# binds). state: one person's attributes. unlock: clears a person's failed
# count. connections: the TCP connections this DC has accepted since it
# started, for the test's before-and-after of an empty-password bind.
param([string]$step, [string]$person_password, [string]$name)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$base = $domain.DistinguishedName
switch ($step) {
  'seed' {
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 10 `
      -LockoutDuration '00:10:00' -LockoutObservationWindow '00:10:00' -MinPasswordAge '0.00:00:00'
    $pw = ConvertTo-SecureString $person_password -AsPlainText -Force
    foreach ($name in 'alice', 'carol', 'dave') {
      Set-ADAccountPassword -Identity $name -Reset -NewPassword $pw
      Enable-ADAccount -Identity $name
      Unlock-ADAccount -Identity $name
    }
    foreach ($name in 'l67-expired', 'l67-disabled', 'l67-mustchange', 'l67-locked') {
      if (Get-ADUser -Filter "sAMAccountName -eq '$name'") {
        Set-ADAccountPassword -Identity $name -Reset -NewPassword $pw
        Unlock-ADAccount -Identity $name
      } else {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@corp.example.com" -EmailAddress "$name@corp.example.com" -Path "OU=Staff,$base" -AccountPassword $pw -Enabled $true
      }
    }
    Disable-ADAccount -Identity 'l67-disabled'
    Set-ADUser -Identity 'l67-mustchange' -ChangePasswordAtLogon $true
    # An expired password needs a maximum age shorter than the password's age,
    # for this person alone: a fine-grained policy. If the DC refuses one that
    # short the person is left as they are and the answer says so; the test
    # reads the state back and records the cell as not measurable.
    $expired = $false
    $why = ''
    try {
      Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'l67-expire'" | Remove-ADFineGrainedPasswordPolicy -Confirm:$false
      New-ADFineGrainedPasswordPolicy -Name 'l67-expire' -Precedence 1 -MaxPasswordAge '00:00:30' -MinPasswordAge '0.00:00:00' `
        -MinPasswordLength 1 -PasswordHistoryCount 0 -ComplexityEnabled $false -ReversibleEncryptionEnabled $false `
        -LockoutThreshold 10 -LockoutDuration '00:10:00' -LockoutObservationWindow '00:10:00'
      Add-ADFineGrainedPasswordPolicySubject -Identity 'l67-expire' -Subjects 'l67-expired'
      Start-Sleep -Seconds 40
      $expired = [bool](Get-ADUser -Identity 'l67-expired' -Properties PasswordExpired).PasswordExpired
    } catch {
      $why = $_.Exception.Message
    }
    @{ expired_set = $expired; expired_why = $why.Substring(0, [Math]::Min(300, $why.Length)) }
  }
  'state' {
    $u = Get-ADUser -Identity $name -Properties Enabled, LockedOut, PasswordExpired, pwdLastSet, badPwdCount, whenCreated
    @{ enabled = [bool]$u.Enabled; locked_out = [bool]$u.LockedOut; password_expired = [bool]$u.PasswordExpired
       must_change = ($u.pwdLastSet -eq 0); bad_pwd_count = [int]$u.badPwdCount
       when_created = $u.whenCreated.ToUniversalTime().ToString('o') }
  }
  'unlock' {
    Unlock-ADAccount -Identity $name
    $u = Get-ADUser -Identity $name -Properties badPwdCount
    @{ bad_pwd_count = [int]$u.badPwdCount }
  }
  'connections' {
    $s = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    @{ accepted = [int64]$s.ConnectionsAccepted }
  }
  default { throw "l67: no step $step" }
}
