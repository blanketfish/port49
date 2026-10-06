# L44: port49's keytab, as an operator makes one with ktpass: AES256, the
# principal port49@CORP.EXAMPLE.COM mapped onto the port49 account. ktpass sets
# the password it is given (this run's, unchanged) and the account's UPN to the
# principal. The keytab leaves as base64 in the result and its file is deleted.
param([string]$port49_password)
$ErrorActionPreference = 'Stop'
$out = Join-Path $env:TEMP ('l44-' + [guid]::NewGuid() + '.keytab')
try {
  # ktpass writes its progress to stderr, and under Windows PowerShell 5.1 a
  # redirected native stderr line is an error record that Stop turns into a
  # throw. So it runs in a child scope that continues, its text (which can carry
  # the derived key) is thrown away unread, and only its exit code and the
  # file judge it.
  $code = & {
    $ErrorActionPreference = 'Continue'
    & ktpass.exe -princ port49@CORP.EXAMPLE.COM -mapuser 'CORP\port49' -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL `
      -pass $port49_password -mapop set +answer -out $out *> $null
    $LASTEXITCODE
  }
  if ($code -ne 0 -or -not (Test-Path $out)) { throw "ktpass: exit $code" }
  @{ keytab_b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($out)) }
} finally {
  Remove-Item $out -ErrorAction SilentlyContinue
}
