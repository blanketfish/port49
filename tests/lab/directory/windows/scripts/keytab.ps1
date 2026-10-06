# L44: port49's keytab, as an operator makes one with ktpass: AES256, the
# principal port49@CORP.EXAMPLE.COM mapped onto the port49 account. ktpass sets
# the password it is given (this run's, unchanged) and the account's UPN to the
# principal. The keytab leaves as base64 in the result and its file is deleted.
param([string]$port49_password)
$ErrorActionPreference = 'Stop'
$out = Join-Path $env:TEMP ('l44-' + [guid]::NewGuid() + '.keytab')
try {
  & ktpass.exe -princ port49@CORP.EXAMPLE.COM -mapuser 'CORP\port49' -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL `
    -pass $port49_password -mapop set +answer -out $out *> $null
  if ($LASTEXITCODE -ne 0) { throw "ktpass: exit $LASTEXITCODE" }
  @{ keytab_b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($out)) }
} finally {
  Remove-Item $out -ErrorAction SilentlyContinue
}
