# L44: trust one of the harness's CAs as AD trusts an issuing CA for logon:
# the DC's Root store, NTAuth in the forest, and the DC's cached NTAuth.
param([string]$ca_pem, [string]$name)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\l44 | Out-Null
$f = "C:\l44\$name.cer"
Set-Content $f $ca_pem -Encoding ascii
certutil.exe -f -addstore Root $f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -addstore Root: exit $LASTEXITCODE" }
certutil.exe -f -dspublish $f NTAuthCA | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -dspublish NTAuthCA: exit $LASTEXITCODE" }
certutil.exe -f -enterprise -addstore NTAuth $f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -enterprise -addstore NTAuth: exit $LASTEXITCODE" }
@{ trusted = $name }
