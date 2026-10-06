# L44: submit a request the harness made (its key never leaves the host) to
# the enterprise CA under a template, as the Administrator, and return the
# certificate.
param([string]$csr_pem, [string]$template)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\l44 | Out-Null
$id = [guid]::NewGuid()
$in = "C:\l44\$id.req"; $out = "C:\l44\$id.cer"; $rsp = "C:\l44\$id.rsp"
try {
  Set-Content $in $csr_pem -Encoding ascii
  certreq.exe -submit -q -config "$env:COMPUTERNAME.corp.example.com\corp-L44-CA" -attrib "CertificateTemplate:$template" $in $out | Out-Null
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "certreq -submit ${template}: exit $LASTEXITCODE" }
  @{ cert_pem = (Get-Content $out -Raw) }
} finally {
  Remove-Item $in, $out, $rsp -ErrorAction SilentlyContinue
}
