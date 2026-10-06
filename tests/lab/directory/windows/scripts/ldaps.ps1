# L44: LDAPS on a certificate from the lab CA. "request" makes the DC's key
# and a request; "install" trusts the lab CA, accepts the certificate the
# harness signed, and makes it the one LDAPS serves by placing it in the NTDS
# service's own store (Microsoft's procedure for a third-party certificate),
# then asks NTDS to reload it.
param([string]$step, [string]$cert_pem, [string]$lab_ca_pem)
$ErrorActionPreference = 'Stop'
$dir = 'C:\l44'
New-Item -ItemType Directory -Force $dir | Out-Null
if ($step -eq 'request') {
  @(
    '[NewRequest]', 'Subject = "CN=dc1.corp.example.com"', 'KeyAlgorithm = RSA', 'KeyLength = 2048',
    'MachineKeySet = TRUE', 'Exportable = FALSE', 'RequestType = PKCS10',
    '[EnhancedKeyUsageExtension]', 'OID = 1.3.6.1.5.5.7.3.1'
  ) | Set-Content "$dir\ldaps.inf" -Encoding ascii
  Remove-Item "$dir\ldaps.req" -ErrorAction SilentlyContinue
  certreq.exe -new -q -machine "$dir\ldaps.inf" "$dir\ldaps.req" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "certreq -new: exit $LASTEXITCODE" }
  return @{ csr_pem = (Get-Content "$dir\ldaps.req" -Raw) }
}
Set-Content "$dir\lab-ca.cer" $lab_ca_pem -Encoding ascii
certutil.exe -f -addstore Root "$dir\lab-ca.cer" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -addstore Root: exit $LASTEXITCODE" }
Set-Content "$dir\ldaps.cer" $cert_pem -Encoding ascii
certreq.exe -accept -q -machine "$dir\ldaps.cer" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certreq -accept: exit $LASTEXITCODE" }
$t = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 "$dir\ldaps.cer").Thumbprint
# A kept DC holds each earlier run's certificate in the NTDS store, and Schannel
# need not pick the newest: remove the ones the lab CA issued (by its name, which
# every run's CA shares), never the rest of the store.
$labCA = New-Object Security.Cryptography.X509Certificates.X509Certificate2 "$dir\lab-ca.cer"
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -eq $labCA.Subject -and $_.Thumbprint -ne $t } | ForEach-Object {
  Remove-Item "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\$($_.Thumbprint)" -Recurse -ErrorAction SilentlyContinue
}
$src = "HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$t"
$dst = "HKLM\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\$t"
reg.exe copy $src $dst /s /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "reg copy to the NTDS store: exit $LASTEXITCODE" }
$root = [ADSI]'LDAP://localhost/RootDSE'
$root.Put('renewServerCertificate', 1)
$root.SetInfo()
@{ thumbprint = $t }
