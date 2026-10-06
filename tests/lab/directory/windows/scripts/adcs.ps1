# L44: an enterprise root CA on the DC, so the DC maps certificates it issued
# (KB5014754's SID extension included); OfflineRouter published, for requests
# whose subject the harness supplies; and the DC's KerberosAuthentication
# certificate, which PKINIT needs. Idempotent: a kept DC answers the same.
param()
$ErrorActionPreference = 'Stop'
function ConvertTo-Pem($raw) {
  "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($raw, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
}
if (-not (Get-Service CertSvc -ErrorAction SilentlyContinue)) {
  Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'corp-L44-CA' `
    -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 `
    -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
}
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Service CertSvc).Status -ne 'Running') {
  if ((Get-Date) -gt $deadline) { throw 'CertSvc did not start' }
  Start-Sleep 5
}
Import-Module ADCSAdministration
if (-not (Get-CATemplate | Where-Object Name -eq 'OfflineRouter')) { Add-CATemplate -Name OfflineRouter -Force }
$kdcEku = '1.3.6.1.5.2.3.5'
# A certificate with the KDC Authentication EKU from the machine's store: not
# necessarily the one the KDC presents (the note says so; control-ski proves
# the KDC's PKINIT works).
function Get-KdcCert {
  Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains $kdcEku } | Select-Object -First 1
}
if (-not (Get-KdcCert)) {
  certreq.exe -enroll -machine -q KerberosAuthentication | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "certreq -enroll KerberosAuthentication: exit $LASTEXITCODE" }
}
$kdc = Get-KdcCert
if (-not $kdc) { throw 'no certificate with the KDC Authentication EKU after enrollment' }
$ca = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=corp-L44-CA*' } | Select-Object -First 1
if (-not $ca) { throw 'the enterprise CA certificate is not in the Root store' }
@{ ca_pem = (ConvertTo-Pem $ca.RawData); kdc_pem = (ConvertTo-Pem $kdc.RawData) }
