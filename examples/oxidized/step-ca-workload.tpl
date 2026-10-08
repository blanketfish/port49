{{- /*
  step-ca x509 template for workload certificates (the provisioner's
  options.x509.templateFile). It is step's default leaf, with clientAuth alone
  and one addition: a CRL distribution point naming the CA's CRL.

  step-ca's CRL names its own distribution point in a critical issuing
  distribution point extension, and port49 applies that CRL only to a
  certificate whose CRL distribution points name it, byte for byte (RFC 5280
  §5.2.5; L48). A certificate without the name is undecided, and the broker
  refuses it (503 certificate_status_unavailable).

  Replace the URL below with the name in your CA's CRL: crl.idpURL when it is
  set, otherwise https://<the first of ca.json's dnsNames>/1.0/crl. Check it
  with `step crl inspect` (Issuing Distribution Point, Full Name).
*/ -}}
{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["clientAuth"],
	"crlDistributionPoints": ["https://ca.corp.example.com/1.0/crl"]
}
