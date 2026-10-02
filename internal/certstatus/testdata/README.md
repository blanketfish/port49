# certstatus test fixtures

Two CRLs built outside Go, so a tagging mistake mirrored in `userCertsOnly` and in the Go-built
test lists cannot pass both (plan 7b, re-check R7):

- `idp-user-certs.der`: a critical Issuing Distribution Point saying `onlyContainsUserCerts` alone.
  It loads, and covers leaves only.
- `idp-distribution-point.der`: a critical Issuing Distribution Point naming a `distributionPoint`.
  It is refused.
- `idp-ca.pem`: their signer. Its key was not kept.

They were made on 2026-10-01 with OpenSSL 3.5.5 and are valid for ten years. **Regenerate them
before 2036-09-28**, when their `nextUpdate` and the CA's `notAfter` pass, with these commands:

```sh
cat > ca.cnf <<'EOF'
[ca]
default_ca = idp_ca

[idp_ca]
dir           = .
database      = ./index.txt
crlnumber     = ./crlnumber
certificate   = ./idp-ca.pem
private_key   = ./idp-ca.key
default_md    = sha256
crl_extensions = crl_ext

[crl_ext]
issuingDistributionPoint = critical, @idp

[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext

[dn]
CN = port49 certstatus IDP fixture CA

[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
openssl ecparam -name prime256v1 -genkey -noout -out idp-ca.key
openssl req -new -x509 -config ca.cnf -key idp-ca.key -days 3650 -out idp-ca.pem
: > index.txt; echo 01 > crlnumber
{ cat ca.cnf; printf '\n[idp]\nonlyuser = TRUE\n'; } > user.cnf
{ cat ca.cnf; printf '\n[idp]\nfullname = URI:http://pki.example.com/a.crl\n'; } > dp.cnf
openssl ca -gencrl -config user.cnf -crldays 3650 -out user.pem
openssl ca -gencrl -config dp.cnf -crldays 3650 -out dp.pem
openssl crl -in user.pem -outform DER -out idp-user-certs.der
openssl crl -in dp.pem -outform DER -out idp-distribution-point.der
```

Copy `idp-ca.pem`, `idp-user-certs.der` and `idp-distribution-point.der` here and discard the rest,
the key included.
