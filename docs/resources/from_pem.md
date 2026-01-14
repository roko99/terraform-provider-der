---
page_title: "DER From PEM resource"
description: |-
  Converts PEM-encoded certificates and private keys to DER format
---

# der_from_pem Resource

Converts PEM-encoded certificates and private keys to DER (Distinguished Encoding Rules) format. This is useful when you need to work with certificate formats required by various systems and applications.

## Example Usage

```hcl
resource "der_from_pem" "example" {
  cert_pem            = tls_self_signed_cert.example.cert_pem
  private_key_pem     = tls_private_key.example.private_key_pem
  # private_key_password = "optional-key-password"  # Only if key is encrypted
}

# Use the converted DER certificate
resource "local_file" "cert" {
  filename             = "${path.module}/certificate.der"
  content_base64       = der_from_pem.example.cert_der
}

# Use the converted DER private key
resource "local_file" "key" {
  filename             = "${path.module}/private_key.der"
  content_base64       = der_from_pem.example.key_der
  file_permission      = "0600"
}
```

## Argument Reference

* `cert_pem` - (Required) The certificate in PEM format. Can be a single certificate or a certificate chain.
* `private_key_pem` - (Required) The private key in PEM format. Supports RSA, EC, and PKCS#8 formats.
* `private_key_password` - (Optional) Password to decrypt the private key if it's encrypted. Leave empty for unencrypted keys.

## Attribute Reference

* `cert_der` - The certificate in DER format, base64-encoded
* `key_der` - The private key in DER format (PKCS#8), base64-encoded
* `cert_der_binary` - Raw binary DER certificate data, base64-encoded
* `key_der_binary` - Raw binary DER private key data (PKCS#8), base64-encoded

## Notes

- All RSA and EC keys are standardized to PKCS#8 format in the output
- The resource uses SHA1 hash of inputs to generate a unique ID
- All sensitive inputs and outputs are marked as sensitive
