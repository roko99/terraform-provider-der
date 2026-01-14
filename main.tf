terraform {
  required_providers {
    der = {
      source  = "local/der"
      version = "0.1.0"
    }
  }
}

provider "der" {
  # No configuration needed
}

resource "tls_private_key" "my_private_key" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "my_cert" {
  private_key_pem       = tls_private_key.my_private_key.private_key_pem
  validity_period_hours = 58440
  early_renewal_hours   = 5844
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
  dns_names          = ["myserver1.local", "myserver2.local"]
  is_ca_certificate  = true
  set_subject_key_id = true

  subject {
    common_name = "myserver.local"
  }
}

# Convert PEM certificate and key to DER format
resource "der_from_pem" "my_der" {
  cert_pem        = tls_self_signed_cert.my_cert.cert_pem
  private_key_pem = tls_private_key.my_private_key.private_key_pem
  # private_key_password = "key-pass"  # Optional: only if key is encrypted
}

# Save DER certificate to file
resource "local_file" "cert_der" {
  filename       = "${path.module}/certificate.der"
  content_base64 = der_from_pem.my_der.cert_der
}

# Save DER private key to file
resource "local_file" "key_der" {
  filename        = "${path.module}/private_key.der"
  content_base64  = der_from_pem.my_der.key_der
  file_permission = "0600"
}


output "my_pkcs12" {
  value     = pkcs12_from_pem.my_pkcs12
  sensitive = true
}
