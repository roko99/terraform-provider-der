# Terraform Provider DER

A Terraform provider for converting PEM-encoded certificates and private keys to DER (Distinguished Encoding Rules) format.

## Features

- Convert PEM certificates to DER format
- Convert PEM private keys (RSA, EC, PKCS#8) to DER format
- Support for encrypted private keys
- Standardizes all keys to PKCS#8 format
- Base64-encoded outputs for easy file storage

## Building the Provider

```shell
go build -o terraform-provider-der
```

## Installation

To install the provider locally:

```shell
make install
```

## Usage

Create a `.tf` file with the following configuration:

```hcl
resource "der_from_pem" "example" {
  cert_pem        = file("${path.module}/cert.pem")
  private_key_pem = file("${path.module}/key.pem")
}

resource "local_file" "cert_der" {
  filename       = "${path.module}/cert.der"
  content_base64 = der_from_pem.example.cert_der
}

resource "local_file" "key_der" {
  filename       = "${path.module}/key.der"
  content_base64 = der_from_pem.example.key_der
}
```

## Testing

To test with the sample configuration:

```shell
terraform init && terraform apply
```

## Documentation

See [docs/resources/from_pem.md](docs/resources/from_pem.md) for detailed resource documentation.
