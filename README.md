# Go-Certs

Go-Certs is a Go library designed to simplify the management and generation of SSL/TLS certificates within Go applications. It enables developers to create self-signed certificates without relying on external tools, facilitating secure communications for services like web servers, mail servers, and more.

## Features

- **Self-Signed Certificate Generation**: Easily generate self-signed SSL/TLS certificates programmatically within your Go applications.
- **Customizable Certificate Attributes**: Specify details such as country, organization, organizational unit, locality, and common name for the certificates.
- **Support for Subject Alternative Names (SANs)**: Include multiple DNS names and IP addresses in the certificate's SANs field.
- **Flexible Directory Structure**: Define custom paths for storing generated certificates and keys.

## Installation

You can download the latest pre-built binary from the [Releases](https://github.com/FootprintAI/go-certs/releases/tag/v0.0.2) page.

Alternatively, you can install Go-Certs into your project using the following `go get` command:

To integrate Go-Certs into your project, use the following `go get` command:

```bash
go get github.com/FootprintAI/go-certs
```

Ensure that your project uses Go modules to handle dependencies.

## Usage

### Programmatic Usage

Below is an example of how to use Go-Certs to generate a self-signed certificate:

```go
package main

import (
    "log"
    "github.com/FootprintAI/go-certs/pkg/gencert"
)

func main() {
    // Define the certificate subject information
    subject := gencert.Subject{
        Country:            "US",
        Organization:       "Example Inc.",
        OrganizationalUnit: "IT Department",
        Locality:           "San Francisco",
        CommonName:         "example.com",
    }

    // Define Subject Alternative Names (SANs)
    sans := gencert.SubjectAltNames{
        DNSNames: []string{"example.com", "www.example.com"},
        IPAddresses: []string{"192.168.1.1"},
    }

    // Generate the certificate
    cert, err := gencert.Generate(subject, sans, "/path/to/cert/dir", 365)
    if err != nil {
        log.Fatalf("Failed to generate certificate: %v", err)
    }

    log.Printf("Certificate and key generated:\nCert: %s\nKey: %s", cert.CertPath, cert.KeyPath)
}
```

In this example:

- We define the subject information for the certificate, including country, organization, organizational unit, locality, and common name.
- We specify the Subject Alternative Names (SANs), including DNS names and IP addresses.
- We call the `Generate` function from the `gencert` package to create the certificate and key, specifying the directory to store them and the validity period in days.
- The generated certificate and key paths are logged upon successful creation.

### CLI Usage

Go-Certs also provides a command-line interface (CLI) for easy certificate generation. After installing the package, you can use the CLI as follows:

```bash
go run main.go generate \
  --country "US" \
  --organization "Example Inc." \
  --organizational-unit "IT Department" \
  --locality "San Francisco" \
  --common-name "example.com" \
  --dns "example.com,www.example.com" \
  --ip "192.168.1.1" \
  --output "/path/to/cert/dir" \
  --days 365
```

This command will generate a self-signed certificate and store it in the specified output directory.

## Directory Structure

The generated certificates and keys are stored in the specified directory, following this structure:

```
[ your-go-app ]
|_ cmd
|_ pkg
|_ internal
|_ etc
   |_ ssl
      |_ server.key   <- Generated key
      |_ server.pem   <- Generated certificate
```

Ensure that the directory exists and has appropriate permissions before running the certificate generation code.

## License

This project is licensed under the Apache-2.0 License. For more details, refer to the [LICENSE](https://github.com/FootprintAI/go-certs/blob/main/LICENSE) file.

## Acknowledgments

Go-Certs is inspired by various Go projects focused on certificate management, including:

- [Go SSL Certificate Generator](https://github.com/KeithAlt/go-cert-generator): A utility package for generating self-signed SSL certificates within Go applications.
- [GoCA](https://github.com/kairoaraujo/goca): A framework that uses `crypto/x509` to manage Certificate Authorities and issue certificates.

These projects have contributed to the development and design of Go-Certs.

