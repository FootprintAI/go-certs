# Go-Certs

Go-Certs is a Go library designed to simplify the management and generation of SSL/TLS certificates within Go applications. It enables developers to create self-signed certificates without relying on external tools, facilitating secure communications for services like web servers, mail servers, and more.

## Features

- **Self-Signed Certificate Generation**: Easily generate self-signed SSL/TLS certificates programmatically within your Go applications.
- **Certificate Inspection**: Analyze certificate details including expiry dates, SANs, and key usage.
- **Customizable Certificate Attributes**: Specify details such as organization, DNS names, and IP addresses for the certificates.
- **Support for Subject Alternative Names (SANs)**: Include multiple DNS names and IP addresses in the certificate's SANs field.
- **Command-Line Interface**: Use the CLI to generate and inspect certificates without writing code.
- **Strongly-Typed Certificate API**: Use a type-safe API for certificate management, preventing common errors.
- **CA Key Export**: Export and reuse CA keys to generate additional certificates with the same CA.

## Installation

You can download the latest pre-built binary from the [Releases](https://github.com/FootprintAI/go-certs/releases) page.

Alternatively, you can install Go-Certs into your project using the following `go get` command:

```bash
go get github.com/FootprintAI/go-certs
```

Ensure that your project uses Go modules to handle dependencies.

## CLI Usage

Go-Certs provides a command-line interface (CLI) with two main commands: `generate` and `inspect`.

### Generate Certificates

Generate CA, client, and server certificates with customizable parameters:

```bash
# Basic usage with default settings (24h validity, localhost, 127.0.0.1)
go-certs generate

# Generate with custom parameters
go-certs generate --duration 720h --org "MyCompany" --dns "example.com,www.example.com" --ips "192.168.1.1,10.0.0.1" --outputdir "./certs"
```

#### Parameters:

- `--duration`: Certificate validity period (default: 24h)
- `--outputdir`: Directory to save certificates (default: "./")
- `--org`: Organization name (default: "Footprint-AI")
- `--dns`: DNS names (comma-separated, default: "localhost")
- `--ips`: IP addresses (comma-separated, default: "127.0.0.1")
- `--ca-cert`: Path to existing CA certificate (if not specified, a new CA will be generated)
- `--ca-key`: Path to existing CA key (required if ca-cert is specified)

### Inspect Certificates

Inspect certificate details including expiry date, Subject Alternative Names (SANs), and other info:

```bash
# Inspect certificates in the current directory
go-certs inspect

# Inspect certificates in a specific directory
go-certs inspect --inputdir "./certs"

# Specify individual certificate paths
go-certs inspect --ca "/path/to/ca.crt" --client "/path/to/client.crt" --server "/path/to/server.crt"

# Inspect only specific certificates
go-certs inspect --ca "/path/to/ca.crt" --server "/path/to/server.crt"
# or
go-certs inspect --client "/path/to/client.crt"

# Verify if a certificate is signed by a specific CA
go-certs inspect --server "./service-a/certs/server.crt" --verify-signed-by "./shared-ca/ca.crt"
```

#### Parameters:

- `--inputdir`: Directory containing certificates (default: "./")
- `--ca`: Path to CA certificate (defaults to inputdir/ca.crt if not specified)
- `--client`: Path to client certificate (optional)
- `--server`: Path to server certificate (optional)
- `--verify-signed-by`: Path to CA certificate to verify if the inspected certificate is signed by this CA

The inspect command provides detailed information about:
- Certificate validity (including exact expiry time and remaining time)
- Subject and issuer details
- Certificate type (CA or not)
- Key usage and extended key usage
- DNS names and IP addresses in the Subject Alternative Names (SANs)
- Public key and signature algorithms
- Certificate chain verification (when using `--verify-signed-by`)

## Examples

### Example 1: Securing a Development Environment

Create certificates for local development with a 30-day validity period:

```bash
# Generate certificates for local development
go-certs generate --duration 720h --org "DevTeam" --dns "localhost,dev.local" --ips "127.0.0.1,192.168.1.100" --outputdir "./dev-certs"

# Verify the certificates
go-certs inspect --inputdir "./dev-certs"
```

### Example 2: Setting Up Mutual TLS for Microservices

Generate certificates for a microservice architecture with mutual TLS authentication:

```bash
# Step 1: Create a shared CA for all services
go-certs generate --duration 8760h --org "CompanyName" --outputdir "./shared-ca"

# Step 2: Generate service certificates using the shared CA
go-certs generate --duration 8760h --org "CompanyName" --dns "service-a.internal,service-a.company.com" \
  --ca-cert "./shared-ca/ca.crt" --ca-key "./shared-ca/ca.key" --outputdir "./service-a/certs"

go-certs generate --duration 8760h --org "CompanyName" --dns "service-b.internal,service-b.company.com" \
  --ca-cert "./shared-ca/ca.crt" --ca-key "./shared-ca/ca.key" --outputdir "./service-b/certs"

# Step 3: Verify the CA certificate
go-certs inspect --ca "./shared-ca/ca.crt"

# Step 4: Verify service certificates and confirm they're signed by the shared CA
go-certs inspect --server "./service-a/certs/server.crt" --verify-signed-by "./shared-ca/ca.crt"
go-certs inspect --client "./service-b/certs/client.crt" --verify-signed-by "./shared-ca/ca.crt"
```

For mutual TLS, you'll need to configure each service to:
1. Trust the shared CA certificate
2. Use its own certificate/key pair for authentication
3. Require client certificates from the other service

## Programmatic Usage

Below are examples of how to use Go-Certs programmatically in your Go applications:

### Example 1: Generating Certificates with the New Strongly-Typed API

```go
package main

import (
    "fmt"
    "log"
    "os"
    "time"

    "github.com/FootprintAI/go-certs/pkg/certs"
    "github.com/FootprintAI/go-certs/pkg/certs/gen"
)

func main() {
    notBefore := time.Now()
    notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year
    
    // Generate certificates using the new typed API
    credentials, err := certsgen.NewTLSCredentials(
        notBefore,
        notAfter,
        certsgen.WithOrganizations("Example Inc."),
        certsgen.WithAliasDNSNames("example.com", "www.example.com"),
        certsgen.WithAliasIPs("192.168.1.1", "10.0.0.1"),
    )
    if err != nil {
        log.Fatalf("Failed to generate certificates: %v", err)
    }
    
    // Save the certificates and keys to files
    if err := os.WriteFile("ca.crt", credentials.CACert.Bytes(), 0600); err != nil {
        log.Fatalf("Failed to write CA certificate: %v", err)
    }
    if err := os.WriteFile("ca.key", credentials.CAKey.Bytes(), 0600); err != nil {
        log.Fatalf("Failed to write CA key: %v", err)
    }
    if err := os.WriteFile("client.crt", credentials.ClientCert.Bytes(), 0600); err != nil {
        log.Fatalf("Failed to write client certificate: %v", err)
    }
    // ... and so on for other certificate files
    
    fmt.Println("Certificates successfully generated!")
}
```

### Example 2: Using an Existing CA to Generate New Certificates

```go
package main

import (
    "fmt"
    "log"
    "os"
    "time"

    "github.com/FootprintAI/go-certs/pkg/certs"
    "github.com/FootprintAI/go-certs/pkg/certs/gen"
)

func main() {
    // Read existing CA certificate and key
    caCert, err := os.ReadFile("ca.crt")
    if err != nil {
        log.Fatalf("Failed to read CA certificate: %v", err)
    }
    
    caKey, err := os.ReadFile("ca.key")
    if err != nil {
        log.Fatalf("Failed to read CA key: %v", err)
    }
    
    notBefore := time.Now()
    notAfter := notBefore.Add(180 * 24 * time.Hour) // Valid for 6 months
    
    // Generate new certificates with the existing CA
    credentials, err := certsgen.GenerateWithExistingCA(
        caCert,
        caKey,
        notBefore,
        notAfter,
        certsgen.WithOrganizations("Example Inc."),
        certsgen.WithAliasDNSNames("api.example.com", "service.example.com"),
        certsgen.WithAliasIPs("10.0.0.5"),
    )
    if err != nil {
        log.Fatalf("Failed to generate certificates with existing CA: %v", err)
    }
    
    // Save the new certificates
    if err := os.WriteFile("new-client.crt", credentials.ClientCert.Bytes(), 0600); err != nil {
        log.Fatalf("Failed to write new client certificate: %v", err)
    }
    if err := os.WriteFile("new-client.key", credentials.ClientKey.Bytes(), 0600); err != nil {
        log.Fatalf("Failed to write new client key: %v", err)
    }
    // ... and so on for other certificate files
    
    fmt.Println("New certificates successfully generated with existing CA!")
}
```

### Example 3: Using with gRPC for Secure Communication

```go
package main

import (
    "log"
    "time"

    "github.com/FootprintAI/go-certs/pkg/certs"
    "github.com/FootprintAI/go-certs/pkg/certs/gen"
    "github.com/FootprintAI/go-certs/pkg/certs/mem"
    "github.com/FootprintAI/go-certs/pkg/grpc/certs"
    "google.golang.org/grpc"
)

func main() {
    // Generate TLS credentials
    credentials, err := certsgen.NewTLSCredentials(
        time.Now(),
        time.Now().Add(24 * time.Hour),
        certsgen.WithOrganizations("Example Inc."),
        certsgen.WithAliasDNSNames("localhost"),
        certsgen.WithAliasIPs("127.0.0.1"),
    )
    if err != nil {
        log.Fatalf("Failed to generate TLS credentials: %v", err)
    }
    
    // Create a memory loader from the credentials
    loader := certsmem.NewMemLoaderFromCredentials(credentials)
    
    // Create gRPC certificates
    grpcCerts := grpccerts.NewGrpcCerts(loader)
    
    // Use with gRPC server
    server := grpc.NewServer(grpc.Creds(grpcCerts.NewServerTLSCredentials()))
    
    // Register your gRPC services here
    // ...
    
    // Use with gRPC client
    clientCredentials := grpcCerts.NewClientTLSCredentials()
    conn, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(clientCredentials))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    // Use the gRPC client connection
    // ...
}
```

### Example 4: Certificate Rotation

When service certificates need rotation but you want to maintain the existing CA:

```bash
# Inspect the current certificates to check expiry
go-certs inspect --inputdir "./existing-service/certs"

# Generate new certificates using the existing CA
go-certs generate --duration 4380h --org "CompanyName" --dns "service.company.com,service.internal" \
  --ca-cert "./main-ca/ca.crt" --ca-key "./main-ca/ca.key" --outputdir "./existing-service/new-certs"

# Verify the new certificates
go-certs inspect --inputdir "./existing-service/new-certs"
```

This allows you to rotate service certificates without affecting the trust chain, so clients that already trust your CA don't need to be updated.

### Example 5: Checking Certificate Expiry

Verify when your existing certificates will expire:

```bash
# Check all certificates in production environment
go-certs inspect --inputdir "./prod/certs"

# Check only the CA certificate
go-certs inspect --ca "./prod/certs/ca.crt"
```

## Building from Source

To build Go-Certs from source, use the provided Makefile:

```bash
# Build for all platforms (Windows, Linux, macOS)
make build

# Build for local development
make local

# Run the generate command
make generate

# Run the inspect command
make inspect
```

For more build options, run:

```bash
make help
```

## License

This project is licensed under the Apache-2.0 License. For more details, refer to the [LICENSE](https://github.com/FootprintAI/go-certs/blob/main/LICENSE) file.

## Acknowledgments

Go-Certs is inspired by various Go projects focused on certificate management, including:

- [Go SSL Certificate Generator](https://github.com/KeithAlt/go-cert-generator): A utility package for generating self-signed SSL certificates within Go applications.
- [GoCA](https://github.com/kairoaraujo/goca): A framework that uses `crypto/x509` to manage Certificate Authorities and issue certificates.

These projects have contributed to the development and design of Go-Certs.
