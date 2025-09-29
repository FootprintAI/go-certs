// Copyright 2024 FootprintAI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpccerts

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/footprintai/go-certs/pkg/certs"
	certsmem "github.com/footprintai/go-certs/pkg/certs/mem"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TypeHostAndPort represents a network address with host and port components.
// It provides type-safe parsing and access to host/port components for gRPC connections.
type TypeHostAndPort struct {
	address string
}

// NewTypeHostAndPort creates a new TypeHostAndPort from an address string.
// The address can be in format "host:port" or just "host".
// Examples: "127.0.0.1:50090", "service.example.svc.cluster.local:50090", "localhost"
func NewTypeHostAndPort(address string) *TypeHostAndPort {
	return &TypeHostAndPort{address: address}
}

// Host extracts and returns the hostname portion of the address.
// For "service.example.svc.cluster.local:50090" returns "service.example.svc.cluster.local"
// For "localhost:8080" returns "localhost"
// For "localhost" (no port) returns "localhost"
func (t *TypeHostAndPort) Host() string {
	if host, _, err := net.SplitHostPort(t.address); err == nil {
		return host
	}
	// If no port, return the address as-is
	return t.address
}

// Port extracts and returns the port portion of the address.
// Returns empty string if no port is specified.
func (t *TypeHostAndPort) Port() string {
	if _, port, err := net.SplitHostPort(t.address); err == nil {
		return port
	}
	return ""
}

// String returns the original address string.
func (t *TypeHostAndPort) String() string {
	return t.address
}

// HasPort returns true if the address includes a port component.
func (t *TypeHostAndPort) HasPort() bool {
	_, _, err := net.SplitHostPort(t.address)
	return err == nil
}

func NewGrpcCerts(certs certs.Certificates) *GrpcCerts {
	return &GrpcCerts{certs: certs}
}

// NewGrpcCertsFromFiles creates GrpcCerts by loading certificates from local files
// This is useful when you have downloaded certificates from a remote server
func NewGrpcCertsFromFiles(caCertPath, clientCertPath, clientKeyPath string) (*GrpcCerts, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}

	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}

	// Create mem loader with real certificates
	// Note: We use dummy server cert/key since this is for client-only usage
	l := certsmem.NewMemLoader(
		caCert,     // Real CA cert
		clientKey,  // Real client key
		clientCert, // Real client cert
		[]byte{},   // Empty server key (not needed for client)
		[]byte{},   // Empty server cert (not needed for client)
	)

	return NewGrpcCerts(l), nil
}

type GrpcCerts struct {
	certs certs.Certificates
}

func (g *GrpcCerts) NewServerTLSCredentials() (grpccredentials.TransportCredentials, error) {
	return g.newServerCredentials()
}

func (g *GrpcCerts) newServerCredentials() (grpccredentials.TransportCredentials, error) {
	// Check if insecure mode is enabled
	if g.certs.IsTLSInsecure() {
		return insecure.NewCredentials(), nil
	}

	caCert := g.certs.CaCert()
	serverKey := g.certs.ServerKey()
	serverCrt := g.certs.ServerCrt()
	serverCert, err := tls.X509KeyPair(serverCrt, serverKey)
	if err != nil {
		return nil, errors.New("grpc/certificates: invalid server crt")
	}
	
	// Create CA pool for client certificate verification (enable mTLS by default)
	cPool := x509.NewCertPool()
	if !cPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("grpc/certificates: failed to parse client CA")
	}
	
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enable mutual TLS by default
		ClientCAs:    cPool,                          // Verify client certs against CA
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2"}, // Required for gRPC v1.67+ ALPN enforcement
		MinVersion:   tls.VersionTLS12, // Ensure TLS 1.2+ for HTTP/2 compatibility
	}
	return grpccredentials.NewTLS(tlsConfig), nil
}

// NewClientTLSCredentials creates client TLS credentials with ServerName extracted from target.
// The ServerName is automatically set to the hostname portion (without port) for certificate verification.
func (g *GrpcCerts) NewClientTLSCredentials(target *TypeHostAndPort) (grpccredentials.TransportCredentials, error) {
	return g.newClientCredentialsWithHostAndPort(target)
}


// NewClientDialOptions creates both TLS credentials and gRPC dial options with proper 
// authority handling. This is the recommended method for creating gRPC client connections.
//
// It automatically:
// 1. Uses TypeHostAndPort to safely extract hostname from target
// 2. Sets TLS ServerName to the hostname for certificate verification  
// 3. Sets gRPC Authority to prevent ServerName from including the port
// 4. Returns ready-to-use dial options
//
// Example usage:
//   target := NewTypeHostAndPort("service.example.svc.cluster.local:50090")
//   dialOpts, err := grpcCerts.NewClientDialOptions(target)
//   if err != nil { return err }
//   conn, err := grpc.NewClient(target.String(), dialOpts...)
func (g *GrpcCerts) NewClientDialOptions(target *TypeHostAndPort) ([]grpc.DialOption, error) {
	creds, err := g.NewClientTLSCredentials(target)
	if err != nil {
		return nil, err
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Set authority to hostname (without port)
	if host := target.Host(); host != "" {
		dialOpts = append(dialOpts, grpc.WithAuthority(host))
	}

	return dialOpts, nil
}


func (g *GrpcCerts) newClientCredentialsWithHostAndPort(target *TypeHostAndPort) (grpccredentials.TransportCredentials, error) {
	// Check if insecure mode is enabled
	if g.certs.IsTLSInsecure() {
		return insecure.NewCredentials(), nil
	}

	caCert := g.certs.CaCert()
	clientKey := g.certs.ClientKey()
	clientCrt := g.certs.ClientCrt()
	
	cPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("grpc/certificates: failed to load system ca pool")
	}
	if !cPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("grpc/certificates: failed to parse CA crt")
	}

	clientCert, err := tls.X509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, errors.New("grpc/certificates: invalid client crt")
	}

	clientTLSConfig := &tls.Config{
		RootCAs:            cPool,
		Certificates:       []tls.Certificate{clientCert},
		NextProtos:         []string{"h2"}, // Required for gRPC v1.67+ ALPN enforcement
		MinVersion:         tls.VersionTLS12, // Ensure TLS 1.2+ for HTTP/2 compatibility
		InsecureSkipVerify: false, // Explicitly enable verification
	}
	creds := grpccredentials.NewTLS(clientTLSConfig)
	return creds, nil
}
