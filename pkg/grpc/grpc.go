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
	"bytes"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/footprintai/go-certs/pkg/certs"
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
// Examples: "127.0.0.1:50090", "authz.kafeido-mlops.svc.cluster.local:50090", "localhost"
func NewTypeHostAndPort(address string) *TypeHostAndPort {
	return &TypeHostAndPort{address: address}
}

// Host extracts and returns the hostname portion of the address.
// For "authz.kafeido-mlops.svc.cluster.local:50090" returns "authz.kafeido-mlops.svc.cluster.local"
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
	cPool := x509.NewCertPool()
	if !cPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("grpc/certificates: failed to parse client CA")
	}
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cPool,
		Certificates: []tls.Certificate{serverCert},
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
//   target := NewTypeHostAndPort("authz.kafeido-mlops.svc.cluster.local:50090")
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

	// Extract hostname from target for ServerName
	serverName := target.Host()
	if serverName == "" {
		// Default fallback for backward compatibility
		serverName = "localhost"
	}

	caCert := g.certs.CaCert()
	clientKey := g.certs.ClientKey()
	clientCrt := g.certs.ClientCrt()
	cPool := x509.NewCertPool()
	if !cPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("grpc/certificates: failed to parse CA crt")
	}

	clientCert, err := tls.X509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, errors.New("grpc/certificates: invalid client crt")
	}
	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Custom verification for self-signed certificates in development
			if len(rawCerts) == 0 {
				return errors.New("no certificate presented")
			}
			
			serverCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			
			// Verify the server certificate was issued by our CA
			caCerts := cPool.Subjects()
			if len(caCerts) == 0 {
				return errors.New("no CA certificates in pool")
			}
			
			// Parse CA certificate
			caCertPEM := g.certs.CaCert()
			caCertBlock, _ := pem.Decode(caCertPEM)
			if caCertBlock == nil {
				return errors.New("failed to decode CA certificate PEM")
			}
			caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
			if err != nil {
				return errors.New("failed to parse CA certificate")
			}
			
			// Verify server certificate issuer matches CA subject
			if !bytes.Equal(serverCert.RawIssuer, caCert.RawSubject) {
				return errors.New("certificate not issued by expected CA")
			}
			
			// Additional verification: check that server cert is valid for the ServerName
			if err := serverCert.VerifyHostname(serverName); err != nil {
				// Try localhost as fallback if ServerName was 127.0.0.1
				if serverName == "127.0.0.1" {
					if err := serverCert.VerifyHostname("localhost"); err != nil {
						return fmt.Errorf("hostname verification failed for both %s and localhost: %w", serverName, err)
					}
				} else {
					return fmt.Errorf("hostname verification failed for %s: %w", serverName, err)
				}
			}
			
			return nil
		},
	}
	creds := grpccredentials.NewTLS(clientTLSConfig)
	return creds, nil
}
