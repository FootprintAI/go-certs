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
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	grpc "google.golang.org/grpc"

	certsembed "github.com/footprintai/go-certs/pkg/certs/embed"
	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	certsmanifests "github.com/footprintai/go-certs/pkg/certs/manifests"
	certsmem "github.com/footprintai/go-certs/pkg/certs/mem"
	examplepb "github.com/footprintai/go-certs/pkg/grpc/example/pb"
)

type mockServer struct {
	examplepb.UnimplementedGreeterServiceServer
}

func (m *mockServer) SayHello(ctx context.Context, req *examplepb.SayHelloRequest) (*examplepb.SayHelloResponse, error) {
	return &examplepb.SayHelloResponse{Pong: "pong"}, nil
}

func TestMemLoaderWithTLS(t *testing.T) {
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	// Use the new constructor that takes a TLSCredentials struct
	l := certsmem.NewMemLoaderFromCredentials(credentials)

	grpcCerts := NewGrpcCerts(l)
	testGrpc(t, grpcCerts)
}

// Add a new test for backward compatibility
func TestLegacyWithTLS(t *testing.T) {
	ca, clientCrt, clientKey, serverCrt, serverKey := certsgen.LegacyNewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)

	l := certsmem.NewMemLoader(
		ca,
		clientKey,
		clientCrt,
		serverKey,
		serverCrt,
	)

	grpcCerts := NewGrpcCerts(l)
	testGrpc(t, grpcCerts)
}

func TestManifestLoaderWithTLS(t *testing.T) {
	grpcCerts := NewGrpcCerts(certsembed.NewEmbedLoader(certsmanifests.Manifests))
	testGrpc(t, grpcCerts)
}

func TestDialOptionsWithAuthority(t *testing.T) {
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Test the new method that returns dial options with authority
	target := NewTypeHostAndPort("127.0.0.1:50052")
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options: %v", err)
	}

	if len(dialOpts) < 2 {
		t.Fatalf("Expected at least 2 dial options (credentials + authority), got %d", len(dialOpts))
	}

	t.Logf("Successfully created %d dial options for target %s", len(dialOpts), target.String())
}

func TestDialOptionsWithDNSName(t *testing.T) {
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("service.example.svc.cluster.local", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Test with DNS name like in the real scenario
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50090")
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options for DNS target: %v", err)
	}

	if len(dialOpts) < 2 {
		t.Fatalf("Expected at least 2 dial options (credentials + authority), got %d", len(dialOpts))
	}

	t.Logf("Successfully created %d dial options for DNS target %s", len(dialOpts), target.String())
}

func TestFQDNServerClientConnection(t *testing.T) {
	// Generate certificates with FQDN in SAN
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("service.example.svc.cluster.local", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Start server on localhost but test with FQDN target
	done := make(chan struct{})
	go func(done chan struct{}) {
		serverCredentials, err := grpcCerts.NewServerTLSCredentials()
		if err != nil {
			t.Errorf("Failed to create server credentials: %v", err)
			return
		}

		server := grpc.NewServer(grpc.Creds(serverCredentials))

		go func() {
			<-done
			server.GracefulStop()
		}()

		examplepb.RegisterGreeterServiceServer(server, &mockServer{})

		listener, err := net.Listen("tcp", "127.0.0.1:50053")
		if err != nil {
			t.Errorf("Failed to listen: %v", err)
			return
		}

		t.Logf("gRPC server is running on port 50053...")
		if err := server.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}(done)

	// Wait for server to start
	<-time.After(1 * time.Second)

	// Test client connection using FQDN target but connecting to localhost
	// This simulates the real scenario where DNS resolves FQDN to localhost
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50053")
	clientCredentials, err := grpcCerts.NewClientTLSCredentials(target)
	if err != nil {
		t.Fatalf("Failed to create client credentials: %v", err)
	}

	// Connect to localhost but with FQDN in the target for ServerName
	// Note: In real scenario, this would require DNS resolution or port-forwarding
	// For this test, we'll connect to localhost but the TLS config should handle FQDN
	conn, err := grpc.NewClient("127.0.0.1:50053", grpc.WithTransportCredentials(clientCredentials))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := examplepb.NewGreeterServiceClient(conn)

	// Call the SayHello method
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.SayHello(ctx, &examplepb.SayHelloRequest{Ping: "FQDN Test"})
	if err != nil {
		t.Fatalf("Failed to call SayHello with FQDN target: %v", err)
	}

	t.Logf("Successfully connected using FQDN target: %s", target.String())
	
	done <- struct{}{}
	<-time.After(1 * time.Second)
}

func TestFQDNWithAuthorityOverride(t *testing.T) {
	// Generate certificates with FQDN in SAN
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("service.example.svc.cluster.local", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Start server on localhost
	done := make(chan struct{})
	go func(done chan struct{}) {
		serverCredentials, err := grpcCerts.NewServerTLSCredentials()
		if err != nil {
			t.Errorf("Failed to create server credentials: %v", err)
			return
		}

		server := grpc.NewServer(grpc.Creds(serverCredentials))

		go func() {
			<-done
			server.GracefulStop()
		}()

		examplepb.RegisterGreeterServiceServer(server, &mockServer{})

		listener, err := net.Listen("tcp", "127.0.0.1:50054")
		if err != nil {
			t.Errorf("Failed to listen: %v", err)
			return
		}

		t.Logf("gRPC server is running on port 50054...")
		if err := server.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}(done)

	// Wait for server to start
	<-time.After(1 * time.Second)

	// Test using NewClientDialOptions which includes WithAuthority
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50054")
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options: %v", err)
	}

	// Connect to localhost but with FQDN authority
	conn, err := grpc.NewClient("127.0.0.1:50054", dialOpts...)
	if err != nil {
		t.Fatalf("Failed to connect with WithAuthority: %v", err)
	}
	defer conn.Close()

	client := examplepb.NewGreeterServiceClient(conn)

	// Call the SayHello method
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.SayHello(ctx, &examplepb.SayHelloRequest{Ping: "WithAuthority Test"})
	if err != nil {
		t.Fatalf("Failed to call SayHello with WithAuthority: %v", err)
	}

	t.Logf("Successfully connected using WithAuthority - target: %s, actual address: 127.0.0.1:50054", target.String())
	
	done <- struct{}{}
	<-time.After(1 * time.Second)
}

func TestClientCredentialsWithManualAuthority(t *testing.T) {
	// Generate certificates with FQDN in SAN
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1), /*one day after*/
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("service.example.svc.cluster.local", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Start server on localhost
	done := make(chan struct{})
	go func(done chan struct{}) {
		serverCredentials, err := grpcCerts.NewServerTLSCredentials()
		if err != nil {
			t.Errorf("Failed to create server credentials: %v", err)
			return
		}

		server := grpc.NewServer(grpc.Creds(serverCredentials))

		go func() {
			<-done
			server.GracefulStop()
		}()

		examplepb.RegisterGreeterServiceServer(server, &mockServer{})

		listener, err := net.Listen("tcp", "127.0.0.1:50055")
		if err != nil {
			t.Errorf("Failed to listen: %v", err)
			return
		}

		t.Logf("gRPC server is running on port 50055...")
		if err := server.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}(done)

	// Wait for server to start
	<-time.After(1 * time.Second)

	// Test manual configuration: get credentials separately and add WithAuthority manually
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50055")
	clientCredentials, err := grpcCerts.NewClientTLSCredentials(target)
	if err != nil {
		t.Fatalf("Failed to create client credentials: %v", err)
	}

	// Manual dial options with custom authority
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(clientCredentials),
		grpc.WithAuthority("service.example.svc.cluster.local"), // Override authority
	}

	// Connect to localhost but with FQDN authority
	conn, err := grpc.NewClient("127.0.0.1:50055", dialOpts...)
	if err != nil {
		t.Fatalf("Failed to connect with manual WithAuthority: %v", err)
	}
	defer conn.Close()

	client := examplepb.NewGreeterServiceClient(conn)

	// Call the SayHello method
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.SayHello(ctx, &examplepb.SayHelloRequest{Ping: "Manual Authority Test"})
	if err != nil {
		t.Fatalf("Failed to call SayHello with manual WithAuthority: %v", err)
	}

	t.Logf("Successfully connected using manual WithAuthority: %s", target.Host())
	
	done <- struct{}{}
	<-time.After(1 * time.Second)
}

func TestWithDownloadedCertificates(t *testing.T) {
	// Test with real certificates downloaded from the server
	// Skip test if certificates are not available
	certsDir := "/tmp"
	requiredFiles := map[string]string{
		"ca":        fmt.Sprintf("%s/example-ca.crt", certsDir),
		"client":    fmt.Sprintf("%s/example-client-cluster.crt", certsDir),
		"clientKey": fmt.Sprintf("%s/example-client.key", certsDir),
		"server":    fmt.Sprintf("%s/example-server-cluster.crt", certsDir),
	}
	
	// Check if files exist
	for name, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Skipf("Skipping test: required certificate file not found: %s (%s)", name, file)
		}
	}

	// Read certificate files
	caCert, err := os.ReadFile(requiredFiles["ca"])
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}

	clientCert, err := os.ReadFile(requiredFiles["client"])
	if err != nil {
		t.Fatalf("Failed to read client certificate: %v", err)
	}

	clientKey, err := os.ReadFile(requiredFiles["clientKey"])
	if err != nil {
		t.Fatalf("Failed to read client key: %v", err)
	}

	serverCert, err := os.ReadFile(requiredFiles["server"])
	if err != nil {
		t.Fatalf("Failed to read server certificate: %v", err)
	}

	// Generate dummy server key since we only need client credentials for testing
	dummyServerCredentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1),
		certsgen.WithOrganizations("test"),
	)
	if err != nil {
		t.Fatalf("Failed to generate dummy server credentials: %v", err)
	}

	// Create mem loader using real certificates and keys from cluster
	l := certsmem.NewMemLoader(
		caCert,                                // Real CA cert from cluster
		clientKey,                             // Real client key from cluster
		clientCert,                            // Real client cert from cluster
		dummyServerCredentials.ServerKey.Bytes(), // Dummy server key (not needed for client)
		serverCert,                            // Real server cert from cluster
	)

	grpcCerts := NewGrpcCerts(l)

	// Test creating client credentials with FQDN
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50090")
	
	t.Logf("Testing with downloaded certificates:")
	t.Logf("  CA cert: %s", requiredFiles["ca"])
	t.Logf("  Client cert: %s", requiredFiles["client"])
	t.Logf("  Client key: %s", requiredFiles["clientKey"])
	t.Logf("  Server cert: %s", requiredFiles["server"])

	// Test dial options creation (this should work even without a running server)
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options with downloaded certificates: %v", err)
	}

	if len(dialOpts) < 2 {
		t.Fatalf("Expected at least 2 dial options (credentials + authority), got %d", len(dialOpts))
	}

	t.Logf("Successfully created %d dial options using downloaded certificates for target: %s", 
		len(dialOpts), target.String())

	// Test credentials creation
	clientCreds, err := grpcCerts.NewClientTLSCredentials(target)
	if err != nil {
		t.Fatalf("Failed to create client credentials with downloaded certificates: %v", err)
	}

	if clientCreds == nil {
		t.Fatal("Client credentials should not be nil")
	}

	t.Logf("Successfully created client credentials using downloaded certificates")
	
	// Note: To test actual connection with real keys, you would do:
	// conn, err := grpc.NewClient("127.0.0.1:50090", dialOpts...)
	// But this requires port-forwarding to be active and real private keys
}

func TestNewGrpcCertsFromFiles(t *testing.T) {
	// Test the convenience function for loading from files
	certsDir := "/tmp"
	caCertPath := fmt.Sprintf("%s/example-ca.crt", certsDir)
	clientCertPath := fmt.Sprintf("%s/example-client-cluster.crt", certsDir)
	clientKeyPath := fmt.Sprintf("%s/example-client.key", certsDir)

	// Check if files exist
	requiredFiles := []string{caCertPath, clientCertPath, clientKeyPath}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Skipf("Skipping test: required certificate file not found: %s", file)
		}
	}

	// Test the convenience function
	grpcCerts, err := NewGrpcCertsFromFiles(caCertPath, clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to create GrpcCerts from files: %v", err)
	}

	// Test creating client credentials
	target := NewTypeHostAndPort("service.example.svc.cluster.local:50090")
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options: %v", err)
	}

	if len(dialOpts) < 2 {
		t.Fatalf("Expected at least 2 dial options, got %d", len(dialOpts))
	}

	t.Logf("Successfully created GrpcCerts from files and generated %d dial options", len(dialOpts))
	
	// Example usage that would work with port-forwarding:
	t.Logf("Example usage:")
	t.Logf("  grpcCerts, err := NewGrpcCertsFromFiles(\"%s\", \"%s\", \"%s\")", caCertPath, clientCertPath, clientKeyPath)
	t.Logf("  target := NewTypeHostAndPort(\"service.example.svc.cluster.local:50090\")")
	t.Logf("  dialOpts, err := grpcCerts.NewClientDialOptions(target)")
	t.Logf("  conn, err := grpc.NewClient(\"127.0.0.1:50090\", dialOpts...)")
}

func TestNewClientTLSCredentials(t *testing.T) {
	credentials, err := certsgen.NewTLSCredentials(
		time.Now(),
		time.Now().AddDate(0, 0, 1),
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("example.com", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Test with target parameter
	target := NewTypeHostAndPort("example.com:443")
	clientCreds, err := grpcCerts.NewClientTLSCredentials(target)
	if err != nil {
		t.Fatalf("Failed to create client credentials: %v", err)
	}

	if clientCreds == nil {
		t.Fatal("Client credentials should not be nil")
	}

	t.Logf("Successfully created client credentials for target %s", target.String())
}

func TestTypeHostAndPort(t *testing.T) {
	tests := []struct {
		address      string
		expectedHost string
		expectedPort string
		hasPort      bool
	}{
		{"service.example.svc.cluster.local:50090", "service.example.svc.cluster.local", "50090", true},
		{"127.0.0.1:8080", "127.0.0.1", "8080", true},
		{"localhost:443", "localhost", "443", true},
		{"localhost", "localhost", "", false},
		{"example.com", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			target := NewTypeHostAndPort(tt.address)
			
			if host := target.Host(); host != tt.expectedHost {
				t.Errorf("Host() = %v, want %v", host, tt.expectedHost)
			}
			
			if port := target.Port(); port != tt.expectedPort {
				t.Errorf("Port() = %v, want %v", port, tt.expectedPort)
			}
			
			if hasPort := target.HasPort(); hasPort != tt.hasPort {
				t.Errorf("HasPort() = %v, want %v", hasPort, tt.hasPort)
			}
			
			if str := target.String(); str != tt.address {
				t.Errorf("String() = %v, want %v", str, tt.address)
			}
		})
	}
}

func testGrpc(t *testing.T, grpcCerts *GrpcCerts) {

	done := make(chan struct{})
	go func(done chan struct{}) {
		serverCredentials, err := grpcCerts.NewServerTLSCredentials()
		if err != nil {
			t.Errorf("Failed to create server credentials: %v", err)
			return
		}

		server := grpc.NewServer(grpc.Creds(serverCredentials))

		go func() {
			<-done
			server.GracefulStop()
		}()

		examplepb.RegisterGreeterServiceServer(server, &mockServer{})

		listener, err := net.Listen("tcp", "127.0.0.1:50051")
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}

		log.Println("gRPC server is running on port 50051...")
		if err := server.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}(done)

	// wait for ready
	<-time.After(1 * time.Second)

	target := NewTypeHostAndPort("localhost:50051")
	clientCredentials, err := grpcCerts.NewClientTLSCredentials(target)
	if err != nil {
		t.Fatalf("Failed to create client credentials: %v", err)
	}

	conn, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(clientCredentials))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := examplepb.NewGreeterServiceClient(conn)

	// Call the SayHello method
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = client.SayHello(ctx, &examplepb.SayHelloRequest{Ping: "World"})
	if err != nil {
		log.Fatalf("Failed to call SayHello: %v", err)
	}
	done <- struct{}{}

	// wait for close
	<-time.After(1 * time.Second)

}
