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
	"log"
	"net"
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
		certsgen.WithAliasDNSNames("authz.kafeido-mlops.svc.cluster.local", "localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate TLS credentials: %v", err)
	}

	l := certsmem.NewMemLoaderFromCredentials(credentials)
	grpcCerts := NewGrpcCerts(l)

	// Test with DNS name like in the real scenario
	target := NewTypeHostAndPort("authz.kafeido-mlops.svc.cluster.local:50090")
	dialOpts, err := grpcCerts.NewClientDialOptions(target)
	if err != nil {
		t.Fatalf("Failed to create dial options for DNS target: %v", err)
	}

	if len(dialOpts) < 2 {
		t.Fatalf("Expected at least 2 dial options (credentials + authority), got %d", len(dialOpts))
	}

	t.Logf("Successfully created %d dial options for DNS target %s", len(dialOpts), target.String())
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
		{"authz.kafeido-mlops.svc.cluster.local:50090", "authz.kafeido-mlops.svc.cluster.local", "50090", true},
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
