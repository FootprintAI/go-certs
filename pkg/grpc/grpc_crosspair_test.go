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
	"net"
	"testing"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	certsmem "github.com/footprintai/go-certs/pkg/certs/mem"
	examplepb "github.com/footprintai/go-certs/pkg/grpc/example/pb"
	grpc "google.golang.org/grpc"
)

// TestCrossPairCertsWithSameCA verifies that when two sets of server/client
// certificates (A and B) are signed by the same CA, they can be mixed:
// A.server + B.client and B.server + A.client should both work.
func TestCrossPairCertsWithSameCA(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, 1)

	// Generate the CA first, then use it to sign two independent cert pairs
	credentialsA, err := certsgen.NewTLSCredentials(notBefore, notAfter,
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials A: %v", err)
	}

	// Generate a second set of certs using the same CA
	credentialsB, err := certsgen.GenerateWithExistingCA(
		credentialsA.CACert.Bytes(),
		credentialsA.CAKey.Bytes(),
		notBefore, notAfter,
		certsgen.WithOrganizations("unittest"),
		certsgen.WithAliasDNSNames("localhost"),
		certsgen.WithAliasIPs("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials B with existing CA: %v", err)
	}

	tests := []struct {
		name      string
		serverCrt []byte
		serverKey []byte
		clientCrt []byte
		clientKey []byte
	}{
		{
			name:      "A.server + A.client (same set)",
			serverCrt: credentialsA.ServerCert.Bytes(),
			serverKey: credentialsA.ServerKey.Bytes(),
			clientCrt: credentialsA.ClientCert.Bytes(),
			clientKey: credentialsA.ClientKey.Bytes(),
		},
		{
			name:      "B.server + B.client (same set)",
			serverCrt: credentialsB.ServerCert.Bytes(),
			serverKey: credentialsB.ServerKey.Bytes(),
			clientCrt: credentialsB.ClientCert.Bytes(),
			clientKey: credentialsB.ClientKey.Bytes(),
		},
		{
			name:      "A.server + B.client (cross-pair)",
			serverCrt: credentialsA.ServerCert.Bytes(),
			serverKey: credentialsA.ServerKey.Bytes(),
			clientCrt: credentialsB.ClientCert.Bytes(),
			clientKey: credentialsB.ClientKey.Bytes(),
		},
		{
			name:      "B.server + A.client (cross-pair)",
			serverCrt: credentialsB.ServerCert.Bytes(),
			serverKey: credentialsB.ServerKey.Bytes(),
			clientCrt: credentialsA.ClientCert.Bytes(),
			clientKey: credentialsA.ClientKey.Bytes(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCert := credentialsA.CACert.Bytes()

			// Build server-side loader: CA + server cert/key (client certs irrelevant on server side)
			serverLoader := certsmem.NewMemLoader(
				caCert,
				[]byte{}, // client key not needed on server
				[]byte{}, // client cert not needed on server
				tt.serverKey,
				tt.serverCrt,
			)

			// Build client-side loader: CA + client cert/key (server certs irrelevant on client side)
			clientLoader := certsmem.NewMemLoader(
				caCert,
				tt.clientKey,
				tt.clientCrt,
				[]byte{}, // server key not needed on client
				[]byte{}, // server cert not needed on client
			)

			serverGrpcCerts := NewGrpcCerts(serverLoader)
			clientGrpcCerts := NewGrpcCerts(clientLoader)

			// Start server
			serverCreds, err := serverGrpcCerts.NewServerTLSCredentials()
			if err != nil {
				t.Fatalf("Failed to create server credentials: %v", err)
			}

			server := grpc.NewServer(grpc.Creds(serverCreds))
			examplepb.RegisterGreeterServiceServer(server, &mockServer{})

			listener, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("Failed to listen: %v", err)
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			addr := "localhost:" + port

			done := make(chan struct{})
			go func() {
				if err := server.Serve(listener); err != nil {
					t.Logf("Server stopped: %v", err)
				}
				close(done)
			}()
			defer func() {
				server.GracefulStop()
				<-done
			}()

			// Create client and connect
			target := NewTypeHostAndPort(addr)
			dialOpts, err := clientGrpcCerts.NewClientDialOptions(target)
			if err != nil {
				t.Fatalf("Failed to create client dial options: %v", err)
			}

			conn, err := grpc.NewClient(addr, dialOpts...)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer conn.Close()

			client := examplepb.NewGreeterServiceClient(conn)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := client.SayHello(ctx, &examplepb.SayHelloRequest{Ping: "cross-pair"})
			if err != nil {
				t.Fatalf("SayHello failed: %v", err)
			}

			if resp.Pong != "pong" {
				t.Errorf("unexpected response: got %q, want %q", resp.Pong, "pong")
			}
		})
	}
}
