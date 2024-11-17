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
	ca, clientCrt, clientKey, serverCrt, serverKey := certsgen.NewTLSCredentials(
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

func testGrpc(t *testing.T, grpcCerts *GrpcCerts) {

	done := make(chan struct{})
	go func(done chan struct{}) {
		serverCredentials := grpcCerts.NewServerTLSCredentials()

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

	clientCredentials := grpcCerts.NewClientTLSCredentials()

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
