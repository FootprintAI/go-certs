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

	"github.com/footprintai/go-certs/pkg/certs"
	grpccredentials "google.golang.org/grpc/credentials"
)

func NewGrpcCerts(certs certs.Certificates) *GrpcCerts {
	return &GrpcCerts{certs: certs}
}

type GrpcCerts struct {
	certs certs.Certificates
}

func (g *GrpcCerts) NewServerTLSCredentials() grpccredentials.TransportCredentials {
	creds, err := g.newServerCredentials()
	if err != nil {
		panic(err)
	}
	return creds
}

func (g *GrpcCerts) newServerCredentials() (grpccredentials.TransportCredentials, error) {

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

func (g *GrpcCerts) NewClientTLSCredentials() grpccredentials.TransportCredentials {
	creds, err := g.newClientCredentials()
	if err != nil {
		panic(err)
	}
	return creds
}

func (g *GrpcCerts) newClientCredentials() (grpccredentials.TransportCredentials, error) {

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
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}
	creds := grpccredentials.NewTLS(clientTLSConfig)
	return creds, nil
}
