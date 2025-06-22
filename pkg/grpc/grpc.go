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

	"github.com/footprintai/go-certs/pkg/certs"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

func (g *GrpcCerts) NewClientTLSCredentials() grpccredentials.TransportCredentials {
	creds, err := g.newClientCredentials()
	if err != nil {
		panic(err)
	}
	return creds
}

func (g *GrpcCerts) newClientCredentials() (grpccredentials.TransportCredentials, error) {
	// Check if insecure mode is enabled
	if g.certs.IsTLSInsecure() {
		return insecure.NewCredentials(), nil
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
		ServerName:   "localhost",
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
			
			// Additional verification: check that server cert is valid for localhost
			if err := serverCert.VerifyHostname("localhost"); err != nil {
				return err
			}
			
			return nil
		},
	}
	creds := grpccredentials.NewTLS(clientTLSConfig)
	return creds, nil
}
