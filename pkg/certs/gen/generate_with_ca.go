// Copyright 2024 FootprintAI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certsgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/footprintai/go-certs/pkg/certs"
)

// GenerateWithExistingCA creates client and server certificates signed by an existing CA
// It returns all credentials in a TLSCredentials struct, using the provided CA cert and key
func GenerateWithExistingCA(caCertPEM, caKeyPEM []byte, notBefore, notAfter time.Time, opts ...templateOption) (*certs.TLSCredentials, error) {
	// Parse the CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse the CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}

	var caKey *rsa.PrivateKey
	if caKeyBlock.Type == "RSA PRIVATE KEY" {
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA key: %w", err)
		}
	} else {
		return nil, errors.New("unsupported CA key type")
	}

	// Verify that the CA certificate is actually a CA
	if !caCert.IsCA {
		return nil, errors.New("the provided certificate is not a CA certificate")
	}

	/*******************************************************************
	  Server Cert
	  *******************************************************************/

	// Create a key-pair for the server
	servKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating random key for server: %w", err)
	}

	// Create a template for the server
	servCertTmpl, err := CertTemplate(notBefore, notAfter, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating cert template for server: %w", err)
	}
	servCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	servCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// Create a certificate which wraps the server's public key, sign it with the CA private key
	_, servCertPEM, err := CreateCert(servCertTmpl, caCert, &servKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("error creating server cert: %w", err)
	}

	// Provide the private key and the cert
	servKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
	})

	/*******************************************************************
	  Client Cert
	  *******************************************************************/

	// Create a key-pair for the client
	clientKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating random key for client: %w", err)
	}

	// Create a template for the client
	clientCertTmpl, err := CertTemplate(notBefore, notAfter, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating cert template for client: %w", err)
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// The CA cert signs the cert by providing its private key
	_, clientCertPEM, err := CreateCert(clientCertTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("error creating client cert: %w", err)
	}

	// Encode and load the cert and private key for the client
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	// Return all PEM data in a strongly typed struct, passing through the provided CA cert and key
	return &certs.TLSCredentials{
		CACert:     certs.CACert(caCertPEM),
		CAKey:      certs.CAKey(caKeyPEM),
		ClientCert: certs.ClientCert(clientCertPEM),
		ClientKey:  certs.ClientKey(clientKeyPEM),
		ServerCert: certs.ServerCert(servCertPEM),
		ServerKey:  certs.ServerKey(servKeyPEM),
	}, nil
}

// For backward compatibility with existing code
func LegacyGenerateWithExistingCA(caCertPEM, caKeyPEM []byte, notBefore, notAfter time.Time, opts ...templateOption) ([]byte, []byte, []byte, []byte, error) {
	credentials, err := GenerateWithExistingCA(caCertPEM, caKeyPEM, notBefore, notAfter, opts...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return credentials.ClientCert.Bytes(),
		credentials.ClientKey.Bytes(),
		credentials.ServerCert.Bytes(),
		credentials.ServerKey.Bytes(),
		nil
}
