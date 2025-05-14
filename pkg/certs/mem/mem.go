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

package certsmem

import (
	"os"

	"github.com/footprintai/go-certs/pkg/certs"
)

func NewFileLoader(ca, clientKey, clientCert, serverKey, serverCert string) MemLoader {
	return MemLoader{
		ca:         certs.CACert(readAllIfNotEmpty(ca)),
		clientKey:  certs.ClientKey(readAllIfNotEmpty(clientKey)),
		clientCert: certs.ClientCert(readAllIfNotEmpty(clientCert)),
		serverKey:  certs.ServerKey(readAllIfNotEmpty(serverKey)),
		serverCert: certs.ServerCert(readAllIfNotEmpty(serverCert)),
	}
}

func readAllIfNotEmpty(file string) []byte {
	if file == "" {
		return []byte{}
	}
	blob, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return blob
}

// NewMemLoader creates a memory-based certificate loader with the provided certificates and keys
func NewMemLoader(ca, clientKey, clientCert, serverKey, serverCert []byte) MemLoader {
	return MemLoader{
		ca:         certs.CACert(ca),
		clientKey:  certs.ClientKey(clientKey),
		clientCert: certs.ClientCert(clientCert),
		serverKey:  certs.ServerKey(serverKey),
		serverCert: certs.ServerCert(serverCert),
	}
}

// NewMemLoaderWithCAKey creates a memory-based certificate loader with CA key included
func NewMemLoaderWithCAKey(ca, caKey, clientKey, clientCert, serverKey, serverCert []byte) MemLoaderWithCAKey {
	return MemLoaderWithCAKey{
		MemLoader: MemLoader{
			ca:         certs.CACert(ca),
			clientKey:  certs.ClientKey(clientKey),
			clientCert: certs.ClientCert(clientCert),
			serverKey:  certs.ServerKey(serverKey),
			serverCert: certs.ServerCert(serverCert),
		},
		caKey: certs.CAKey(caKey),
	}
}

// NewMemLoaderFromCredentials creates a memory-based certificate loader from a TLSCredentials struct
func NewMemLoaderFromCredentials(credentials *certs.TLSCredentials) MemLoaderWithCAKey {
	return MemLoaderWithCAKey{
		MemLoader: MemLoader{
			ca:         credentials.CACert,
			clientKey:  credentials.ClientKey,
			clientCert: credentials.ClientCert,
			serverKey:  credentials.ServerKey,
			serverCert: credentials.ServerCert,
		},
		caKey: credentials.CAKey,
	}
}

type MemLoader struct {
	ca         certs.CACert
	clientKey  certs.ClientKey
	clientCert certs.ClientCert
	serverKey  certs.ServerKey
	serverCert certs.ServerCert
}

type MemLoaderWithCAKey struct {
	MemLoader
	caKey certs.CAKey
}

var (
	_ certs.Certificates          = MemLoader{}
	_ certs.CertificatesWithCAKey = MemLoaderWithCAKey{}
	_ certs.TypedCertificates     = MemLoaderWithCAKey{}
)

// Implementations for certs.Certificates interface
func (e MemLoader) CaCert() []byte {
	return e.ca.Bytes()
}

func (e MemLoader) ServerKey() []byte {
	return e.serverKey.Bytes()
}

func (e MemLoader) ServerCrt() []byte {
	return e.serverCert.Bytes()
}

func (e MemLoader) ClientKey() []byte {
	return e.clientKey.Bytes()
}

func (e MemLoader) ClientCrt() []byte {
	return e.clientCert.Bytes()
}

// Implementation for CertificatesWithCAKey interface
func (e MemLoaderWithCAKey) CAKey() []byte {
	return e.caKey.Bytes()
}

// Implementations for TypedCertificates interface
func (e MemLoaderWithCAKey) GetCACert() certs.CACert {
	return e.ca
}

func (e MemLoaderWithCAKey) GetCAKey() certs.CAKey {
	return e.caKey
}

func (e MemLoaderWithCAKey) GetServerCert() certs.ServerCert {
	return e.serverCert
}

func (e MemLoaderWithCAKey) GetServerKey() certs.ServerKey {
	return e.serverKey
}

func (e MemLoaderWithCAKey) GetClientCert() certs.ClientCert {
	return e.clientCert
}

func (e MemLoaderWithCAKey) GetClientKey() certs.ClientKey {
	return e.clientKey
}

func (e MemLoaderWithCAKey) GetCredentials() *certs.TLSCredentials {
	return &certs.TLSCredentials{
		CACert:     e.ca,
		CAKey:      e.caKey,
		ClientCert: e.clientCert,
		ClientKey:  e.clientKey,
		ServerCert: e.serverCert,
		ServerKey:  e.serverKey,
	}
}
