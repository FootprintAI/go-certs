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

package certs

// Certificate types for better type safety
type CACert []byte
type CAKey []byte
type ClientCert []byte
type ClientKey []byte
type ServerCert []byte
type ServerKey []byte

// Helper methods for the certificate types
func (c CACert) Bytes() []byte {
	return []byte(c)
}

func (k CAKey) Bytes() []byte {
	return []byte(k)
}

func (c ClientCert) Bytes() []byte {
	return []byte(c)
}

func (k ClientKey) Bytes() []byte {
	return []byte(k)
}

func (c ServerCert) Bytes() []byte {
	return []byte(c)
}

func (k ServerKey) Bytes() []byte {
	return []byte(k)
}

// TLSCredentials holds all the generated certificates and keys
type TLSCredentials struct {
	CACert     CACert
	CAKey      CAKey
	ClientCert ClientCert
	ClientKey  ClientKey
	ServerCert ServerCert
	ServerKey  ServerKey
}

// Certificates is the original interface for accessing certificates
type Certificates interface {
	CaCert() []byte
	ServerKey() []byte
	ServerCrt() []byte
	ClientKey() []byte
	ClientCrt() []byte
	IsTLSInsecure() bool
}

// CertificatesWithCAKey extends the Certificates interface to include access to the CA key
type CertificatesWithCAKey interface {
	Certificates
	CAKey() []byte
}

// TypedCertificates provides access to strongly-typed certificates and keys
type TypedCertificates interface {
	GetCACert() CACert
	GetCAKey() CAKey
	GetServerCert() ServerCert
	GetServerKey() ServerKey
	GetClientCert() ClientCert
	GetClientKey() ClientKey
	GetCredentials() *TLSCredentials
}
