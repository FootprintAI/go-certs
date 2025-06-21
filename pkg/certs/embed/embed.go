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

package certsembed

import (
	"embed"
	"fmt"

	"github.com/footprintai/go-certs/pkg/certs"
)

func NewEmbedLoader(fs embed.FS) EmbedLoader {
	return EmbedLoader{fs: fs}
}

type EmbedLoader struct {
	fs embed.FS
}

var (
	_ certs.Certificates      = EmbedLoader{}
	_ certs.TypedCertificates = EmbedLoader{}
)

// Implementations for certs.Certificates interface
func (e EmbedLoader) CaCert() []byte {
	return e.mustLoad("ca.crt")
}

func (e EmbedLoader) ServerKey() []byte {
	return e.mustLoad("server.key")
}

func (e EmbedLoader) ServerCrt() []byte {
	return e.mustLoad("server.crt")
}

func (e EmbedLoader) ClientKey() []byte {
	return e.mustLoad("client.key")
}

func (e EmbedLoader) ClientCrt() []byte {
	return e.mustLoad("client.crt")
}

func (e EmbedLoader) IsTLSInsecure() bool {
	return false
}

// Implementation for TypedCertificates interface
func (e EmbedLoader) GetCACert() certs.CACert {
	return certs.CACert(e.mustLoad("ca.crt"))
}

func (e EmbedLoader) GetCAKey() certs.CAKey {
	// CA key might not be available in embedded certs for security reasons
	data, err := e.fs.ReadFile("ca.key")
	if err != nil {
		return nil
	}
	return certs.CAKey(data)
}

func (e EmbedLoader) GetServerCert() certs.ServerCert {
	return certs.ServerCert(e.mustLoad("server.crt"))
}

func (e EmbedLoader) GetServerKey() certs.ServerKey {
	return certs.ServerKey(e.mustLoad("server.key"))
}

func (e EmbedLoader) GetClientCert() certs.ClientCert {
	return certs.ClientCert(e.mustLoad("client.crt"))
}

func (e EmbedLoader) GetClientKey() certs.ClientKey {
	return certs.ClientKey(e.mustLoad("client.key"))
}

func (e EmbedLoader) GetCredentials() *certs.TLSCredentials {
	return &certs.TLSCredentials{
		CACert:     e.GetCACert(),
		CAKey:      e.GetCAKey(),
		ClientCert: e.GetClientCert(),
		ClientKey:  e.GetClientKey(),
		ServerCert: e.GetServerCert(),
		ServerKey:  e.GetServerKey(),
	}
}

func (e EmbedLoader) mustLoad(filepath string) []byte {
	b, err := e.fs.ReadFile(filepath)
	if err != nil {
		panic(fmt.Sprintf("credentials: missing file :%s\n", filepath))
	}
	return b
}
