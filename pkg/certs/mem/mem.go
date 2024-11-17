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
	certs "github.com/footprintai/go-certs/pkg/certs"
)

func NewMemLoader(ca, clientKey, clientCert, serverKey, serverCert []byte) MemLoader {
	return MemLoader{
		ca:         ca,
		clientKey:  clientKey,
		clientCert: clientCert,
		serverKey:  serverKey,
		serverCert: serverCert,
	}
}

type MemLoader struct {
	ca, clientKey, clientCert, serverKey, serverCert []byte
}

var (
	_ certs.Certificates = MemLoader{}
)

func (e MemLoader) CaCert() []byte {
	return e.ca
}

func (e MemLoader) ServerKey() []byte {
	return e.serverKey
}

func (e MemLoader) ServerCrt() []byte {
	return e.serverCert
}

func (e MemLoader) ClientKey() []byte {
	return e.clientKey
}

func (e MemLoader) ClientCrt() []byte {
	return e.clientCert
}
