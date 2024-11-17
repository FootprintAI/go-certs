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

package certsflags

import (
	"flag"
	"fmt"
	"os"

	"github.com/footprintai/go-certs/pkg/certs"
	"github.com/golang/glog"
)

var (
	caCertPath    string
	severKeyPath  string
	serverCrtPath string
	clientKeyPath string
	clientCrtPath string
)

func init() {
	flag.StringVar(&caCertPath, "tls_root_crt", "", "credentials: ca crt file path")
	flag.StringVar(&severKeyPath, "tls_server_key", "", "credentials: server key file path")
	flag.StringVar(&serverCrtPath, "tls_server_crt", "", "credentials: server crt file path")
	flag.StringVar(&clientKeyPath, "tls_client_key", "", "credentials: client key file path")
	flag.StringVar(&clientCrtPath, "tls_client_crt", "", "credentials: client crt file path")
}

func NewFlagLoader() FlagLoader {
	return FlagLoader{}
}

type FlagLoader struct{}

var (
	_ certs.Certificates = FlagLoader{}
)

func (f FlagLoader) CaCert() []byte {
	return mustLoad(caCertPath)
}

func (f FlagLoader) ServerKey() []byte {
	return mustLoad(severKeyPath)
}

func (f FlagLoader) ServerCrt() []byte {
	return mustLoad(serverCrtPath)
}

func (f FlagLoader) ClientKey() []byte {
	return mustLoad(clientKeyPath)
}

func (f FlagLoader) ClientCrt() []byte {
	return mustLoad(clientCrtPath)
}

func mustLoad(filepath string) []byte {
	glog.Info("credentials: loading file :%s\n", filepath)
	b, err := os.ReadFile(filepath)
	if err != nil {
		panic(fmt.Sprintf("credentials: missing file :%s\n", filepath))
	}
	return b
}
