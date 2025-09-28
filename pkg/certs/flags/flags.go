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
	"fmt"
	"os"

	"github.com/footprintai/go-certs/pkg/certs"
)

var (
	CaCertPath    string
	SeverKeyPath  string
	ServerCrtPath string
	ClientKeyPath string
	ClientCrtPath string
	TLSInsecure   bool
)

func NewFlagLoader() FlagLoader {
	return FlagLoader{}
}

type FlagLoader struct{}

var (
	_ certs.Certificates = FlagLoader{}
)

func (f FlagLoader) CaCert() []byte {
	if TLSInsecure {
		return []byte("")
	}
	return mustLoad(CaCertPath)
}

func (f FlagLoader) ServerKey() []byte {
	if TLSInsecure {
		return []byte("")
	}
	return mustLoad(SeverKeyPath)
}

func (f FlagLoader) ServerCrt() []byte {
	if TLSInsecure {
		return []byte("")
	}
	return mustLoad(ServerCrtPath)
}

func (f FlagLoader) ClientKey() []byte {
	if TLSInsecure {
		return []byte("")
	}
	return mustLoad(ClientKeyPath)
}

func (f FlagLoader) ClientCrt() []byte {
	if TLSInsecure {
		return []byte("")
	}
	return mustLoad(ClientCrtPath)
}

func (f FlagLoader) IsTLSInsecure() bool {
	return TLSInsecure
}

func mustLoad(filepath string) []byte {
	fmt.Printf("credentials: loading file: %s\n", filepath)
	b, err := os.ReadFile(filepath)
	if err != nil {
		panic(fmt.Sprintf("credentials: missing file :%s\n", filepath))
	}
	return b
}
