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
	"testing"
)

func TestMemLoader_IsTLSInsecure(t *testing.T) {
	tests := []struct {
		name     string
		loader   MemLoader
		expected bool
	}{
		{
			name:     "secure mem loader",
			loader:   NewMemLoader([]byte("ca"), []byte("clientKey"), []byte("clientCert"), []byte("serverKey"), []byte("serverCert")),
			expected: false,
		},
		{
			name:     "insecure mem loader",
			loader:   NewInsecureMemLoader(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.loader.IsTLSInsecure(); got != tt.expected {
				t.Errorf("MemLoader.IsTLSInsecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMemLoaderWithCAKey_IsTLSInsecure(t *testing.T) {
	tests := []struct {
		name     string
		loader   MemLoaderWithCAKey
		expected bool
	}{
		{
			name:     "secure mem loader with CA key",
			loader:   NewMemLoaderWithCAKey([]byte("ca"), []byte("caKey"), []byte("clientKey"), []byte("clientCert"), []byte("serverKey"), []byte("serverCert")),
			expected: false,
		},
		{
			name:     "insecure mem loader with CA key",
			loader:   NewInsecureMemLoaderWithCAKey(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.loader.IsTLSInsecure(); got != tt.expected {
				t.Errorf("MemLoaderWithCAKey.IsTLSInsecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMemLoader_CertMethodsWithInsecure(t *testing.T) {
	testData := map[string][]byte{
		"ca":         []byte("test-ca-cert"),
		"clientKey":  []byte("test-client-key"),
		"clientCert": []byte("test-client-cert"),
		"serverKey":  []byte("test-server-key"),
		"serverCert": []byte("test-server-cert"),
	}

	tests := []struct {
		name     string
		loader   MemLoader
		insecure bool
	}{
		{
			name:     "secure mode - returns actual data",
			loader:   NewMemLoader(testData["ca"], testData["clientKey"], testData["clientCert"], testData["serverKey"], testData["serverCert"]),
			insecure: false,
		},
		{
			name:     "insecure mode - returns empty bytes",
			loader:   NewInsecureMemLoader(),
			insecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.insecure {
				// In insecure mode, all cert methods should return empty bytes
				if got := tt.loader.CaCert(); len(got) != 0 {
					t.Errorf("CaCert() in insecure mode = %v, want empty bytes", got)
				}
				if got := tt.loader.ServerKey(); len(got) != 0 {
					t.Errorf("ServerKey() in insecure mode = %v, want empty bytes", got)
				}
				if got := tt.loader.ServerCrt(); len(got) != 0 {
					t.Errorf("ServerCrt() in insecure mode = %v, want empty bytes", got)
				}
				if got := tt.loader.ClientKey(); len(got) != 0 {
					t.Errorf("ClientKey() in insecure mode = %v, want empty bytes", got)
				}
				if got := tt.loader.ClientCrt(); len(got) != 0 {
					t.Errorf("ClientCrt() in insecure mode = %v, want empty bytes", got)
				}
			} else {
				// In secure mode, all cert methods should return actual data
				if got := string(tt.loader.CaCert()); got != string(testData["ca"]) {
					t.Errorf("CaCert() in secure mode = %v, want %v", got, string(testData["ca"]))
				}
				if got := string(tt.loader.ServerKey()); got != string(testData["serverKey"]) {
					t.Errorf("ServerKey() in secure mode = %v, want %v", got, string(testData["serverKey"]))
				}
				if got := string(tt.loader.ServerCrt()); got != string(testData["serverCert"]) {
					t.Errorf("ServerCrt() in secure mode = %v, want %v", got, string(testData["serverCert"]))
				}
				if got := string(tt.loader.ClientKey()); got != string(testData["clientKey"]) {
					t.Errorf("ClientKey() in secure mode = %v, want %v", got, string(testData["clientKey"]))
				}
				if got := string(tt.loader.ClientCrt()); got != string(testData["clientCert"]) {
					t.Errorf("ClientCrt() in secure mode = %v, want %v", got, string(testData["clientCert"]))
				}
			}
		})
	}
}

func TestMemLoaderWithCAKey_CAKey(t *testing.T) {
	testCAKey := []byte("test-ca-key")
	
	tests := []struct {
		name     string
		loader   MemLoaderWithCAKey
		insecure bool
	}{
		{
			name:     "secure mode with CA key",
			loader:   NewMemLoaderWithCAKey([]byte("ca"), testCAKey, []byte("clientKey"), []byte("clientCert"), []byte("serverKey"), []byte("serverCert")),
			insecure: false,
		},
		{
			name:     "insecure mode with CA key",
			loader:   NewInsecureMemLoaderWithCAKey(),
			insecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.insecure {
				// CAKey should return empty bytes since the MemLoader has no CA key data in insecure mode
				if got := tt.loader.CAKey(); len(got) != 0 {
					t.Errorf("CAKey() in insecure mode = %v, want empty bytes", got)
				}
			} else {
				// CAKey should return actual data in secure mode
				if got := string(tt.loader.CAKey()); got != string(testCAKey) {
					t.Errorf("CAKey() in secure mode = %v, want %v", got, string(testCAKey))
				}
			}
		})
	}
}

func TestNewFileLoader_Insecure(t *testing.T) {
	tests := []struct {
		name     string
		loader   MemLoader
		expected bool
	}{
		{
			name:     "secure file loader",
			loader:   NewFileLoader("", "", "", "", "", false),
			expected: false,
		},
		{
			name:     "insecure file loader with param",
			loader:   NewFileLoader("", "", "", "", "", true),
			expected: true,
		},
		{
			name:     "insecure file loader with helper",
			loader:   NewInsecureFileLoader(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.loader.IsTLSInsecure(); got != tt.expected {
				t.Errorf("IsTLSInsecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}