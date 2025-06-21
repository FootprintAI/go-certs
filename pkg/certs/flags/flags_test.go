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
	"os"
	"path/filepath"
	"testing"
)

func TestFlagLoader_IsTLSInsecure(t *testing.T) {
	tests := []struct {
		name     string
		insecure bool
		expected bool
	}{
		{
			name:     "secure mode",
			insecure: false,
			expected: false,
		},
		{
			name:     "insecure mode",
			insecure: true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the global TLSInsecure flag
			originalTLSInsecure := TLSInsecure
			defer func() {
				TLSInsecure = originalTLSInsecure
			}()
			
			TLSInsecure = tt.insecure
			
			loader := NewFlagLoader()
			if got := loader.IsTLSInsecure(); got != tt.expected {
				t.Errorf("FlagLoader.IsTLSInsecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFlagLoader_CertMethodsWithInsecure(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()
	
	testFiles := map[string]string{
		"ca.crt":     "test-ca-cert",
		"server.key": "test-server-key",
		"server.crt": "test-server-cert",
		"client.key": "test-client-key",
		"client.crt": "test-client-cert",
	}
	
	// Write test files
	for filename, content := range testFiles {
		filePath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}
	
	tests := []struct {
		name     string
		insecure bool
	}{
		{
			name:     "secure mode - loads files",
			insecure: false,
		},
		{
			name:     "insecure mode - returns empty bytes",
			insecure: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			originalTLSInsecure := TLSInsecure
			originalCaCertPath := CaCertPath
			originalServerKeyPath := SeverKeyPath
			originalServerCrtPath := ServerCrtPath
			originalClientKeyPath := ClientKeyPath
			originalClientCrtPath := ClientCrtPath
			
			defer func() {
				TLSInsecure = originalTLSInsecure
				CaCertPath = originalCaCertPath
				SeverKeyPath = originalServerKeyPath
				ServerCrtPath = originalServerCrtPath
				ClientKeyPath = originalClientKeyPath
				ClientCrtPath = originalClientCrtPath
			}()
			
			// Set test values
			TLSInsecure = tt.insecure
			CaCertPath = filepath.Join(tmpDir, "ca.crt")
			SeverKeyPath = filepath.Join(tmpDir, "server.key")
			ServerCrtPath = filepath.Join(tmpDir, "server.crt")
			ClientKeyPath = filepath.Join(tmpDir, "client.key")
			ClientCrtPath = filepath.Join(tmpDir, "client.crt")
			
			loader := NewFlagLoader()
			
			if tt.insecure {
				// In insecure mode, all cert methods should return empty bytes
				if got := loader.CaCert(); len(got) != 0 {
					t.Errorf("CaCert() in insecure mode = %v, want empty bytes", got)
				}
				if got := loader.ServerKey(); len(got) != 0 {
					t.Errorf("ServerKey() in insecure mode = %v, want empty bytes", got)
				}
				if got := loader.ServerCrt(); len(got) != 0 {
					t.Errorf("ServerCrt() in insecure mode = %v, want empty bytes", got)
				}
				if got := loader.ClientKey(); len(got) != 0 {
					t.Errorf("ClientKey() in insecure mode = %v, want empty bytes", got)
				}
				if got := loader.ClientCrt(); len(got) != 0 {
					t.Errorf("ClientCrt() in insecure mode = %v, want empty bytes", got)
				}
			} else {
				// In secure mode, all cert methods should return file contents
				if got := string(loader.CaCert()); got != testFiles["ca.crt"] {
					t.Errorf("CaCert() in secure mode = %v, want %v", got, testFiles["ca.crt"])
				}
				if got := string(loader.ServerKey()); got != testFiles["server.key"] {
					t.Errorf("ServerKey() in secure mode = %v, want %v", got, testFiles["server.key"])
				}
				if got := string(loader.ServerCrt()); got != testFiles["server.crt"] {
					t.Errorf("ServerCrt() in secure mode = %v, want %v", got, testFiles["server.crt"])
				}
				if got := string(loader.ClientKey()); got != testFiles["client.key"] {
					t.Errorf("ClientKey() in secure mode = %v, want %v", got, testFiles["client.key"])
				}
				if got := string(loader.ClientCrt()); got != testFiles["client.crt"] {
					t.Errorf("ClientCrt() in secure mode = %v, want %v", got, testFiles["client.crt"])
				}
			}
		})
	}
}

func TestFlagLoader_InsecureModeWithMissingFiles(t *testing.T) {
	// Save original values
	originalTLSInsecure := TLSInsecure
	originalCaCertPath := CaCertPath
	originalServerKeyPath := SeverKeyPath
	originalServerCrtPath := ServerCrtPath
	originalClientKeyPath := ClientKeyPath
	originalClientCrtPath := ClientCrtPath
	
	defer func() {
		TLSInsecure = originalTLSInsecure
		CaCertPath = originalCaCertPath
		SeverKeyPath = originalServerKeyPath
		ServerCrtPath = originalServerCrtPath
		ClientKeyPath = originalClientKeyPath
		ClientCrtPath = originalClientCrtPath
	}()
	
	// Set insecure mode with non-existent files
	TLSInsecure = true
	CaCertPath = "/non/existent/ca.crt"
	SeverKeyPath = "/non/existent/server.key"
	ServerCrtPath = "/non/existent/server.crt"
	ClientKeyPath = "/non/existent/client.key"
	ClientCrtPath = "/non/existent/client.crt"
	
	loader := NewFlagLoader()
	
	// Should not panic and return empty bytes even with missing files
	if got := loader.CaCert(); len(got) != 0 {
		t.Errorf("CaCert() with missing file in insecure mode = %v, want empty bytes", got)
	}
	if got := loader.ServerKey(); len(got) != 0 {
		t.Errorf("ServerKey() with missing file in insecure mode = %v, want empty bytes", got)
	}
	if got := loader.ServerCrt(); len(got) != 0 {
		t.Errorf("ServerCrt() with missing file in insecure mode = %v, want empty bytes", got)
	}
	if got := loader.ClientKey(); len(got) != 0 {
		t.Errorf("ClientKey() with missing file in insecure mode = %v, want empty bytes", got)
	}
	if got := loader.ClientCrt(); len(got) != 0 {
		t.Errorf("ClientCrt() with missing file in insecure mode = %v, want empty bytes", got)
	}
}