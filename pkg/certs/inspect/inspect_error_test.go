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

package inspect_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	"github.com/footprintai/go-certs/pkg/certs/inspect"
)

// TestInvalidCertificates tests error handling with invalid certificates
func TestInvalidCertificates(t *testing.T) {
	// Test with invalid PEM data
	t.Run("InvalidPEM", func(t *testing.T) {
		invalidPEM := []byte("THIS IS NOT A VALID PEM CERTIFICATE")

		// Create a temporary file with invalid PEM
		tmpFile, err := os.CreateTemp("", "invalid-cert-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(invalidPEM); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		if err := tmpFile.Close(); err != nil {
			t.Fatalf("Failed to close temp file: %v", err)
		}

		// Try to load the invalid certificate
		_, err = inspect.LoadCertificateFromFile(tmpFile.Name())
		if err == nil {
			t.Error("Expected error when loading invalid PEM, but got nil")
		}
	})

	// Test with valid PEM format but invalid certificate data
	t.Run("InvalidCertData", func(t *testing.T) {
		// Create PEM with invalid certificate data
		invalidCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("THIS IS NOT A VALID CERTIFICATE"),
		})

		// Create a temporary file with invalid certificate
		tmpFile, err := os.CreateTemp("", "invalid-cert-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(invalidCertPEM); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		if err := tmpFile.Close(); err != nil {
			t.Fatalf("Failed to close temp file: %v", err)
		}

		// Try to load the invalid certificate
		_, err = inspect.LoadCertificateFromFile(tmpFile.Name())
		if err == nil {
			t.Error("Expected error when loading certificate with invalid data, but got nil")
		}
	})

	// Test with non-existent file
	t.Run("NonExistentFile", func(t *testing.T) {
		_, err := inspect.LoadCertificateFromFile("/path/to/nonexistent/certificate.crt")
		if err == nil {
			t.Error("Expected error when loading non-existent file, but got nil")
		}
	})

	// Test VerifySignedBy with invalid CA path
	t.Run("InvalidCAPath", func(t *testing.T) {
		// Create a dummy certificate for testing
		dummyCert := &x509.Certificate{
			SerialNumber: big.NewInt(123),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}

		// Try to verify with non-existent CA
		_, err := inspect.VerifySignedBy(dummyCert, "/path/to/nonexistent/ca.crt")
		if err == nil {
			t.Error("Expected error when verifying with non-existent CA, but got nil")
		}
	})
}

// TestExpiredCertificate tests parsing and verification of expired certificates
func TestExpiredCertificate(t *testing.T) {
	// Create a temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "certs-test-expired-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate expired certificates
	notBefore := time.Now().Add(-48 * time.Hour) // 2 days ago
	notAfter := time.Now().Add(-24 * time.Hour)  // 1 day ago (expired)

	credentials, err := certsgen.NewTLSCredentials(
		notBefore,
		notAfter,
		certsgen.WithOrganizations("Expired Cert Test"),
	)
	if err != nil {
		t.Fatalf("Failed to generate expired certificates: %v", err)
	}

	// Write certificates to temp directory
	caPath := filepath.Join(tempDir, "expired-ca.crt")
	clientCertPath := filepath.Join(tempDir, "expired-client.crt")

	if err := os.WriteFile(caPath, credentials.CACert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write expired CA cert: %v", err)
	}
	if err := os.WriteFile(clientCertPath, credentials.ClientCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write expired client cert: %v", err)
	}

	// Test ParseCertificateInfo with expired certificate
	t.Run("ExpiredCertInfo", func(t *testing.T) {
		// Load the expired client certificate
		cert, err := inspect.LoadCertificateFromFile(clientCertPath)
		if err != nil {
			t.Fatalf("Failed to load expired certificate: %v", err)
		}

		// Parse certificate info
		certInfo := inspect.ParseCertificateInfo(cert)

		// Check expiry information
		if !certInfo.IsExpired {
			t.Error("Certificate should be marked as expired")
		}

		if certInfo.TimeUntilExpiry >= 0 {
			t.Error("TimeUntilExpiry should be negative for an expired certificate")
		}
	})

	// Test VerifySignedBy with expired certificates
	t.Run("VerifyExpiredCerts", func(t *testing.T) {
		// Load the expired client certificate
		clientCert, err := inspect.LoadCertificateFromFile(clientCertPath)
		if err != nil {
			t.Fatalf("Failed to load expired client certificate: %v", err)
		}

		// Verify against expired CA
		result, err := inspect.VerifySignedBy(clientCert, caPath)
		if err != nil {
			t.Fatalf("Verification error: %v", err)
		}

		// Check if the CA is correctly identified as expired
		if !result.IsCAExpired {
			t.Error("CA certificate should be marked as expired")
		}

		// Check if the time until expiry is negative for an expired certificate
		if result.CATimeUntilExpiry >= 0 {
			t.Errorf("CA TimeUntilExpiry should be negative for an expired certificate, got: %v",
				result.CATimeUntilExpiry)
		}

		// Print the actual values for debugging
		t.Logf("CA NotAfter: %v, Current time: %v, Difference: %v",
			result.CACertInfo.NotAfter, time.Now(), result.CATimeUntilExpiry)
	})
}
