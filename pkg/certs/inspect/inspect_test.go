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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	"github.com/footprintai/go-certs/pkg/certs/inspect"
)

// TestCertificateInfo tests the certificate information extraction
func TestCertificateInfo(t *testing.T) {
	// Create a temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "certs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	org := "Test Organization"
	dnsNames := []string{"example.com", "www.example.com"}
	ips := []string{"192.168.1.1", "10.0.0.1"}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // Valid for 1 day

	// Generate CA, client, and server certificates
	credentials, err := certsgen.NewTLSCredentials(
		notBefore,
		notAfter,
		certsgen.WithOrganizations(org),
		certsgen.WithAliasDNSNames(dnsNames...),
		certsgen.WithAliasIPs(ips...),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials: %v", err)
	}

	// Write certificates to temp directory
	caPath := filepath.Join(tempDir, "ca.crt")
	clientCertPath := filepath.Join(tempDir, "client.crt")
	clientKeyPath := filepath.Join(tempDir, "client.key")
	serverCertPath := filepath.Join(tempDir, "server.crt")
	serverKeyPath := filepath.Join(tempDir, "server.key")

	if err := os.WriteFile(caPath, credentials.CACert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	if err := os.WriteFile(clientCertPath, credentials.ClientCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, credentials.ClientKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write client key: %v", err)
	}
	if err := os.WriteFile(serverCertPath, credentials.ServerCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyPath, credentials.ServerKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server key: %v", err)
	}

	// Test LoadCertificateFromFile
	t.Run("LoadCertificateFromFile", func(t *testing.T) {
		cert, err := inspect.LoadCertificateFromFile(caPath)
		if err != nil {
			t.Fatalf("Failed to load CA certificate: %v", err)
		}

		if cert == nil {
			t.Fatal("Loaded certificate is nil")
		}

		// Basic validation
		if !cert.IsCA {
			t.Errorf("Expected CA certificate to have IsCA=true")
		}
	})

	// Test ParseCertificateInfo
	t.Run("ParseCertificateInfo", func(t *testing.T) {
		// Load the server certificate
		cert, err := inspect.LoadCertificateFromFile(serverCertPath)
		if err != nil {
			t.Fatalf("Failed to load server certificate: %v", err)
		}

		// Parse certificate info
		certInfo := inspect.ParseCertificateInfo(cert)

		// Validate basic information
		if certInfo.IsCA {
			t.Errorf("Server certificate should not be a CA")
		}

		if !sliceContains(certInfo.ExtKeyUsage, "ServerAuth") {
			t.Errorf("Server certificate should have ServerAuth extended key usage")
		}

		// Check DNS names
		for _, dns := range dnsNames {
			if !sliceContains(certInfo.DNSNames, dns) {
				t.Errorf("Certificate is missing DNS name: %s", dns)
			}
		}

		// Check IP addresses
		for _, ip := range ips {
			if !sliceContains(certInfo.IPAddresses, ip) {
				t.Errorf("Certificate is missing IP address: %s", ip)
			}
		}

		// Check organization
		if !stringContains(certInfo.Subject, org) {
			t.Errorf("Certificate subject does not contain organization: %s", org)
		}

		// Check validity period
		if certInfo.NotBefore.After(time.Now()) {
			t.Errorf("Certificate NotBefore is in the future")
		}

		if certInfo.NotAfter.Before(time.Now()) {
			t.Errorf("Certificate is already expired")
		}

		if certInfo.TimeUntilExpiry <= 0 {
			t.Errorf("TimeUntilExpiry should be positive for a valid certificate")
		}

		if certInfo.IsExpired {
			t.Errorf("Certificate should not be marked as expired")
		}
	})

	// Test VerifySignedBy
	t.Run("VerifySignedBy", func(t *testing.T) {
		// Load server certificate
		serverCert, err := inspect.LoadCertificateFromFile(serverCertPath)
		if err != nil {
			t.Fatalf("Failed to load server certificate: %v", err)
		}

		// Verify against CA
		result, err := inspect.VerifySignedBy(serverCert, caPath)
		if err != nil {
			t.Fatalf("Verification error: %v", err)
		}

		if !result.IsValid {
			t.Errorf("Expected server certificate to be verified by CA: %v", result.Error)
		}

		if result.CACertInfo == nil {
			t.Errorf("CA certificate info should not be nil")
		}

		if result.CACertInfo != nil && !result.CACertInfo.IsCA {
			t.Errorf("CA certificate should have IsCA=true")
		}

		// Negative test - verify with wrong CA
		// First, generate a different CA
		wrongCACredentials, err := certsgen.NewTLSCredentials(
			notBefore,
			notAfter,
			certsgen.WithOrganizations("Wrong CA"),
		)
		if err != nil {
			t.Fatalf("Failed to generate wrong CA credentials: %v", err)
		}

		wrongCAPath := filepath.Join(tempDir, "wrong-ca.crt")
		if err := os.WriteFile(wrongCAPath, wrongCACredentials.CACert.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write wrong CA cert: %v", err)
		}

		result, err = inspect.VerifySignedBy(serverCert, wrongCAPath)
		if err != nil {
			t.Fatalf("Verification error with wrong CA: %v", err)
		}

		if result.IsValid {
			t.Errorf("Server certificate should NOT be verified by wrong CA")
		}
	})

	// Test certificate chain generation and verification
	t.Run("CertificateChain", func(t *testing.T) {
		// Generate a brand new CA and key specifically for this test
		caNotBefore := time.Now()
		caNotAfter := caNotBefore.Add(24 * time.Hour)

		// Use certsgen.NewTLSCredentials to generate a new CA
		testCACredentials, err := certsgen.NewTLSCredentials(
			caNotBefore,
			caNotAfter,
			certsgen.WithOrganizations("Test Chain CA"),
		)
		if err != nil {
			t.Fatalf("Failed to generate test CA credentials: %v", err)
		}

		// Write the CA to files
		chainCAPath := filepath.Join(tempDir, "chain-ca.crt")
		chainCAKeyPath := filepath.Join(tempDir, "chain-ca.key")

		if err := os.WriteFile(chainCAPath, testCACredentials.CACert.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain CA cert: %v", err)
		}
		if err := os.WriteFile(chainCAKeyPath, testCACredentials.CAKey.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain CA key: %v", err)
		}

		// Generate a certificate using this CA
		chainNotBefore := time.Now()
		chainNotAfter := chainNotBefore.Add(12 * time.Hour)
		chainCredentials, err := certsgen.GenerateWithExistingCA(
			testCACredentials.CACert.Bytes(),
			testCACredentials.CAKey.Bytes(),
			chainNotBefore,
			chainNotAfter,
			certsgen.WithOrganizations("Chain Test Org"),
			certsgen.WithAliasDNSNames("chain-test.com"),
		)
		if err != nil {
			t.Fatalf("Failed to generate certificate with existing CA: %v", err)
		}

		// Write the chain certificates to files
		chainClientCertPath := filepath.Join(tempDir, "chain-client.crt")
		chainClientKeyPath := filepath.Join(tempDir, "chain-client.key")
		chainServerCertPath := filepath.Join(tempDir, "chain-server.crt")
		chainServerKeyPath := filepath.Join(tempDir, "chain-server.key")

		if err := os.WriteFile(chainClientCertPath, chainCredentials.ClientCert.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain client cert: %v", err)
		}
		if err := os.WriteFile(chainClientKeyPath, chainCredentials.ClientKey.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain client key: %v", err)
		}
		if err := os.WriteFile(chainServerCertPath, chainCredentials.ServerCert.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain server cert: %v", err)
		}
		if err := os.WriteFile(chainServerKeyPath, chainCredentials.ServerKey.Bytes(), 0600); err != nil {
			t.Fatalf("Failed to write chain server key: %v", err)
		}

		// Now test verification against the CA
		// Load the client certificate
		chainClientCert, err := inspect.LoadCertificateFromFile(chainClientCertPath)
		if err != nil {
			t.Fatalf("Failed to load chain client certificate: %v", err)
		}

		// Verify against the CA
		clientResult, err := inspect.VerifySignedBy(chainClientCert, chainCAPath)
		if err != nil {
			t.Fatalf("Chain client verification error: %v", err)
		}

		if !clientResult.IsValid {
			t.Errorf("Expected chain client certificate to be verified by CA: %v", clientResult.Error)
		}

		// Load and verify the server certificate too
		chainServerCert, err := inspect.LoadCertificateFromFile(chainServerCertPath)
		if err != nil {
			t.Fatalf("Failed to load chain server certificate: %v", err)
		}

		serverResult, err := inspect.VerifySignedBy(chainServerCert, chainCAPath)
		if err != nil {
			t.Fatalf("Chain server verification error: %v", err)
		}

		if !serverResult.IsValid {
			t.Errorf("Expected chain server certificate to be verified by CA: %v", serverResult.Error)
		}

		// Verify certificate info
		clientCertInfo := inspect.ParseCertificateInfo(chainClientCert)
		if !sliceContains(clientCertInfo.DNSNames, "chain-test.com") {
			t.Errorf("Chain client certificate is missing expected DNS name")
		}

		if !stringContains(clientCertInfo.Subject, "Chain Test Org") {
			t.Errorf("Chain client certificate subject does not contain expected organization")
		}

		// Verify client certificate has correct key usage
		if !sliceContains(clientCertInfo.ExtKeyUsage, "ClientAuth") {
			t.Errorf("Chain client certificate should have ClientAuth extended key usage")
		}

		// Verify server certificate has correct key usage
		serverCertInfo := inspect.ParseCertificateInfo(chainServerCert)
		if !sliceContains(serverCertInfo.ExtKeyUsage, "ServerAuth") {
			t.Errorf("Chain server certificate should have ServerAuth extended key usage")
		}
	})

	// Test FormatDuration
	t.Run("FormatDuration", func(t *testing.T) {
		testCases := []struct {
			duration time.Duration
			expected string
		}{
			{10 * time.Second, "10s"},
			{65 * time.Second, "1m 5s"},
			{3665 * time.Second, "1h 1m 5s"},
			{90061 * time.Second, "1d 1h 1m 1s"},
		}

		for _, tc := range testCases {
			result := inspect.FormatDuration(tc.duration)
			if result != tc.expected {
				t.Errorf("FormatDuration(%v) = %s, expected %s", tc.duration, result, tc.expected)
			}
		}
	})

	// Test key usage formatting
	t.Run("FormatKeyUsage", func(t *testing.T) {
		usages := inspect.FormatKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign)
		if !sliceContains(usages, "DigitalSignature") || !sliceContains(usages, "CertSign") {
			t.Errorf("Key usage formatting failed: %v", usages)
		}
	})

	// Test extended key usage formatting
	t.Run("FormatExtKeyUsage", func(t *testing.T) {
		usages := inspect.FormatExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		if !sliceContains(usages, "ServerAuth") || !sliceContains(usages, "ClientAuth") {
			t.Errorf("Extended key usage formatting failed: %v", usages)
		}
	})
}

// Helper function to check if a string slice contains a specific string
func sliceContains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// Helper function to check if a string contains a substring
func stringContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
