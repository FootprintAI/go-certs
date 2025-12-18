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

package certsgen

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpenSSLVerification tests that generated certificates can be verified by OpenSSL
func TestOpenSSLVerification(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping test")
	}

	// Create a temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "certs-openssl-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	credentials, err := NewTLSCredentials(
		notBefore,
		notAfter,
		WithOrganizations("Footprint-AI"),
		WithAliasDNSNames("management-server", "inference-server"),
		WithAliasIPs("192.168.1.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials: %v", err)
	}

	// Write certificates to temp directory
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")
	serverCertPath := filepath.Join(tempDir, "server.crt")
	serverKeyPath := filepath.Join(tempDir, "server.key")
	clientCertPath := filepath.Join(tempDir, "client.crt")
	clientKeyPath := filepath.Join(tempDir, "client.key")

	if err := os.WriteFile(caCertPath, credentials.CACert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(caKeyPath, credentials.CAKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}
	if err := os.WriteFile(serverCertPath, credentials.ServerCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyPath, credentials.ServerKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server key: %v", err)
	}
	if err := os.WriteFile(clientCertPath, credentials.ClientCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, credentials.ClientKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write client key: %v", err)
	}

	// Test 1: Verify server certificate against CA using OpenSSL
	t.Run("VerifyServerCertWithOpenSSL", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, serverCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of server cert failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Server cert verification output: %s", string(output))
		}
	})

	// Test 2: Verify client certificate against CA using OpenSSL
	t.Run("VerifyClientCertWithOpenSSL", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, clientCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of client cert failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Client cert verification output: %s", string(output))
		}
	})

	// Test 3: Check that CA certificate is valid and self-signed
	t.Run("VerifyCACertIsSelfSigned", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, caCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of CA cert (self-signed) failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("CA cert verification output: %s", string(output))
		}
	})

	// Test 4: Inspect server certificate details
	t.Run("InspectServerCertWithOpenSSL", func(t *testing.T) {
		cmd := exec.Command("openssl", "x509", "-in", serverCertPath, "-text", "-noout")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL inspect of server cert failed: %v\nOutput: %s", err, string(output))
		} else {
			outputStr := string(output)
			t.Logf("Server cert details:\n%s", outputStr)

			// Check for expected SANs
			if !strings.Contains(outputStr, "DNS:localhost") {
				t.Errorf("Server cert missing DNS:localhost SAN")
			}
			if !strings.Contains(outputStr, "DNS:management-server") {
				t.Errorf("Server cert missing DNS:management-server SAN")
			}
			if !strings.Contains(outputStr, "IP Address:127.0.0.1") {
				t.Errorf("Server cert missing IP:127.0.0.1 SAN")
			}
		}
	})

	// Test 5: Inspect CA certificate details
	t.Run("InspectCACertWithOpenSSL", func(t *testing.T) {
		cmd := exec.Command("openssl", "x509", "-in", caCertPath, "-text", "-noout")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL inspect of CA cert failed: %v\nOutput: %s", err, string(output))
		} else {
			outputStr := string(output)
			t.Logf("CA cert details:\n%s", outputStr)

			// Check that CA has CA:TRUE
			if !strings.Contains(outputStr, "CA:TRUE") {
				t.Errorf("CA cert should have CA:TRUE in Basic Constraints")
			}
		}
	})

	// Test 6: Verify the certificate chain
	t.Run("VerifyCertChainWithOpenSSL", func(t *testing.T) {
		// Create a certificate chain file
		chainPath := filepath.Join(tempDir, "chain.pem")
		chainContent := append(credentials.ServerCert.Bytes(), credentials.CACert.Bytes()...)
		if err := os.WriteFile(chainPath, chainContent, 0600); err != nil {
			t.Fatalf("Failed to write chain file: %v", err)
		}

		// Verify using partial chain (allows intermediate verification)
		cmd := exec.Command("openssl", "verify", "-partial_chain", "-CAfile", caCertPath, serverCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL partial chain verification failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Partial chain verification output: %s", string(output))
		}
	})

	// Test 7: Verify key matches certificate
	t.Run("VerifyServerKeyMatchesCert", func(t *testing.T) {
		// Get modulus of certificate
		cmdCert := exec.Command("openssl", "x509", "-in", serverCertPath, "-noout", "-modulus")
		certModulus, err := cmdCert.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to get cert modulus: %v\nOutput: %s", err, string(certModulus))
		}

		// Get modulus of key
		cmdKey := exec.Command("openssl", "rsa", "-in", serverKeyPath, "-noout", "-modulus")
		keyModulus, err := cmdKey.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to get key modulus: %v\nOutput: %s", err, string(keyModulus))
		}

		if string(certModulus) != string(keyModulus) {
			t.Errorf("Server key does not match certificate\nCert modulus: %s\nKey modulus: %s", string(certModulus), string(keyModulus))
		}
	})
}

// TestOpenSSLVerificationWithExistingCA tests certificates generated with an existing CA
func TestOpenSSLVerificationWithExistingCA(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping test")
	}

	// Create a temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "certs-openssl-existing-ca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// First, generate a CA using our library
	caNotBefore := time.Now()
	caNotAfter := caNotBefore.Add(365 * 24 * time.Hour) // 1 year

	caCredentials, err := NewTLSCredentials(
		caNotBefore,
		caNotAfter,
		WithOrganizations("Test CA"),
	)
	if err != nil {
		t.Fatalf("Failed to generate CA credentials: %v", err)
	}

	// Now generate new server/client certs using the existing CA
	certNotBefore := time.Now()
	certNotAfter := certNotBefore.Add(14 * 24 * time.Hour) // 14 days

	credentials, err := GenerateWithExistingCA(
		caCredentials.CACert.Bytes(),
		caCredentials.CAKey.Bytes(),
		certNotBefore,
		certNotAfter,
		WithOrganizations("Footprint-AI"),
		WithAliasDNSNames("management-server", "inference-server"),
		WithAliasIPs("192.168.1.1"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials with existing CA: %v", err)
	}

	// Write certificates to temp directory
	caCertPath := filepath.Join(tempDir, "ca.crt")
	serverCertPath := filepath.Join(tempDir, "server.crt")
	clientCertPath := filepath.Join(tempDir, "client.crt")

	if err := os.WriteFile(caCertPath, credentials.CACert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(serverCertPath, credentials.ServerCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert: %v", err)
	}
	if err := os.WriteFile(clientCertPath, credentials.ClientCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write client cert: %v", err)
	}

	// Verify server certificate against CA
	t.Run("VerifyServerCertWithExistingCA", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, serverCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of server cert (existing CA) failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Server cert verification output: %s", string(output))
		}
	})

	// Verify client certificate against CA
	t.Run("VerifyClientCertWithExistingCA", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, clientCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of client cert (existing CA) failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Client cert verification output: %s", string(output))
		}
	})
}

// TestOpenSSLGeneratedCACompatibility tests that we can use an OpenSSL-generated CA
func TestOpenSSLGeneratedCACompatibility(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping test")
	}

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "certs-openssl-ca-compat-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")

	// Generate CA private key using OpenSSL (use -traditional to output PKCS#1 format)
	cmdKey := exec.Command("openssl", "genrsa", "-traditional", "-out", caKeyPath, "4096")
	if output, err := cmdKey.CombinedOutput(); err != nil {
		// Fall back to older OpenSSL version without -traditional flag
		cmdKey = exec.Command("openssl", "genrsa", "-out", caKeyPath, "4096")
		if output, err = cmdKey.CombinedOutput(); err != nil {
			t.Fatalf("Failed to generate CA key with OpenSSL: %v\nOutput: %s", err, string(output))
		}
	}

	// Generate CA certificate using OpenSSL
	cmdCert := exec.Command("openssl", "req", "-x509", "-new", "-nodes",
		"-key", caKeyPath,
		"-sha256",
		"-days", "365",
		"-out", caCertPath,
		"-subj", "/O=OpenSSL-Test-CA")
	if output, err := cmdCert.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate CA cert with OpenSSL: %v\nOutput: %s", err, string(output))
	}

	// Read the OpenSSL-generated CA
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("Failed to read CA key: %v", err)
	}

	// Generate certificates using our library with the OpenSSL CA
	certNotBefore := time.Now()
	certNotAfter := certNotBefore.Add(14 * 24 * time.Hour)

	credentials, err := GenerateWithExistingCA(
		caCertPEM,
		caKeyPEM,
		certNotBefore,
		certNotAfter,
		WithOrganizations("Footprint-AI"),
		WithAliasDNSNames("management-server", "inference-server"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials with OpenSSL CA: %v", err)
	}

	// Write server certificate
	serverCertPath := filepath.Join(tempDir, "server.crt")
	if err := os.WriteFile(serverCertPath, credentials.ServerCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert: %v", err)
	}

	// Verify server certificate against OpenSSL-generated CA
	t.Run("VerifyGoGeneratedCertAgainstOpenSSLCA", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, serverCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Verification output: %s", string(output))
		}
	})
}

// TestCrossVerification tests that Go's crypto/x509 can verify OpenSSL certs and vice versa
func TestCrossVerification(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH, skipping test")
	}

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "certs-cross-verify-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate certificates using Go
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	credentials, err := NewTLSCredentials(
		notBefore,
		notAfter,
		WithOrganizations("Cross-Verify-Test"),
		WithAliasDNSNames("test.example.com"),
	)
	if err != nil {
		t.Fatalf("Failed to generate credentials: %v", err)
	}

	// Write all certificates
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")
	serverCertPath := filepath.Join(tempDir, "server.crt")
	serverKeyPath := filepath.Join(tempDir, "server.key")

	if err := os.WriteFile(caCertPath, credentials.CACert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(caKeyPath, credentials.CAKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}
	if err := os.WriteFile(serverCertPath, credentials.ServerCert.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyPath, credentials.ServerKey.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server key: %v", err)
	}

	// Generate an OpenSSL server cert using our Go CA
	opensslServerCertPath := filepath.Join(tempDir, "openssl-server.crt")
	opensslServerKeyPath := filepath.Join(tempDir, "openssl-server.key")
	opensslServerCSRPath := filepath.Join(tempDir, "openssl-server.csr")
	extFilePath := filepath.Join(tempDir, "server-ext.cnf")

	// Generate OpenSSL server key
	cmdKey := exec.Command("openssl", "genrsa", "-out", opensslServerKeyPath, "4096")
	if output, err := cmdKey.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate OpenSSL server key: %v\nOutput: %s", err, string(output))
	}

	// Generate CSR
	cmdCSR := exec.Command("openssl", "req", "-new",
		"-key", opensslServerKeyPath,
		"-out", opensslServerCSRPath,
		"-subj", "/O=Footprint-AI")
	if output, err := cmdCSR.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate CSR: %v\nOutput: %s", err, string(output))
	}

	// Create extension file for SANs
	extContent := "subjectAltName = DNS:localhost,DNS:openssl-server,IP:127.0.0.1"
	if err := os.WriteFile(extFilePath, []byte(extContent), 0600); err != nil {
		t.Fatalf("Failed to write ext file: %v", err)
	}

	// Sign the CSR with our Go CA
	cmdSign := exec.Command("openssl", "x509", "-req",
		"-in", opensslServerCSRPath,
		"-CA", caCertPath,
		"-CAkey", caKeyPath,
		"-CAcreateserial",
		"-out", opensslServerCertPath,
		"-days", "14",
		"-extfile", extFilePath)
	if output, err := cmdSign.CombinedOutput(); err != nil {
		t.Fatalf("Failed to sign cert with Go CA: %v\nOutput: %s", err, string(output))
	}

	// Verify the OpenSSL-generated cert against our Go CA using OpenSSL
	t.Run("VerifyOpenSSLCertAgainstGoCA", func(t *testing.T) {
		cmd := exec.Command("openssl", "verify", "-CAfile", caCertPath, opensslServerCertPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("OpenSSL verification of OpenSSL cert against Go CA failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Verification output: %s", string(output))
		}
	})
}
