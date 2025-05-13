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

package cli

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	inputDir         string
	clientCertPath   string
	serverCertPath   string
	verifySignedByCA string
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect TLS certificates",
	Long:  `Inspect TLS certificates to view expiry, SANs, and other details.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize an empty map of certificates to inspect
		certFiles := make(map[string]string)

		// Add certificates based on provided flags
		if caCertPath != "" {
			certFiles["CA"] = caCertPath
		} else {
			// Default CA path if not specified
			defaultCAPath := filepath.Join(inputDir, "ca.crt")
			if _, err := os.Stat(defaultCAPath); !os.IsNotExist(err) {
				certFiles["CA"] = defaultCAPath
			}
		}

		// Only add client certificate if specified
		if clientCertPath != "" {
			certFiles["Client"] = clientCertPath
		}

		// Only add server certificate if specified
		if serverCertPath != "" {
			certFiles["Server"] = serverCertPath
		}

		// If no certificates were specified, inform the user
		if len(certFiles) == 0 {
			fmt.Println("No certificates specified for inspection. Use --ca, --client, or --server flags to specify certificates.")
			return
		}

		// Inspect each specified certificate
		for certType, certPath := range certFiles {
			// Check if the certificate file exists
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				fmt.Printf("Certificate file not found: %s\n", certPath)
				continue
			}

			// Read and parse the certificate
			certData, err := os.ReadFile(certPath)
			if err != nil {
				fmt.Printf("Error reading certificate %s: %v\n", certPath, err)
				continue
			}

			// Parse the PEM data
			block, _ := pem.Decode(certData)
			if block == nil {
				fmt.Printf("Failed to decode PEM block from %s\n", certPath)
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Printf("Error parsing certificate %s: %v\n", certPath, err)
				continue
			}

			// Print certificate information
			fmt.Printf("\n=== Certificate Details: %s (%s) ===\n", certType, certPath)

			// Basic information
			fmt.Printf("Subject: %s\n", cert.Subject)
			fmt.Printf("Issuer: %s\n", cert.Issuer)
			fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
			fmt.Printf("Version: %d\n", cert.Version)

			// Validity period
			fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
			fmt.Printf("Not After: %s\n", cert.NotAfter.Format(time.RFC3339))

			// Time until expiry
			timeUntilExpiry := cert.NotAfter.Sub(time.Now())
			if timeUntilExpiry > 0 {
				fmt.Printf("Expires in: %s\n", formatDuration(timeUntilExpiry))
			} else {
				fmt.Printf("Expired: %s ago\n", formatDuration(-timeUntilExpiry))
			}

			// Is it a CA?
			fmt.Printf("Is CA: %t\n", cert.IsCA)

			// Key Usage
			fmt.Printf("Key Usage: %v\n", formatKeyUsage(cert.KeyUsage))

			// Extended Key Usage
			if len(cert.ExtKeyUsage) > 0 {
				fmt.Printf("Extended Key Usage: %v\n", formatExtKeyUsage(cert.ExtKeyUsage))
			}

			// Subject Alternative Names (SANs)
			if len(cert.DNSNames) > 0 {
				fmt.Printf("DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
			}

			// IP addresses
			if len(cert.IPAddresses) > 0 {
				ips := make([]string, len(cert.IPAddresses))
				for i, ip := range cert.IPAddresses {
					ips[i] = ip.String()
				}
				fmt.Printf("IP Addresses: %s\n", strings.Join(ips, ", "))
			}

			// Public key algorithm
			fmt.Printf("Public Key Algorithm: %v\n", cert.PublicKeyAlgorithm)

			// Signature algorithm
			fmt.Printf("Signature Algorithm: %v\n", cert.SignatureAlgorithm)

			// Check if we need to verify if this certificate is signed by a specific CA
			if verifySignedByCA != "" {
				// Read and parse the CA certificate
				caCertData, err := os.ReadFile(verifySignedByCA)
				if err != nil {
					fmt.Printf("Error reading CA certificate for verification: %v\n", err)
				} else {
					// Parse the CA PEM data
					caBlock, _ := pem.Decode(caCertData)
					if caBlock == nil {
						fmt.Printf("Failed to decode CA PEM block\n")
					} else {
						caCert, err := x509.ParseCertificate(caBlock.Bytes)
						if err != nil {
							fmt.Printf("Error parsing CA certificate: %v\n", err)
						} else {
							// Create a certificate pool and add the CA certificate
							roots := x509.NewCertPool()
							roots.AddCert(caCert)

							// Verify the certificate against the CA
							opts := x509.VerifyOptions{
								Roots: roots,
								// For client certs, we need to specify ClientAuth
								KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
							}

							if _, err := cert.Verify(opts); err != nil {
								fmt.Printf("\033[31mVerification FAILED: Certificate is NOT signed by the specified CA: %v\033[0m\n", err)
							} else {
								fmt.Printf("\033[32mVerification SUCCESS: Certificate is signed by the specified CA\033[0m\n")
								// If cert and CA match, calculate and show remaining time in CA's validity period
								caTimeUntilExpiry := caCert.NotAfter.Sub(time.Now())
								if caTimeUntilExpiry > 0 {
									fmt.Printf("CA Certificate expires in: %s\n", formatDuration(caTimeUntilExpiry))
								} else {
									fmt.Printf("\033[31mWARNING: CA Certificate is EXPIRED: %s ago\033[0m\n", formatDuration(-caTimeUntilExpiry))
								}
							}
						}
					}
				}
			}
		}
	},
}

// Helper function to format duration in a human-readable way
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Helper function to format key usage
func formatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return usages
}

// Helper function to format extended key usage
func formatExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var usages []string

	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", u))
		}
	}

	return usages
}

func init() {
	// Define flags for the inspect command
	inspectCmd.Flags().StringVar(&inputDir, "inputdir", "./", "directory containing certificates to inspect")
	inspectCmd.Flags().StringVar(&caCertPath, "ca", "", "path to CA certificate (defaults to inputdir/ca.crt if not specified)")
	inspectCmd.Flags().StringVar(&clientCertPath, "client", "", "path to client certificate (optional)")
	inspectCmd.Flags().StringVar(&serverCertPath, "server", "", "path to server certificate (optional)")
	inspectCmd.Flags().StringVar(&verifySignedByCA, "verify-signed-by", "", "verify if certificate is signed by the specified CA certificate")
}
