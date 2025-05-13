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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/footprintai/go-certs/pkg/certs"
	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	"github.com/spf13/cobra"
)

var (
	certValidDuration time.Duration
	outputDir         string
	organization      string
	dns               string
	ips               string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate TLS certificates",
	Long:  `Generate TLS certificates including CA, client, and server certificates.`,
	Run: func(cmd *cobra.Command, args []string) {
		notBefore := time.Now()
		notAfter := notBefore.Add(certValidDuration)

		// Create the output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Fatal(err)
		}

		// Check if existing CA cert and key are provided
		if (caCertPath != "") != (caKeyPath != "") {
			log.Fatal("Both CA certificate and CA key must be provided together, or neither")
		}

		var credentials *certs.TLSCredentials
		var err error

		if caCertPath != "" && caKeyPath != "" {
			// Use existing CA to generate certificates
			fmt.Printf("Using existing CA from %s to generate certificates with duration: %+v to dir=%s\n",
				caCertPath, certValidDuration, outputDir)

			// Read CA cert and key
			caCert, err := os.ReadFile(caCertPath)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}

			caKey, err := os.ReadFile(caKeyPath)
			if err != nil {
				log.Fatalf("Failed to read CA key: %v", err)
			}

			// Generate certificates using the existing CA
			credentials, err = certsgen.GenerateWithExistingCA(
				caCert,
				caKey,
				notBefore,
				notAfter,
				certsgen.WithOrganizations(organization),
				certsgen.WithAliasDNSNames(strings.Split(dns, ",")...),
				certsgen.WithAliasIPs(strings.Split(ips, ",")...),
			)
			if err != nil {
				log.Fatalf("Failed to generate certificates: %v", err)
			}
		} else {
			// Generate a new CA and certificates
			fmt.Printf("Generate certificates between %v -> %v with duration: %+v to dir=%s\n",
				notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), certValidDuration, outputDir)

			credentials, err = certsgen.NewTLSCredentials(
				notBefore,
				notAfter,
				certsgen.WithOrganizations(organization),
				certsgen.WithAliasDNSNames(strings.Split(dns, ",")...),
				certsgen.WithAliasIPs(strings.Split(ips, ",")...),
			)
			if err != nil {
				log.Fatalf("Failed to generate certificates: %v", err)
			}
		}

		// Write certificates and keys to files
		if err := os.WriteFile(filepath.Join(outputDir, "ca.crt"), credentials.CACert.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "ca.key"), credentials.CAKey.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "client.crt"), credentials.ClientCert.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "client.key"), credentials.ClientKey.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "server.crt"), credentials.ServerCert.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "server.key"), credentials.ServerKey.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Certificates successfully generated!")
	},
}

func init() {
	// Define flags for the generate command
	generateCmd.Flags().DurationVar(&certValidDuration, "duration", 24*time.Hour, "valid duration for certificates")
	generateCmd.Flags().StringVar(&outputDir, "outputdir", "./", "output directory")
	generateCmd.Flags().StringVar(&organization, "org", "Footprint-AI", "organization")
	generateCmd.Flags().StringVar(&dns, "dns", "localhost", "dns, delimited by comma")
	generateCmd.Flags().StringVar(&ips, "ips", "127.0.0.1", "ips, delimited by comma")
	generateCmd.Flags().StringVar(&caCertPath, "ca-cert", "", "path to existing CA certificate (if not specified, a new CA will be generated)")
	generateCmd.Flags().StringVar(&caKeyPath, "ca-key", "", "path to existing CA key (required if ca-cert is specified)")
}
