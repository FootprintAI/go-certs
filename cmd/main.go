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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	certsgen "github.com/footprintai/go-certs/pkg/certs/gen"
	version "github.com/footprintai/go-certs/pkg/version"
)

var (
	certValidDuration time.Duration
	outputDir         string
	organization      string
	dns               string
	ips               string
)

func init() {
	flag.DurationVar(&certValidDuration, "duration", 24*time.Hour, "valid duration for certificates")
	flag.StringVar(&outputDir, "outputdir", "./", "output dir")
	flag.StringVar(&organization, "org", "Footprint-AI", "organization")
	flag.StringVar(&dns, "dns", "localhost", "dns, delimitered by comma")
	flag.StringVar(&ips, "ips", "127.0.0.1", "ips, delimitered by comma")
}

func main() {
	flag.Parse()

	version.Print()

	notBefore := time.Now()
	notAfter := notBefore.Add(certValidDuration)
	fmt.Printf("generate certificates between %v -> %v with duration: %+v\n", notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), certValidDuration)

	ca, clientCert, clientKey, serverCert, serverKey := certsgen.NewTLSCredentials(
		notBefore,
		notAfter,
		certsgen.WithOrganizations(organization),
		certsgen.WithAliasDNSNames(strings.Split(dns, ",")...),
		certsgen.WithAliasIPs(strings.Split(ips, ",")...),
	)
	if err := os.WriteFile(filepath.Join(outputDir, "ca.crt"), ca, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "client.crt"), clientCert, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "client.key"), clientKey, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "server.crt"), serverCert, 0600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "server.key"), serverKey, 0600); err != nil {
		log.Fatal(err)
	}

}
