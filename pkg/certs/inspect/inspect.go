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

package inspect

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertificateInfo contains parsed certificate details
type CertificateInfo struct {
	Certificate     *x509.Certificate
	NotBefore       time.Time
	NotAfter        time.Time
	IsCA            bool
	Subject         string
	Issuer          string
	SerialNumber    string
	DNSNames        []string
	IPAddresses     []string
	KeyUsage        []string
	ExtKeyUsage     []string
	SignatureAlgo   string
	TimeUntilExpiry time.Duration
	IsExpired       bool
}

// VerificationResult contains the result of certificate verification
type VerificationResult struct {
	IsValid           bool
	Error             error
	CACertInfo        *CertificateInfo
	VerifiedChains    [][]*x509.Certificate
	CATimeUntilExpiry time.Duration
	IsCAExpired       bool
}

// LoadCertificateFromFile loads and parses a certificate from a file
func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	// Read certificate file
	certData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Parse PEM data
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// ParseCertificateInfo extracts detailed information from a certificate
func ParseCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	// Create certificate info struct
	info := &CertificateInfo{
		Certificate:   cert,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		IsCA:          cert.IsCA,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		DNSNames:      cert.DNSNames,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Parse key usage
	info.KeyUsage = FormatKeyUsage(cert.KeyUsage)

	// Parse extended key usage
	info.ExtKeyUsage = FormatExtKeyUsage(cert.ExtKeyUsage)

	// Calculate time until expiry
	info.TimeUntilExpiry = cert.NotAfter.Sub(time.Now())
	info.IsExpired = info.TimeUntilExpiry < 0

	return info
}

// VerifySignedBy checks if a certificate is signed by a specific CA certificate
func VerifySignedBy(cert *x509.Certificate, caCertPath string) (*VerificationResult, error) {
	result := &VerificationResult{
		IsValid: false,
	}

	// Load and parse the CA certificate
	caCert, err := LoadCertificateFromFile(caCertPath)
	if err != nil {
		return result, fmt.Errorf("failed to load CA certificate: %v", err)
	}

	// Parse CA certificate info
	result.CACertInfo = ParseCertificateInfo(caCert)

	// Calculate CA expiry information directly
	result.CATimeUntilExpiry = caCert.NotAfter.Sub(time.Now())
	result.IsCAExpired = result.CATimeUntilExpiry < 0

	// Create a certificate pool and add the CA certificate
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify the certificate against the CA
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		result.Error = err
		return result, nil // Return nil for the error since it's part of the result
	}

	// Verification succeeded
	result.IsValid = true
	result.VerifiedChains = chains

	return result, nil
}

// FormatDuration formats a duration in a human-readable format
func FormatDuration(d time.Duration) string {
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

// FormatKeyUsage formats x509.KeyUsage into a string slice
func FormatKeyUsage(ku x509.KeyUsage) []string {
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

// FormatExtKeyUsage formats x509.ExtKeyUsage into a string slice
func FormatExtKeyUsage(eku []x509.ExtKeyUsage) []string {
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
