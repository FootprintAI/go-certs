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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/footprintai/go-certs/pkg/certs"
)

// Keep all the original template option code
type templateOption interface {
	apply(o *Option)
}

type Option struct {
	organizations []string
	aliasDNSNames []string
	aliasIPs      []net.IP
}

type organizationOption struct {
	organizations []string
}

var (
	_ templateOption = organizationOption{}
)

func (o organizationOption) apply(t *Option) {
	t.organizations = o.organizations
}

func WithOrganizations(organizations ...string) organizationOption {
	return organizationOption{organizations: organizations}
}

type aliasDNSNamesOption struct {
	aliasDNSNames []string
}

var (
	_ templateOption = aliasDNSNamesOption{}
)

func (o aliasDNSNamesOption) apply(t *Option) {
	t.aliasDNSNames = o.aliasDNSNames
}

func WithAliasDNSNames(aliasDNSNames ...string) aliasDNSNamesOption {
	return aliasDNSNamesOption{aliasDNSNames: aliasDNSNames}
}

type aliasIPsOption struct {
	aliasIPs []net.IP
}

var (
	_ templateOption = aliasIPsOption{}
)

func (o aliasIPsOption) apply(t *Option) {
	t.aliasIPs = o.aliasIPs
}

func WithAliasIPs(aliasIPs ...string) aliasIPsOption {
	var parsed []net.IP
	for _, aliasIP := range aliasIPs {
		if aliasIP == "" {
			continue
		}
		ip := net.ParseIP(aliasIP)
		if ip == nil {
			continue
		}
		parsed = append(parsed, ip)
	}
	return aliasIPsOption{aliasIPs: parsed}
}

// CertTemplate is a helper function to create a cert template with a serial number and other required fields
func CertTemplate(notBefore, notAfter time.Time, opts ...templateOption) (*x509.Certificate, error) {
	o := &Option{}
	for _, opt := range opts {
		opt.apply(o)
	}

	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	// Ensure localhost and 127.0.0.1 are always included
	dnsNames := append([]string{"localhost"}, o.aliasDNSNames...)
	ipAddresses := append([]net.IP{net.ParseIP("127.0.0.1")}, o.aliasIPs...)
	
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: o.organizations},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter, // valid for a month
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	return &tmpl, nil
}

// CreateCert invokes x509.CreateCertificate and returns it in the x509.Certificate format
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// NewTLSCredentials creates signed certificates for both the client and server
// Returns CA cert, CA key, client cert, client key, server cert, server key in a TLSCredentials struct
func NewTLSCredentials(notBefore, notAfter time.Time, opts ...templateOption) (*certs.TLSCredentials, error) {
	// generate a new key-pair
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}

	// Build CA template without SANs/ExtKeyUsage (those are leaf cert properties)
	o := &Option{}
	for _, opt := range opts {
		opt.apply(o)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	caOrgs := o.organizations
	if len(caOrgs) > 0 {
		orgs := make([]string, len(caOrgs))
		for i, org := range caOrgs {
			orgs[i] = org + " CA"
		}
		caOrgs = orgs
	} else {
		caOrgs = []string{"Root CA"}
	}

	rootCertTmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: caOrgs},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootCert, rootCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cert: %w", err)
	}

	// encode the CA private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	/*******************************************************************
	  Server Cert
	  *******************************************************************/

	// create a key-pair for the server
	servKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}

	// create a template for the server
	servCertTmpl, err := CertTemplate(notBefore, notAfter, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating cert template: %w", err)
	}
	servCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	servCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	// Set AuthorityKeyId to link this certificate to the CA - required for OpenSSL verification
	servCertTmpl.AuthorityKeyId = rootCert.SubjectKeyId

	// create a certificate which wraps the server's public key, sign it with the root private key
	_, servCertPEM, err := CreateCert(servCertTmpl, rootCert, &servKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cert: %w", err)
	}

	// provide the private key and the cert
	servKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
	})

	/*******************************************************************
	  Client Cert
	  *******************************************************************/

	// create a key-pair for the client
	clientKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}

	// create a template for the client
	clientCertTmpl, err := CertTemplate(notBefore, notAfter, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating cert template: %w", err)
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	// Set AuthorityKeyId to link this certificate to the CA - required for OpenSSL verification
	clientCertTmpl.AuthorityKeyId = rootCert.SubjectKeyId

	// the root cert signs the cert by again providing its private key
	_, clientCertPEM, err := CreateCert(clientCertTmpl, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cert: %w", err)
	}

	// encode and load the cert and private key for the client
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	// Return all PEM data in a strongly typed struct
	return &certs.TLSCredentials{
		CACert:     certs.CACert(rootCertPEM),
		CAKey:      certs.CAKey(rootKeyPEM),
		ClientCert: certs.ClientCert(clientCertPEM),
		ClientKey:  certs.ClientKey(clientKeyPEM),
		ServerCert: certs.ServerCert(servCertPEM),
		ServerKey:  certs.ServerKey(servKeyPEM),
	}, nil
}

