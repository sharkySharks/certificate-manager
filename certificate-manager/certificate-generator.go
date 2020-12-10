package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type Subject struct {
	Organization string `json:"organization"`
	Country      string `json:"country"`
	Locality     string `json:"locality"`
}

type CertificateOptions struct {
	Subject        *Subject `json:"subject"`
	ExpYearsLength int      `json:"expYearsLength"`
	Hosts          []string `json:"hosts"`
	isCA           bool     `json:"-"`
}

//TODO: store CA cert information in db for longer term storage
var (
	caCert               *x509.Certificate
	caPrivKey            *rsa.PrivateKey
	certificateAuthority = &CertificateOptions{
		isCA: true,
		Subject: &Subject{
			Organization: "Sharky's Certificate Authority",
			Country:      "US",
			Locality:     "Austin",
		},
		ExpYearsLength: 10,
	}
)

func generateCertificate(options *CertificateOptions) (*bytes.Buffer, *bytes.Buffer, error) {
	privateKey, err := createPrivateKey()
	if err != nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, fmt.Errorf("failed to generate serial number: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{options.Subject.Organization},
			Country:      []string{options.Subject.Country},
			Locality:     []string{options.Subject.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(options.ExpYearsLength, 0, 0),
		IsCA:                  options.isCA,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if options.isCA {
		cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		caCert = cert
		caPrivKey = privateKey
	} else {
		if caCert == nil || caPrivKey == nil {
			return &bytes.Buffer{}, &bytes.Buffer{}, fmt.Errorf("CA Certificate and CA Private Key must be generated first in order to sign non-CA certificates")
		}

		cert.KeyUsage = x509.KeyUsageDigitalSignature

		for _, h := range options.Hosts {
			if ip := net.ParseIP(h); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, h)
			}
		}
	}
	// sign the cert with the CA certificate
	certByte, err := x509.CreateCertificate(rand.Reader, cert, caCert, &privateKey.PublicKey, caPrivKey)
	if err != nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, err
	}

	//PEM encode
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certByte,
	})
	if err != nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, err
	}
	return certPEM, certPrivKeyPEM, nil
}

func createPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
