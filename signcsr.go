package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// SignCsrInput the input of the function
type SignCsrInput struct {
	CaCert    []byte // CaCert
	CaKey     []byte // CaKey
	Csr       []byte // Csr the certficiate request to sign
	IsCa      bool   // IsCa whether to sign the certificate as Certificate authority
	ValidDays int    // ValidDays
}

// SignCsrOutput output of the function
type SignCsrOutput struct {
	Cert []byte
}

// SignCsr signs CSR
func SignCsr(g SignCsrInput) (SignCsrOutput, error) {
	if g.CaCert == nil || g.CaKey == nil {
		return SignCsrOutput{}, fmt.Errorf("Please specify CA certs and key")
	}

	// Decode and Parse CA Cert
	certDecoded, _ := pem.Decode(g.CaCert)
	caCert, err := x509.ParseCertificate(certDecoded.Bytes)
	if err != nil {
		return SignCsrOutput{}, err
	}

	// Decode and Parse CA Key
	keyDecoded, _ := pem.Decode(g.CaKey)
	caKey, err := x509.ParsePKCS1PrivateKey(keyDecoded.Bytes)
	if err != nil {
		return SignCsrOutput{}, err
	}

	// Decode and Parse Csr
	csrDecoded, _ := pem.Decode(g.Csr)
	clientCsr, err := x509.ParseCertificateRequest(csrDecoded.Bytes)
	if err != nil {
		return SignCsrOutput{}, err
	}
	if err = clientCsr.CheckSignature(); err != nil {
		return SignCsrOutput{}, err
	}

	// Create the client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCsr.Signature,
		SignatureAlgorithm: clientCsr.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCsr.PublicKeyAlgorithm,
		PublicKey:          clientCsr.PublicKey,

		SerialNumber:          big.NewInt(2),
		Issuer:                caCert.Subject,
		Subject:               clientCsr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(g.ValidDays*24) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		DNSNames:              clientCsr.DNSNames,
		EmailAddresses:        clientCsr.EmailAddresses,
		BasicConstraintsValid: g.IsCa,
		IsCA:                  g.IsCa,
	}
	if g.IsCa {
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		clientCRTTemplate.KeyUsage |= x509.KeyUsageCertSign
	}
	clientCert, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCert, clientCsr.PublicKey, caKey)
	if err != nil {
		return SignCsrOutput{}, err
	}
	fmt.Println("fuckyou")
	fmt.Println(clientCert)
	return SignCsrOutput{
		Cert: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert}), g.CaCert...),
	}, nil
}
