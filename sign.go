package klinpki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

func SignCSRv2(crtpath, keypath string, csrBytes []byte, days float64) ([]byte, error) {
	// load CA key pair
	//      public key
	var clientCRTRaw []byte
	caPublicKeyFile, err := ioutil.ReadFile(crtpath)
	if err != nil {
		return clientCRTRaw, err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return clientCRTRaw, err
	}

	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile(keypath)
	if err != nil {
		return clientCRTRaw, err
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	der := pemBlock.Bytes
	//	der, err := x509.DecryptPEMBlock(pemBlock, []byte("shit"))
	//	if err != nil {
	//		return clientCRTRaw,err
	//	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return clientCRTRaw, err
	}

	// load client certificate request
	if err != nil {
		return clientCRTRaw, err
	}
	clientCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return clientCRTRaw, err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return clientCRTRaw, err
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(days*24) * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     clientCSR.DNSNames,
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return clientCRTRaw, err
	}

	// save the certificate
	return clientCRTRaw, nil
}
func SignCSR(crtpath, keypath, csrpath string, days float64) ([]byte, error) {
	// load CA key pair
	//      public key
	var clientCRTRaw []byte
	caPublicKeyFile, err := ioutil.ReadFile(crtpath)
	if err != nil {
		return clientCRTRaw, err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return clientCRTRaw, err
	}

	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile(keypath)
	if err != nil {
		return clientCRTRaw, err
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	der := pemBlock.Bytes
	//	der, err := x509.DecryptPEMBlock(pemBlock, []byte("shit"))
	//	if err != nil {
	//		return clientCRTRaw,err
	//	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return clientCRTRaw, err
	}

	// load client certificate request
	clientCSRFile, err := ioutil.ReadFile(csrpath)
	if err != nil {
		return clientCRTRaw, err
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return clientCRTRaw, err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return clientCRTRaw, err
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(days*24) * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     clientCSR.DNSNames,
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return clientCRTRaw, err
	}

	// save the certificate
	return clientCRTRaw, nil
}
