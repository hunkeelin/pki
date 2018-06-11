package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func main() {
	// load CA key pair
	//      public key
	caPublicKeyFile, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		panic(err)
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}

	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile("ca.key")
	if err != nil {
		panic(err)
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	der := pemBlock.Bytes
	//	der, err := x509.DecryptPEMBlock(pemBlock, []byte("shit"))
	//	if err != nil {
	//		panic(err)
	//	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		panic(err)
	}

	// load client certificate request
	clientCSRFile, err := ioutil.ReadFile("test1.klin-pro.com.csr")
	if err != nil {
		panic(err)
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		panic(err)
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
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     clientCSR.DNSNames,
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	// save the certificate
	clientCRTFile, err := os.Create("test1.klin-pro.com.crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile.Close()
}
