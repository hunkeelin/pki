package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func main() {
	crtname := "test1.klin-pro.com"

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	keyOut, err := os.OpenFile(crtname+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Print("written key\n")

	subj := pkix.Name{
		CommonName:         crtname,
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"KLIN-PRO"},
		OrganizationalUnit: []string{"IT"},
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	template.DNSNames = append(template.DNSNames, "test1.klin-pro.com")
	template.EmailAddresses = append(template.EmailAddresses, "support@klin-pro.com")
	csrOut, err := os.Create(crtname + ".csr")
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

}
