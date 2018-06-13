package klinpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"os"
)

func GenCSRv2(rsaBits int) (*pem.Block, *pem.Block) {
	hname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		panic(err)
	}
	subj := pkix.Name{
		CommonName:         hname,
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"KCA"},
		OrganizationalUnit: []string{"IT"},
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	template.DNSNames = append(template.DNSNames, hname)
	template.EmailAddresses = append(template.EmailAddresses, "support@klin-pro.com")
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	return &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}, pemBlockForKey(priv)
}

// original
func GenCSR(rsaBits int, keypath, csrpath string) {
	hname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		panic(err)
	}
	keyOut, err := os.OpenFile(keypath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Print("written key\n")

	subj := pkix.Name{
		CommonName:         hname,
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"KCA"},
		OrganizationalUnit: []string{"IT"},
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	template.DNSNames = append(template.DNSNames, hname)
	template.EmailAddresses = append(template.EmailAddresses, "support@klin-pro.com")
	csrOut, err := os.Create(csrpath + hname + ".csr")
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
