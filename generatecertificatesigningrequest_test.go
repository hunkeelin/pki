package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenCsr(t *testing.T) {
	f, err := GenerateCertificateSigningRequest(GenerateCertificateSigningRequestInput{
		EmailAddresses:     []string{"foo@klin-pro.com"},
		RsaBits:            4096,
		Province:           []string{"CA"},
		Locality:           []string{"SF"},
		Organization:       []string{"klin-pro"},
		OrganizationalUnit: []string{"IT"},
		CommonName:         "pii-vault",
		DNSNames:           []string{""},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	csrDecoded, _ := pem.Decode(f.Csr)
	_, err = x509.ParseCertificateRequest(csrDecoded.Bytes)
	if err != nil {
		t.Errorf(err.Error())
	}

}
