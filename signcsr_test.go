package pki

import (
	"fmt"
	"testing"
)

func TestSignCsr(t *testing.T) {
	csr, err := GenerateCertificateSigningRequest(GenerateCertificateSigningRequestInput{
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
	ca, err := GenerateCaCertificate(GenerateCaCertificateInput{
		EmailAddresses: []string{"foo@klin-pro.com"},
		MaxDays:        30,
		RsaBits:        4096,
		Organization:   "klin-pro",
		DNSNames:       []string{"test1.klin-pro.com"},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	cert, err := SignCsr(SignCsrInput{
		IsCa:   true,
		CaCert: ca.Cert,
		CaKey:  ca.Key,
		Csr:    csr.Csr,
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Println(string(cert.Cert))
}
