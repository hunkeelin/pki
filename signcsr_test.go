package pki

import (
	"testing"
)

func TestSignCsr(t *testing.T) {
	csr, err := GenerateCertificateSigningRequest(GenerateCertificateSigningRequestInput{
		EmailAddresses:     []string{"devops@varomoney.com"},
		RsaBits:            4096,
		Province:           []string{"CA"},
		Locality:           []string{"SF"},
		Organization:       []string{"varomoney"},
		OrganizationalUnit: []string{"IT"},
		CommonName:         "pii-vault",
		DNSNames:           []string{""},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	ca, err := GenerateCaCertificate(GenerateCaCertificateInput{
		EmailAddresses: []string{"devops@varomoney.com"},
		MaxDays:        7200,
		RsaBits:        4096,
		Organization:   "varomoney",
		DNSNames:       []string{"rootca"},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = SignCsr(SignCsrInput{
		IsCa:      true,
		CaCert:    ca.Cert,
		CaKey:     ca.Key,
		Csr:       csr.Csr,
		ValidDays: 2,
	})
	if err != nil {
		t.Errorf(err.Error())
	}
}
