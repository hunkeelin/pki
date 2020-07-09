package pki

import (
	"fmt"
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
	fmt.Println(string(f.Key))
	fmt.Println(string(f.Csr))
}
