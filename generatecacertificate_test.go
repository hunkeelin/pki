package pki

import (
	"testing"
)

func TestGenCa(t *testing.T) {
	_, err := GenerateCaCertificate(GenerateCaCertificateInput{
		EmailAddresses: []string{"foo@klin-pro.com"},
		MaxDays:        30,
		RsaBits:        4096,
		Organization:   "klin-pro",
		DNSNames:       []string{"test1.klin-pro.com"},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
}
