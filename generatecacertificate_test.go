package pki

import (
	"fmt"
	"testing"
)

func TestGenCa(t *testing.T) {
	f, err := GenerateCaCertificate(GenerateCaCertificateInput{
		EmailAddresses: []string{"foo@klin-pro.com"},
		MaxDays:        30,
		RsaBits:        4096,
		Organization:   "klin-pro",
		DNSNames:       []string{"test1.klin-pro.com"},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Println(string(f.Key))
	fmt.Println(string(f.Cert))
}
