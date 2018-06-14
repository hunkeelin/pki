package klinpki

import (
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func TestSignCSR(t *testing.T) {
	fmt.Println("testing sign CSR")
	csr, _ := GenCSRv2(2048)
	rawcert, err := SignCSRv2("ca.crt", "ca.key", csr.Bytes, 7200)
	if err != nil {
		panic(err)
	}

	clientCRTFile, err := os.Create("test1.klin-pro.com" + ".crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: rawcert})
	clientCRTFile.Close()
}
func TestGenCA(t *testing.T) {
	fmt.Println("testing GenCA")
	j := &CAConfig{
		EmailAddress: "support@klin-pro.com",
		EcdsaCurve:   "",
		Certpath:     "ca.crt",
		Keypath:      "ca.key",
		MaxDays:      7200,
		RsaBits:      4096,
		Organization: "klin-pro",
	}
	GenCA(j)
}
func TestGenCSR(t *testing.T) {
	//fmt.Println("testing genCSR")
	//GenCSR(2048, "test1.klin-pro.com.key", "")
	fmt.Println("testv2")
	csr, key := GenCSRv2(2048)
	certOut, err := os.Create("shit.csr")
	if err != nil {
		panic(err)
	}
	pem.Encode(certOut, csr)
	certOut.Close()

	keyOut, err := os.OpenFile("shit.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, key)
	keyOut.Close()
}
