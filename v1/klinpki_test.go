package klinpki

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestSignCSR(t *testing.T) {
	fmt.Println("testing sign CSR")
	csr, err := ioutil.ReadFile("noobshit")
	if err != nil {
		panic(err)
	}
	f := &SignConfig{
		Crtpath:  "ca.crt",
		Keypath:  "ca.key",
		CsrBytes: csr,
		Days:     7200,
		IsCA:     true,
	}
	//	ff, _ := os.Create("noob")
	//	defer ff.Close()
	//	ff.Write(csr.Bytes)
	rawcert, err := SignCSRv2(f)
	if err != nil {
		panic(err)
	}

	clientCRTFile, err := os.Create("testcert" + ".crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: rawcert})
	clientCRTFile.Close()
}
func TestGenCA(t *testing.T) {
	fmt.Println("testing GenCA")
	j := &CAConfig{
		EmailAddress: "devops@varomoney.com",
		EcdsaCurve:   "",
		Certpath:     "pii-vault.crt",
		Keypath:      "pii-vault.key",
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
	j := &CSRConfig{
		EmailAddress:       "support@klin-superpro.com",
		RsaBits:            1024,
		Country:            "USA",
		Province:           "CA",
		Locality:           "SF",
		OrganizationalUnit: "ITS",
		Organization:       "pro",
		DNSNames:           []string{"fuck", "fuckboi.square.com"},
	}
	csr, key := GenCSRv2(j)
	csrout, err := os.Create("shit.csr")
	if err != nil {
		panic(err)
	}
	pem.Encode(csrout, csr)
	ff, _ := os.Create("noobshit")
	defer ff.Close()
	ff.Write(csr.Bytes)
	csrout.Close()

	keyOut, err := os.OpenFile("shit.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, key)
	keyOut.Close()
}
