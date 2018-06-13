package klinpki

import (
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func TestSignCSR(t *testing.T) {
	fmt.Println("testing sign CSR")
	rawcert, err := SignCSR("ca.crt", "ca.key", "test1.klin-pro.com.csr", 7200)
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
	GenCA("support@klin-pro.com", "", "ca", 7200, 2048)
}
func TestGenCSR(t *testing.T) {
	fmt.Println("testing genCSR")
	GenCSR(2048, "test1.klin-pro.com.key", "")
}
