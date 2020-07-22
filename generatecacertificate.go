package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateCaCertificateInput the input of the function.
type GenerateCaCertificateInput struct {
	EmailAddresses []string          // EmailAddresses
	EcdsaCurve     string            // EcdsaCurve specify this if you want EcsdasCurve, if you leave it blank it will default to RSA
	MaxDays        float64           // MaxDays
	RsaBits        int               // RsaBits
	Password       string            // Password
	Organization   string            // Orgnaization
	DNSNames       []string          // DNSNames The list of DNS names
	RawCertificate *x509.Certificate // RawCertificate alternative one can forgo all the params above and simply stick the raw certficiate to be generated
}

// GenerateCaCertificate the CA certificate
func GenerateCaCertificate(g GenerateCaCertificateInput) (GenerateCaCertificateOutput, error) {
	var priv interface{}
	var err error

	switch g.EcdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, g.RsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("Unrecognized elliptic curve: %q", g.EcdsaCurve)
	}
	if err != nil {
		return GenerateCaCertificateOutput{}, err
	}

	// Initializing serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return GenerateCaCertificateOutput{}, err
	}

	// Initializing certificate template
	var template x509.Certificate
	template = x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{g.Organization},
		},
		NotBefore:             time.Now(),
		DNSNames:              g.DNSNames,
		NotAfter:              time.Now().Add(time.Duration(g.MaxDays*24) * time.Hour),
		IsCA:                  true,
		EmailAddresses:        g.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.KeyUsage |= x509.KeyUsageCertSign

	// Since they have rawcertificate we are ignoring other fields
	if g.RawCertificate != nil {
		template = *g.RawCertificate
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return GenerateCaCertificateOutput{}, err
	}
	keyPem, err := pemBlockForKey(g.Password, priv)
	if err != nil {
		return GenerateCaCertificateOutput{}, err
	}
	return GenerateCaCertificateOutput{
		Key:  pem.EncodeToMemory(keyPem),
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
	}, nil
}

// GenerateCaCertificateOutput the output of the function
type GenerateCaCertificateOutput struct {
	Key  []byte
	Cert []byte
}

//A Helper function to determine the hash algorithm
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
