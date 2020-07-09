package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// GenerateCertificateSigningRequestInput
type GenerateCertificateSigningRequestInput struct {
	RsaBits               int                      // RsaBits
	Country               []string                 // Country
	Province              []string                 // Province
	Locality              []string                 // Locality
	EmailAddresses        []string                 // EmailAddresses
	Organization          []string                 // Orginzation
	OrganizationalUnit    []string                 // OrginzationUnit
	CommonName            string                   // CommonName
	DNSNames              []string                 // DnsNames
	RawCertificateRequest *x509.CertificateRequest // RawCertificateRequest
}

//GenerateCertificateSigningRequestOutput
type GenerateCertificateSigningRequestOutput struct {
	Csr []byte // Csr
	Key []byte // Key
}

// GenerateCertificateSigningRequest
func GenerateCertificateSigningRequest(g GenerateCertificateSigningRequestInput) (GenerateCertificateSigningRequestOutput, error) {

	priv, err := rsa.GenerateKey(rand.Reader, g.RsaBits)
	if err != nil {
		return GenerateCertificateSigningRequestOutput{}, err
	}
	subj := pkix.Name{
		CommonName:         g.CommonName,
		Country:            g.Country,
		Province:           g.Province,
		Locality:           g.Locality,
		OrganizationalUnit: g.OrganizationalUnit,
		Organization:       g.Organization,
	}
	var template x509.CertificateRequest
	template = x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           g.DNSNames,
		EmailAddresses:     g.EmailAddresses,
	}
	template.DNSNames = append(template.DNSNames, g.CommonName)
	if g.RawCertificateRequest != nil {
		template = *g.RawCertificateRequest
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return GenerateCertificateSigningRequestOutput{}, err
	}
	return GenerateCertificateSigningRequestOutput{
		Csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}),
		Key: pem.EncodeToMemory(pemBlockForKey(priv)),
	}, nil
}
