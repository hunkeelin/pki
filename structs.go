package klinpki

type CAConfig struct {
	EmailAddress string
	EcdsaCurve   string
	Certpath     string
	Keypath      string
	MaxDays      float64
	RsaBits      int
	Organization string
}

type CSRConfig struct {
	EmailAddress       string
	RsaBits            int
	Country            string
	Province           string
	Locality           string
	EmailAddress       string
	OrganizationalUnit string
}
