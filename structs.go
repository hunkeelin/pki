package klinpki

type PkiConfig struct {
	EmailAddress string
	EcdsaCurve   string
	Certpath     string
	Keypath      string
	MaxDays      float64
	RsaBits      int
	Organization string
}
