package klinpki

type PkiConfig struct {
	emailAddress string
	ecdsaCurve   string
	certpath     string
	keypath      string
	maxDays      float64
	rsaBits      int
	organization string
}
