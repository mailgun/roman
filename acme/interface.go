package acme

import (
	"crypto/tls"
)

type CertificateForDomainer interface {
	// CertificateForDomain obtains a certificate for a given hostname.
	CertificateForDomain(hostname string) (*tls.Certificate, error)
}
