package roman

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
	"golang.org/x/sync/singleflight"

	"github.com/mailgun/log"
	"github.com/mailgun/roman/acme"
	"github.com/mailgun/timetools"
)

var (
	clock timetools.TimeProvider = &timetools.RealTime{} // used to mock time in tests
)

// CertificateManager will obtain and cache TLS certificates from an ACME server.
// CertificateManager is inspired by autocert.Manager with the primary difference
// being pluggable challenge performers.
type CertificateManager struct {
	sync.RWMutex

	// Cache is used to speed up process start up and to avoid hitting any
	// rate limits imposed by the ACME server.
	Cache autocert.Cache

	// KnownHosts is a slice of hosts for whom the CertificateManager will try
	// to obtain tls certificates for.
	KnownHosts []string

	// ACMEClient is something that implements CertificateForDomainer (simple
	// wrapper around a golang.org/x/crypto/acme.Client).
	ACMEClient acme.CertificateForDomainer

	// RenewBefore represents how long before certificate expiration a new
	// certificate will be requested from the ACME server.
	RenewBefore time.Duration

	// singleflight group to make sure we only make one request for certificate
	// at a time
	group singleflight.Group

	// memoryCache is a in-memory cache used to store certificates
	memoryCache map[string]*tls.Certificate
}

// Start is a blocking function that ensures the CertificateManager cache
// contains valid certificates for all known hosts. If it doesn't contain a
// cached TLS certificate, it requests one and put its in the cache.
func (m *CertificateManager) Start() error {
	// this is a both a blocking call and a function that can potentially take
	// a lot of time, but it makes sure we have working certificates for
	// all known hosts before we start the process.
	errs := m.renewCertificates()
	if errs != nil {
		return fmt.Errorf("unable to start due to the following errors: %v", errs)
	}

	// kick off a go routine that will update certificates in the background
	go m.renewCertificatesForever()

	return nil
}

// GetCertificate is passed into a *tls.Config so that an *http.Server can
// automatically reload certificates. GetCertificate always retrieves
// certificates from a cache while a background go routine updates certificates.
func (m *CertificateManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.getCertificateFromCache(clientHello.ServerName)
}

// getCertificateFromCache returns a certificate from either an in-memory cache or disk cache.
func (m *CertificateManager) getCertificateFromCache(hostname string) (*tls.Certificate, error) {
	m.RLock()
	defer m.RUnlock()

	if m.memoryCache == nil {
		m.memoryCache = make(map[string]*tls.Certificate)
	}

	// look in the in-memory cache first
	certificate, ok := m.memoryCache[hostname]
	if ok {
		return certificate, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// couldn't find it in the in-memory cache, look for it on disk
	certificateBytes, err := m.Cache.Get(ctx, hostname)
	if err != nil {
		return nil, err
	}

	// found certificate, decode and rebuild it
	tlsCertificate, err := bytesToCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	// put it back in the in-memory cache
	m.memoryCache[hostname] = tlsCertificate

	return tlsCertificate, nil
}

// putCertificateInCache puts a *tls.Certificate in both the in-memory and disk cache.
func (m *CertificateManager) putCertificateInCache(hostname string, certificate *tls.Certificate) error {
	m.Lock()
	defer m.Unlock()

	// first put the certificate into the in-memory cache
	if m.memoryCache == nil {
		m.memoryCache = make(map[string]*tls.Certificate)
	}

	m.memoryCache[hostname] = certificate

	// get bytes
	certificateBytes, err := certificateToBytes(certificate)
	if err != nil {
		return err
	}

	// write them to disk
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	return m.Cache.Put(ctx, hostname, certificateBytes)
}

// deleteCertificateFromCache remove the certificate from both the in-memory cache and from disk.
func (m *CertificateManager) deleteCertificateFromCache(hostname string) error {
	m.Lock()
	defer m.Unlock()

	if m.memoryCache == nil {
		m.memoryCache = make(map[string]*tls.Certificate)
	}

	delete(m.memoryCache, hostname)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	return m.Cache.Delete(ctx, hostname)
}

func (m *CertificateManager) renewCertificate(hostname string) error {
	certificate, err := m.getCertificateFromCache(hostname)

	// if we got an error, and it was something other than a cache miss, return it right away
	if err != nil && err != autocert.ErrCacheMiss {
		return err
	}

	// if we didn't get any error, check if we need to renew the certificate
	if err == nil {
		// if we don't need to renew, move on to the next one
		if needToRenew(certificate.Leaf.NotAfter, m.RenewBefore) == false {
			return nil
		}
	}

	// go get a new certificate from the ACME server
	certificateI, err, _ := m.group.Do("rcfd", func() (interface{}, error) {
		return m.ACMEClient.CertificateForDomain(hostname)
	})
	if err != nil {
		return fmt.Errorf("unable to request certificate for hostname %q: %v", hostname, err)
	}
	certificate = certificateI.(*tls.Certificate)

	// so delete it from the cache (if it's in it)
	err = m.deleteCertificateFromCache(hostname)
	if err != nil {
		return fmt.Errorf("unable to delete certificate from cache for %q: %v", hostname, err)
	}

	// put the new certificate in the cache
	err = m.putCertificateInCache(hostname, certificate)
	if err != nil {
		return fmt.Errorf("unable to put certificate in cache for %q: %v", hostname, err)
	}

	return nil
}

// renewCertificates loops over all hostnames and makes sure they are all valid and cached.
func (m *CertificateManager) renewCertificates() []error {
	var errs []error

	for _, hostname := range m.KnownHosts {
		err := m.renewCertificate(hostname)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

// renewCertificatesForever calls renewCertificates every 24 hours.
func (m *CertificateManager) renewCertificatesForever() {
	for {
		errs := m.renewCertificates()
		if errs != nil {
			log.Errorf("unable to renew certificates: %v", errs)
		}

		time.Sleep(24 * time.Hour)
	}
}

// needToRenew will return true if it's time to renew a certificate.
func needToRenew(notAfter time.Time, renewBefore time.Duration) bool {
	return clock.UtcNow().Add(renewBefore).After(notAfter)
}

func bytesToCertificate(certificateBytes []byte) (*tls.Certificate, error) {
	// build the private key (*rsa.PrivateKey) first
	privateKeyBlock, publicKeyBytes := pem.Decode(certificateBytes)

	certificatePrivateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// build the certificate chain next
	var certificateBlock *pem.Block
	var remainingBytes []byte = publicKeyBytes
	var certificateChain [][]byte

	for {
		certificateBlock, remainingBytes = pem.Decode(remainingBytes)
		certificateChain = append(certificateChain, certificateBlock.Bytes)

		if len(remainingBytes) == 0 {
			break
		}
	}

	// build a concatenated certificate chain
	var buf bytes.Buffer
	for _, cc := range certificateChain {
		buf.Write(cc)
	}

	// parse the chain and get a slice of x509.Certificates.
	x509Chain, err := x509.ParseCertificates(buf.Bytes())
	if err != nil {
		return nil, err
	}

	// return the tls.Certificate
	return &tls.Certificate{
		Certificate: certificateChain,
		PrivateKey:  certificatePrivateKey,
		Leaf:        x509Chain[0],
	}, nil
}

func certificateToBytes(tlsCertificate *tls.Certificate) ([]byte, error) {
	// next create buf which will hold the bytes for the tls.Certificate that we will write to disk
	var buf bytes.Buffer

	// get the private key bytes in pkcs1 format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(tlsCertificate.PrivateKey.(*rsa.PrivateKey))

	// create a pem block that contains the private key
	privateKeyPEMBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// write private key to buf
	err := pem.Encode(&buf, &privateKeyPEMBlock)
	if err != nil {
		return nil, err
	}

	// loop over the certificate chain and make them into pem blocks
	// and write them to buf
	for _, certificateBytes := range tlsCertificate.Certificate {
		certificatePEMBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificateBytes,
		}

		err = pem.Encode(&buf, &certificatePEMBlock)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
