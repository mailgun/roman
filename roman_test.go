package roman

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"

	"github.com/mailgun/timetools"
)

var _ = fmt.Printf // for testing

func TestStart(t *testing.T) {
	var waitOneSecond time.Duration = 1 * time.Second

	// create a CertificateManager we can manipulate
	mm := make(map[string]int)
	cc := countingCache{&mm}
	m := CertificateManager{
		ACMEClient:  &sleepingCertificateForDomainer{waitOneSecond},
		Cache:       &cc,
		KnownHosts:  []string{"foo.example.com"},
		RenewBefore: 30 * 24 * time.Hour, // 30 days
	}

	start := time.Now()
	m.Start()
	elapsed := time.Since(start)

	if elapsed < waitOneSecond {
		t.Fatalf("Start is not blocking, took less than %v", waitOneSecond)
	}
}

func TestGetPutCertificateCycle(t *testing.T) {
	// create a CertificateManager we can manipulate
	mm := make(map[string]int)
	cc := countingCache{&mm}
	m := CertificateManager{
		ACMEClient:  &countingCertificateForDomainer{},
		Cache:       &cc,
		KnownHosts:  []string{"foo.example.com"},
		RenewBefore: 30 * 24 * time.Hour, // 30 days
	}

	// generate a dummy certificate
	certificate, err := generateCertificate("foo.example.com", clock.UtcNow(), clock.UtcNow())
	if err != nil {
		t.Fatalf("Unexpected response from generateCertificate: %v", err)
	}

	// before we put anything in the cache, try to get something, we do
	// this to make sure we can access the countingCache
	m.getCertificateFromCache("foo.example.com")

	// make sure we hit the countingCache once
	if got, want := cc.CountFor("get"), 1; got != want {
		t.Errorf("Get Got called %v times, Want: %v", got, want)
	}

	// put generated certificate in cache
	err = m.putCertificateInCache("foo.example.com", certificate)
	if err != nil {
		t.Fatalf("Unexpected response from putCertificateInCache: %v", err)
	}

	// check both the roman cache as well as the Cache
	if got, want := len(m.memoryCache), 1; got != want {
		t.Errorf("Got %v items in memoryCache, Want: %v", got, want)
	}
	if got, want := cc.CountFor("put"), 1; got != want {
		t.Errorf("Put Got called %v times, Want: %v", got, want)
	}

	// now delete it
	certificateFromCache, err := m.getCertificateFromCache("foo.example.com")
	if err != nil {
		t.Fatalf("Unexpected response from deleteCertificateFromCache: %v", err)
	}

	// check both the roman cache as well as the Cache and make
	// sure the cert we pulled out has the same SerialNumber.
	// the countingCache should not see an increase in counts
	// because the in-memory will return it
	if got, want := len(m.memoryCache), 1; got != want {
		t.Errorf("Got %v items in memoryCache, Want: %v", got, want)
	}
	if got, want := cc.CountFor("put"), 1; got != want {
		t.Errorf("Put Got called %v times, Want: %v", got, want)
	}
	if got, want := cc.CountFor("get"), 1; got != want {
		t.Errorf("Get Got called %v times, Want: %v", got, want)
	}
	if got, want := certificate.Leaf.SerialNumber, certificateFromCache.Leaf.SerialNumber; got != want {
		t.Errorf("Got SerialNumber: %v, Want: %v", got, want)
	}
}

func TestDeleteCertificate(t *testing.T) {
	// create a CertificateManager we can manipulate
	mm := make(map[string]int)
	cc := countingCache{&mm}
	m := CertificateManager{
		ACMEClient:  &countingCertificateForDomainer{},
		Cache:       &cc,
		KnownHosts:  []string{"foo.example.com"},
		RenewBefore: 30 * 24 * time.Hour, // 30 days
	}

	// generate a dummy certificate
	certificate, err := generateCertificate("foo.example.com", clock.UtcNow(), clock.UtcNow())
	if err != nil {
		t.Fatalf("Unexpected response from generateCertificate: %v", err)
	}

	// put generated certificate in cache
	err = m.putCertificateInCache("foo.example.com", certificate)
	if err != nil {
		t.Fatalf("Unexpected response from putCertificateInCache: %v", err)
	}

	// check both the roman cache as well as the Cache
	if got, want := len(m.memoryCache), 1; got != want {
		t.Errorf("Got %v items in memoryCache, Want: %v", got, want)
	}
	if got, want := cc.CountFor("put"), 1; got != want {
		t.Errorf("Put Got called %v times, Want: %v", got, want)
	}

	// now delete it
	err = m.deleteCertificateFromCache("foo.example.com")
	if err != nil {
		t.Fatalf("Unexpected response from deleteCertificateFromCache: %v", err)
	}

	// check both the roman cache as well as the Cache
	if got, want := len(m.memoryCache), 0; got != want {
		t.Errorf("Got %v items in memoryCache, Want: %v", got, want)
	}
	if got, want := cc.CountFor("put"), 1; got != want {
		t.Errorf("Put Got called %v times, Want: %v", got, want)
	}
	if got, want := cc.CountFor("delete"), 1; got != want {
		t.Errorf("Delete Got called %v times, Want: %v", got, want)
	}
}

func TestRenewCertificate(t *testing.T) {
	tests := []struct {
		inClock     timetools.TimeProvider // initialize time to this value
		inNotBefore time.Time              // time from when certificate is valid
		inNotAfter  time.Time              // time after which certificate is not valid
		outNotAfter time.Time              // expected value of certificate expiration after renew is called
		outCount    int                    // to see if CertificateForDomain was called
	}{
		// 0 - renew time has not arrived
		{
			//                                y    m  d  h  m  s  n  loc
			&timetools.FreezedTime{time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC)},
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC),
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC).Add(31 * 24 * time.Hour),
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC).Add(31 * 24 * time.Hour),
			0,
		},
		// 1 - renew time has arrived
		{
			//                                y    m  d  h  m  s  n  loc
			&timetools.FreezedTime{time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC)},
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC),
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC).Add(29 * 24 * time.Hour),
			time.Date(2006, 1, 2, 3, 4, 0, 0, time.UTC).Add(90 * 24 * time.Hour),
			1,
		},
	}

	// run tests
	for i, tt := range tests {
		// setup time for test
		clock = tt.inClock

		// create a CertificateManager we can manipulate, it will issue certificates
		// that will expire 90 days from now
		ccfd := countingCertificateForDomainer{
			count:     0,
			notBefore: clock.UtcNow().Add(90 * 24 * time.Hour),
			notAfter:  clock.UtcNow().Add(90 * 24 * time.Hour),
		}
		mm := make(map[string]int)
		cc := countingCache{&mm}
		m := CertificateManager{
			ACMEClient:  &ccfd,
			Cache:       &cc,
			KnownHosts:  []string{"foo.example.com"},
			RenewBefore: 30 * 24 * time.Hour, // 30 days
		}

		// generate a certificate with passed in notBefore and notAfter
		certificate, err := generateCertificate("foo.example.com", tt.inNotBefore, tt.inNotAfter)
		if err != nil {
			t.Fatalf("Test(%v) Unexpected response from generateCertificate: %v", i, err)
		}

		// put generated certificate in cache
		err = m.putCertificateInCache("foo.example.com", certificate)
		if err != nil {
			t.Fatalf("Test(%v) Unexpected response from putCertificateInCache: %v", i, err)
		}

		// renew the certificate, this should cause the CertificateManager to
		// issue a request for a new certificate and a new certificate will be
		// put in the cache
		err = m.renewCertificate("foo.example.com")
		if err != nil {
			t.Fatalf("Test(%v) Unexpected response from renewCertificate: %v", i, err)
		}

		// get new certificate from cache
		certificate, err = m.getCertificateFromCache("foo.example.com")
		if err != nil {
			t.Fatalf("Test(%v) Unexpected response from getCertificateFromCache: %v", i, err)
		}

		// check that the certificate now has a updated and CertificateForDomain was called
		if got, want := certificate.Leaf.NotAfter, tt.outNotAfter; got != want {
			t.Errorf("Test(%v) Got certificate.Leaf.NotAfter, Want: %v", i, got, want)
		}
		if got, want := ccfd.count, tt.outCount; got != want {
			t.Errorf("Test(%v) Got called CertificateForDomain %v time , Want: %v", i, got, want)
		}
	}
}

// sleepingCertificateForDomainer is used in tests to manipulate when certificates are issued
// to control how long it takes to get a certificate.
type sleepingCertificateForDomainer struct {
	t time.Duration
}

func (s *sleepingCertificateForDomainer) CertificateForDomain(hostname string) (*tls.Certificate, error) {
	time.Sleep(s.t)
	return generateCertificate(hostname, clock.UtcNow(), clock.UtcNow())
}

// countingCertificateForDomainer is used in tests to manipulate when certificates are issued
// and check how often it was called.
type countingCertificateForDomainer struct {
	count     int
	notBefore time.Time
	notAfter  time.Time
}

func (n *countingCertificateForDomainer) CertificateForDomain(hostname string) (*tls.Certificate, error) {
	n.count = n.count + 1
	return generateCertificate(hostname, n.notBefore, n.notAfter)
}

// generateCertificate is used in tests to create dummy certificates.
func generateCertificate(hostname string, notBefore time.Time, notAfter time.Time) (*tls.Certificate, error) {
	keypair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"foo"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:     true,
		DNSNames: []string{hostname},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, keypair.Public(), keypair)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certificateBytes},
		PrivateKey:  keypair,
		Leaf:        leaf,
	}, nil
}

// countingCache is used in tests to cache certificates and count calls.
// this looks weird, why do we use a pointer to a map? it's because the autocert.Cache
// interface doesn't support pointer receivers so we can't change the map
// in Get, Put, or Delete. So instead we pass in a pointer to a map that
// we then access by doing (*m.m) to access and manipulate.
type countingCache struct {
	m *map[string]int
}

func (m countingCache) Get(ctx context.Context, key string) ([]byte, error) {
	(*m.m)["get"] = (*m.m)["get"] + 1
	return nil, autocert.ErrCacheMiss
}

func (m countingCache) Put(ctx context.Context, key string, data []byte) error {
	(*m.m)["put"] = (*m.m)["put"] + 1
	return nil
}

func (m countingCache) Delete(ctx context.Context, key string) error {
	(*m.m)["delete"] = (*m.m)["delete"] + 1
	return nil
}

func (m countingCache) CountFor(key string) int {
	return (*m.m)[key]
}
