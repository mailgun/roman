package acme

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"

	"github.com/mailgun/roman/challenge"
)

type Client struct {
	Directory          string
	AgreeTOS           func(tosURL string) bool
	Email              string
	ChallengePerformer challenge.Performer
}

// CertificateForDomain returns a *tls.Certificate for a given hostname.
func (c *Client) CertificateForDomain(hostname string) (*tls.Certificate, error) {
	// create disposable account and client
	acmeClient, err := createClient(c.Directory, c.Email, c.AgreeTOS)
	if err != nil {
		return nil, err
	}

	// request authorization for our public key to obtain certificates for hostname
	authorization, err := getAuthorization(acmeClient, hostname)
	if err != nil {
		return nil, err
	}

	// perform the challenge requested in the authorization
	err = c.ChallengePerformer.Perform(acmeClient, authorization, hostname)
	if err != nil {
		return nil, err
	}

	// we've proven we own the domain, request the actual certificate
	return requestCertificate(acmeClient, hostname)
}

// createClient will create disposable account credentials and return
// a acme.Client that will be used to get certificates.
func createClient(directory string, email string, agreeTOS func(tosURL string) bool) (*acme.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// create disposable key pair.
	// TODO: consider not using disposable accounts
	keypair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// create a client with a dummy account
	client := &acme.Client{
		Key:          keypair,
		DirectoryURL: directory,
	}
	contactAccount := acme.Account{
		Contact: []string{"mailto:" + email},
	}

	// register returns a real account, but we throw it away because
	// we use disposable accounts
	_, err = client.Register(ctx, &contactAccount, agreeTOS)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// getAuthorization requests authorization to obtain certificates for a hostname.
func getAuthorization(acmeClient *acme.Client, hostname string) (*acme.Authorization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	authorization, err := acmeClient.Authorize(ctx, hostname)
	if err != nil {
		return nil, err
	}

	switch authorization.Status {
	case acme.StatusValid:
	case acme.StatusPending:
		return authorization, nil
	case acme.StatusProcessing:
		return nil, fmt.Errorf("certificate authorization already in progress")
	case acme.StatusInvalid:
	case acme.StatusRevoked:
	case acme.StatusUnknown:
	default:
		return nil, fmt.Errorf("invalid certificate authorization status: %v", authorization.Status)
	}

	return authorization, nil
}

func requestCertificate(acmeClient *acme.Client, hostname string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// generate private key for certificate
	certificatePrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// create certificate request
	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, certificatePrivateKey)
	if err != nil {
		return nil, err
	}

	// ask the acme server for a certificates
	certificateChain, _, err := acmeClient.CreateCert(ctx, csr, 90*24*time.Hour, true)
	if err != nil {
		return nil, err
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

	// validate the chain to make sure the certificate will actually work
	err = validateCertificateChain(hostname, certificateChain)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: certificateChain,
		PrivateKey:  certificatePrivateKey,
		Leaf:        x509Chain[0],
	}, nil
}

// validateCertificateChain parses entire certificate chain received from ACME
// server and makes sure it's valid.
func validateCertificateChain(domainName string, certificateChain [][]byte) error {
	// build a concatenated certificate chain
	var buf bytes.Buffer
	for _, cc := range certificateChain {
		buf.Write(cc)
	}

	// parse the chain and get a slice of x509.Certificates.
	x509Chain, err := x509.ParseCertificates(buf.Bytes())
	if err != nil {
		return err
	}

	if len(certificateChain) < 2 {
		return fmt.Errorf("not enough certificates in chain: %v", len(certificateChain))
	}

	// extract the roots, intermediates, and leaf certificate chains
	roots := x509.NewCertPool()
	roots.AddCert(x509Chain[len(x509Chain)-1])

	intermediates := x509.NewCertPool()
	if len(certificateChain) > 2 {
		for _, v := range x509Chain[1 : len(x509Chain)-2] {
			intermediates.AddCert(v)
		}
	}

	leaf := x509Chain[0]

	// verify the entire chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       domainName,
	}

	_, err = leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("unable to verify certificates chain: %v", err)
	}

	return nil
}
