package acme

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"

	"github.com/mailgun/roman/challenge"
)

var _ = fmt.Printf // for testing

func TestCertificateForDomain(t *testing.T) {
	// read in config
	config, err := readConfiguration()
	if err != nil {
		t.Errorf("Unexpected response from readConfiguration: %v", err)
	}

	// generate a random domain to use during tests
	hostname, err := randomString(20)
	if err != nil {
		t.Fatalf("Unexpected response from randomString: %v", err)
	}
	hostname = fmt.Sprintf("%v.%v", hostname, config.HostedDomainName)

	acmeClient := &Client{
		Directory: LetsEncryptStaging,
		AgreeTOS:  acme.AcceptTOS,
		Email:     "foo@" + config.HostedDomainName,
		ChallengePerformer: &challenge.Route53{
			Region:           config.Region,
			AccessKeyID:      config.AccessKeyID,
			SecretAccessKey:  config.SecretAccessKey,
			HostedZoneID:     config.HostedZoneID,
			HostedDomainName: config.HostedDomainName,
			WaitForSync:      true,
		},
	}

	_, err = acmeClient.CertificateForDomain(hostname)
	if err != nil {
		t.Errorf("Unexpected response from CertificateForDomain: %v", err)
	}
}

func readConfiguration() (*challenge.Route53, error) {
	file, err := os.Open("../.roman.configuration")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var c challenge.Route53

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "=")
		keyName := strings.Trim(parts[0], " ")
		keyValue := strings.Trim(parts[1], " ")

		switch keyName {
		case "Route53-Region":
			c.Region = keyValue
		case "Route53-AccessKeyID":
			c.AccessKeyID = keyValue
		case "Route53-SecretAccessKey":
			c.SecretAccessKey = keyValue
		case "Route53-HostedZoneID":
			c.HostedZoneID = keyValue
		case "Route53-HostedDomainName":
			c.HostedDomainName = keyValue
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)

	// get n-byte random number from /dev/urandom
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
