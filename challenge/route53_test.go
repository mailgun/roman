package challenge

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

var _ = fmt.Printf // for testing

func TestRoute53CRUD(t *testing.T) {
	// read in aws config
	c, err := readConfiguration()
	if err != nil {
		t.Fatalf("Unexpected response from readConfiguration: %v", err)
	}

	// generate fqdn to use during test
	hostname, err := randomString(20)
	if err != nil {
		t.Fatalf("Unexpected response from randomString: %v", err)
	}
	fqdn := fmt.Sprintf("%v.%v", hostname, c.HostedDomainName)

	// generate challenge value to use during test
	challengeValue, err := randomString(20)
	if err != nil {
		t.Fatalf("Unexpected response from randomString: %v", err)
	}

	// create a new upsetter, it should pick up credentials
	r53, err := newRoute53Client(*c)
	if err != nil {
		t.Fatalf("Unexpected response from NewAmazonUpserter: %v\n", err)
	}

	// remove dns record that may exist
	err = r53.Delete(fqdn, challengeValue)
	if err != nil {
		t.Fatalf("Unexpected response from Delete: %v", err)
	}

	// create a new dns record
	err = r53.Upsert(fqdn, challengeValue)
	if err != nil {
		t.Fatalf("Unexpected response from Upsert: %v", err)
	}

	// read in dns record
	cv, err := r53.Read(fqdn)
	if err != nil {
		t.Fatalf("Unexpected response form Read: %v", err)
	}

	// check the value of the record
	if got, want := cv, challengeValue; got != want {
		t.Fatalf("Got ACME challenge value: %v, Want: %v", got, want)
	}

	// cleanup
	err = r53.Delete(fqdn, challengeValue)
	if err != nil {
		t.Fatalf("Unexpected response from Delete: %v", err)
	}
}

func readConfiguration() (*Route53, error) {
	file, err := os.Open("../.roman.configuration")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var c Route53

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
