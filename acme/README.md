## acme

The `acme` package provides a simple API for requesting certificates from
and Automated Certificate Management Environment (ACME) Certificate Authority
(CA). You probably don't want to use this directly, instead use
`roman.CertificateManager`.

### Example


```go

import (
    "crypto/tls"
    "fmt"
    "net/http"
    "os"

    "github.com/mailgun/roman/acme"
	"github.com/mailgun/roman/challenge"

	golang_acme "golang.org/x/crypto/acme"
)

// create a roman acme client
acmeClient := &Client{
	Directory: acme.LetsEncryptProduction,
	AgreeTOS:  golang_acme.AcceptTOS,
	Email:     "foo@example.com",
	ChallengePerformer: &challenge.Route53{
		Region:           "us-east-1",
		AccessKeyID:      "AK000000000000000000",
		SecretAccessKey:  "a000000000000000000000000000000000000000",
		HostedZoneID:     "Z0000000000000",
		HostedDomainName: "example.com",
		WaitForSync:      true,
	},
}

// go get a certificate for example.com
certificate, err = acmeClient.CertificateForDomain("example.com")
if err != nil {
    fmt.Printf("Unexpected response from CertificateForDomain: %v", err)
    os.Exit(255)
}

// start a server or do whatever you want with the certificate
s := &http.Server{
    Addr: ":https",
    TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
}
s.ListenAndServeTLS("", "")
```

### Tests

To run tests against a file called `.roman.configuration`
needs to exist the root of the `roman` repo that contains information
needed by the challenge solver. An example configuration file would look like:

```
Route53-Region=us-east-1
Route53-AccessKeyID=AK000000000000000000
Route53-SecretAccessKey=a000000000000000000000000000000000000000
Route53-HostedZoneID=Z0000000000000
Route53-HostedDomainName=example.com
```
