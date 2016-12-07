# roman

Roman is a Go library that obtains, caches, and automatically reloads TLS certificates from an ACME server. Roman is inspired by [golang.org/x/crypto/acme/autocert](https://godoc.org/golang.org/x/crypto/acme/autocert) with the primary difference being pluggable challenge performers.

**Example**

```go
import (
    "os"
    "net/http"

	"golang.org/x/crypto/acme/autocert"

    "github.com/mailgun/roman"
    "github.com/mailgun/roman/acme"
    "github.com/mailgun/roman/performer"
)

// create and start the certificate manager
m := roman.CertificateManager{
  ACMEClient:  &acme.Client{
      Directory:          acme.LetsEncryptProduction,
      AgreeTOS:           acme.AcceptTOS,
      Email:              "foo@example.com",
      ChallengePerformer: &challenge.Route53 {
         Region:           "us-east-1",
         AccessKeyID:      "AK000000000000000000",
         SecretAccessKey:  "a000000000000000000000000000000000000000",
         HostedZoneID:     "Z0000000000000",
         HostedDomainName: "example.com.",
         WaitForSync:      true,
      },
   },
   Cache:       autocert.DirCache(".")
   KnownHosts:  []string{"foo.example.com"},
   RenewBefore: 30 * 24 * time.Hour, // 30 days
}
err := m.Start()
if err != nil {
    fmt.Printf("Unable to start the CertificateManager: %v", err)
    os.Exit(255)
}

s := &http.Server{
    Addr: ":https",
    TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
}
s.ListenAndServeTLS("", "")
```
