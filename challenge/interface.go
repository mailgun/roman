package challenge

import (
	"golang.org/x/crypto/acme"
)

type Performer interface {
	Perform(acmeClient *acme.Client, authorization *acme.Authorization, hostname string) error
}
