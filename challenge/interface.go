package challenge

import (
	"golang.org/x/crypto/acme"
)

type Performer interface {
	// Perform will perform the requested challenge in *acme.Authorization against the *acme.Client.
	Perform(acmeClient *acme.Client, authorization *acme.Authorization, hostname string) error
}
