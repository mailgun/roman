package acme

import (
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
)

type nopCache struct {
}

func Get(ctx context.Context, key string) ([]byte, error) {
	return nil, autocert.ErrCacheMiss
}

func Put(ctx context.Context, key string, data []byte) error {
	return nil
}

func Delete(ctx context.Context, key string) error {
	return nil
}
