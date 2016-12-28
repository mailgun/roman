package acme

import (
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
)

type nopCache struct {
}

func (n nopCache) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, autocert.ErrCacheMiss
}

func (n nopCache) Put(ctx context.Context, key string, data []byte) error {
	return nil
}

func (n nopCache) Delete(ctx context.Context, key string) error {
	return nil
}
