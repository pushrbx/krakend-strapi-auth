package local_auth

import (
	"context"
	strapiauth "github.com/pushrbx/krakend-strapi-auth"
	"github.com/pushrbx/krakend-strapi-auth/internal"
	"net/http"
	"net/url"
)

type Config struct {
	IsDisabled bool
	Identifier string
	Password   string
	AuthUrl    string
}

func (c *Config) TokenSource(ctx context.Context) strapiauth.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}

	return strapiauth.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

func (c *Config) Client(ctx context.Context) *http.Client {
	return strapiauth.NewClient(ctx, c.TokenSource(ctx))
}

func (c *tokenSource) Token() (*strapiauth.Token, error) {
	v := url.Values{}
	tk, err := internal.RetrieveToken(c.ctx, c.conf.Identifier, c.conf.Password, c.conf.AuthUrl, v)

	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*strapiauth.RetrieveError)(rErr)
		}
		return nil, err
	}

	t := &strapiauth.Token{
		Jwt:  tk.Jwt,
		User: tk.User,
	}

	return t.WithExtra(tk.Raw), nil
}
