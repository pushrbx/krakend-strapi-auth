package strapi_auth_client

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pushrbx/krakend-strapi-auth/internal"
	"net/http"
	"net/url"
	"time"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

var timeNow = time.Now

type Token struct {
	Jwt  string               `json:"jwt"`
	User internal.UserProfile `json:"user"`
	raw  interface{}
}

func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+t.Jwt)
}

func (t *Token) WithExtra(extra interface{}) *Token {
	t2 := new(Token)
	*t2 = *t
	t2.raw = extra
	return t2
}

func (t *Token) Valid() bool {
	return t != nil && t.Jwt != "" && !t.expired()
}

func (t *Token) expired() bool {
	tokenParser := jwt.Parser{}
	parsedToken, _, err := tokenParser.ParseUnverified(t.Jwt, jwt.MapClaims{})
	if err != nil {
		return true
	}
	unixExp := internal.ExtractExp(parsedToken.Claims)
	expiry := time.Unix(unixExp, 0)
	return expiry.Round(0).Add(-expiryDelta).Before(timeNow())
}

func tokenFromInternal(t *internal.Token) *Token {
	if t == nil {
		return nil
	}
	return &Token{
		Jwt:  t.Jwt,
		User: t.User,
		raw:  t.Raw,
	}
}

func retrieveToken(ctx context.Context, c *Config, v url.Values) (*Token, error) {
	tk, err := internal.RetrieveToken(ctx, c.Identifier, c.Password, c.AuthUrl, v)
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*RetrieveError)(rErr)
		}
		return nil, err
	}
	return tokenFromInternal(tk), nil
}

type RetrieveError struct {
	Response *http.Response
	// Body is the body that was consumed by reading Response.Body.
	// It may be truncated.
	Body []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("strapi_auth: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}

func (c *LocalAuthConfig) TokenSource(ctx context.Context) TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}

	return ReuseTokenSource(nil, source)
}

type LocalAuthConfig struct {
	IsDisabled bool
	Identifier string
	Password   string
	AuthUrl    string
}

type tokenSource struct {
	ctx  context.Context
	conf *LocalAuthConfig
}

func (c *LocalAuthConfig) Client(ctx context.Context) *http.Client {
	return NewClient(ctx, c.TokenSource(ctx))
}

func (c *tokenSource) Token() (*Token, error) {
	v := url.Values{}
	tk, err := internal.RetrieveToken(c.ctx, c.conf.Identifier, c.conf.Password, c.conf.AuthUrl, v)

	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*RetrieveError)(rErr)
		}
		return nil, err
	}

	t := &Token{
		Jwt:  tk.Jwt,
		User: tk.User,
	}

	return t.WithExtra(tk.Raw), nil
}
