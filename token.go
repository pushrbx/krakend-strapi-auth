package strapi_auth_client

import (
	"context"
	"fmt"
	"github.com/pushrbx/krakend-strapi-auth/internal"
	"net/http"
	"net/url"
)

// todo: implement expiry
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

// todo: implement expiry
func (t *Token) Valid() bool {
	return t != nil && t.Jwt != ""
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
