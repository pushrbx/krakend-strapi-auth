package strapi_auth_client

import (
	"context"
	"github.com/pushrbx/krakend-strapi-auth/internal"
	"net/http"
	"net/url"
	"sync"
)

type Config struct {
	IsDisabled bool
	Identifier string
	Password   string
	AuthUrl    string
}

type TokenSource interface {
	Token() (*Token, error)
}

func ReuseTokenSource(t *Token, src TokenSource) TokenSource {
	// Don't wrap a reuseTokenSource in itself. That would work,
	// but cause an unnecessary number of mutex operations.
	// Just build the equivalent one.
	if rt, ok := src.(*reuseTokenSource); ok {
		if t == nil {
			// Just use it directly.
			return rt
		}
		src = rt.new
	}
	return &reuseTokenSource{
		t:   t,
		new: src,
	}
}

type tokenRefresher struct {
	ctx          context.Context // used to get HTTP requests
	conf         *Config
	refreshToken string
}

func (tf *tokenRefresher) Token() (*Token, error) {
	//if tf.refreshToken == "" {
	//	return nil, errors.New("oauth2: token expired and refresh token is not set")
	//}

	tk, err := retrieveToken(tf.ctx, tf.conf, url.Values{})

	if err != nil {
		return nil, err
	}

	return tk, err
}

type reuseTokenSource struct {
	new TokenSource // called when t is expired.

	mu sync.Mutex // guards t
	t  *Token
}

func (s *reuseTokenSource) Token() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, nil
}

func NewClient(ctx context.Context, src TokenSource) *http.Client {
	if src == nil {
		return internal.ContextClient(ctx)
	}

	return &http.Client{
		Transport: &Transport{
			Base:   internal.ContextClient(ctx).Transport,
			Source: ReuseTokenSource(nil, src),
		},
	}
}

func (c *Config) TokenSource(ctx context.Context, t *Token) TokenSource {
	tkr := &tokenRefresher{
		ctx:  ctx,
		conf: c,
	}
	//if t != nil {
	//	tkr.refreshToken = t.RefreshToken
	//}
	return &reuseTokenSource{
		t:   t,
		new: tkr,
	}
}
