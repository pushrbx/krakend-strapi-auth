package strapi_auth_client

import (
	"context"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/transport/http/client"
	"net/http"
)

const Namespace = "github.com/pushrbx/krakend-strapi-auth"

func NewHTTPClient(cfg *config.Backend) client.HTTPClientFactory {
	strapiAuth, ok := configGetter(cfg.ExtraConfig).(Config)
	if !ok || strapiAuth.IsDisabled {
		return client.NewHTTPClient
	}

	c := LocalAuthConfig{
		Identifier: strapiAuth.Identifier,
		Password:   strapiAuth.Password,
		AuthUrl:    strapiAuth.AuthUrl,
	}

	cli := c.Client(context.Background())

	return func(_ context.Context) *http.Client {
		return cli
	}
}

var ZeroCfg = Config{}

func configGetter(e config.ExtraConfig) interface{} {
	v, ok := e[Namespace]
	if !ok {
		return nil
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	cfg := Config{}
	if v, ok := tmp["is_disabled"]; ok {
		cfg.IsDisabled = v.(bool)
	}
	if v, ok := tmp["identifier"]; ok {
		cfg.Identifier = v.(string)
	}
	if v, ok := tmp["password"]; ok {
		cfg.Password = v.(string)
	}
	if v, ok := tmp["auth_url"]; ok {
		cfg.AuthUrl = v.(string)
	}

	return cfg
}
