package strapi_auth_client

import (
	"context"
	"net/http"
	"strings"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/transport/http/client"
)

const Namespace = "github.com/pushrbx/krakend-strapi-auth"

func NewHTTPClient(cfg *config.Backend) client.HTTPClientFactory {
	strapi_auth, ok := configGetter(cfg.ExtraConfig).(Config)
	if !ok || strapi_auth.IsDisabled {
		return client.NewHTTPClient
	}
}

type Config struct {
	IsDisabled     bool
	Identifier       string
	Password   string
	AuthURL       string
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
		cfg.AuthURL = v.(string)
	}

	return cfg
}