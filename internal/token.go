package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context/ctxhttp"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Jwt    string
	User   UserProfile
	Raw    interface{}
	Expiry time.Time
}

// tokenJSON is the struct representing the HTTP response from Strapi's /auth/local endpoint
// https://strapi.io/documentation/3.0.0-beta.x/guides/authentication.html
type tokenJSON struct {
	Jwt  string          `json:"jwt"`
	User userProfileJson `json:"user"`
}

func newTokenRequest(authUrl, identifier, password string, v url.Values) (*http.Request, error) {
	v = cloneURLValues(v)
	if identifier != "" {
		v.Set("identifier", identifier)
	}
	if password != "" {
		v.Set("password", password)
	}

	data := v.Encode()
	req, err := http.NewRequest("POST", authUrl, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data)))

	return req, nil
}

func cloneURLValues(v url.Values) url.Values {
	v2 := make(url.Values, len(v))
	for k, vv := range v {
		v2[k] = append([]string(nil), vv...)
	}
	return v2
}

func RetrieveToken(ctx context.Context, identifier, password, authUrl string, v url.Values) (*Token, error) {
	req, err := newTokenRequest(authUrl, identifier, password, v)
	if err != nil {
		return nil, err
	}
	token, err := doTokenRoundTrip(ctx, req)

	if err != nil {
		return nil, err
	}

	return token, err
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (*Token, error) {
	r, err := ctxhttp.Do(ctx, ContextClient(ctx), req)

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("strapi-auth: cannot fetch token: %v", err)
	}

	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	var token *Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	// todo: decode jwt and save when the token expires
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		token = &Token{
			Jwt:  vals.Get("jwt"),
			User: UserProfile{},
			Raw:  vals,
		}

		parsedToken, err := ParseJwt(token.Jwt)
		if err != nil {
			return nil, err
		}

		expires := ExtractExp(parsedToken.Claims)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON

		if err = json.Unmarshal(body, &tj); err != nil {
			return nil, err
		}

		token = &Token{
			Jwt:    tj.Jwt,
			Expiry: tj.expiry(),
			User: UserProfile{
				Id:        tj.User.Id,
				Blocked:   tj.User.Blocked,
				Confirmed: tj.User.Confirmed,
				CreatedAt: tj.User.CreatedAt,
				Email:     tj.User.Email,
				Provider:  tj.User.Provider,
				Role: StrapiRole{
					Id:          tj.User.Role.Id,
					Name:        tj.User.Role.Name,
					Description: tj.User.Role.Description,
					Type:        tj.User.Role.Type,
				},
				UpdatedAt: tj.User.UpdatedAt,
				Username:  tj.User.Username,
			},
		}

		_ = json.Unmarshal(body, &token.Raw)
	}

	if token.Jwt == "" {
		return nil, errors.New("strapi-auth: server response missing jwt field")
	}

	return token, nil
}

type RetrieveError struct {
	Response *http.Response
	Body     []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("strapi-auth: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}

func (e *tokenJSON) expiry() (t time.Time) {
	parsedToken, err := ParseJwt(e.Jwt)
	if err != nil {
		return
	}

	if v := ExtractExp(parsedToken.Claims); v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

func ExtractExp(c jwt.Claims) int64 {
	claims := c.(jwt.MapClaims)
	switch exp := claims["exp"].(type) {
	case float64:
		return int64(exp)
	case json.Number:
		v, _ := exp.Int64()
		return v
	}

	return 0
}

func ParseJwt(_jwt string) (*jwt.Token, error) {
	parser := jwt.Parser{}
	parsedToken, _, err := parser.ParseUnverified(_jwt, jwt.MapClaims{})
	return parsedToken, err
}
