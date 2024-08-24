package registry

import "encoding/json"

// Option is the registry token authorization server configuration options
type Option struct {
	// an Authorizer implementation to authorize registry users
	Authorizer Authorizer
	// an Authenticator implementation to authenticate registry users
	Authenticator Authenticator
	// a pluggable tokenGenerator
	TokenGenerator TokenGenerator
	// .crt & .key file to sign JWT tokens
	Certfile string
	Keyfile  string
	// token expiration time
	TokenExpiration int64
	// token issuer specified in docker registry configuration file
	TokenIssuer string
}

type TokenOption struct {
	Expire int64
	Issuer string
}

const tokenSeparator = "."

type Header struct {
	Type       string           `json:"typ"`
	SigningAlg string           `json:"alg"`
	KeyID      string           `json:"kid,omitempty"`
	X5c        []string         `json:"x5c,omitempty"`
	RawJWK     *json.RawMessage `json:"jwk,omitempty"`
}

type ClaimSet struct {
	// Public claims
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	NotBefore  int64  `json:"nbf"`
	IssuedAt   int64  `json:"iat"`
	JWTID      string `json:"jti"`

	// Private claims
	Access []*ResourceActions `json:"access"`
}

type ResourceActions struct {
	Type    string   `json:"type"`
	Class   string   `json:"class,omitempty"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// AuthorizationRequest is the authorization request data
type AuthorizationRequest struct {
	Username string
	Service  string
	Scopes   []*ResourceActions
}
