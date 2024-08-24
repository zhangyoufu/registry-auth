package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const signAuth = "AUTH"

// AuthServer is the token authentication server
type AuthServer struct {
	authorizer     Authorizer
	authenticator  Authenticator
	tokenGenerator TokenGenerator
	crt, key       string
}

// NewAuthServer creates a new AuthServer
func NewAuthServer(opt *Option) (*AuthServer, error) {
	if opt.Authenticator == nil {
		opt.Authenticator = &DefaultAuthenticator{}
	}
	if opt.Authorizer == nil {
		opt.Authorizer = &DefaultAuthorizer{}
	}

	pb, prk, err := loadCertAndKey(opt.Certfile, opt.Keyfile)
	if err != nil {
		return nil, err
	}
	tk := &TokenOption{Expire: opt.TokenExpiration, Issuer: opt.TokenIssuer}
	if opt.TokenGenerator == nil {
		opt.TokenGenerator = newTokenGenerator(pb, prk, tk)
	}
	return &AuthServer{
		authorizer:     opt.Authorizer,
		authenticator:  opt.Authenticator,
		tokenGenerator: opt.TokenGenerator, crt: opt.Certfile, key: opt.Keyfile,
	}, nil
}

func (srv *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// bypass basic auth if possible
	username := srv.authenticator.Bypass(r)
	if username == "" {
		// grab user's auth parameters
		var (
			password string
			ok       bool
		)
		switch r.Method {
		case http.MethodGet:
			username, password, ok = r.BasicAuth()
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		case http.MethodPost:
			if r.PostForm.Get("grant_type") != "password" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			username = r.PostForm.Get("username")
			password = r.PostForm.Get("password")
		default:
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := srv.authenticator.Authenticate(username, password); err != nil {
			http.Error(w, "unauthorized: invalid auth credentials", http.StatusUnauthorized)
			return
		}
	}
	req := srv.parseRequest(r)
	req.Username = username
	access, err := srv.authorizer.Authorize(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// create token for this user using the actions returned
	// from the authorization check
	tk, err := srv.tokenGenerator.Generate(req, access)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	srv.ok(w, tk)
}

func (srv *AuthServer) parseRequest(r *http.Request) *AuthorizationRequest {
	scopes := []*ResourceActions{}
	for _, scopeString := range r.Form["scope"] {
		for _, s := range strings.Split(scopeString, " ") {
			scope := &ResourceActions{}
			parts := strings.Split(s, ":")
			if len(parts) > 0 {
				scope.Type = parts[0]
			}
			if len(parts) > 1 {
				scope.Name = parts[1]
			}
			if len(parts) > 2 {
				scope.Actions = strings.Split(parts[2], ",")
			}
			scopes = append(scopes, scope)
		}
	}
	return &AuthorizationRequest{
		Service: r.Form.Get("service"),
		Scopes:  scopes,
	}
}

func (srv *AuthServer) Run(addr string) error {
	http.Handle("/", srv)
	fmt.Printf("Authentication server running at %s", addr)
	return http.ListenAndServeTLS(addr, srv.crt, srv.key, nil)
}

func (srv *AuthServer) ok(w http.ResponseWriter, tk *Token) {
	data, _ := json.Marshal(tk)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
