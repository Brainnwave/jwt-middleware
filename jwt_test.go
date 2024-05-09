package jwt_middleware

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

type Test struct {
	Name                  string             // The name of the test
	Allowed               bool               // Whether the request was actually allowed through by the plugin (set by next)
	Expect                int                // Response status code expected
	ExpectCounts          map[string]int     // Map of expected counts
	ExpectPluginError     string             // If set, expect this error message from plugin
	ExpectRedirect        string             // Full URL to expect redirection to
	ExpectHeaders         map[string]string  // Headers to expect in the downstream request as passed to next
	ExpectCookies         map[string]string  // Cookies to expect in the downstream request as passed to next
	ExpectResponseHeaders map[string]string  // Headers to expect in the response
	Config                string             // The dynamic yml configuration to pass to the plugin
	URL                   string             // Used to pass the URL from the server to the handlers (which must exist before the server)
	Keys                  jose.JSONWebKeySet // JWKS used in test server
	Method                jwt.SigningMethod  // Signing method for the token
	Private               string             // Private key to use to sign the token rather than generating one
	Kid                   string             // Kid for private key to use to sign the token rather than generating one
	CookieName            string             // The name of the cookie to use
	HeaderName            string             // The name of the header to use
	ParameterName         string             // The name of the parameter to use
	BearerPrefix          bool               // Whether to use the Bearer prefix or not
	Cookies               map[string]string  // Cookies to set in the incomming request
	Claims                string             // The claims to use in the token as a JSON string
	ClaimsMap             jwt.MapClaims      // claims mapped from `Claims`
	GrpcRequest           bool               // Whether to use the gRPC request context
	Actions               map[string]string  // Map of "actions" to take during the test, some are just flags and some have values
	Environment           map[string]string  // Map of environment variables to simulate for the test
	Counts                map[string]int     // Map of arbitrary counts recorded in the test
}

const (
	jwksCalls          = "jwksCalls"
	useFixedSecret     = "useFixedSecret"
	noAddIsser         = "noAddIsser"
	rotateKey          = "rotateKey"
	excludeIss         = "excludeIss"
	configBadBody      = "configBadBody"
	keysBadURL         = "keysBadURL"
	keysBadBody        = "keysBadBody"
	configServerStatus = "configServerStatus"
	keysServerStatus   = "keysServerStatus"
	invalidJSON        = "invalidJSON"
	traefikURL         = "traefikURL"
	yes                = "yes"
	invalid            = "invalid/dummy"
)

func TestServeHTTP(tester *testing.T) {
	tests := []Test{
		{
			Name:   "no token",
			Expect: http.StatusUnauthorized,
			Config: `
				issuers: https://example.com
				require:
					aud: test
				parameterName: token`,
		},
		{
			Name:        "no token grpc",
			GrpcRequest: true,
			Expect:      http.StatusOK,
			ExpectResponseHeaders: map[string]string{
				"grpc-status":  "16",
				"grpc-message": "UNAUTHENTICATED",
			},
			Config: `
				issuers: https://example.com
				require:
					aud: test
				parameterName: token`,
		},
		{
			Name:   "optional with no token",
			Expect: http.StatusOK,
			Config: `
				issuers: https://example.com
				require:
					aud: test
				optional: true
				parameterName: token`,
		},
		{
			Name:         "token in cookie",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 1},
			Config: `
				issuers:
					- https://dummy.example.com
					- https://example.com
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			CookieName: "Authorization",
		},
		{
			Name:         "token in header",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 1},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:         "token in header with Bearer prefix",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 1},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:       `{"aud": "test"}`,
			Method:       jwt.SigningMethodHS256,
			HeaderName:   "Authorization",
			BearerPrefix: true,
		},

		{
			Name:         "token in query string",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 1},
			Config: `
				secret: fixed secret
				require:
					aud: test
				parameterName: "token"
				forwardToken: false`,
			Claims:        `{"aud": "test"}`,
			Method:        jwt.SigningMethodHS256,
			ParameterName: "token",
		},

		{
			Name:   "expired token",
			Expect: http.StatusUnauthorized,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "invalid claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:        "invalid claim grpc",
			GrpcRequest: true,
			Expect:      http.StatusOK,
			ExpectResponseHeaders: map[string]string{
				"grpc-status":  "7",
				"grpc-message": "PERMISSION_DENIED",
			},
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "value requirement with invalid type of claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: 123`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "missing claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "StatusUnauthorized when within window of freshness",
			Expect: http.StatusUnauthorized,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "other", "iat": 1692451139}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Host}}"`,
			Claims:     `{"authority": "app.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement wth wildcard claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Host}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "template requirement from environment variable",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:      `{"authority": "*.example.com"}`,
			Method:      jwt.SigningMethodHS256,
			HeaderName:  "Authorization",
			Environment: map[string]string{"Domain": "app.example.com"},
		},
		{
			Name:   "invalid claim for template requirement from environment variable",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:      `{"authority": "*.example.com"}`,
			Method:      jwt.SigningMethodHS256,
			HeaderName:  "Authorization",
			Environment: map[string]string{"Domain": "app.other.com"},
		},
		{
			Name:   "template requirement from missing environment variable",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "{{.Domain}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad template requirement",
			Expect: http.StatusForbidden, // TODO add check on startup
			Config: `
				secret: fixed secret
				require:
					authority: "{{.XHost}}"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: test.example.com`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard claim no subdomain",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: example.com`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard list claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: test.example.com`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "list with wildcard list claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: ["test.example.com", "other.other.com"]`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single required and nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "user"`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single requred and multilpe nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "user"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and multiple required and single nested",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": ["user", "admin"]`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and irrelevant nested value claim",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object bad nested value claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority:
						"test.example.com": "admin"`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "guest"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "test.company.com"`,
			Claims:     `{"authority": "*.example.com"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard list claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims:     `{"authority": ["*.company.com", "other.example.com"]}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "bad wildcard object claim",
			Expect: http.StatusForbidden,
			Config: `
				secret: fixed secret
				require:
					authority: "test.example.com"`,
			Claims: `{
				"authority": {
					"*.company.com": ["user", "admin"]
				}
			}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodHS256",
			Expect: http.StatusOK,
			Config: `
				secret: fixed secret
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS256",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS384",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS384,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS512",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES256",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES384",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodES512",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
		},
		{
			Name:   "SigningMethodRS256 with missing kid",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:   "SigningMethodRS256 with bad n",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:n": invalid},
		},
		{
			Name:   "SigningMethodRS256 with bad e",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:e": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing kid",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:   "SigningMethodES256 with bad x",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:x": invalid},
		},
		{
			Name:   "SigningMethodES256 with bad y",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:y": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodES256 with missing crv and alg",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid, "set:alg": invalid},
		},
		{
			Name:   "SigningMethodES384 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodES512 with missing crv",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": invalid},
		},
		{
			Name:   "SigningMethodRS256 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodRS512 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES256 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES384 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES384,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:   "SigningMethodES512 in fixed secret",
			Expect: http.StatusOK,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES512,
			HeaderName: "Authorization",
			Actions:    map[string]string{useFixedSecret: yes, noAddIsser: yes},
		},
		{
			Name:              "bad fixed secret",
			ExpectPluginError: "invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key",
			Config: `
				secret: -----BEGIN RSA PUBLIC KEY 
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
		},
		{
			Name:         "EC fixed secrets",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 0},
			Config: `
				secrets:
					43263adb454e2217b26212b925498a139438912d: |
						-----BEGIN EC PUBLIC KEY-----
						MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1
						nbCeipqfvK1rkqmKfhb7rlVehfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
						-----END EC PUBLIC KEY-----
				skipPrefetch: true
				require:
					aud: test`,
			Claims: `{"aud": "test"}`,
			Method: jwt.SigningMethodES256,
			Private: `
				-----BEGIN EC PRIVATE KEY-----
				MHcCAQEEIOGYoXIkNQh/7WBgOwZ+epQFMdkgGcdHwLQFL69oYEodoAoGCCqGSM49
				AwEHoUQDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1nbCeipqfvK1rkqmKfhb7rlVe
				hfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
				-----END EC PRIVATE KEY-----`,
			Kid:        "43263adb454e2217b26212b925498a139438912d",
			CookieName: "Authorization",
		},
		{
			Name:              "bad fixed secrets",
			ExpectPluginError: "kid b6a5717df9dc13c9b15aab32dc811fd38144d43c: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key",
			Config: `
				secrets:
				  b6a5717df9dc13c9b15aab32dc811fd38144d43c: |
				    -----BEGIN RSA PUBLIC KEY 
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
		},
		{
			Name:              "empty fixed secrets",
			ExpectPluginError: "kid b6a5717df9dc13c9b15aab32dc811fd38144d43c: invalid key: Key is empty",
			Config: `
				secrets:
				  b6a5717df9dc13c9b15aab32dc811fd38144d43c: ""
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS512,
			CookieName: "Authorization",
		},
		{
			Name:   "unknown issuer",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test", "iss": "unknown.com"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "no issuer",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{excludeIss: yes},
		},
		{
			Name:   "wildcard isser",
			Expect: http.StatusOK,
			Config: `
				issuers:
				    - "http://127.0.0.1:*/"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:   "bad wildcard isser",
			Expect: http.StatusUnauthorized,
			Config: `
				issuers:
				    - "http://example.com:*/"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{noAddIsser: yes},
		},
		{
			Name:         "key rotation",
			Expect:       http.StatusOK,
			ExpectCounts: map[string]int{jwksCalls: 3},
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodRS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{rotateKey: yes},
		},
		{
			Name:   "config bad body",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{configBadBody: yes},
		},
		{
			Name:   "keys bad url",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysBadURL: yes},
		},
		{
			Name:   "keys bad body",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysBadBody: yes},
		},
		{
			Name:   "config server internal error",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{configServerStatus: "500"},
		},
		{
			Name:   "keys server internal error",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{keysServerStatus: "500"},
		},
		{
			Name:   "invalid json",
			Expect: http.StatusUnauthorized,
			Config: `
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			Actions:    map[string]string{invalidJSON: invalid},
		},
		{
			Name:           "redirect with expired token",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/login?return_to=https://app.example.com/home?id=1",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{.URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{.URL}}`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:           "redirect with expired token and traefik-style URL",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/login?return_to=https://app.example.com/home?id=1",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{.URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{.URL}}`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
			Actions:    map[string]string{traefikURL: invalid},
		},
		{
			Name:           "redirect with missing claim",
			Expect:         http.StatusFound,
			ExpectRedirect: "https://example.com/unauthorized?return_to=https://app.example.com/home?id=1",
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{.URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{.URL}}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:   "redirect with bad interpolation",
			Expect: http.StatusInternalServerError,
			Config: `
				secret: fixed secret
				require:
					aud: test
				redirectUnauthorized: https://example.com/login?return_to={{.URL}}
				redirectForbidden: https://example.com/unauthorized?return_to={{.Unknown}}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:          "map headers",
			Expect:        http.StatusOK,
			ExpectHeaders: map[string]string{"X-Id": "1234"},
			Config: `
				issuers:
					- https://dummy.example.com
					- https://example.com
				secret: fixed secret
				require:
					aud: test
				headerMap:
					X-Id: user
				forwardToken: false`,
			Claims:     `{"aud": "test", "user": "1234"}`,
			Method:     jwt.SigningMethodHS256,
			HeaderName: "Authorization",
		},
		{
			Name:          "cookies",
			Expect:        http.StatusOK,
			ExpectCookies: map[string]string{"Test": "test", "Other": "other"},
			Cookies:       map[string]string{"Test": "test", "Other": "other"},
			Config: `
				issuers:
					- https://dummy.example.com
					- https://example.com
				secret: fixed secret
				require:
					aud: test
				forwardToken: false`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodHS256,
			CookieName: "Authorization",
		},
		{
			Name:   "InsecureSkipVerify",
			Expect: http.StatusOK,
			Config: `
				issuers:
					- "https://127.0.0.1/"
				InsecureSkipVerify:
					- "127.0.0.1"
				require:
					aud: test`,
			Claims:     `{"aud": "test"}`,
			Method:     jwt.SigningMethodES256,
			HeaderName: "Authorization",
			//			Actions:    map[string]string{noAddIsser: yes},
		},
	}

	for _, test := range tests {
		tester.Run(test.Name, func(tester *testing.T) {
			plugin, request, server, err := setup(&test)
			if err != nil {
				tester.Fatal(err)
			}
			if plugin == nil {
				return
			}
			defer server.Close()

			// Set up response
			response := httptest.NewRecorder()

			// Run the request
			plugin.ServeHTTP(response, request)

			// Check expectations
			if response.Code != test.Expect {
				tester.Fatalf("incorrect result code: got:%d expected:%d body: %s", response.Code, test.Expect, response.Body.String())
			}

			expectAllow := test.Expect == http.StatusOK && test.GrpcRequest == false
			if test.Allowed != expectAllow {
				tester.Fatalf("incorrect allowed/denied: was allowed:%t should allow:%t", test.Allowed, expectAllow)
			}

			if test.ExpectRedirect != "" {
				if response.Header().Get("Location") != test.ExpectRedirect {
					tester.Fatalf("Expected redirect of %s but got %s", test.ExpectRedirect, response.Header().Get("Location"))
				}
			}

			if test.ExpectHeaders != nil {
				for key, value := range test.ExpectHeaders {
					if request.Header.Get(key) != value {
						tester.Fatalf("Expected header %s=%s in %v", key, value, request.Header)
					}
				}
			}

			if test.ExpectResponseHeaders != nil {
				for key, value := range test.ExpectResponseHeaders {
					if response.Result().Header.Get(key) != value {
						tester.Fatalf("Expected response header %s=%s in %v", key, value, request.Header)
					}
				}
			}

			if test.ExpectCookies != nil {
				for key, value := range test.ExpectCookies {
					if cookie, err := request.Cookie(key); err != nil {
						tester.Fatalf("Expected cookie %s=%s in %v", key, value, request.Cookies())
					} else if cookie.Value != value {
						tester.Fatalf("Expected cookie %s=%s in %v", key, value, request.Cookies())
					}
				}
			}

			if test.ExpectCounts != nil {
				for key, value := range test.ExpectCounts {
					if test.Counts[key] != value {
						tester.Fatalf("Expected count of %d for %s but got %d (%v)", value, key, test.Counts[key], test.Counts)
					}
				}
			}
		})
	}
}

// createConfig creates a configuration from a YAML string using the same method traefik
func createConfig(text string) (*Config, error) {
	var config map[string]interface{}
	err := yaml.Unmarshal([]byte(strings.Replace(text, "\t", "    ", -1)), &config)
	if err != nil {
		return nil, err
	}

	result := CreateConfig()
	if len(config) == 0 {
		return result, nil
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToSliceHookFunc(","),
		WeaklyTypedInput: true,
		Result:           result,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create configuration decoder: %w", err)
	}

	err = decoder.Decode(config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}
	return result, nil
}

func setup(test *Test) (http.Handler, *http.Request, *httptest.Server, error) {
	// Set up test record
	if test.ClaimsMap == nil {
		if test.Claims == "" {
			test.Claims = "{}"
		}
		err := json.Unmarshal([]byte(test.Claims), &test.ClaimsMap)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Set up the config
	config, err := createConfig(test.Config)
	if err != nil {
		return nil, nil, nil, err
	}

	context := context.Background()

	request, err := http.NewRequestWithContext(context, http.MethodGet, "https://app.example.com/home?id=1", nil)
	if err != nil {
		return nil, nil, nil, err
	}

	if test.GrpcRequest == true {
		addGrpcHeaderToRequest(request)
	}

	if test.Actions[useFixedSecret] == yes {
		addTokenToRequest(test, config, request)
	}

	// Set up the environment
	if test.Environment != nil {
		for key, value := range test.Environment {
			os.Setenv(key, value)
		}
		defer func() {
			for key := range test.Environment {
				os.Unsetenv(key)
			}
		}()
	}

	test.Counts = make(map[string]int)

	// Run a test server to provide the key(s)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(response http.ResponseWriter, request *http.Request) {
		test.Counts[jwksCalls]++

		if _, ok := test.Actions[keysBadBody]; ok {
			response.Header().Add("Content-Length", "1")
			return
		}
		if status, ok := test.Actions[keysServerStatus]; ok {
			status, err := strconv.Atoi(status)
			if err != nil {
				panic(err)
			}
			response.WriteHeader(status)
			return
		} else {
			response.WriteHeader(http.StatusOK)
		}
		payload, err := json.Marshal(test.Keys)
		if err != nil {
			panic(err)
		}
		if test.Actions != nil {
			payload, err = jsonActions(test.Actions, payload)
			if err != nil {
				panic(err)
			}
		}
		fmt.Fprintln(response, string(payload))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(response http.ResponseWriter, request *http.Request) {
		if _, ok := test.Actions[configBadBody]; ok {
			response.Header().Add("Content-Length", "1")
			return
		}
		if status, ok := test.Actions[configServerStatus]; ok {
			status, err := strconv.Atoi(status)
			if err != nil {
				panic(err)
			}
			response.WriteHeader(status)
			return
		} else {
			response.WriteHeader(http.StatusOK)
		}
		var url string
		if _, ok := test.Actions[keysBadURL]; ok {
			url = "https://dummy.example.com"
		} else {
			url = test.URL
		}
		config := OpenIDConfiguration{
			JWKSURI: url + "/.well-known/jwks.json",
		}
		payload, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(response, string(payload))
	})
	server := httptest.NewServer(mux)
	test.URL = server.URL

	if _, present := test.Actions[noAddIsser]; !present {
		config.Issuers = append(config.Issuers, server.URL)
	}

	if test.ClaimsMap["iss"] == nil && test.Actions[excludeIss] == "" {
		test.ClaimsMap["iss"] = server.URL
	}

	// Create the plugin
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { test.Allowed = true })
	plugin, err := New(context, next, config, "test-jwt-middleware")
	if err != nil {
		if err.Error() == test.ExpectPluginError {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	if test.Actions[useFixedSecret] != yes {
		if _, ok := test.Actions[rotateKey]; ok {
			// Similate a key rotation by ...
			addTokenToRequest(test, config, request)          // adding a new key to the server ...
			plugin.ServeHTTP(httptest.NewRecorder(), request) // causing the plugin to fetch it and then ...
			test.Keys.Keys = nil                              // removing it from the server
		}

		addTokenToRequest(test, config, request)
	}
	return plugin, request, server, nil
}

func addGrpcHeaderToRequest(request *http.Request) {
	request.Header.Add("content-type", "application/grpc")
}

func addTokenToRequest(test *Test, config *Config, request *http.Request) {
	// Set up request
	if _, ok := test.Actions[traefikURL]; ok {
		request.URL.Host = ""
	}

	for key, value := range test.Cookies {
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	// Set the token in the request
	token := createTokenAndSaveKey(test, config)
	if token != "" {
		if test.CookieName != "" {
			request.AddCookie(&http.Cookie{Name: test.CookieName, Value: token})
		} else if test.HeaderName != "" {
			if test.BearerPrefix {
				token = "Bearer " + token
			}
			request.Header[test.HeaderName] = []string{token}
		} else if test.ParameterName != "" {
			query := request.URL.Query()
			query.Set(test.ParameterName, token)
			request.URL.RawQuery = query.Encode()
		}
	}
}

// jsonActions manipulates the JSON keys to test the middleware.
func jsonActions(actions map[string]string, keys []byte) ([]byte, error) {
	var data map[string]interface{}
	err := json.Unmarshal(keys, &data)
	if err != nil {
		return nil, err
	}
	if data["keys"] != nil {
		for _, key := range data["keys"].([]interface{}) {
			key := key.(map[string]interface{})
			for action, value := range actions {
				if strings.HasPrefix(action, "set:") {
					key[action[4:]] = value
				}
			}
		}
	}
	keys, err = json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if value, ok := actions[invalidJSON]; ok {
		keys = []byte(value)
	}
	return keys, nil
}

// createTokenAndSaveKey creates a token, a key pair as needed, signs the token and saves the key in the test.
func createTokenAndSaveKey(test *Test, config *Config) string {
	method := test.Method
	if method == nil {
		return ""
	}

	// Create a token from the claims
	token := jwt.NewWithClaims(method, test.ClaimsMap)

	// Generate or use a key pair based on the method and test mode
	var private interface{}
	var public interface{}
	var publicPEM string
	switch method {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		// HMAC - use the provided key from the config Secret.
		if config.Secret == "" {
			panic(fmt.Errorf("Secret is required for %s", method.Alg()))
		}
		private = []byte(config.Secret)
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		// RSA
		if test.Private == "" {
			// Generate a test RSA key pair
			secret, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			private = secret
			public = &secret.PublicKey
			publicPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&secret.PublicKey),
			}))
		} else {
			// Use the provided private key
			secret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(trimLines(test.Private)))
			if err != nil {
				panic(err)
			}
			private = secret
		}
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		// ECDSA
		if test.Private == "" {
			// Generate a test EC key pair
			var curve elliptic.Curve
			switch method {
			case jwt.SigningMethodES256:
				curve = elliptic.P256()
			case jwt.SigningMethodES384:
				curve = elliptic.P384()
			case jwt.SigningMethodES512:
				curve = elliptic.P521()
			}
			secret, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				panic(err)
			}
			private = secret
			public = &secret.PublicKey
			der, err := x509.MarshalPKIXPublicKey(&secret.PublicKey)
			if err != nil {
				panic(err)
			}
			publicPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: der,
			}))
		} else {
			// Use the provided private key
			secret, err := jwt.ParseECPrivateKeyFromPEM([]byte(trimLines(test.Private)))
			if err != nil {
				panic(err)
			}
			private = secret
		}
	default:
		panic("Unsupported signing method")
	}

	// Choose how to use the public key and/or kid based on the test type
	if test.Actions[useFixedSecret] == yes {
		// Take the generated public key to the fixed Secret
		config.Secret = publicPEM
	} else if public != nil {
		// Add the public key to the key set and set the kid in the token
		jwk, kid := convertKeyToJWKWithKID(public, method.Alg())
		test.Keys.Keys = append(test.Keys.Keys, jwk)
		token.Header["kid"] = kid
	} else if test.Private != "" {
		// Using a provided private key (and coresponding public key in the test config) so just set the kid
		if test.Kid == "" {
			panic("Kid is required for test with Private set")
		}
		token.Header["kid"] = test.Kid
	}

	// Sign with the private key and return the token
	signed, err := token.SignedString(private)
	if err != nil {
		panic(err)
	}
	return signed
}

// convertKeyToJWKWithKID converts a RSA key to a JWK JSON string
func convertKeyToJWKWithKID(key interface{}, algorithm string) (jose.JSONWebKey, string) {
	jwk := jose.JSONWebKey{
		Key:       key,
		Algorithm: algorithm,
		Use:       "sig",
	}
	bytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(bytes)
	return jwk, jwk.KeyID
}

func TestCanonicalizeDomains(tester *testing.T) {
	tests := []struct {
		Name     string
		domains  []string
		expected []string
	}{
		{
			Name:     "Default",
			domains:  []string{"https://example.com", "example.org/"},
			expected: []string{"https://example.com/", "example.org/"},
		},
	}
	for _, test := range tests {
		tester.Run(test.Name, func(tester *testing.T) {
			result := canonicalizeDomains(test.domains)
			if !reflect.DeepEqual(result, test.expected) {
				tester.Errorf("got: %s expected: %s", result, test.expected)
			}
		})
	}
}

func TestHostname(tester *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"https://test.example.com/", "test.example.com"},
		{"https://example.com:8080", "example.com"},
		{"https://example.com:8080/", "example.com"},
		{"https://example.com:8080/path", "example.com"},
		{"https://example.com:8080/path/", "example.com"},
		{"https://example.com:8080/path?query", "example.com"},
		{"https://example.\x00com", ""},
	}
	for _, test := range tests {
		tester.Run(test.input, func(tester *testing.T) {
			result := hostname(test.input)
			if result != test.expected {
				tester.Errorf("got: %s expected: %s", result, test.expected)
			}
		})
	}
}

func BenchmarkServeHTTP(benchmark *testing.B) {
	test := Test{
		Name:   "SigningMethodRS256 passes",
		Expect: http.StatusOK,
		Method: jwt.SigningMethodRS256,
		Config: `
			require:
				aud: test`,
		Claims:     `{"aud": "test"}`,
		HeaderName: "Authorization",
	}

	plugin, request, server, err := setup(&test)
	if err != nil {
		benchmark.Fatal(err)
	}
	if plugin == nil {
		return
	}
	defer server.Close()

	// Set up response
	response := httptest.NewRecorder()

	// Run one the request first to ensure the key is cached (as our test setup deliberately doens't)
	plugin.ServeHTTP(response, request)
	benchmark.ResetTimer()

	for count := 0; count < benchmark.N; count++ {
		// Run the request
		plugin.ServeHTTP(response, request)
	}
}

// trimLines trims leading and trailing spaces from all lines in a string
func trimLines(text string) string {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
