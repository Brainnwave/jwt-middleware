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
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

type Test struct {
	Isolate              int
	Name                 string
	Result               bool
	Expect               int
	ExpectPluginError    string
	ExpectRedirect       string
	ExpectHeaders        map[string]string
	ExpectCookies        map[string]string
	Issuer               string   // Issuer is the issuer to use for the token's iss claim
	Issuers              []string // Issuers is for the Plugin to prefetch / allow
	Keys                 jose.JSONWebKeySet
	Secret               string
	Method               jwt.SigningMethod
	Require              string
	RequireMap           map[string]interface{}
	Optional             bool
	RedirectUnauthorized string
	RedirectForbidden    string
	CookieName           string
	HeaderName           string
	ParameterName        string
	BearerPrefix         bool
	HeaderMap            map[string]string
	Cookies              map[string]string
	ForwardToken         bool
	Claims               string
	ClaimsMap            jwt.MapClaims
	Actions              map[string]string
}

func TestServeHTTP(tester *testing.T) {
	tests := []Test{
		{
			Name:          "no token",
			Expect:        http.StatusUnauthorized,
			Method:        nil,
			Require:       `{"aud": "test"}`,
			CookieName:    "Authorization",
			HeaderName:    "Authorization",
			ParameterName: "token",
		},
		{
			Name:          "optional with no token",
			Expect:        http.StatusOK,
			Method:        nil,
			Require:       `{"aud": "test"}`,
			Optional:      true,
			CookieName:    "Authorization",
			HeaderName:    "Authorization",
			ParameterName: "token",
		},
		{
			Name:       "token in cookie",
			Expect:     http.StatusOK,
			Issuers:    []string{"https://dummy.exmaple.com", "https://exmaple.com"},
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			CookieName: "Authorization",
		},
		{
			Name:                 "token in header",
			Expect:               http.StatusOK,
			Secret:               "fixed secret",
			Method:               jwt.SigningMethodHS256,
			RedirectUnauthorized: "https://example.com/login?return_to={{.URL}}",
			RedirectForbidden:    "https://example.com/unauthorized?return_to={{.URL}}",
			Require:              `{"aud": "test"}`,
			Claims:               `{"aud": "test"}`,
			HeaderName:           "Authorization",
		},
		{
			Name:         "token in header with Bearer prefix",
			Expect:       http.StatusOK,
			Secret:       "fixed secret",
			Method:       jwt.SigningMethodHS256,
			Require:      `{"aud": "test"}`,
			Claims:       `{"aud": "test"}`,
			HeaderName:   "Authorization",
			BearerPrefix: true,
		},
		{
			Name:          "token in query string",
			Expect:        http.StatusOK,
			Secret:        "fixed secret",
			Method:        jwt.SigningMethodHS256,
			Require:       `{"aud": "test"}`,
			Claims:        `{"aud": "test"}`,
			ParameterName: "token",
		},
		{
			Name:       "expired token",
			Expect:     http.StatusUnauthorized,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test", "exp": 1692043084}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "invalid claim",
			Expect:     http.StatusForbidden,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "other"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "value requirement with invalid type of claim",
			Expect:     http.StatusForbidden,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": 123}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "missing claim",
			Expect:     http.StatusForbidden,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:    "StatusUnauthorized when within window of freshness",
			Expect:  http.StatusUnauthorized,
			Secret:  "fixed secret",
			Method:  jwt.SigningMethodHS256,
			Require: `{"aud": "test"}`,
			ClaimsMap: jwt.MapClaims{
				"aud": "other",
				"iat": 1692451139, //time.Now().Unix(),
			},
			HeaderName: "Authorization",
		},
		{
			Name:       "template requirement",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "{{.Host}}"}`,
			Claims:     `{"authority": "*.example.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "bad template requirement",
			Expect:     http.StatusForbidden, // TODO add check on startup
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "{{.XHost}}"}`,
			Claims:     `{"authority": "*.example.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "wildcard claim",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "test.example.com"}`,
			Claims:     `{"authority": "*.example.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "wildcard claim no subdomain",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "example.com"}`,
			Claims:     `{"authority": "*.example.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "wildcard list claim",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "test.example.com"}`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "integer claim",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"group": 456}`,
			Claims:     `{"group": [123, 456]}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "list with wildcard list claim",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": ["test.example.com", "other.other.com"]}`,
			Claims:     `{"authority": ["*.example.com", "other.example.com"]}`,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single required and nested",
			Expect: http.StatusOK,
			Secret: "fixed secret",
			Method: jwt.SigningMethodHS256,
			Require: `{
				"authority": {
					"test.example.com": "user"
				}
			}`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and single requred and multilpe nested",
			Expect: http.StatusOK,
			Secret: "fixed secret",
			Method: jwt.SigningMethodHS256,
			Require: `{
				"authority": {
					"test.example.com": "user"
				}
			}`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and multiple required and single nested",
			Expect: http.StatusOK,
			Secret: "fixed secret",
			Method: jwt.SigningMethodHS256,
			Require: `{
				"authority": {
					"test.example.com": ["user", "admin"]
				}
			}`,
			Claims: `{
				"authority": {
					"*.example.com": "user"
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object and irrelevant nested value claim",
			Expect: http.StatusOK,
			Secret: "fixed secret",
			Method: jwt.SigningMethodHS256,
			Require: `{
				"authority": "test.example.com"
			}`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "admin"]
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:   "wildcard object bad nested value claim",
			Expect: http.StatusForbidden,
			Secret: "fixed secret",
			Method: jwt.SigningMethodHS256,
			Require: `{
				"authority": {
					"test.example.com": "admin"
				}
			}`,
			Claims: `{
				"authority": {
					"*.example.com": ["user", "guest"]
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "bad wildcard claim",
			Expect:     http.StatusForbidden,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "test.company.com"}`,
			Claims:     `{"authority": "*.example.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "bad wildcard list claim",
			Expect:     http.StatusForbidden,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"authority": "test.example.com"}`,
			Claims:     `{"authority": ["*.company.com", "other.example.com"]}`,
			HeaderName: "Authorization",
		},
		{
			Name:    "bad wildcard object claim",
			Expect:  http.StatusForbidden,
			Secret:  "fixed secret",
			Method:  jwt.SigningMethodHS256,
			Require: `{"authority": "test.example.com"}`,
			Claims: `{
				"authority": {
					"*.company.com": ["user", "admin"]
				}
			}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodHS256",
			Expect:     http.StatusOK,
			Secret:     "fixed secret",
			Method:     jwt.SigningMethodHS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodRS256",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodRS512",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS512,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodES256",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodES384",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES384,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodES512",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES512,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "SigningMethodRS256 with missing kid",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:       "SigningMethodRS256 with bad n",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:n": "dummy"},
		},
		{
			Name:       "SigningMethodRS256 with bad e",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:e": "dummy"},
		},
		{
			Name:       "SigningMethodES256 with missing kid",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:kid": ""},
		},
		{
			Name:       "SigningMethodES256 with bad x",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:x": "dummy"},
		},
		{
			Name:       "SigningMethodES256 with bad y",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:y": "dummy"},
		},
		{
			Name:       "SigningMethodES256 with missing crv",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": "dummy"},
		},
		{
			Name:       "SigningMethodES256 with missing crv and alg",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": "dummy", "set:alg": "dummy"},
		},
		{
			Name:       "SigningMethodES384 with missing crv",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES384,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": "dummy"},
		},
		{
			Name:       "SigningMethodES512 with missing crv",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES512,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"set:crv": "dummy"},
		},
		{
			Name:       "SigningMethodRS256 in fixed secret",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"useFixedSecret": "yes", "noAddIsser": "yes"},
		},
		{
			Name:       "SigningMethodRS512 in fixed secret",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS512,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"useFixedSecret": "yes", "noAddIsser": "yes"},
		},
		{
			Name:       "SigningMethodES256 in fixed secret",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"useFixedSecret": "yes", "noAddIsser": "yes"},
		},
		{
			Name:       "SigningMethodES384 in fixed secret",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES384,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"useFixedSecret": "yes", "noAddIsser": "yes"},
		},
		{
			Name:       "SigningMethodES512 in fixed secret",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodES512,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"useFixedSecret": "yes", "noAddIsser": "yes"},
		},
		{
			Name:              "bad fixed secret",
			ExpectPluginError: "invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key",
			Secret:            "-----BEGIN RSA PUBLIC KEY",
			Method:            jwt.SigningMethodRS512,
			Require:           `{"aud": "test"}`,
			Claims:            `{"aud": "test"}`,
			CookieName:        "Authorization",
		},
		{
			Name:       "unknown issuer",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test", "iss": "unknown.com"}`,
			HeaderName: "Authorization",
		},
		{
			Name:       "no issuer",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"excludeIss": "yes"},
		},
		{
			Name:       "wildcard isser",
			Expect:     http.StatusOK,
			Issuers:    []string{"http://127.0.0.1:*/"},
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"noAddIsser": "yes"},
		},
		{
			Name:       "bad wildcard isser",
			Expect:     http.StatusUnauthorized,
			Issuers:    []string{"http://example.com:*/"},
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"noAddIsser": "yes"},
		},
		{
			Name:       "key rotation",
			Expect:     http.StatusOK,
			Method:     jwt.SigningMethodRS256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"rotateKey": "yes"},
		},
		{
			Name:       "server internal error",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"serverStatus": "500"},
		},
		{
			Name:       "invalid json",
			Expect:     http.StatusUnauthorized,
			Method:     jwt.SigningMethodES256,
			Require:    `{"aud": "test"}`,
			Claims:     `{"aud": "test"}`,
			HeaderName: "Authorization",
			Actions:    map[string]string{"invalidJSON": "invalid"},
		},
		{
			Name:                 "redirect with expired token",
			Expect:               http.StatusFound,
			ExpectRedirect:       "https://example.com/login?return_to=https://app.example.com/home?id=1",
			Secret:               "fixed secret",
			Method:               jwt.SigningMethodHS256,
			Require:              `{"aud": "test"}`,
			RedirectUnauthorized: "https://example.com/login?return_to={{.URL}}",
			RedirectForbidden:    "https://example.com/unauthorized?return_to={{.URL}}",
			Claims:               `{"aud": "test", "exp": 1692043084}`,
			HeaderName:           "Authorization",
		},
		{
			Name:                 "redirect with expired token and traefik-style URL",
			Expect:               http.StatusFound,
			ExpectRedirect:       "https://example.com/login?return_to=https://app.example.com/home?id=1",
			Secret:               "fixed secret",
			Method:               jwt.SigningMethodHS256,
			Require:              `{"aud": "test"}`,
			RedirectUnauthorized: "https://example.com/login?return_to={{.URL}}",
			RedirectForbidden:    "https://example.com/unauthorized?return_to={{.URL}}",
			Claims:               `{"aud": "test", "exp": 1692043084}`,
			HeaderName:           "Authorization",
			Actions:              map[string]string{"traefikURL": "invalid"},
		},
		{
			Name:                 "redirect with missing claim",
			Expect:               http.StatusFound,
			ExpectRedirect:       "https://example.com/unauthorized?return_to=https://app.example.com/home?id=1",
			Secret:               "fixed secret",
			Method:               jwt.SigningMethodHS256,
			Require:              `{"aud": "test"}`,
			RedirectUnauthorized: "https://example.com/login?return_to={{.URL}}",
			RedirectForbidden:    "https://example.com/unauthorized?return_to={{.URL}}",
			Claims:               `{}`,
			HeaderName:           "Authorization",
		},
		{
			Name:                 "redirect with bad interpolation",
			Expect:               http.StatusInternalServerError,
			ExpectRedirect:       "https://example.com/unauthorized?return_to=https://app.example.com/home?id=1",
			Secret:               "fixed secret",
			Method:               jwt.SigningMethodHS256,
			Require:              `{"aud": "test"}`,
			RedirectUnauthorized: "https://example.com/login?return_to={{.URL}}",
			RedirectForbidden:    "https://example.com/unauthorized?return_to={{.Unknown}}",
			Claims:               `{}`,
			HeaderName:           "Authorization",
		},
		{
			Name:          "map headers",
			Expect:        http.StatusOK,
			ExpectHeaders: map[string]string{"X-Id": "1234"},
			Issuers:       []string{"https://dummy.exmaple.com", "https://exmaple.com"},
			Secret:        "fixed secret",
			Method:        jwt.SigningMethodHS256,
			Require:       `{"aud": "test"}`,
			HeaderMap:     map[string]string{"X-Id": "user"},
			Claims:        `{"aud": "test", "user": "1234"}`,
			HeaderName:    "Authorization",
		},
		{
			Name:          "cookies",
			Expect:        http.StatusOK,
			ExpectCookies: map[string]string{"Test": "test", "Other": "other"},
			Issuers:       []string{"https://dummy.exmaple.com", "https://exmaple.com"},
			Secret:        "fixed secret",
			Method:        jwt.SigningMethodHS256,
			Require:       `{"aud": "test"}`,
			Claims:        `{"aud": "test"}`,
			Cookies:       map[string]string{"Test": "test", "Other": "other"},
			CookieName:    "Authorization",
			ForwardToken:  false,
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
				tester.Fatal("incorrect result code: got:", response.Code, "expected:", test.Expect, "body:", response.Body.String())
			}

			if test.Result != (test.Expect == http.StatusOK) {
				tester.Fatal("incorrect allowed/denied: was allowed:", test.Result, "should allow:", test.Expect == http.StatusOK)
			}

			if response.Code == http.StatusFound && test.ExpectRedirect != "" {
				if response.Header().Get("Location") != test.ExpectRedirect {
					tester.Fatal("Expected redirect of " + test.ExpectRedirect + " but got " + response.Header().Get("Location"))
				}
			}

			if test.ExpectHeaders != nil {
				for key, value := range test.ExpectHeaders {
					if request.Header.Get(key) != value {
						tester.Fatalf("Expected header %s=%s in %v", key, value, request.Header)
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
		})
	}
}

func setup(test *Test) (http.Handler, *http.Request, *httptest.Server, error) {
	// Set up the config
	if test.RequireMap == nil {
		if test.Require == "" {
			test.Require = "{}"
		}
		err := json.Unmarshal([]byte(test.Require), &test.RequireMap)
		if err != nil {
			return nil, nil, nil, err
		}
	}

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

	context := context.Background()

	request, err := http.NewRequestWithContext(context, http.MethodGet, "https://app.example.com/home?id=1", nil)
	if err != nil {
		return nil, nil, nil, err
	}

	if test.Actions["useFixedSecret"] == "yes" {
		addTokenToRequest(test, request)
	}

	defaults := CreateConfig()
	config := Config{
		ValidMethods:         defaults.ValidMethods,
		Issuers:              test.Issuers,
		Secret:               test.Secret,
		Require:              test.RequireMap,
		Optional:             test.Optional,
		RedirectUnauthorized: test.RedirectUnauthorized,
		RedirectForbidden:    test.RedirectForbidden,
		CookieName:           coalesce(test.CookieName, defaults.CookieName),
		HeaderName:           coalesce(test.HeaderName, defaults.HeaderName),
		ParameterName:        coalesce(test.ParameterName, defaults.ParameterName),
		HeaderMap:            test.HeaderMap,
		ForwardToken:         test.ForwardToken, // || defaults.ForwardToken,
		Freshness:            defaults.Freshness,
	}

	// Run a test server to provide the key(s)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if status, ok := test.Actions["serverStatus"]; ok {
			status, err := strconv.Atoi(status)
			if err != nil {
				panic(err)
			}
			response.WriteHeader(status)
			return
		} else {
			response.WriteHeader(http.StatusOK)
		}
		keysJSON, err := json.Marshal(test.Keys)
		if err != nil {
			panic(err)
		}
		if test.Actions != nil {
			keysJSON, err = jsonActions(test.Actions, keysJSON)
			if err != nil {
				panic(err)
			}
		}
		fmt.Fprintln(response, string(keysJSON))
	}))
	test.Issuer = server.URL
	if _, present := test.Actions["noAddIsser"]; !present {
		config.Issuers = append(config.Issuers, server.URL)
	}

	if test.Issuer != "" && test.ClaimsMap["iss"] == nil && test.Actions["excludeIss"] == "" {
		test.ClaimsMap["iss"] = test.Issuer
	}

	// Create the plugin
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { test.Result = true })
	plugin, err := New(context, next, &config, "test-jwt-middleware")
	if err != nil {
		if err.Error() == test.ExpectPluginError {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	if test.Actions["useFixedSecret"] != "yes" {
		if _, ok := test.Actions["rotateKey"]; ok {
			// Similate a key rotation by ...
			addTokenToRequest(test, request)                  // adding a new key to the server ...
			plugin.ServeHTTP(httptest.NewRecorder(), request) // causing the plugin to fetch it and then ...
			test.Keys.Keys = nil                              // removing it from the server
		}

		addTokenToRequest(test, request)
	}
	return plugin, request, server, nil
}

func addTokenToRequest(test *Test, request *http.Request) {
	// Set up request
	if _, ok := test.Actions["traefikURL"]; ok {
		request.URL.Host = ""
	}

	for key, value := range test.Cookies {
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}

	// Set the token in the request
	token := createTokenAndSaveKey(test)
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
	if value, ok := actions["invalidJSON"]; ok {
		keys = []byte(value)
	}
	return keys, nil
}

// createTokenAndSaveKey creates a key, then a token and adds it to the key set, then token and keys for the test.
func createTokenAndSaveKey(test *Test) string {
	method := test.Method
	if method == nil {
		return ""
	}
	token := jwt.NewWithClaims(method, test.ClaimsMap)
	var private interface{}
	var public interface{}
	var publicPEM string
	switch method {
	case jwt.SigningMethodHS256:
		if test.Secret == "" {
			panic(fmt.Errorf("secret is required for %s", method.Alg()))
		}
		private = []byte(test.Secret)
	case jwt.SigningMethodRS256, jwt.SigningMethodRS512:
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
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
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
	default:
		panic("Unsupported signing method")
	}

	if test.Actions["useFixedSecret"] == "yes" {
		test.Secret = publicPEM
	} else if method != jwt.SigningMethodHS256 {
		jwk, kid := convertKeyToJWKWithKID(public, method.Alg())
		test.Keys.Keys = append(test.Keys.Keys, jwk)
		token.Header["kid"] = kid
	}
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

// coalesce returns the first non empty string
func coalesce(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func BenchmarkServeHTTP(benchmark *testing.B) {
	test := Test{
		Name:       "SigningMethodRS256 passes",
		Expect:     http.StatusOK,
		Method:     jwt.SigningMethodRS256,
		Require:    `{"aud": "test"}`,
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
