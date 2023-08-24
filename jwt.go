package jwt_middleware

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/danwakefield/fnmatch"
	"github.com/golang-jwt/jwt/v5"
)

// Config is the configuration for the plugin.
type Config struct {
	ValidMethods         []string
	Issuers              []string
	Secret               string                 `json:"secret,omitempty"`
	Require              map[string]interface{} `json:"require,omitempty"`
	Optional             bool                   `json:"optional,omitempty"`
	RedirectUnauthorized string                 `json:"redirectUnauthorized,omitempty"`
	RedirectForbidden    string                 `json:"redirectForbidden,omitempty"`
	CookieName           string                 `json:"cookieName,omitempty"`
	HeaderName           string                 `json:"headerName,omitempty"`
	ParameterName        string                 `json:"parameterName,omitempty"`
	HeaderMap            map[string]string      `json:"headerMap,omitempty"`
	ForwardToken         bool                   `json:"forwardToken,omitempty"`
	Freshness            int64                  `json:"freshness,omitempty"`
}

// JWTPlugin is a traefik middleware plugin that authorizes access based on JWT tokens.
type JWTPlugin struct {
	next                 http.Handler
	name                 string
	parser               *jwt.Parser
	secret               string
	issuers              []string
	require              map[string][]*template.Template
	lock                 sync.RWMutex
	keys                 map[string]interface{}
	issuerKeys           map[string]map[string]interface{}
	optional             bool
	redirectUnauthorized *template.Template
	redirectForbidden    *template.Template
	cookieName           string
	headerName           string
	parameterName        string
	headerMap            map[string]string
	forwardToken         bool
	freshness            int64
}

// TemplateVariables are the variables passed various Go templates for interpolation, such as the require and redirect templates.
type TemplateVariables struct {
	URL    string
	Scheme string
	Host   string
	Path   string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ValidMethods: []string{"RS256", "RS512", "ES256", "ES384", "ES512", "HS256"},
		CookieName:   "Authorization",
		HeaderName:   "Authorization",
		ForwardToken: true,
		Freshness:    3600,
	}
}

// New creates a new JWTPlugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.SetFlags(0)

	require, err := canonicalizeRequire(config.Require)
	if err != nil {
		return nil, err
	}
	plugin := JWTPlugin{
		next:                 next,
		name:                 name,
		parser:               jwt.NewParser(jwt.WithValidMethods(config.ValidMethods)),
		secret:               config.Secret,
		issuers:              canonicalizeDomains(config.Issuers),
		require:              require,
		keys:                 make(map[string]interface{}),
		issuerKeys:           make(map[string]map[string]interface{}),
		optional:             config.Optional,
		redirectUnauthorized: createTemplate(config.RedirectUnauthorized),
		redirectForbidden:    createTemplate(config.RedirectForbidden),
		cookieName:           config.CookieName,
		headerName:           config.HeaderName,
		parameterName:        config.ParameterName,
		headerMap:            config.HeaderMap,
		forwardToken:         config.ForwardToken,
		freshness:            config.Freshness,
	}

	for _, issuer := range plugin.issuers {
		if strings.Contains(issuer, "*") {
			continue
		}
		err := plugin.fetchKeys(issuer)
		if err != nil {
			log.Printf("failed to prefetch keys for %s: %v", issuer, err)
		}
	}

	return &plugin, nil
}

// ServeHTTP is the middleware entry point.
func (plugin *JWTPlugin) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	variables := plugin.createTemplateVariables(request)
	status, err := plugin.Validate(request)
	if err != nil {
		if plugin.redirectUnauthorized != nil {
			// Interactive clients should be redirected to the login page or unauthorized page.
			var redirectTemplate *template.Template
			if status == http.StatusUnauthorized || plugin.redirectForbidden == nil {
				redirectTemplate = plugin.redirectUnauthorized
			} else {
				redirectTemplate = plugin.redirectForbidden
			}
			url, err := expandTemplate(redirectTemplate, variables)
			if err != nil {
				log.Printf("failed to get redirect URL: %v", err)
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(response, request, url, http.StatusFound)
		} else {
			// Non-interactive (i.e. API) clients should get a 401 or 403 response.
			http.Error(response, err.Error(), status)
		}
		return
	}
	plugin.next.ServeHTTP(response, request)
}

// Validate validates the request and returns the HTTP status code or an error if the request is not valid. It also sets any headers that should be forwarded to the backend.
func (plugin *JWTPlugin) Validate(request *http.Request) (int, error) {
	token := plugin.extractToken(request)
	if token == "" {
		// No token provided
		if !plugin.optional {
			return http.StatusUnauthorized, fmt.Errorf("no token provided")
		}
	} else {
		// Token provided
		token, err := plugin.parser.Parse(token, plugin.GetKey)
		if err != nil {
			return http.StatusUnauthorized, err
		}

		claims := token.Claims.(jwt.MapClaims)

		// Validate claims
		for claim, expected := range plugin.require {
			expected, err := expandTemplates(expected, plugin.createTemplateVariables(request))
			if err != nil {
				return http.StatusInternalServerError, err
			}
			result := plugin.ValidateClaim(claim, expected, claims)
			if !result {
				err := fmt.Errorf("claim is not valid: %s", claim)
				// If the token is older than out freshness window, we allow that reauthorization might fix it
				iat, ok := claims["iat"]
				if ok && plugin.freshness != 0 && time.Now().Unix()-int64(iat.(float64)) > plugin.freshness {
					return http.StatusUnauthorized, err
				} else {
					return http.StatusForbidden, err
				}
			}
		}

		// Map any require claims to headers
		for header, claim := range plugin.headerMap {
			value, ok := claims[claim]
			if ok {
				request.Header.Add(header, fmt.Sprint(value))
			}
		}
	}

	return http.StatusOK, nil
}

// ValidateClaim validates a single claim, switching on the type and calling ValidateValue for each until valid or not.
func (plugin *JWTPlugin) ValidateClaim(claim string, expected []string, claims jwt.MapClaims) bool {
	value, ok := claims[claim]
	if ok {
		switch value := value.(type) {
		case string:
			return plugin.ValidateValue(value, expected)

		case []interface{}: // List
			for _, item := range value {
				switch item := item.(type) {
				case string:
					if plugin.ValidateValue(item, expected) {
						return true
					}
				}
			}

		case map[string]interface{}: // Object
			for item := range value {
				if plugin.ValidateValue(item, expected) {
					return true
				}
			}
		}
	}
	return false
}

// ValidateValue validates a single value against a list of expected values using fnmatch-style matching if specified
func (plugin *JWTPlugin) ValidateValue(value string, expected []string) bool {
	for _, expected := range expected {
		if fnmatch.Match(value, expected, 0) {
			return true
		}
	}
	return false
}

// GetKey gets the key for the given key ID from the plugin's key cache. If the key isn't present and the iss is valid according to the plugin's configuration, all keys for the iss are fetched and the key is looked up again.
func (plugin *JWTPlugin) GetKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"]
	if ok {
		for fetched := false; ; fetched = true {
			plugin.lock.RLock()
			key, ok := plugin.keys[kid.(string)]
			plugin.lock.RUnlock()
			if ok {
				return key, nil
			}

			if fetched {
				log.Printf("key %s: fetched and no match", kid)
				break
			}

			issuer, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
			if ok {
				issuer = canonicalizeDomain(issuer)
				if plugin.IsValidIssuer(issuer) {
					plugin.lock.Lock()
					if _, ok := plugin.keys[kid.(string)]; !ok {
						err := plugin.fetchKeys(issuer) // issue has trailing slash
						if err != nil {
							log.Printf("failed to fetch keys for %s: %v", issuer, err)
						}
					}
					plugin.lock.Unlock()
				}
			} else {
				break
			}
		}
	}

	// We fall back to any fixed secret
	if plugin.secret == "" {
		return nil, fmt.Errorf("no secret configured")
	}

	return []byte(plugin.secret), nil
}

// IsValidIssuer returns true if the issuer is allowed by the Issers configuration.
func (plugin *JWTPlugin) IsValidIssuer(issuer string) bool {
	for _, allowed := range plugin.issuers {
		if fnmatch.Match(allowed, issuer, 0) {
			return true
		}
	}
	return false
}

// fetchKeys fetches the keys from well-known jwks endpoint for the given issuer and adds them to the key map.
func (plugin *JWTPlugin) fetchKeys(issuer string) error {
	url := issuer + ".well-known/jwks.json" // issuer has trailing slash
	jwks, err := FetchJWKS(url)
	if err != nil {
		return err
	}
	for keyID, key := range jwks {
		log.Printf("fetched key:%s from url:%s", keyID, url)
		plugin.keys[keyID] = key
	}

	previous := plugin.issuerKeys[url]
	for keyID := range previous {
		if _, ok := jwks[keyID]; !ok {
			log.Printf("key:%s dropped by url:%s", keyID, url)
			delete(plugin.keys, keyID)
		}
	}
	plugin.issuerKeys[url] = jwks

	return nil
}

// canonicalizeRequire converts the require map from a map of stings or lists to a map of lists
func canonicalizeRequire(require map[string]interface{}) (map[string][]*template.Template, error) {
	converted := make(map[string][]*template.Template, len(require))
	for key, value := range require {
		var templates []*template.Template
		var err error
		switch value := value.(type) {
		case string:
			templates, err = createTemplates([]interface{}{value})
		case []interface{}:
			templates, err = createTemplates(value)
		default:
			return nil, fmt.Errorf("invalid type (%s) for required claim: %s", reflect.TypeOf(value), key)
		}
		if err != nil {
			return nil, err
		}
		converted[key] = templates
	}
	return converted, nil
}

// canonicalizeDomain adds a trailing slash to the domain
func canonicalizeDomain(domain string) string {
	if !strings.HasSuffix(domain, "/") {
		domain += "/"
	}
	return domain
}

// canonicalizeDomains adds a trailing slash to all domains
func canonicalizeDomains(domains []string) []string {
	for index, domain := range domains {
		domains[index] = canonicalizeDomain(domain)
	}
	return domains
}

// createTemplates creates a list of templates from the given  strings
func createTemplates(texts []interface{}) ([]*template.Template, error) {
	templates := make([]*template.Template, len(texts))
	for index, text := range texts {
		switch text := text.(type) {
		case string:
			templates[index] = createTemplate(text)
		default:
			return nil, fmt.Errorf("invalid type %s for template", reflect.TypeOf(text))
		}
	}
	return templates, nil
}

// createTemplate creates a template from the given redirect string, or nil if no specified.
func createTemplate(text string) *template.Template {
	if text == "" {
		return nil
	}
	return template.Must(template.New("template").Parse(text))
}

// createTemplateVariables creates a template data object for the given request.
func (plugin *JWTPlugin) createTemplateVariables(request *http.Request) *TemplateVariables {
	var variables TemplateVariables

	if request.URL.Host != "" {
		variables.URL = request.URL.String()
		variables.Scheme = request.URL.Scheme
		variables.Host = request.URL.Host
		variables.Path = request.URL.Path
	} else {
		// (In at lease some situations) Traefik set only the path in the request.URL, so we need to reconstruct it
		variables.Scheme = request.Header.Get("X-Forwarded-Proto")
		if variables.Scheme == "" {
			variables.Scheme = "https"
		}
		variables.Host = request.Host
		variables.Path = request.URL.RequestURI()
		variables.URL = fmt.Sprintf("%s://%s%s", variables.Scheme, variables.Host, variables.Path)
	}

	return &variables
}

// expandTemplates expands all templates in the given map.
func expandTemplates(templates []*template.Template, variables *TemplateVariables) ([]string, error) {
	// Expand all templates
	result := make([]string, len(templates))
	for index, template := range templates {
		value, err := expandTemplate(template, variables)
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

// expandTemplate returns the redirect URL from the plugin.redirect template and expands it with the given parameters.
func expandTemplate(redirectTemplate *template.Template, variables *TemplateVariables) (string, error) {
	var bytes bytes.Buffer
	err := redirectTemplate.Execute(&bytes, variables)
	if err != nil {
		return "", err
	}
	return bytes.String(), nil

}

// extractToken extracts the token from the request using the first configured method that finds one, in order of cookie, header, query parameter.
func (plugin *JWTPlugin) extractToken(request *http.Request) string {
	token := ""
	if plugin.cookieName != "" {
		token = plugin.extractTokenFromCookie(request)
	}
	if len(token) == 0 && plugin.headerName != "" {
		token = plugin.extractTokenFromHeader(request)
	}
	if len(token) == 0 && plugin.parameterName != "" {
		token = plugin.extractTokenFromQuery(request)
	}
	return token
}

// extractTokenFromCookie extracts the token from the cookie. If the token is found, it is removed from the cookies unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromCookie(request *http.Request) string {
	cookie, error := request.Cookie(plugin.cookieName)
	if error != nil {
		return ""
	}
	if !plugin.forwardToken {
		cookies := request.Cookies()
		request.Header.Del("Cookie")
		for _, cookie := range cookies {
			if cookie.Name != plugin.cookieName {
				request.AddCookie(cookie)
			}
		}
	}
	return cookie.Value
}

// extractTokenFromHeader extracts the token from the header. If the token is found, it is removed from the header unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromHeader(request *http.Request) string {
	header, ok := request.Header[plugin.headerName]
	if !ok {
		return ""
	}

	token := header[0]

	if !plugin.forwardToken {
		request.Header.Del(plugin.headerName)
	}

	if strings.HasPrefix(token, "Bearer ") {
		return token[7:]
	}
	return token
}

// extractTokenFromQuery extracts the token from the query parameter. If the token is found, it is removed from the query unless forwardToken is true.
func (plugin *JWTPlugin) extractTokenFromQuery(request *http.Request) string {
	if request.URL.Query().Has(plugin.parameterName) {
		token := request.URL.Query().Get(plugin.parameterName)
		if !plugin.forwardToken {
			query := request.URL.Query()
			query.Del(plugin.parameterName)
			request.URL.RawQuery = query.Encode()
			request.RequestURI = request.URL.RequestURI()
		}
		return token
	}
	return ""
}
