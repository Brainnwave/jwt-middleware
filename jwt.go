package jwt_middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/danwakefield/fnmatch"
	"github.com/golang-jwt/jwt/v5"
)

// Config is the configuration for the plugin.
type Config struct {
	ValidMethods         []string               `json:"validMethods,omitempty"`
	Issuers              []string               `json:"issuers,omitempty"`
	SkipPrefetch         bool                   `json:"skipPrefetch,omitempty"`
	InsecureSkipVerify   []string               `json:"insecureSkipVerify,omitempty"`
	Secret               string                 `json:"secret,omitempty"`
	Secrets              map[string]string      `json:"secrets,omitempty"`
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
	secret               interface{}
	issuers              []string
	clients              map[string]*http.Client
	defaultClient        *http.Client
	require              map[string][]Requirement
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
	environment          map[string]string
}

// TemplateVariables are the per-request variables passed to Go templates for interpolation, such as the require and redirect templates.
// This has become a map rather than a struct now because we add the environment variables to it.
type TemplateVariables map[string]string

// Requirement is a requirement for a claim.
type Requirement interface {
	Validate(value interface{}, variables *TemplateVariables) bool
}

// ValueRequirement is a requirement for a claim that is a known value.
type ValueRequirement struct {
	value  interface{}
	nested interface{}
}

// TemplateRequirement is a dynamic requirement for a claim that uses a template that needs interpolating per request.
type TemplateRequirement struct {
	template *template.Template
	nested   interface{}
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ValidMethods: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256"},
		CookieName:   "Authorization",
		HeaderName:   "Authorization",
		ForwardToken: true,
		Freshness:    3600,
	}
}

func setupSecret(secret string) (interface{}, error) {
	// If secret is empty, we don't have a fixed secret
	if secret == "" {
		return nil, nil
	}

	// If plugin.secret is a PEM-encoded public key, return the public key
	if strings.HasPrefix(secret, "-----BEGIN RSA PUBLIC KEY") {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(secret))
	}

	if strings.HasPrefix(secret, "-----BEGIN EC PUBLIC KEY") || strings.HasPrefix(secret, "-----BEGIN PUBLIC KEY") {
		return jwt.ParseECPublicKeyFromPEM([]byte(secret))
	}

	// Otherwise, we assume it's a shared HMAC secret
	return []byte(secret), nil
}

// environment returns the environment variables as a map
func environment() map[string]string {
	environment := os.Environ()
	variables := make(map[string]string, len(environment))
	for _, variable := range environment {
		pair := strings.Split(variable, "=")
		variables[pair[0]] = pair[1]
	}
	return variables
}

// New creates a new JWTPlugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.SetFlags(0)

	secret, err := setupSecret(config.Secret)
	if err != nil {
		return nil, err
	}

	plugin := JWTPlugin{
		next:                 next,
		name:                 name,
		parser:               jwt.NewParser(jwt.WithValidMethods(config.ValidMethods)),
		secret:               secret,
		issuers:              canonicalizeDomains(config.Issuers),
		clients:              createClients(config.InsecureSkipVerify),
		defaultClient:        &http.Client{},
		require:              convertRequire(config.Require),
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
		environment:          environment(),
	}

	// If we have secrets, add them to the key cache
	for kid, raw := range config.Secrets {
		secret, err := setupSecret(raw)
		if err != nil {
			return nil, fmt.Errorf("kid %s: %v", kid, err)
		}
		if secret == nil {
			return nil, fmt.Errorf("kid %s: invalid key: Key is empty", kid)
		}
		plugin.keys[kid] = secret
	}
	plugin.issuerKeys["internal"] = internalIssuerKeys(config.Secrets)

	// Prefetch keys for all issuers (that don't contain a wildcard) unless skipPrefetch was set
	if !config.SkipPrefetch {
		for _, issuer := range plugin.issuers {
			if !strings.Contains(issuer, "*") {
				err := plugin.fetchKeys(issuer)
				if err != nil {
					log.Printf("failed to prefetch keys for %s: %v", issuer, err)
				}
			}
		}
	}

	return &plugin, nil
}

// internalIssuerKeys returns a dummy keyset for the keys in config.Secrets
func internalIssuerKeys(secrets map[string]string) map[string]interface{} {
	keys := make(map[string]interface{}, len(secrets))
	for kid := range secrets {
		keys[kid] = nil
	}
	return keys
}

// ServeHTTP is the middleware entry point.
func (plugin *JWTPlugin) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	variables := plugin.createTemplateVariables(request)
	status, err := plugin.validate(request, variables)
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
			// If the request is a GRPC request, we return a GRPC compatible response.
			if strings.Contains(request.Header.Get("Content-Type"), "application/grpc") {
				// Set the content type to application/grpc
				response.Header().Set("Content-Type", "application/grpc")
				// If status code is 401, set grpc-status to 16 (UNAUTHENTICATED), else if status code is 403, set grpc-status to 7 (PERMISSION_DENIED)
				if status == http.StatusUnauthorized {
					response.Header().Set("grpc-status", "16")
					response.Header().Set("grpc-message", "UNAUTHENTICATED")
				} else if status == http.StatusForbidden {
					response.Header().Set("grpc-status", "7")
					response.Header().Set("grpc-message", "PERMISSION_DENIED")
				}
				// Set HTTP status code to 200
				response.WriteHeader(http.StatusOK)
			} else {
				// Regular HTTP response
				http.Error(response, err.Error(), status)
			}
		}
		return
	}
	plugin.next.ServeHTTP(response, request)
}

// validate validates the request and returns the HTTP status code or an error if the request is not valid. It also sets any headers that should be forwarded to the backend.
func (plugin *JWTPlugin) validate(request *http.Request, variables *TemplateVariables) (int, error) {
	token := plugin.extractToken(request)
	if token == "" {
		// No token provided
		if !plugin.optional {
			return http.StatusUnauthorized, fmt.Errorf("no token provided")
		}
	} else {
		// Token provided
		token, err := plugin.parser.Parse(token, plugin.getKey)
		if err != nil {
			return http.StatusUnauthorized, err
		}

		claims := token.Claims.(jwt.MapClaims)

		// Validate that claims match - AND
		for claim, requirements := range plugin.require {
			if !plugin.validateClaim(claim, claims, requirements, variables) {
				err := fmt.Errorf("claim is not valid: %s", claim)
				// If the token is older than our freshness window, we allow that reauthorization might fix it
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

// Validate checks value against the requirement, calling ourself recursively for object and array values.
// variables is required in the interface and passed on recusrively but ultimately ignored by ValueRequirement
// having been already interpolated by TemplateRequirement
func (requirement ValueRequirement) Validate(value interface{}, variables *TemplateVariables) bool {
	switch value := value.(type) {
	case []interface{}:
		for _, value := range value {
			if requirement.Validate(value, variables) {
				return true
			}
		}
	case map[string]interface{}:
		for value, nested := range value {
			if requirement.Validate(value, variables) && requirement.ValidateNested(nested) {
				return true
			}
		}
	case string:
		required, ok := requirement.value.(string)
		if !ok {
			return false
		}
		return fnmatch.Match(value, required, 0) || value == fmt.Sprintf("*.%s", required)
	}

	return reflect.DeepEqual(value, requirement.value)
}

// ValidateNested checks value against the nested requirement
func (requirement ValueRequirement) ValidateNested(value interface{}) bool {
	// The nested requirement may be a single required value, or an OR choice of acceptable values. Convert to a slice of values.
	var required []interface{}
	switch nested := requirement.nested.(type) {
	case nil:
		// If the nested requirement is nil, we don't care about the nested claims that brought us here and the value is always valid.
		return true
	case []interface{}:
		required = nested
	case interface{}:
		required = []interface{}{nested}
	}

	// Likewise, the value may be a single claim value or an array of several granted claims values. Convert to a slice of values.
	var supplied []interface{}
	switch value := value.(type) {
	case []interface{}:
		supplied = value
	case interface{}:
		supplied = []interface{}{value}
	}

	// If any of the values match any of the nested requirement, the claim is valid.
	for _, required := range required {
		for _, supplied := range supplied {
			if reflect.DeepEqual(required, supplied) {
				return true
			}
		}
	}
	return false
}

// Validate interpolates the requirement template with the given variables and then delegates to ValueRequirement.
func (requirement TemplateRequirement) Validate(value interface{}, variables *TemplateVariables) bool {
	var buffer bytes.Buffer
	err := requirement.template.Execute(&buffer, variables)
	if err != nil {
		log.Printf("Error executing template: %s", err)
		return false
	}
	return ValueRequirement{value: buffer.String(), nested: requirement.nested}.Validate(value, variables)
}

// convertRequire converts the require configuration to a map of requirements.
func convertRequire(require map[string]interface{}) map[string][]Requirement {
	converted := make(map[string][]Requirement, len(require))
	for key, value := range require {
		switch value := value.(type) {
		case []interface{}:
			requirements := make([]Requirement, len(value))
			for index, value := range value {
				requirements[index] = createRequirement(value, nil)
			}
			converted[key] = requirements
		case map[string]interface{}:
			requirements := make([]Requirement, len(value))
			index := 0
			for key, value := range value {
				requirements[index] = createRequirement(key, value)
				index++
			}
			converted[key] = requirements
		default:
			converted[key] = []Requirement{createRequirement(value, nil)}
		}

	}
	return converted
}

// createRequirement creates a Requirement of the correct type from the given value (and any nested value).
func createRequirement(value interface{}, nested interface{}) Requirement {
	switch value := value.(type) {
	case string:
		if strings.Contains(value, "{{") && strings.Contains(value, "}}") {
			return TemplateRequirement{
				template: template.Must(template.New("template").Option("missingkey=error").Parse(value)),
				nested:   nested,
			}
		}
	}
	return ValueRequirement{value: value, nested: nested}
}

// validateClaim valideates a single claim against the requirement(s) for that claim (any match with satisfy - OR).
func (plugin *JWTPlugin) validateClaim(claim string, claims jwt.MapClaims, requirements []Requirement, variables *TemplateVariables) bool {
	value, ok := claims[claim]
	if ok {
		for _, requirement := range requirements {
			if requirement.Validate(value, variables) {
				return true
			}
		}
	}
	return false
}

// getKey gets the key for the given key ID from the plugin's key cache. If the key isn't present and the iss is valid according to the plugin's configuration, all keys for the iss are fetched and the key is looked up again.
func (plugin *JWTPlugin) getKey(token *jwt.Token) (interface{}, error) {
	err := fmt.Errorf("no secret configured")
	if len(plugin.issuers) > 0 {
		kid, ok := token.Header["kid"]
		if ok {
			fetched := false
			for looped := false; ; looped = true {
				plugin.lock.RLock()
				key, ok := plugin.keys[kid.(string)]
				plugin.lock.RUnlock()
				if ok {
					return key, nil
				}

				if looped {
					if fetched {
						log.Printf("key %s: fetched and no match", kid)
					}
					break
				}

				issuer, ok := token.Claims.(jwt.MapClaims)["iss"].(string)
				if ok {
					issuer = canonicalizeDomain(issuer)
					if plugin.isValidIssuer(issuer) {
						plugin.lock.Lock()
						if _, ok := plugin.keys[kid.(string)]; !ok {
							err = plugin.fetchKeys(issuer)
							if err == nil {
								fetched = true
							} else {
								log.Printf("failed to fetch keys for %s: %v", issuer, err)
							}
						}
						plugin.lock.Unlock()
					} else {
						err = fmt.Errorf("issuer %s is not valid", issuer)
					}
				} else {
					break
				}
			}
		}
	}

	// We fall back to any fixed secret
	if plugin.secret == nil {
		return nil, err
	}

	return plugin.secret, nil
}

// isValidIssuer returns true if the issuer is allowed by the Issers configuration.
func (plugin *JWTPlugin) isValidIssuer(issuer string) bool {
	for _, allowed := range plugin.issuers {
		if fnmatch.Match(allowed, issuer, 0) {
			return true
		}
	}
	return false
}

// hostname returns the hostname for the given URL.
func hostname(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		log.Printf("failed to parse url %s: %v", address, err)
		return ""
	}
	return parsed.Hostname()
}

// clientForURL returns the http.Client for the given URL, or the default client if no specific client is configured.
func (plugin *JWTPlugin) clientForURL(address string) *http.Client {
	client, ok := plugin.clients[hostname(address)]
	if ok {
		return client
	} else {
		return plugin.defaultClient
	}
}

// fetchKeys fetches the keys from well-known jwks endpoint for the given issuer and adds them to the key map.
func (plugin *JWTPlugin) fetchKeys(issuer string) error {
	configURL := issuer + ".well-known/openid-configuration" // issuer has trailing slash
	config, err := FetchOpenIDConfiguration(configURL, plugin.clientForURL(configURL))
	if err != nil {
		return err
	}
	log.Printf("fetched openid-configuration from url:%s", configURL)

	url := config.JWKSURI
	jwks, err := FetchJWKS(url, plugin.clientForURL(url))
	if err != nil {
		return err
	}
	for keyID, key := range jwks {
		log.Printf("fetched key:%s from url:%s", keyID, url)
		plugin.keys[keyID] = key
	}

	plugin.issuerKeys[url] = jwks
	plugin.purgeKeys()

	return nil
}

// isIssuedKey returns true if the key exists in the issuerKeys map
func (plugin *JWTPlugin) isIssuedKey(keyID string) bool {
	for _, issuerKeys := range plugin.issuerKeys {
		if _, ok := issuerKeys[keyID]; ok {
			return true
		}
	}
	return false
}

// purgeKeys purges all keys from plugin.keys that are not in the issuerKeys map.
func (plugin *JWTPlugin) purgeKeys() {
	for keyID := range plugin.keys {
		if !plugin.isIssuedKey(keyID) {
			log.Printf("key:%s dropped", keyID)
			delete(plugin.keys, keyID)
		}
	}
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

// createClients reads a list of domains in the InsecureSkipVerify configuration and creates a map of domains to http.Client with InsecureSkipVerify set.
func createClients(insecureSkipVerify []string) map[string]*http.Client {
	// Create a single client with InsecureSkipVerify set
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}

	// Use it for all issuers in the InsecureSkipVerify configuration
	clients := make(map[string]*http.Client, len(insecureSkipVerify))
	for _, issuer := range insecureSkipVerify {
		clients[issuer] = client
	}
	return clients
}

// createTemplate creates a template from the given string, or nil if not specified.
func createTemplate(text string) *template.Template {
	if text == "" {
		return nil
	}
	return template.Must(template.New("template").Option("missingkey=error").Parse(text))
}

// createTemplateVariables creates a template data map for the given request.
// We start with a clone of our environment variables and add the the per-request variables.
// The purpose of environment variables is to allow a easier way to set a configurable but then fixed value for a claim
// requirement in the configuration file (as rewriting the configuration file is harder than setting environment variables).
func (plugin *JWTPlugin) createTemplateVariables(request *http.Request) *TemplateVariables {
	// copy the environment variables
	variables := make(TemplateVariables, len(plugin.environment)+4)
	for key, value := range plugin.environment {
		variables[key] = value
	}

	if request.URL.Host != "" {
		variables["Scheme"] = request.URL.Scheme
		variables["Host"] = request.URL.Host
		variables["Path"] = request.URL.Path
		variables["URL"] = request.URL.String()
	} else {
		// (In at lease some situations) Traefik sets only the path in the request.URL, so we need to reconstruct it
		variables["Scheme"] = request.Header.Get("X-Forwarded-Proto")
		if variables["Scheme"] == "" {
			variables["Scheme"] = "https"
		}
		variables["Host"] = request.Host
		variables["Path"] = request.URL.RequestURI()
		variables["URL"] = fmt.Sprintf("%s://%s%s", variables["Scheme"], variables["Host"], variables["Path"])
	}

	return &variables
}

// expandTemplate returns the redirect URL from the plugin.redirect template and expands it with the given parameters.
func expandTemplate(redirectTemplate *template.Template, variables *TemplateVariables) (string, error) {
	var buffer bytes.Buffer
	err := redirectTemplate.Execute(&buffer, variables)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil

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
