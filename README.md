[![Build](https://github.com/Brainnwave/jwt-middleware/actions/workflows/build.yml/badge.svg)](https://github.com/Brainnwave/jwt-middleware/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Brainnwave_jwt-middleware&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Brainnwave_jwt-middleware)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Brainnwave_jwt-middleware&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Brainnwave_jwt-middleware)

# Dynamic JWT Validation Middleware

This is a middleware plugin for [Traefik](https://github.com/containous/traefik) with the following features:
* Validation of JSON Web Tokens in cookies, headers, and/or query string parameters for access control.
* Dynamic lookup of public keys from the well-known OpenID configuration of whitelisted issuers.
* Flexible claim checks, including optional wildcards and Go template interpolation.
* Configurable HTTP redirects for unauthorized and forbidden calls for interactive requests.

## Configuration

1a. Add the plugin to traefik, either in your static traefik config file:
```yaml
experimental:
  plugins:
    jwt:
      moduleName: github.com/Brainnwave/jwt-middleware
      version: v1.1.10
```
1b. or with command-line options:

```yaml
command:
  ...
  - "--experimental.plugins.jwt.modulename=github.com/Brainnwave/jwt-middleware"
  - "--experimental.plugins.jwt.version=v1.1.10"
```

2) Configure and activate the plugin as a middleware in your dynamic traefik config:
```yaml
http:
  middlewares:
    secure-api:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          require:
            aud: test.example.com
```

3) use the middleware in services via docker-compose labels
```yaml
  labels:
    - "traefik.http.routers.my-service.middlewares=secure-api@file"
```

### Options

The plugin supports the following configuration options.

Name | Description
---- | ----
`issuers` | A list of trusted issuers to fetch JWKs from. Keys will be prefetched from these issuers on startup. If a token contains a `kid` that is not known and the `iss` claim matches one of the `issuers`, a call will be made to refresh the keys in the plugin. Any keys previously fetched from the issuer that are no longer retrieved will be removed from the plugin's cache on each fetch. fnmatch-style wildcards are supported to accommodate some multitenancy scenarios (e.g. `https://*.example.com`). It is not recommended to use wildcard `issuers` unless you understand the implication that any webserver on your domain could be used to spoof a JWK endpoint unless you have full confidence in your DNS security and what is running on all servers within the domain in question. 
`secret` | A shared secret or a fixed public key to use for signature validation. A fixed secret may be used in conjunction with `issuers` to combine dynamic and static keys. This can be useful when transitioning from earlier systems or for machine-to-machine tokens signed with internal keys. Note that if a dynamic key is not matched but a static secret is configured, the static secret will be used as a fallback key. If this secret is not of the correct type for the presented key, an error such as `token signature is invalid: key is of invalid type` will be returned to the user, which may be confusing. 
`require` | A map of zero or more claims that must be present and match against one or more values. If no claims are specified in `require`, all tokens that are validly signed by the trusted issuers or secrets will pass. If more than one claim is specified, each is required (i.e. an AND relationship exists for all the specified claims). For each claim, multiple values may be specified and the claim will be valid if any matches (i.e. an OR relations exists for values within a claim). fnmatch-style wildcards are optionally supported for claim values. If you do not wish to support wildcard claims, simply do not put such wildcards into the JWTs that you issue. See below for variables available with template interpolation.
`headerMap` | A map in the form of header: claim. Headers will be added (or overwritten) to the forwarded HTTP request from the claim values in the token. If the claim is not present, no action for that value is taken (and any existing header will remain unchanged).
`cookieName` | Name of the cookie to retrieve the token from if present. Default: `Authorization`. If token retrieval from cookies must be disabled for some reason, set to an empty string.  If `forwardAuth` is `false`, the cookie will be removed before forwarding to the backend.
`headerName` | Name of the Header to retrieve the token from if present. Default: `Authorization`. If token retrieval from headers must be disabled for some reason, set to an empty string. Tokens are supported either with or without a `Bearer ` prefix. If `forwardAuth` is `false`, the header will be removed before forwarding to the backend.
`parameterName` | Name of the query string parameter to retrieve the token from if present. Default: disabled. If `forwardAuth` is `false`, the query string parameter will be removed before forwarding to the backend.
`redirectUnauthorized` | URL to redirect Unauthorized (401) claims to instead of returning a 401 status code. This is intended for interactive requests where the user should be redirected to login and then returned to the page that access was attempted from. Go template interpolation may be used to construct a `return_to` parameter for the redirection. See examples and template variables below. 
`redirectForbidden` | URL to redirect Unauthorized (403) claims to instead of returning a 403 status code. As above, this is intended for interactive requests and the same template interpolation applies. This is most useful to redirect a user to explain that they do not have access to the resource, even though they are authenticated. Such pages may, for example, offer explanations of how access may be obtained or may offer to allow the user to try using a different identity. If `redirectUnauthorized` is given but not `redirectForbidden` the URL for `redirectUnauthorized` will be used, rather than returning an HTTP status to an interactive session.
`freshness` | Integer value in seconds to consider a token as "fresh" based on its `iat` claim, if present. If a token is not within this freshness window, the plugin allows that a user may have recently had new permissions and thus new claims granted since last logging in, and will issue a 401 in place of a 403 (as well as redirecting interactive sessions as if Unauthorized). Once a user as logged in again, their token will be within the freshness window and a definitive 403 can be returned or not. Default 3600 = 1 hour. Set freshness = 0 to disable.
`forwardToken` | Boolean indicating whether the token should be forwarded to the backend. Default true. If multiple tokens are present in different locations (e.g. cookie and header) and forwarding is false, only the token used will be removed. 
`optional` | Validate tokens according to the normal rules but don't require that a token be present. If specific claim requirements are specified in `require` but with `optional` set to `true` and a token is not present, access will be permitted even though the requirements are obviously not met, which may not be what you want or expect. In this case, no headers will be set from claims (as there aren't any). 

### Template Interpolation
The following per-request variables are available for Go template interpolation:

Name | Description
----|----
`{{.URL}}` | Full request URL including scheme and any query string parameters.
`{{.Scheme}}` | https or http
`{{.Host}}` | Host name only, without scheme, including port if any
`{{.Path}}` | Path and any query string parameters

These variables are useful with dynamic requirements, particularly in multitenancy scenarios. However, if using `Host`, care must be taken to ensure that the traefik router can only be reached through that hostname, i.e. through some well-controlled route, such as behind an API gateway, proxy or other ingress.  If the traefik router is reachable directly by some public IP, it would be easy to spoof a different `Host` by manipulating DNS for the IP externally; a static requirement should be used instead in such an architecture.

Addiionally, all environment variables are accessible with template interpolation, which makes programmatically setting a static value in the traefik dynamic config file easier.
Note that the per-request variables will overwrite traefiks view of an environment variable with the same name, so any shadowed enviorment variables need to be renamed appropriately.`


### Claim Matching

The following config snippet / JWT example pairs illustrate requirements and claims that satisfy them:
#### Simple
```yaml
require:
  aud: "customer.example.com"
```

```json
{
  "iss": "auth.example.com",
  "aud": "customer.example.com"
}
```

#### Dynamic Requirement
E.g. for requiring that a token's audience matches the domain being accessed (see notes in [Template Interpolation](###Template-Interpolation) above for caution on how and when this is safe to use dynamically like this)

Will succeed when called on https://customer.example.com/example but fail on https://other.example.com/example
Note that it is necessary to escape the Go template to prevent traefik from attempting to interpret it.
```yaml
require:
  aud: "{{`{{.Host}}`}}"
```

```json
{
  "iss": "auth.example.com",
  "aud": "customer.example.com"
}
```

#### Wildcard Claim
Will suceed when called on https://customer.example.com/example
```yaml
require:
  aud: "customer.example.com"
```

```json
{
  "iss": "auth.example.com",
  "aud": "*.example.com"
}
```
Note that the wildcard is granted to the _user_ in their claim, not asked for in the requirements. If you don't want to support these optional wildcards, simply do not issue such JWTs.

#### Custom Nested Claims
```yaml
require:
  authority:
    app1.example.com: ["admin", "superuser"]
```

```json
{
  "iss": "auth.example.com",
  "authority": {
    "app1.example.com": ["user", "admin"],
    "app2.example.com": ["user"]
  }
}
```

### Examples

#### Interactive webserver with redirection to login and error pages
```yaml
http:
  middlewares:
    secure-interactive:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          require:
            aud: test.example.com
          redirectUnauthorized: "https://example.com/login?return_to={{`{{.URL}}`}}"
          redirectForbidden: "https://example.com/unauthorized"
```

#### Specifying a fixed ECDSA public key
```yaml
http:
  middlewares:
    secure-interactive:
      plugin:
        jwt:
          secret: |
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmHp6e95bmF2NqgziUMZP/+x8r2dH
            m/UisMRtEhOY6vE92LCdFpyqtwYwPVryYexT0ITtQldD5O091QcuIOm6KQ==
            -----END PUBLIC KEY-----
          require:
            aud: test.example.com
```

## Forking
If you require some different behaviour, please do raise an issue or pull request in GitHub in the first instance rather than simply forking and modifying, and we'll try to accommodate it promptly (so 
as to reduce fragmentation of functionality).

## Acknowledgements

Inspired by code from https://github.com/legege/jwt-validation-middleware, https://github.com/23deg/jwt-middleware and https://github.com/team-carepay/traefik-jwt-plugin
