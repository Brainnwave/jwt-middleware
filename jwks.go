// This file contains code taken from github.com/team-carepay/traefik-jwt-plugin
// We would like to simply use github.com/go-jose/go-jose/v3 for the JWKS instead but traefik's yaegi interpreter messes up the unmarshalling.
package jwt_middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

// JSONWebKey  is a JSON web key returned by the JWKS request.
type JSONWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	K   string   `json:"k,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	D   string   `json:"d,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Crv string   `json:"crv,omitempty"`
}

// JSONWebKeySet represents a set of JSON web keys.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

func FetchJWKS(url string) (map[string]interface{}, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d from %s", response.StatusCode, url)
	}
	var jwks JSONWebKeySet
	err = json.NewDecoder(response.Body).Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		var public interface{}
		switch jwk.Kty {
		case "RSA":
			{
				nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
				if err != nil {
					break
				}
				eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
				if err != nil {
					break
				}
				key := new(rsa.PublicKey)
				key.N = new(big.Int).SetBytes(nBytes)
				key.E = int(new(big.Int).SetBytes(eBytes).Uint64())
				public = key
			}
		case "EC":
			{
				var curve elliptic.Curve
				switch jwk.Crv {
				case "P-256":
					curve = elliptic.P256()
				case "P-384":
					curve = elliptic.P384()
				case "P-521":
					curve = elliptic.P521()
				default:
					switch jwk.Alg {
					case "ES256":
						curve = elliptic.P256()
					case "ES384":
						curve = elliptic.P384()
					case "ES512":
						curve = elliptic.P521()
					default:
						curve = elliptic.P256()
					}
				}
				xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
				if err != nil {
					break
				}
				yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
				if err != nil {
					break
				}
				key := new(ecdsa.PublicKey)
				key.Curve = curve
				key.X = new(big.Int).SetBytes(xBytes)
				key.Y = new(big.Int).SetBytes(yBytes)
				public = key
			}
		}
		if jwk.Kid == "" {
			jwk.Kid = JWKThumbprint(jwk)
		}
		keys[jwk.Kid] = public
	}

	return keys, nil
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(jwk JSONWebKey) string {
	var text string
	switch jwk.Kty {
	case "RSA":
		text = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N)
	case "EC":
		text = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	}
	bytes := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
