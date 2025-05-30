// OIDC specific parts of Goliath
//
// Author: torstein
package iam

import (
	"errors"
	"log"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ReqParam string
type Scope string
type RespType string
type Claim string

const (
	ReqParamNonce        ReqParam = "nonce"
	ReqParamClientId     ReqParam = "client_id"
	ReqParamResponseType ReqParam = "response_type"
)

const (
	ScopeOpenId        Scope = "openid"
	ScopeOfflineAccess Scope = "offline_access"
)

const (
	ResponseTypeCode RespType = "code"
)

type OIDCSession struct {
	state       string
	nonce       string
	code        string
	redirectURI string
}

// Validates according to https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func ValidateResponseType(respType string) error {
	if respType == string(ResponseTypeCode) {
		return nil
	} else {
		return errors.New("goliath only supports " + string(ReqParamResponseType) + "=" + string(ResponseTypeCode))
	}
}

// Validates according to
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
func ValidateScopes(scopes []string) error {
	if slices.Contains(scopes, string(ScopeOpenId)) {
		return nil
	}

	return errors.New("scopes lack: " + string(ScopeOpenId))

}

func ValidateClientId(clientId string, conf GoliathConf) error {
	configuredClientId := conf.String("app.client_id")
	if clientId == configuredClientId {
		return nil
	}

	return errors.New(
		"client id: " +
			clientId +
			" doesn't correspond to server conf: " +
			configuredClientId)
}

func ValidateRedirectURI(uri string, conf GoliathConf) error {
	if slices.Contains(conf.Strings("app.allowed_redirect_uris"), uri) {
		return nil
	}
	return errors.New("disallowed redirect uri: " + uri + "\n")

}

func IdToken(
	iss string,
	nonce string,
	conf GoliathConf) (string, error) {

	exp := conf.MillisAsTime("token.refresh_token_exp_ms")
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			string(ClaimIssuedAt):       time.Now().Unix(),
			string(ClaimExpirationTime): exp.Unix(),
			string(ClaimIssuer):         iss,
			string(ReqParamNonce):       nonce,
		})
	signingKey := []byte(conf.String("token.signing_key"))
	ss, err := token.SignedString(signingKey)
	log.Printf(ss, err)
	return ss, err
}

func TokenResponseExpiresIn(conf GoliathConf) int {
	now := time.Now()
	// Although three tokens are returned from the /token
	// endpoint, it's the the access token expiry, in seconds,
	// that's to be in the expires_in field, see
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
	expires := conf.MillisAsTime("token.access_token_exp_ms")

	expiresIn := expires.UnixMilli() - now.UnixMilli()
	return int(expiresIn / 1000)
}
