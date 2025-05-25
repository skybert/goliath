// OIDC specific parts of Goliath
//
// Author: torstein
package iam

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"slices"
	"time"
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
	ScopeOpenId Scope = "openid"
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

func IdToken(exp time.Time, iss string, nonce string) (string, error) {
	// TODO read signing key from conf
	mySigningKey := []byte("AllYourBase")
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			string(ClaimIssuedAt):       time.Now().Unix(),
			string(ClaimExpirationTime): exp.Unix(),
			string(ClaimIssuer):         iss,
			string(ReqParamNonce):       nonce,
		})
	ss, err := token.SignedString(mySigningKey)
	fmt.Println(ss, err)
	return ss, err
}
