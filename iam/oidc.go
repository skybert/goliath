// OIDC specific parts of Goliath
//
// Author: torstein
package iam

import "slices"

import "errors"

type ReqParam string
type Scope string
type RespType string
type Claim string

const (
	ClaimIssuer Claim = "iss"
)

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
