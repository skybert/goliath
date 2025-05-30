package iam

import "testing"

/*
 * Tests to see if we're OIDC compliant.
 *
 * Author: torstein at skybert.net
 */
func TestValidateResponseType(t *testing.T) {
	err := ValidateResponseType("code")
	if err != nil {
		t.Errorf("code should be a valid response type %v", err)
	}
}

func TestValidateResponseTypeInvalid(t *testing.T) {
	err := ValidateResponseType("something-else")
	if err == nil {
		t.Errorf("Must use code as response type: %v", err)
	}
}

func TestValidateScopes(t *testing.T) {
	input := []string{string(ScopeOpenId)}
	err := ValidateScopes(input)

	if err != nil {
		t.Errorf("Scopes: %v should be valid, but was: %v", input, err)
	}
}

func TestValidateScopesInvalid(t *testing.T) {
	input := []string{string(ScopeOfflineAccess)}
	err := ValidateScopes(input)
	if err == nil {
		t.Errorf("Scopes: %v should be invalid, but was: %v", input, err)
	}
}
