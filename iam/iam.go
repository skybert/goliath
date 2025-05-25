// Author: torstein
package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var sessions = map[string]OIDCSession{}
var nonceByCode = map[string]string{}

type GoliathIAM interface {
	Ping() (string, error)
	Authorize() (string, error)
	Token(string, string) (string, error)
}

type InMemoryIAM struct {
}
type TokenResonse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (iam InMemoryIAM) Ping() (string, error) {
	return "Pong from in memory", nil
}
func (iam InMemoryIAM) Authorize() (string, error) {
	return "Starting code flow", nil
}
func (iam InMemoryIAM) Token(iss, code string) (string, error) {
	// Validate the token request according to section 3.1.3.2
	// https://openid.net/specs/openid-connect-core-1_0.html
	if nonceByCode[code] == "" {
		return "", errors.New("I don't know about code=" + code + "\n")
	}

	nonce := nonceByCode[code]
	// Ensure the same code isn't used multiple times
	nonceByCode[code] = ""

	// TODO get token expiry from conf
	exp := time.Now().Add(2 * time.Hour)

	idToken, err := IdToken(exp, iss, nonce)
	if err != nil {
		return "", err
	}
	// TODO different exp of access token than id token
	accessToken, err := AccessToken(iss, exp)
	if err != nil {
		return "", err
	}
	// TODO different exp of refresh token than id token
	refreshToken, err := RefreshToken(iss, exp)
	if err != nil {
		return "", err
	}

	// TODO read token expiry from conf
	expiresIn := 3600
	tokenResponse := TokenResonse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IdToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}

	result, err := json.Marshal(&tokenResponse)
	if err != nil {
		return "", err
	}

	return string(result), err
}

type Controller struct {
	iam GoliathIAM
}

func (c Controller) Ping(w http.ResponseWriter, r *http.Request) {
	message, err := c.iam.Ping()
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(message + "\n"))
}

// https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
//
// POST /token HTTP/1.1
//
//	Host: server.example.com
//	Content-Type: application/x-www-form-urlencoded
//	Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//
//	grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
//	  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
func (c Controller) Token(w http.ResponseWriter, r *http.Request) {
	// TODO hardening, check post, that the form contains the
	// values and so on.
	code := r.FormValue(string(ResponseTypeCode))
	fmt.Printf("code: %v\n", code)
	fmt.Printf("nonceByCode: %v\n", nonceByCode)

	// TODO r.URL.Scheme is empty
	iss := r.URL.Scheme + "://" + r.Host
	t, err := c.iam.Token(iss, code)
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(t + "\n"))

}

// https://authorization-server.com/authorize?
//
//	response_type=code
//	&client_id=iPs-oFyjhRW7aytq69p9-nj3
//	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
//	&scope=photo+offline_access
//	&state=WdunT3HwhqOFXxLI
func (c Controller) Authorize(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("%v\n", r.URL.Query())
	// TODO validate responseType
	responseType := r.URL.Query().Get("response_type")
	fmt.Printf("%v\n", responseType)

	// TODO is this the OIDC client we know about?
	clientId := r.URL.Query().Get(string(ReqParamClientId))
	fmt.Printf("%v\n", clientId)

	// TOOD validate that redirect URI is allowed
	redirectURI := r.URL.Query().Get("redirect_uri")
	fmt.Printf("redirect_uri=%v\n", redirectURI)

	// TODO validate that scope is allowed
	scope := r.URL.Query().Get("scope")
	scopes := strings.Split(scope, " ")
	err := ValidateScopes(scopes)
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	fmt.Printf("%v\n", scopes)

	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")

	message, err := c.iam.Authorize()
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	code := GenerateServerCode()
	oidcSession := OIDCSession{
		state:       state,
		nonce:       nonce,
		redirectURI: redirectURI,
		code:        code,
	}
	sessions[state] = oidcSession
	fmt.Printf("%v\n", sessions)

	queryParameters := u.Query()
	queryParameters.Add("state", state)
	queryParameters.Add("code", code)
	nonceByCode[code] = nonce

	// TODO is this really the best/safest way of manipulating the
	// URI parameters?
	u.RawQuery = queryParameters.Encode()
	fmt.Printf("u query=%v\n", u.Query())

	locationURI := u.String()
	w.Header().Add("Location", locationURI)
	w.Write([]byte(message + "\n"))
}

func NewController() Controller {
	return Controller{
		iam: NewInMemoryIAM(),
	}
}

func NewInMemoryIAM() InMemoryIAM {
	return InMemoryIAM{}
}

func Run() {
	c := NewController()
	http.HandleFunc("/ping", c.Ping)
	http.HandleFunc("/authorize", c.Authorize)
	http.HandleFunc("/token", c.Token)
	http.ListenAndServe(":8000", nil)
}
