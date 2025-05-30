// Author: torstein at skybert.net
package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var sessions = map[string]OIDCSession{}
var nonceByCode = map[string]string{}

type GoliathIAM interface {
	Ping() (string, error)
	Authorize() (string, error)
	Token(string, string) (string, error)
	Conf() GoliathConf
}

type InMemoryIAM struct {
	conf GoliathConf
}

type TokenResonse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (iam InMemoryIAM) Conf() GoliathConf {
	return iam.conf
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
		return "", errors.New("I don't know about code " + code + "\n")
	}

	nonce := nonceByCode[code]
	// Ensure the same code isn't used multiple times
	nonceByCode[code] = ""

	idToken, err := IdToken(iss, nonce, iam.conf)
	if err != nil {
		return "", err
	}
	accessToken, err := AccessToken(iss, iam.conf)
	if err != nil {
		return "", err
	}
	refreshToken, err := RefreshToken(iss, iam.conf)
	if err != nil {
		return "", err
	}

	tokenResponse := TokenResonse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IdToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    TokenResponseExpiresIn(iam.conf),
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
		log.Printf("Got err: %v", err)
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
		log.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	// TODO Why doesn't DetectContentType work here?
	fmt.Printf("Detected: %v\n", http.DetectContentType([]byte(t)))

	w.Header().Set("Content-type", "application/json")

	// OIDC mandates no-store:
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
	w.Header().Set("Cache-Control", "no-store")

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
	log.Printf("/authorize query: %v", r.URL.Query())

	responseType := r.URL.Query().Get(string(ReqParamResponseType))
	err := ValidateResponseType(responseType)
	if err != nil {
		log.Printf("Got err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	clientId := r.URL.Query().Get(string(ReqParamClientId))
	fmt.Printf("%v\n", clientId)
	err = ValidateClientId(clientId, c.iam.Conf())
	if err != nil {
		log.Printf("Got err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	err = ValidateRedirectURI(redirectURI, c.iam.Conf())
	if err != nil {
		log.Printf("Got err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	scope := r.URL.Query().Get("scope")
	scopes := strings.Split(scope, " ")
	err = ValidateScopes(scopes)
	if err != nil {
		fmt.Printf("Got err: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

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
	return InMemoryIAM{
		conf: NewGoliathConf(),
	}
}

func Run(args GoliathCLIArgs) {
	c := NewController()
	http.HandleFunc("/ping", c.Ping)
	http.HandleFunc("/authorize", c.Authorize)
	http.HandleFunc("/token", c.Token)

	port := c.iam.Conf().String("server.port")
	if args.ServerPort > 0 {
		port = strconv.Itoa(args.ServerPort)
	}

	log.Printf("starting Goliath on port %s ...", port)
	http.ListenAndServe(":"+port, nil)
}
