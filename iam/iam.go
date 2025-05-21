// Author: torstein
package iam

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/url"
	"strings"
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

func (iam InMemoryIAM) Ping() (string, error) {
	return "Pong from in memory", nil
}
func (iam InMemoryIAM) Authorize() (string, error) {
	return "Starting code flow", nil
}
func (iam InMemoryIAM) Token(iss, code string) (string, error) {
	mySigningKey := []byte("AllYourBase")
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			string(ClaimIssuer):   iss,
			string(ReqParamNonce): nonceByCode[code],
		})
	ss, err := token.SignedString(mySigningKey)
	fmt.Println(ss, err)
	return ss, err
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
