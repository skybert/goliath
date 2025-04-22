package iam

import (
	"fmt"
	"net/http"
	"net/url"
)

type GoliathIAM interface {
	Ping() (string, error)
	Authorize() (string, error)
	Token() (string, error)
}

type InMemoryIAM struct {
}

func (iam InMemoryIAM) Ping() (string, error) {
	return "Pong from in memory", nil
}
func (iam InMemoryIAM) Authorize() (string, error) {
	return "Starting code flow", nil
}
func (iam InMemoryIAM) Token() (string, error) {
	return "ey.234.24323", nil
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

// https://authorization-server.com/authorize?
//
//	response_type=code
//	&client_id=iPs-oFyjhRW7aytq69p9-nj3
//	&redirect_uri=https://www.oauth.com/playground/authorization-code.html
//	&scope=photo+offline_access
//	&state=WdunT3HwhqOFXxLI
func (c Controller) Authorize(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("%v\n", r.URL.Query())
	responseType := r.URL.Query().Get("response_type")
	fmt.Printf("%v\n", responseType)

	// TODO validate responseType
	clientId := r.URL.Query().Get("client_id")
	fmt.Printf("%v\n", clientId)

	redirectURI := r.URL.Query().Get("redirect_uri")
	fmt.Printf("redirect_uri=%v\n", redirectURI)

	// TOOD validate that redirect URI is allowed
	scope := r.URL.Query().Get("scope")
	fmt.Printf("%v\n", scope)

	// TODO validate that scope is allowed
	state := r.URL.Query().Get("state")
	// TODO keep track of state

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

	queryParameters := u.Query()
	queryParameters.Add("state", state)
	// TODO generate server side code
	code := "server-generated-code"
	queryParameters.Add("code", code)

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
	http.ListenAndServe(":8000", nil)
}
