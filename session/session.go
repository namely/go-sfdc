// Package session provides handles creation of a Salesforce session
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/namely/go-sfdc/v3"
	"github.com/namely/go-sfdc/v3/credentials"
)

// Session is the authentication response.  This is used to generate the
// authorization header for the Salesforce API calls.
type Session struct {
	response   *sessionPasswordResponse
	responseMu sync.RWMutex // response guardian
	config     sfdc.Configuration
}

// Clienter interface provides the HTTP client used by the
// the resources.
type Clienter interface {
	Client() *http.Client
}

// InstanceFormatter is the session interface that
// formaters the session instance information used
// by the resources.
//
// InstanceURL will return the Salesforce instance.
//
// AuthorizationHeader will add the authorization to the
// HTTP request's header.
type InstanceFormatter interface {
	InstanceURL() string
	AuthorizationHeader(*http.Request)
	Clienter
}

// ServiceFormatter is the session interface that
// formats the session for service resources.
//
// ServiceURL provides the service URL for resources to
// user.
type ServiceFormatter interface {
	InstanceFormatter
	ServiceURL() string
}

type sessionPasswordResponse struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"`
}

const oauthEndpoint = "/services/oauth2/token"

// Open is used to authenticate with Salesforce and open a session.  The user will need to
// supply the proper credentials and a HTTP client.
func Open(config sfdc.Configuration) (*Session, error) {
	if config.Credentials == nil {
		return nil, errors.New("session: configuration credentials can not be nil")
	}
	if config.Client == nil {
		return nil, errors.New("session: configuration client can not be nil")
	}
	if config.Version <= 0 {
		return nil, errors.New("session: configuration version can not be less than zero")
	}
	request, err := passwordSessionRequest(config.Credentials)

	if err != nil {
		return nil, err
	}

	response, err := passwordSessionResponse(request, config.Client)
	if err != nil {
		return nil, err
	}

	session := &Session{
		response: response,
		config:   config,
	}

	return session, nil
}

func passwordSessionRequest(creds *credentials.Credentials) (*http.Request, error) {
	oauthURL := creds.URL() + oauthEndpoint

	body, err := creds.Retrieve()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, body)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")
	return request, nil
}

func passwordSessionResponse(request *http.Request, client *http.Client) (*sessionPasswordResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	// TODO: call before status check:
	defer response.Body.Close()

	var sessionResponse sessionPasswordResponse
	err = decoder.Decode(&sessionResponse)
	if err != nil {
		return nil, err
	}

	return &sessionResponse, nil
}

// InstanceURL will return the Salesforce instance
// from the session authentication.
func (s *Session) InstanceURL() string {
	s.responseMu.RLock()
	defer s.responseMu.RUnlock()

	return s.response.InstanceURL
}

// ServiceURL will return the Salesforce instance for the
// service URL.
func (s *Session) ServiceURL() string {
	s.responseMu.RLock()
	defer s.responseMu.RUnlock()

	return fmt.Sprintf("%s/services/data/v%d.0", s.response.InstanceURL, s.config.Version)
}

// AuthorizationHeader will add the authorization to the
// HTTP request's header.
func (s *Session) AuthorizationHeader(req *http.Request) {
	s.responseMu.RLock()
	defer s.responseMu.RUnlock()

	s.authorizationHeader(req)
}

// Client returns the HTTP client to be used in APIs calls.
func (s *Session) Client() *http.Client {
	return s.config.Client
}

func (s *Session) authorizationHeader(req *http.Request) {
	auth := s.response.TokenType + " " + s.response.AccessToken
	req.Header.Add("Authorization", auth)
}
