package session

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/namely/go-sfdc/v3"
	"github.com/namely/go-sfdc/v3/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_passwordSessionRequest(t *testing.T) {
	scenarios := []struct {
		desc  string
		creds credentials.PasswordCredentials
		err   error
	}{
		{
			desc: "Passing HTTP request",
			creds: credentials.PasswordCredentials{
				URL:          "http://test.password.session",
				Username:     "myusername",
				Password:     "12345",
				ClientID:     "some client id",
				ClientSecret: "shhhh its a secret",
			},
			err: nil,
		},
		{
			desc: "Bad URL",
			creds: credentials.PasswordCredentials{
				URL:          "123://something.com",
				Username:     "myusername",
				Password:     "12345",
				ClientID:     "some client id",
				ClientSecret: "shhhh its a secret",
			},
			err: errors.New(`parse "123://something.com/services/oauth2/token": first path segment in URL cannot contain colon`),
		},
	}

	for _, scenario := range scenarios {

		passwordCreds, err := credentials.NewPasswordCredentials(scenario.creds)
		if err != nil {
			t.Fatal("password credentials can not return an error for these tests")
		}
		request, err := passwordSessionRequest(passwordCreds)

		if err != nil && scenario.err == nil {
			t.Errorf("%s Error was not expected %s", scenario.desc, err.Error())
		} else if err == nil && scenario.err != nil {
			t.Errorf("%s Error was expected %s", scenario.desc, scenario.err.Error())
		} else {
			if err != nil {
				if err.Error() != scenario.err.Error() {
					t.Errorf("%s Error %s :: %s", scenario.desc, err.Error(), scenario.err.Error())
				}
			} else {
				if request.Method != http.MethodPost {
					t.Errorf("%s HTTP request method needs to be POST not %s", scenario.desc, request.Method)
				}

				if request.URL.String() != scenario.creds.URL+oauthEndpoint {
					t.Errorf("%s URL not matching %s :: %s", scenario.desc, scenario.creds.URL+oauthEndpoint, request.URL.String())
				}

				buf, err := ioutil.ReadAll(request.Body)
				request.Body.Close()
				if err != nil {
					t.Fatal(err.Error())
				}
				reader, err := passwordCreds.Retrieve()
				if err != nil {
					t.Fatal(err.Error())
				}
				body, err := ioutil.ReadAll(reader)
				if err != nil {
					t.Fatal(err.Error())
				}

				if string(body) != string(buf) {
					t.Errorf("%s Form data %s :: %s", scenario.desc, string(buf), string(body))
				}
			}
		}
	}

}

func Test_passwordSessionResponse(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		client   *http.Client
		response *sessionPasswordResponse
		wantErr  error
	}{
		{
			name: "PassingResponse",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				resp := `
				{
					"access_token": "token",
					"instance_url": "https://some.salesforce.instance.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello"
				}`

				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(resp)),
					Header:     make(http.Header),
				}
			}),
			response: &sessionPasswordResponse{
				AccessToken: "token",
				InstanceURL: "https://some.salesforce.instance.com",
				ID:          "https://test.salesforce.com/id/123456789",
				TokenType:   "Bearer",
				IssuedAt:    "1553568410028",
				Signature:   "hello",
			},
			wantErr: nil,
		},
		{
			name: "FailedResponse",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Status:     "Some status",
					Body:       ioutil.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}
			}),
			response: &sessionPasswordResponse{},
			wantErr:  fmt.Errorf("session response error: %d %s", http.StatusInternalServerError, "Some status"),
		},
		{
			name: "ResponseDecodeError",
			url:  "http://example.com/foo",
			client: mockHTTPClient(func(req *http.Request) *http.Response {
				resp := `
				{
					"access_token": "token",
					"instance_url": "https://some.salesforce.instance.com",
					"id": "https://test.salesforce.com/id/123456789",
					"token_type": "Bearer",
					"issued_at": "1553568410028",
					"signature": "hello",
				}`

				return &http.Response{
					StatusCode: 200,
					Body:       ioutil.NopCloser(strings.NewReader(resp)),
					Header:     make(http.Header),
				}
			}),
			response: &sessionPasswordResponse{},
			wantErr:  errors.New("invalid character '}' looking for beginning of object key string"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, tc.url, nil)
			if err != nil {
				t.Fatal(err.Error())
			}

			response, err := passwordSessionResponse(request, tc.client)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
			} else {
				require.NoError(t, err)

				if response.AccessToken != tc.response.AccessToken {
					t.Errorf("%s Access Tokens %s %s", tc.name, tc.response.AccessToken, response.AccessToken)
				}

				if response.InstanceURL != tc.response.InstanceURL {
					t.Errorf("%s Instance URL %s %s", tc.name, tc.response.InstanceURL, response.InstanceURL)
				}

				if response.ID != tc.response.ID {
					t.Errorf("%s ID %s %s", tc.name, tc.response.ID, response.ID)
				}

				if response.TokenType != tc.response.TokenType {
					t.Errorf("%s Token Type %s %s", tc.name, tc.response.TokenType, response.TokenType)
				}

				if response.IssuedAt != tc.response.IssuedAt {
					t.Errorf("%s Issued At %s %s", tc.name, tc.response.IssuedAt, response.IssuedAt)
				}

				if response.Signature != tc.response.Signature {
					t.Errorf("%s Signature %s %s", tc.name, tc.response.Signature, response.Signature)
				}
			}
		})
	}
}

func testNewPasswordCredentials(t *testing.T, cred credentials.PasswordCredentials) *credentials.Credentials {
	creds, err := credentials.NewPasswordCredentials(cred)
	if err != nil {
		t.Error(err)
		return nil
	}
	return creds
}

func TestNewPasswordSession(t *testing.T) {
	scenarios := []struct {
		desc    string
		config  sfdc.Configuration
		session *Session
		err     error
	}{
		{
			desc: "Passing",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(t, credentials.PasswordCredentials{
					URL:          "http://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					resp := `
					{
						"access_token": "token",
						"instance_url": "https://some.salesforce.instance.com",
						"id": "https://test.salesforce.com/id/123456789",
						"token_type": "Bearer",
						"issued_at": "1553568410028",
						"signature": "hello"
					}`

					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(strings.NewReader(resp)),
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: &Session{
				response: &sessionPasswordResponse{
					AccessToken: "token",
					InstanceURL: "https://some.salesforce.instance.com",
					ID:          "https://test.salesforce.com/id/123456789",
					TokenType:   "Bearer",
					IssuedAt:    "1553568410028",
					Signature:   "hello",
				},
			},
			err: nil,
		},

		{
			desc: "Error Request",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(t, credentials.PasswordCredentials{
					URL:          "123://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 500,
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: nil,
			err:     errors.New(`parse "123://test.password.session/services/oauth2/token": first path segment in URL cannot contain colon`),
		},
		{
			desc: "Error Response",
			config: sfdc.Configuration{
				Credentials: testNewPasswordCredentials(t, credentials.PasswordCredentials{
					URL:          "http://test.password.session",
					Username:     "myusername",
					Password:     "12345",
					ClientID:     "some client id",
					ClientSecret: "shhhh its a secret",
				}),
				Client: mockHTTPClient(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Status:     "Some status",
						Body:       ioutil.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}
				}),
				Version: 45,
			},
			session: nil,
			err:     fmt.Errorf("session response error: %d %s", http.StatusInternalServerError, "Some status"),
		},
	}

	for _, scenario := range scenarios {
		session, err := Open(scenario.config)

		if err != nil && scenario.err == nil {
			t.Errorf("%s Error was not expected %s", scenario.desc, err.Error())
		} else if err == nil && scenario.err != nil {
			t.Errorf("%s Error was expected %s", scenario.desc, scenario.err.Error())
		} else {
			if err != nil {
				if err.Error() != scenario.err.Error() {
					t.Errorf("%s Error %s :: %s", scenario.desc, err.Error(), scenario.err.Error())
				}
			} else {
				if session.response.AccessToken != scenario.session.response.AccessToken {
					t.Errorf("%s Access Tokens %s %s", scenario.desc, scenario.session.response.AccessToken, session.response.AccessToken)
				}

				if session.response.InstanceURL != scenario.session.response.InstanceURL {
					t.Errorf("%s Instance URL %s %s", scenario.desc, scenario.session.response.InstanceURL, session.response.InstanceURL)
				}

				if session.response.ID != scenario.session.response.ID {
					t.Errorf("%s ID %s %s", scenario.desc, scenario.session.response.ID, session.response.ID)
				}

				if session.response.TokenType != scenario.session.response.TokenType {
					t.Errorf("%s Token Type %s %s", scenario.desc, scenario.session.response.TokenType, session.response.TokenType)
				}

				if session.response.IssuedAt != scenario.session.response.IssuedAt {
					t.Errorf("%s Issued At %s %s", scenario.desc, scenario.session.response.IssuedAt, session.response.IssuedAt)
				}

				if session.response.Signature != scenario.session.response.Signature {
					t.Errorf("%s Signature %s %s", scenario.desc, scenario.session.response.Signature, session.response.Signature)
				}

			}
		}

	}
}

func TestSession_ServiceURL(t *testing.T) {
	type fields struct {
		response *sessionPasswordResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Passing URL",
			fields: fields{
				response: &sessionPasswordResponse{
					InstanceURL: "https://www.my.salesforce.instance",
				},
				config: sfdc.Configuration{
					Version: 43,
				},
			},
			want: "https://www.my.salesforce.instance/services/data/v43.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.ServiceURL(); got != tt.want {
				t.Errorf("Session.ServiceURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_AuthorizationHeader(t *testing.T) {
	type fields struct {
		response *sessionPasswordResponse
		config   sfdc.Configuration
	}
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "Authorization Test",
			fields: fields{
				response: &sessionPasswordResponse{
					TokenType:   "Type",
					AccessToken: "Access",
				},
				config: sfdc.Configuration{},
			},
			args: args{
				request: &http.Request{
					Header: make(http.Header),
				},
			},
			want: "Type Access",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			session.AuthorizationHeader(tt.args.request)

			if got := tt.args.request.Header.Get("Authorization"); got != tt.want {
				t.Errorf("Session.AuthorizationHeader() = %v, want %v", got, tt.want)
			}

		})
	}
}

func TestSession_Client(t *testing.T) {
	type fields struct {
		response *sessionPasswordResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   *http.Client
	}{
		{
			name: "Session Client",
			fields: fields{
				response: &sessionPasswordResponse{},
				config: sfdc.Configuration{
					Client: http.DefaultClient,
				},
			},
			want: http.DefaultClient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.Client(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Session.Client() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_InstanceURL(t *testing.T) {
	type fields struct {
		response *sessionPasswordResponse
		config   sfdc.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Passing URL",
			fields: fields{
				response: &sessionPasswordResponse{
					InstanceURL: "https://www.my.salesforce.instance",
				},
				config: sfdc.Configuration{
					Version: 43,
				},
			},
			want: "https://www.my.salesforce.instance",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				response: tt.fields.response,
				config:   tt.fields.config,
			}
			if got := session.InstanceURL(); got != tt.want {
				t.Errorf("Session.InstanceURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_isExpired(t *testing.T) {
	tests := map[string]struct {
		expiresAt time.Time
		want      bool
	}{
		"expired": {
			expiresAt: time.Now().Add(-1 * time.Hour).UTC(),
			want:      true,
		},
		"not_expired": {
			expiresAt: time.Now().Add(1 * time.Hour).UTC(),
			want:      false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Session{
				expiresAt: tt.expiresAt,
			}

			got := s.isExpired()

			assert.Equal(t, got, tt.want)
		})
	}
}

func TestSession_Refresh(t *testing.T) {
	const (
		oldToken = "oLd:ToKeN"
		newToken = "nEw:ToKeN"
	)

	creds := testNewPasswordCredentials(t, credentials.PasswordCredentials{
		URL:          "http://test.password.session",
		Username:     "myusername",
		Password:     "12345",
		ClientID:     "some client id",
		ClientSecret: "shhhh its a secret",
	})
	client := mockHTTPClient(func(req *http.Request) *http.Response {
		resp := `{"access_token":"nEw:ToKeN"}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(resp)),
		}
	})
	config := sfdc.Configuration{
		SessionDuration: defaultSessionDuration,
		Client:          client,
		Credentials:     creds,
	}
	response := &sessionPasswordResponse{AccessToken: oldToken}

	t.Run("expired", func(t *testing.T) {
		s := &Session{
			response:  response,
			expiresAt: time.Now().Add(-2 * defaultSessionDuration).UTC(),
			config:    config,
		}

		err := s.Refresh()
		require.NoError(t, err)
		assert.Equal(t, newToken, s.response.AccessToken)
	})

	t.Run("not_expired", func(t *testing.T) {
		s := &Session{
			response:  response,
			expiresAt: time.Now().Add(2 * defaultSessionDuration).UTC(),
			config:    config,
		}

		err := s.Refresh()
		require.NoError(t, err)
		assert.Equal(t, oldToken, s.response.AccessToken)
	})
}
