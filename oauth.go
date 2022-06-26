package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type authzCode struct {
	code  string
	state string
	err   string
}

type codeReceiver struct {
	http.Server
	authzCode chan authzCode
}

func newServer() *codeReceiver {
	s := &codeReceiver{
		authzCode: make(chan authzCode),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.callback(s.authzCode))
	s.Server = http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}
	s.Server.SetKeepAlivesEnabled(false)
	return s
}

// callback receives and returns the Authorization Response.
// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
func (s *codeReceiver) callback(ch chan<- authzCode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if e := r.FormValue("error"); e != "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Failed to authorize"))
			ch <- authzCode{
				err: e,
			}
			return
		}

		code := r.FormValue("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Failed to authorize. code is empty"))
			ch <- authzCode{
				err: "failed to authorize. code is empty",
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authorized"))

		ch <- authzCode{
			code:  code,
			state: r.FormValue("state"),
		}
	}
}

func (s *codeReceiver) getAuthzCode() (string, string, error) {
	r := <-s.authzCode
	if r.err != "" {
		return "", "", errors.New(r.err)
	}

	return r.code, r.state, nil
}

type OAuth struct {
	config      *oauth2.Config
	token       *oauth2.Token
	tokenSource oauth2.TokenSource
	file        string
}

func NewOAuth(id, secret string, scopes []string) OAuth {
	return OAuth{
		config: &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  "http://127.0.0.1:8080",
		},
		file: "/tmp/google-oauth-cli.token",
	}
}

// Authorize starts Authorization Code Flow with Proof Key for Code Exchange.
// It gets the access token and the refresh token.
//
// See these documents
// - https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce
// - https://developers.google.com/identity/protocols/oauth2/native-app
func (o *OAuth) Authorize(ctx context.Context) error {
	// Start Server to receive authorization code & state
	s := newServer()
	defer s.Shutdown(context.Background())
	go func() {
		s.ListenAndServe()
	}()

	// Generate code & state
	codeVerifier, err := generateRandomBytes(128)
	if err != nil {
		return err
	}
	b, err := generateRandomBytes(128)
	if err != nil {
		return err
	}
	state := string(b)

	// Start OAuth Process
	url := o.config.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("code_challenge", generateCodeChallenge(string(codeVerifier))),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)

	// Wait to Get code & state
	code, receivedState, err := s.getAuthzCode()
	if err != nil {
		return err
	}
	log.Println("Received code & state")

	if receivedState != state {
		return errors.New("failed to authorize. invalid state")
	}

	token, err := o.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", string(codeVerifier)),
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
	)
	if err != nil {
		return err
	}
	log.Println("Exchange token")

	o.token = token
	return nil
}

// Revoke delete the token.
func (o *OAuth) Revoke() error {
	o.token = nil
	return os.Remove(o.file)
}

// Client returns http.Client with the token.
func (o *OAuth) Client(ctx context.Context) *http.Client {
	o.tokenSource = o.config.TokenSource(ctx, o.token)
	return oauth2.NewClient(ctx, o.tokenSource)
}

// LoadToken reads the token from a file.
func (o *OAuth) LoadToken() error {
	token, err := o.loadTokeFromFile()
	if err != nil {
		return err
	}
	o.token = token
	return nil
}

func (o OAuth) loadTokeFromFile() (*oauth2.Token, error) {
	b, err := os.ReadFile(o.file)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{}
	if err := json.Unmarshal(b, token); err != nil {
		return nil, err
	}
	return token, nil
}

// SaveToken saves the token into a file.
func (o *OAuth) SaveToken() error {
	return o.saveTokeToFile()
}

func (o *OAuth) saveTokeToFile() error {
	// It is not good that updating the token here.
	// It should wrap TokenSource interface to update the token
	// at the same time the Client refreshes the token.
	newToken, err := o.tokenSource.Token()
	if err != nil {
		return err
	}
	o.token = newToken
	b, err := json.Marshal(o.token)
	if err != nil {
		return err
	}

	return os.WriteFile(o.file, b, 0600)
}

// generateCodeChallenge generate Code Challenge.
// See https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateRandomBytes generates secure random string for Code Verifier.
// See https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func generateRandomBytes(n int) ([]byte, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return nil, err
		}
		ret[i] = letters[num.Int64()]
	}

	return ret, nil
}
