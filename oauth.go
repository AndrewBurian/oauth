package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const csrfCookieName = "oauth-csrf"

// OAuth2Handler handles an OAuth handshake
type OAuth2Handler struct {
	conf     *oauth2.Config
	store    TokenStore
	redirect string
}

// TokenStore is any object that can store a token and bind it to a specific user
type TokenStore interface {
	Store(r *http.Request, t *oauth2.Token) error
	Retrieve(r *http.Request) (*oauth2.Token, error)
}

// NewOAuth2Handler creates a handler with the specfied token store
func NewOAuth2Handler(conf *oauth2.Config, store TokenStore, successRedirect string) *OAuth2Handler {
	return &OAuth2Handler{
		conf:     conf,
		store:    store,
		redirect: successRedirect,
	}
}

// RequestAuth is the start of the OAuth handshake where we start the auth process
func (h *OAuth2Handler) RequestAuth(w http.ResponseWriter, r *http.Request) {

	// CSRF Protection is required on the RedirectURL endpoint, so we have to set it up here
	/*
		An attacker can try to get a client to visit the redirectURL through a CSRF attack
		like an img tag with a src of `yoursite.com/oauth/redirect?code=...`

		If unchecked, this would cause a user to inject the attacker's code into our database.

		The attacker won't be able to set cookies on that malicious request, so cookies are tamper safe

		A legitimate redirect will also include a `state=` param that we get to set here.

		So we set the state param in the redirect URL, and at the same time write it to the user's cookies.
		On a legit request, the state param will match the value of this cookie
	*/

	// Generate the random CSRF token
	csrfValue := make([]byte, 8)
	if _, err := rand.Read(csrfValue); err != nil {
		log.WithError(err).Error("random read failed")
		http.Error(w, "Failed to generate random token", http.StatusInternalServerError)
		return
	}

	// Encode it to something URL safe
	csrfString := base64.RawURLEncoding.EncodeToString(csrfValue)

	// Create a cookie for it
	csrfCookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfString,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   1800,
	}

	// Add the cookie to the response
	http.SetCookie(w, csrfCookie)

	// Add the same token to the redirect URL
	authURL := h.conf.AuthCodeURL(csrfString, oauth2.AccessTypeOffline)

	// Redirect the user to the Authorization provider
	http.Redirect(w, r, authURL, http.StatusFound)
}

// RedirectURL handles receiving the redirect with an authorization code
func (h *OAuth2Handler) RedirectURL(w http.ResponseWriter, r *http.Request) {

	// first we extract the csrf token cookie
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		log.WithError(err).Error("Could not extract CSRF cookie")
		http.Error(w, "Invalid CSRF Cookie", http.StatusBadRequest)
		return
	}

	// then the csrf code from the request params
	csrfState := r.FormValue("state")

	// and ensure they match
	if csrfCookie.Value != csrfState || csrfState == "" {
		log.Error("CSRF state did not match cookie")
		http.Error(w, "CSRF Mismatch", http.StatusBadRequest)
		return
	}

	// CSRF Passed!

	// Now we extract the authorization code
	authCode := r.FormValue("code")
	if authCode == "" {
		log.Error("No auth code")
		http.Error(w, "No auth code", http.StatusBadRequest)
		return
	}

	// And exchange it for an access token!
	token, err := h.conf.Exchange(r.Context(), authCode)
	if err != nil {
		log.WithError(err).Error("Could not exchange auth code for access token")
		http.Error(w, "Could not get token", http.StatusInternalServerError)
		return
	}

	// store the token somehow
	if err = h.store.Store(r, token); err != nil {
		log.WithError(err).Error("Failed to store token")
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}

	// unset the cookie
	csrfCookie.MaxAge = -1
	http.SetCookie(w, csrfCookie)

	// done
	http.Redirect(w, r, h.redirect, http.StatusFound)
}
