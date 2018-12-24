package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/AndrewBurian/mediatype"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type userCtxKeyType string

const userCtxKey = userCtxKeyType("user_id")
const bcryptCost = 10

var jsonType *mediatype.ContentType

type UserAuth struct {
	userPass  map[string][]byte
	tokenUser map[string]string
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	Token string `json:"token"`
}

func init() {
	var err error
	jsonType, err = mediatype.ParseSingle("application/json")
	if err != nil {
		panic(err)
	}
}

func NewUserAuth() *UserAuth {
	return &UserAuth{
		userPass:  make(map[string][]byte),
		tokenUser: make(map[string]string),
	}
}

// GetUser pulls the User ID out of a request context
func GetUser(r *http.Request) (string, error) {
	u := r.Context().Value(userCtxKey)
	if u == nil {
		return "", fmt.Errorf("User not set in context")
	}

	userString, ok := u.(string)
	if !ok {
		return "", fmt.Errorf("User identifier not a string")
	}

	return userString, nil
}

// AuthUser authenticates a user by their tokens and adds user info to the request
func (h *UserAuth) AuthUser(w http.ResponseWriter, r *http.Request, n func(w http.ResponseWriter, r *http.Request)) {

	// Extract Authorization bearer token
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "No auth token", http.StatusUnauthorized)
		return
	}

	var token string
	if n, err := fmt.Sscanf(auth, "Bearer: %s", &token); n != 1 || err != nil {
		log.WithError(err).Error("Failed to scan auth token")
		http.Error(w, "Bad bearer token", http.StatusBadRequest)
		return
	}

	// map token to userID
	userID, found := h.tokenUser[token]
	if !found {
		log.Error("Token provided but not found in store")
		http.Error(w, "Token not authorized", http.StatusForbidden)
		return
	}

	// store the user's ID in the request context
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, userID))
	n(w, r)
}

func contentNegotiation(w http.ResponseWriter, r *http.Request) bool {
	ct, accepts, err := mediatype.ParseRequest(r)
	if err != nil {
		log.WithError(err).Error("Failed content type negotiation")
		http.Error(w, "Bad content type", http.StatusBadRequest)
		return false
	}

	if ct == nil || !ct.Matches(jsonType) {
		log.Error("Failed content type negotiation, req not json")
		http.Error(w, "Requests must be JSON encoded", http.StatusNotAcceptable)
		return false
	}

	if len(accepts) > 0 && !accepts.SupportsType(jsonType) {
		log.Error("Failed content type negotiation, res doesn't accept json")
		http.Error(w, "Must support json response", http.StatusNotAcceptable)
		return false
	}

	return true
}

// Signup creates a new user with a password
func (h *UserAuth) Signup(w http.ResponseWriter, r *http.Request) {

	if !contentNegotiation(w, r) {
		return
	}

	// parse the request
	var login loginReq

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&login); err != nil {
		log.WithError(err).Error("Failed to parse signup request")
		http.Error(w, "Bad signup request", http.StatusBadRequest)
		return
	}

	// check we're not clobbering an existing user
	if _, found := h.userPass[login.Username]; found {
		log.Error("User already exists")
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// store password
	hash, err := bcrypt.GenerateFromPassword([]byte(login.Password), bcryptCost)
	if err != nil {
		log.WithError(err).Error("Failed to generate user password hash")
		http.Error(w, "bcrypt error", http.StatusInternalServerError)
		return
	}

	h.userPass[login.Username] = hash
	w.WriteHeader(http.StatusCreated)
}

// Login exchanges a user/pass combination for a token
func (h *UserAuth) Login(w http.ResponseWriter, r *http.Request) {

	if !contentNegotiation(w, r) {
		return
	}

	// parse the request
	var login loginReq

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&login); err != nil {
		log.WithError(err).Error("Failed to parse signup request")
		http.Error(w, "Bad signup request", http.StatusBadRequest)
		return
	}

	// check the user exists
	if _, found := h.userPass[login.Username]; !found {
		log.Error("User not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// check password
	err := bcrypt.CompareHashAndPassword([]byte(login.Password), h.userPass[login.Username])
	if err != nil {
		log.WithError(err).Error("Password does not match")
		http.Error(w, "Incorrect Password", http.StatusForbidden)
		return
	}

	// generate API token
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		log.WithError(err).Error("random read failed")
		http.Error(w, "Failed to generate random token", http.StatusInternalServerError)
		return
	}

	tokenStr := base64.RawStdEncoding.EncodeToString(token)

	// Store
	h.tokenUser[tokenStr] = login.Username

	// Return to the user
	resp := &loginResp{
		Token: tokenStr,
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(resp); err != nil {
		log.WithError(err).Error("Could not encode response")
		http.Error(w, "Error writing JSON response", http.StatusInternalServerError)
		return
	}

	// Done
}
