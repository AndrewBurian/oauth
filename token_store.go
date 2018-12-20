package main

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type InMemTokenStore struct {
	tokens map[string]*oauth2.Token
}

func NewInMemStore() *InMemTokenStore {
	return &InMemTokenStore{
		tokens: make(map[string]*oauth2.Token),
	}
}

func (s *InMemTokenStore) Store(r *http.Request, t *oauth2.Token) error {
	u := r.Context().Value(userCtxKey)
	if u == nil {
		return fmt.Errorf("User not set in context")
	}

	userString, ok := u.(string)
	if !ok {
		return fmt.Errorf("User identifier not a string")
	}

	s.tokens[userString] = t
	return nil
}

func (s *InMemTokenStore) Retrieve(r *http.Request) (*oauth2.Token, error) {
	u := r.Context().Value(userCtxKey)
	if u == nil {
		return nil, fmt.Errorf("User not set in context")
	}

	userString, ok := u.(string)
	if !ok {
		return nil, fmt.Errorf("User identifier not a string")
	}

	t, ok := s.tokens[userString]
	if !ok {
		return nil, fmt.Errorf("No such user token")
	}

	return t, nil
}
