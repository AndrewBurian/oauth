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
	user, err := GetUser(r)
	if err != nil {
		return err
	}
	s.tokens[user] = t
	return nil
}

func (s *InMemTokenStore) Retrieve(r *http.Request) (*oauth2.Token, error) {
	user, err := GetUser(r)
	if err != nil {
		return nil, err
	}

	t, ok := s.tokens[user]
	if !ok {
		return nil, fmt.Errorf("No such user token")
	}

	return t, nil
}
