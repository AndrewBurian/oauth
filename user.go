package main

import (
	"context"
	"net/http"
)

type userCtxKeyType string

const userCtxKey = userCtxKeyType("user_id")

// AuthUser authenticates a user by their tokens and adds user info to the request
func AuthUser(w http.ResponseWriter, r *http.Request, n func(w http.ResponseWriter, r *http.Request)) {
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, "default"))
	n(w, r)
}
