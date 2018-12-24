package main

import (
	"context"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	googleid "google.golang.org/api/oauth2/v2"
)

type GoogleAPI struct {
	store TokenStore
	conf  *oauth2.Config
}

func (h *GoogleAPI) GetUser(w http.ResponseWriter, r *http.Request) {

	// Pull the oauth token out of storage
	token, err := h.store.Retrieve(r)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve user token")
		http.Error(w, "Failed to retrieve token", http.StatusNotFound)
		return
	}

	// generate an oauth client with it
	cli := h.conf.Client(context.Background(), token)
	if cli == nil {
		log.Error("Failed to generate client")
		http.Error(w, "Failed to generate client", http.StatusInternalServerError)
		return
	}

	// create google ID service
	svc, err := googleid.New(cli)
	if err != nil {
		log.WithError(err).Error("Failed to generate client")
		http.Error(w, "Failed to generate client", http.StatusInternalServerError)
		return
	}
	userInfoSvc := googleid.NewUserinfoV2MeService(svc)

	// Fetch user info
	info, err := userInfoSvc.Get().Context(r.Context()).Do()
	if err != nil {
		log.WithError(err).Error("Failed to fetch user info")
		http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}

	// Render response
	encoder := json.NewEncoder(w)
	if err = encoder.Encode(info); err != nil {
		log.WithError(err).Error("Failed to render response")
		http.Error(w, "Failed to render", http.StatusInternalServerError)
		return
	}
}
