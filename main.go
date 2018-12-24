package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AndrewBurian/powermux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	// Flags
	var debug, quiet, help bool

	flag.BoolVar(&debug, "debug", false, "Debug verbosity")
	flag.BoolVar(&quiet, "quiet", false, "Errors only")
	flag.BoolVar(&help, "help", false, "Display usage")
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	// Logging Config
	// ----------------------------------------
	if debug && quiet {
		log.Fatal("Can only set one of -quiet and -debug")
	}

	if debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Running at debug verbosity")
	} else if quiet {
		log.SetLevel(log.ErrorLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// OAuth Config
	// ----------------------------------------
	domain, ok := os.LookupEnv("HOST_DOMAIN")
	if !ok {
		log.Fatal("Environment variable HOST_DOMAIN needs to be set")
	}

	clientID, ok := os.LookupEnv("GOOGLE_OAUTH_CLIENT_ID")
	if !ok {
		log.Fatal("Environment variable GOOGLE_OAUTH_CLIENT_ID needs to be set")
	}

	clientSecret, ok := os.LookupEnv("GOOGLE_OAUTH_CLIENT_SECRET")
	if !ok {
		log.Fatal("Environment variable GOOGLE_OAUTH_CLIENT_SECRET needs to be set")
	}

	oauthConf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("https://%s/oauth/google/redirect", domain),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	tokenStore := NewInMemStore()

	// User Config
	// ----------------------------------------
	authHandler := NewOAuth2Handler(oauthConf, tokenStore, "/")

	userHandler := NewUserAuth()

	// API Config
	// ----------------------------------------
	api := &GoogleAPI{
		conf:  oauthConf,
		store: tokenStore,
	}

	// Router Config
	// ----------------------------------------
	mux := powermux.NewServeMux()

	mux.Route("/oauth").MiddlewareFunc(userHandler.AuthUser).
		Route("/google").GetFunc(authHandler.RequestAuth).
		Route("/redirect").GetFunc(authHandler.RedirectURL)

	mux.Route("/user").PostFunc(userHandler.Signup).
		Route("/login").PostFunc(userHandler.Login)

	mux.Route("/api").MiddlewareFunc(userHandler.AuthUser).
		Route("/me").GetFunc(api.GetUser)

	// Server Config
	// ----------------------------------------
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8080"
	}
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}

	// graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-signals
		log.WithField("signal", s).Info("Trapped signal")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("Error shutting down server")
		}
	}()

	// Run server
	log.WithField("addr", server.Addr).Info("Server Starting")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.WithError(err).Fatal("Error with server")
	}

	log.Info("Server Shutting down")
}
