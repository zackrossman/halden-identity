// Command server runs halden-identity, the public edge of the Halden platform.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zackrossman/halden-identity/internal/api"
	"github.com/zackrossman/halden-identity/internal/auth"
	"github.com/zackrossman/halden-identity/internal/config"
	"github.com/zackrossman/halden-identity/internal/downstream"
	"github.com/zackrossman/halden-identity/internal/jobs"
	"github.com/zackrossman/halden-identity/internal/proxy"
	"github.com/zackrossman/halden-identity/internal/users"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(); err != nil {
		slog.Error("halden-identity stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	keys, err := auth.NewJWKSCache(ctx, cfg.Auth0.JWKSURL)
	if err != nil {
		return err
	}

	minter := downstream.NewMinter(cfg.InternalTokenSecret)

	handler := api.NewRouter(
		auth.NewValidator(keys, cfg.Auth0.Issuer, cfg.Auth0.Audience),
		users.NewStore(),
		proxy.NewThreatScans(cfg.ThreatDetectionURL, minter),
	)

	warmup := jobs.NewWarmup(cfg.ThreatDetectionURL, minter, 5*time.Minute)
	go warmup.Run(ctx)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr)
		errc <- server.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}
