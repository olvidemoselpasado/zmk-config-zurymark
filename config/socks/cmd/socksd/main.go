// Command socksd is a SOCKS5 proxy server.
//
// Configuration comes from the environment:
//
//	ADDR        listen address (default 127.0.0.1:1080)
//	PROXY_USER  if set together with PROXY_PASS, require this login
//	PROXY_PASS
//	LOG_LEVEL   debug, info, warn or error (default info)
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"socks/internal/proxy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		return fmt.Errorf("LOG_LEVEL: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	var creds map[string]string
	if user, pass := os.Getenv("PROXY_USER"), os.Getenv("PROXY_PASS"); user != "" && pass != "" {
		creds = map[string]string{user: pass}
	}

	ln, err := net.Listen("tcp", env("ADDR", "127.0.0.1:1080"))
	if err != nil {
		return err
	}

	srv := &proxy.Server{Log: logger, Credentials: creds, DialTimeout: 10 * time.Second}
	logger.Info("listening", "addr", ln.Addr().String(), "auth", creds != nil)
	err = srv.Serve(ctx, ln)
	logger.Info("stopped")
	return err
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
