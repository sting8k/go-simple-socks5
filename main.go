package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		if err.Error() == "version shown" {
			return
		}
		log.Fatalf("Error loading configuration: %v", err)
	}

	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("SOCKS5 Proxy starting...")
	log.Printf("Configuration: Host=%s, Port=%s, AuthEnabled=%t", cfg.Host, cfg.Port, cfg.Username != "")

	socksServer, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Server listening on %s:%s", cfg.Host, cfg.Port)
		if err := socksServer.Start(shutdownCtx); err != nil {
			if err.Error() != "http: Server closed" && !isNormalCloseError(err, cfg) {
				log.Printf("Server error: %v", err)
			}
			cancelShutdown()
		}
	}()

	select {
	case sig := <-signalChan:
		log.Printf("Received signal: %s. Initiating graceful shutdown...", sig)
	case <-shutdownCtx.Done():
		log.Println("Server goroutine exited. Initiating cleanup...")
	}

	shutdownTimeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if err := socksServer.Shutdown(shutdownTimeoutCtx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
	} else {
		log.Println("Server gracefully stopped.")
	}
}

func isNormalCloseError(err error, cfg *Config) bool {
	errStr := err.Error()
	return errStr == "accept tcp [::]:"+cfg.Port+": use of closed network connection" ||
		errStr == "accept tcp "+cfg.Host+":"+cfg.Port+": use of closed network connection"
}
