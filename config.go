package main

import (
	"flag"
	"fmt"
)

// Config stores the SOCKS5 server configuration
type Config struct {
	Host        string       // Host address to listen on
	Port        string       // Port to listen on
	Username    string       // Optional username for authentication
	Password    string       // Optional password for authentication
	AuthTracker *AuthTracker // Authentication tracking instance
}

// LoadConfig parses command-line flags and returns a Config struct
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.Host, "host", "0.0.0.0", "Host IP address to listen on")
	flag.StringVar(&cfg.Port, "port", "", "Port to listen on (required)")
	flag.StringVar(&cfg.Username, "username", "", "Username for SOCKS5 authentication (optional)")
	flag.StringVar(&cfg.Password, "password", "", "Password for SOCKS5 authentication (optional)")

	flag.Parse()

	if cfg.Port == "" {
		return nil, fmt.Errorf("port is a required parameter")
	}

	// If one credential is provided, both must be provided
	if (cfg.Username != "" && cfg.Password == "") || (cfg.Username == "" && cfg.Password != "") {
		return nil, fmt.Errorf("both username and password must be provided for authentication")
	}

	// Initialize AuthTracker if authentication is enabled
	if cfg.Username != "" {
		cfg.AuthTracker = NewAuthTracker()
	}

	return cfg, nil
}
