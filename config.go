package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
)

// Config stores the SOCKS5 server configuration
type Config struct {
	Host           string       // Host address to listen on
	Port           string       // Port to listen on
	Username       string       // Optional username for authentication
	Password       string       // Optional password for authentication
	AuthTracker    *AuthTracker // Authentication tracking instance
	MaxConnections int          // Maximum concurrent connections (0 = default 256)
}

// LoadConfig parses command-line flags and returns a Config struct
func LoadConfig() (*Config, error) {
	showVersion := flag.Bool("version", false, "Show version and exit")
	cfg := &Config{}

	flag.StringVar(&cfg.Host, "host", "0.0.0.0", "Host IP address to listen on")
	flag.StringVar(&cfg.Port, "port", "", "Port to listen on (required)")
	flag.StringVar(&cfg.Username, "username", "", "Username for SOCKS5 authentication (optional)")
	flag.StringVar(&cfg.Password, "password", "", "Password for SOCKS5 authentication (optional)")
	flag.IntVar(&cfg.MaxConnections, "max-connections", 256, "Maximum concurrent connections (default: 256)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("go-simple-socks5 version %s\n", AppVersion)
		return nil, fmt.Errorf("version shown")
	}

	if cfg.Port == "" {
		return nil, fmt.Errorf("port is a required parameter")
	}

	// Validate port
	if cfg.Port != "" {
		portNum, err := strconv.Atoi(cfg.Port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", cfg.Port)
		}
	}

	// Validate host IP
	if cfg.Host != "0.0.0.0" && cfg.Host != "localhost" {
		if ip := net.ParseIP(cfg.Host); ip == nil {
			return nil, fmt.Errorf("invalid host IP address: %s", cfg.Host)
		}
	}

	// If one credential is provided, both must be provided
	if (cfg.Username != "" && cfg.Password == "") || (cfg.Username == "" && cfg.Password != "") {
		return nil, fmt.Errorf("both username and password must be provided for authentication")
	}

	// Validate credential lengths if provided
	if cfg.Username != "" {
		if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
			return nil, fmt.Errorf("username and password must not exceed 255 characters")
		}
	}

	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 256
	}

	// Initialize AuthTracker if authentication is enabled
	if cfg.Username != "" {
		cfg.AuthTracker = NewAuthTracker()
	}

	return cfg, nil
}
