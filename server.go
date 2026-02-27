package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "sync"
)

// Server struct holds server-specific data
type Server struct {
    config   *Config
    listener net.Listener
    wg       sync.WaitGroup // To wait for all client handlers to finish
    mu       sync.Mutex     // For protecting access to listener during shutdown
    sem      chan struct{}   // Semaphore for limiting concurrent connections
}

// NewServer creates a new SOCKS5 server instance
func NewServer(cfg *Config) (*Server, error) {
    return &Server{
        config: cfg,
        sem:    make(chan struct{}, cfg.MaxConnections),
    }, nil
}

// Start begins listening for incoming SOCKS5 client connections
func (s *Server) Start(ctx context.Context) error {
    listenAddr := fmt.Sprintf("%s:%s", s.config.Host, s.config.Port)
    listener, err := net.Listen("tcp", listenAddr)
    if err != nil {
        return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
    }
    s.mu.Lock()
    s.listener = listener
    s.mu.Unlock()

    defer func() {
        s.mu.Lock()
        if s.listener != nil {
            s.listener.Close()
        }
        s.mu.Unlock()
    }()

    // Listen for shutdown signal
    go func() {
        <-ctx.Done()
        s.mu.Lock()
        if s.listener != nil {
            log.Println("Shutdown signal received, closing listener...")
            s.listener.Close()
        }
        s.mu.Unlock()
    }()

    for {
        conn, err := s.listener.Accept()
        if err != nil {
            select {
            case <-ctx.Done():
                log.Println("Listener closed as part of shutdown.")
                return nil
            default:
                log.Printf("Failed to accept connection: %v", err)
                if ne, ok := err.(net.Error); ok && !ne.Temporary() {
                    return fmt.Errorf("non-temporary accept error: %w", err)
                }
                continue
            }
        }

        log.Printf("Accepted connection from %s", conn.RemoteAddr())

        // Acquire semaphore slot, reject if at capacity
        select {
        case s.sem <- struct{}{}:
            s.wg.Add(1)
            go func() {
                defer s.wg.Done()
                defer func() { <-s.sem }()
                handleConnection(conn, s.config)
            }()
        default:
            log.Printf("Max connections (%d) reached, rejecting %s", s.config.MaxConnections, conn.RemoteAddr())
            conn.Close()
        }
    }
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
    s.mu.Lock()
    if s.listener != nil {
        log.Println("Closing listener from Shutdown method...")
        s.listener.Close()
    }
    s.mu.Unlock()

    done := make(chan struct{})
    go func() {
        s.wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        log.Println("All client handlers finished.")
        return nil
    case <-ctx.Done():
        log.Println("Shutdown timed out. Some connections may be interrupted.")
        return fmt.Errorf("graceful shutdown timed out: %w", ctx.Err())
    }
}