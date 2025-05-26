package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Variable for testing
var dialTimeout = net.DialTimeout

// Max failed attempts before blocking
const maxFailedAttempts = 5
const blockDuration = 5 * time.Minute

// Add near the top with other vars
var validateIP = func(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}
	// Check for private networks
	if ip.IsPrivate() || ip.IsLoopback() {
		return fmt.Errorf("access to private/local networks not allowed")
	}
	return nil
}

// Add to handler.go
type AuthTracker struct {
	failedAttempts map[string]int
	blockedClients map[string]time.Time
	mu             sync.Mutex
	cleanupTicker  *time.Ticker
}

// Config struct is defined in config.go; do not redefine here.

func NewAuthTracker() *AuthTracker {
	at := &AuthTracker{
		failedAttempts: make(map[string]int),
		blockedClients: make(map[string]time.Time),
		cleanupTicker:  time.NewTicker(10 * time.Minute),
	}
	go at.cleanup()
	return at
}

func (at *AuthTracker) cleanup() {
	for range at.cleanupTicker.C {
		at.mu.Lock()
		now := time.Now()
		// Cleanup old blocked entries
		for ip, t := range at.blockedClients {
			if now.After(t) {
				delete(at.blockedClients, ip)
				delete(at.failedAttempts, ip)
			}
		}
		at.mu.Unlock()
	}
}

func setConnTimeout(conn net.Conn) {
	// Increase timeouts if needed for your use case
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
}

// handleConnection manages a single SOCKS5 client connection
func handleConnection(clientConn net.Conn, cfg *Config) {
	defer clientConn.Close()
	setConnTimeout(clientConn)
	remoteAddr := clientConn.RemoteAddr().String()
	log.Printf("Handler started for %s", remoteAddr)

	// 1. SOCKS5 Handshake
	selectedMethod, err := handleHandshake(clientConn, cfg)
	if err != nil {
		if err == io.EOF {
			log.Printf("Client %s disconnected during handshake", remoteAddr)
		} else {
			log.Printf("Handshake failed for %s: %v", remoteAddr, err)
		}
		return
	}

	// 2. Authentication if required
	if selectedMethod == AuthMethodUserPass {
		if err := handleUserPassAuthentication(clientConn, cfg); err != nil {
			if err == io.EOF {
				log.Printf("Client %s disconnected during authentication", remoteAddr)
			} else {
				log.Printf("Authentication failed for %s: %v", remoteAddr, err)
			}
			return
		}
	}

	// 3. Handle client request
	targetConn, err := handleRequest(clientConn)
	if err != nil {
		if err == io.EOF {
			log.Printf("Client %s disconnected before sending request", remoteAddr)
		} else {
			log.Printf("Request handling failed for %s: %v", remoteAddr, err)
		}
		return
	}
	defer targetConn.Close()

	// 4. Relay data between connections
	log.Printf("Starting data relay for %s <-> %s", remoteAddr, targetConn.RemoteAddr())
	if err := relayData(clientConn, targetConn); err != nil {
		if err == io.EOF {
			log.Printf("Connection closed by peer %s", remoteAddr)
		} else {
			log.Printf("Data relay error for %s: %v", remoteAddr, err)
		}
	}
}

// handleHandshake performs the SOCKS5 method negotiation phase
func handleHandshake(clientConn net.Conn, cfg *Config) (byte, error) {
	reader := bufio.NewReader(clientConn)

	// Read version and number of methods
	version, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read version: %w", err)
	}
	if version != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	nmethods, err := reader.ReadByte()
	if err != nil || nmethods == 0 || nmethods > 255 {
		return 0, fmt.Errorf("invalid nmethods value: %w", err)
	}

	// Read methods
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return 0, fmt.Errorf("failed to read methods: %w", err)
	}

	// Select authentication method
	var selectedMethod byte = AuthMethodNoAcceptable
	authRequired := cfg.Username != ""

	for _, method := range methods {
		if authRequired && method == AuthMethodUserPass {
			selectedMethod = AuthMethodUserPass
			break
		}
		if !authRequired && method == AuthMethodNoAuthRequired {
			selectedMethod = AuthMethodNoAuthRequired
			break
		}
	}

	// Send response
	response := []byte{socks5Version, selectedMethod}
	if _, err := clientConn.Write(response); err != nil {
		return 0, fmt.Errorf("failed to send method selection: %w", err)
	}

	if selectedMethod == AuthMethodNoAcceptable {
		return selectedMethod, fmt.Errorf("no acceptable authentication method")
	}

	return selectedMethod, nil
}

// handleUserPassAuthentication performs username/password authentication with protections
func handleUserPassAuthentication(clientConn net.Conn, cfg *Config) error {
	clientAddr, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())

	// Use global or passed AuthTracker instance
	authTracker := cfg.AuthTracker
	if authTracker == nil {
		return fmt.Errorf("auth tracker not initialized")
	}

	// Check if client is blocked
	authTracker.mu.Lock()
	if unblockTime, blocked := authTracker.blockedClients[clientAddr]; blocked {
		if time.Now().Before(unblockTime) {
			authTracker.mu.Unlock()
			return fmt.Errorf("client %s is temporarily blocked", clientAddr)
		}
		delete(authTracker.blockedClients, clientAddr) // Unblock client
	}
	authTracker.mu.Unlock()

	reader := bufio.NewReader(clientConn)

	// Read auth version
	version, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read auth version: %w", err)
	}
	if version != userPassAuthVersion {
		return fmt.Errorf("unsupported auth version: %d", version)
	}

	// Read username length and username
	ulen, err := reader.ReadByte()
	if err != nil || ulen == 0 || ulen > 255 {
		return fmt.Errorf("invalid username length: %w", err)
	}

	username := make([]byte, ulen)
	if _, err := io.ReadFull(reader, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Read password length and password
	plen, err := reader.ReadByte()
	if err != nil || plen == 0 || plen > 255 {
		return fmt.Errorf("invalid password length: %w", err)
	}

	password := make([]byte, plen)
	if _, err := io.ReadFull(reader, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Verify credentials
	var status byte = AuthStatusFailure
	if secureCompare(username, []byte(cfg.Username)) &&
		secureCompare(password, []byte(cfg.Password)) {
		status = AuthStatusSuccess
	}

	if status == AuthStatusFailure {
		// Increment failed attempts
		authTracker.mu.Lock()
		authTracker.failedAttempts[clientAddr]++
		if authTracker.failedAttempts[clientAddr] >= maxFailedAttempts {
			authTracker.blockedClients[clientAddr] = time.Now().Add(blockDuration)
			log.Printf("Client %s is temporarily blocked due to repeated failed attempts", clientAddr)
		}
		authTracker.mu.Unlock()
		return fmt.Errorf("invalid credentials")
	}

	// Reset failed attempts on successful authentication
	authTracker.mu.Lock()
	delete(authTracker.failedAttempts, clientAddr)
	authTracker.mu.Unlock()

	return nil
}

func handleRequest(clientConn net.Conn) (net.Conn, error) {
	reader := bufio.NewReader(clientConn)

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read request version: %w", err)
	}
	if version != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	// Read command
	command, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read command: %w", err)
	}

	// Skip reserved byte
	if _, err := reader.ReadByte(); err != nil {
		return nil, fmt.Errorf("failed to read reserved byte: %w", err)
	}

	// Read address type
	addrType, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read address type: %w", err)
	}

	// Read destination address
	var targetAddr string
	switch addrType {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		ip := net.IP(addr)
		if err := validateIP(ip); err != nil {
			return nil, err
		}
		targetAddr = ip.String()

	case AddrTypeDomain:
		domainLen, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}
		if err := validateDomain(string(domain)); err != nil {
			return nil, err
		}
		targetAddr = string(domain)

	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		targetAddr = net.IP(addr).String()

	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, fmt.Errorf("failed to read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	// Handle command
	switch command {
	case CmdConnect:
		return handleConnect(clientConn, targetAddr, port, addrType)
	default:
		sendReply(clientConn, ReplyCommandNotSupported, nil, 0)
		return nil, fmt.Errorf("unsupported command: %d", command)
	}
}

func handleConnect(clientConn net.Conn, targetAddr string, port uint16, addrType byte) (net.Conn, error) {
	// Connect to target
	target := fmt.Sprintf("%s:%d", targetAddr, port)
	targetConn, err := dialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendReply(clientConn, ReplyHostUnreachable, nil, 0)
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	// Send success reply
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	sendReply(clientConn, ReplySucceeded, localAddr.IP, uint16(localAddr.Port))

	return targetConn, nil
}

func sendReply(conn net.Conn, reply byte, bindAddr net.IP, bindPort uint16) {
	// Prepare response
	response := make([]byte, 0, 10)
	response = append(response, socks5Version, reply, 0x00)

	if bindAddr == nil || len(bindAddr) == 0 {
		response = append(response, AddrTypeIPv4)
		response = append(response, net.IPv4zero.To4()...)
	} else if bindAddr.To4() != nil {
		response = append(response, AddrTypeIPv4)
		response = append(response, bindAddr.To4()...)
	} else {
		response = append(response, AddrTypeIPv6)
		response = append(response, bindAddr.To16()...)
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, bindPort)
	response = append(response, port...)

	conn.Write(response)
}

func relayData(clientConn, targetConn net.Conn) error {
	var wg sync.WaitGroup
	var err error

	wg.Add(2)
	done := make(chan struct{})

	// Client to target
	go func() {
		defer wg.Done()
		defer close(done)
		_, err = io.Copy(targetConn, clientConn)
	}()

	// Target to client
	go func() {
		defer wg.Done()
		_, err = io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
	return err
}

func validateDomain(domain string) error {
	if len(domain) > 255 {
		return fmt.Errorf("domain name too long")
	}
	// Add more domain validation rules
	return nil
}

func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
