package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// Variable for testing
var dialTimeout = net.DialTimeout

// handleConnection manages a single SOCKS5 client connection
func handleConnection(clientConn net.Conn, cfg *Config) {
	defer clientConn.Close()
	log.Printf("Handler started for %s", clientConn.RemoteAddr())

	// Create a single buffered reader for the entire connection lifetime
	reader := bufio.NewReader(clientConn)

	// Set deadline for handshake + auth phase to prevent slowloris attacks
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. SOCKS5 Handshake
	selectedMethod, err := handleHandshake(reader, clientConn, cfg)
	if err != nil {
		log.Printf("Handshake failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// 2. Authentication if required
	if selectedMethod == AuthMethodUserPass {
		if err := handleUserPassAuthentication(reader, clientConn, cfg); err != nil {
			log.Printf("Authentication failed for %s: %v", clientConn.RemoteAddr(), err)
			return
		}
	}

	// 3. Handle client request
	targetConn, err := handleRequest(reader, clientConn)
	if err != nil {
		log.Printf("Request handling failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}
	defer targetConn.Close()

	// Clear deadline before relay phase (relay can be long-lived)
	clientConn.SetDeadline(time.Time{})

	// 4. Relay data between connections
	log.Printf("Starting data relay for %s <-> %s", clientConn.RemoteAddr(), targetConn.RemoteAddr())
	if err := relayData(clientConn, targetConn); err != nil {
		log.Printf("Data relay error for %s: %v", clientConn.RemoteAddr(), err)
	}
}

// handleHandshake performs the SOCKS5 method negotiation phase
func handleHandshake(reader *bufio.Reader, clientConn net.Conn, cfg *Config) (byte, error) {

	// Read version and number of methods
	version, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read version: %w", err)
	}
	if version != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	nmethods, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read nmethods: %w", err)
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

func handleUserPassAuthentication(reader *bufio.Reader, clientConn net.Conn, cfg *Config) error {
	// Check rate limiting first
	if cfg.AuthTracker != nil {
		clientIP := clientConn.RemoteAddr().(*net.TCPAddr).IP.String()
		if cfg.AuthTracker.IsBlocked(clientIP) {
			return fmt.Errorf("client %s is temporarily blocked", clientIP)
		}
	}

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
	if err != nil {
		return fmt.Errorf("failed to read username length: %w", err)
	}

	username := make([]byte, ulen)
	if _, err := io.ReadFull(reader, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Read password length and password
	plen, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}

	password := make([]byte, plen)
	if _, err := io.ReadFull(reader, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Verify credentials using constant-time comparison to prevent timing attacks
	var status byte = AuthStatusFailure
	usernameMatch := subtle.ConstantTimeCompare(username, []byte(cfg.Username))
	passwordMatch := subtle.ConstantTimeCompare(password, []byte(cfg.Password))
	if usernameMatch == 1 && passwordMatch == 1 {
		status = AuthStatusSuccess
	} else if cfg.AuthTracker != nil {
		// Track failed attempt
		clientIP := clientConn.RemoteAddr().(*net.TCPAddr).IP.String()
		cfg.AuthTracker.Track(clientIP)
	}

	// Send response
	response := []byte{userPassAuthVersion, status}
	if _, err := clientConn.Write(response); err != nil {
		return fmt.Errorf("failed to send auth response: %w", err)
	}

	if status == AuthStatusFailure {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

func handleRequest(reader *bufio.Reader, clientConn net.Conn) (net.Conn, error) {

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
		targetAddr = net.IP(addr).String()

	case AddrTypeDomain:
		domainLen, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
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
	// Add IP validation for direct IP connections
	if addrType == AddrTypeIPv4 || addrType == AddrTypeIPv6 {
		ip := net.ParseIP(targetAddr)
		if ip != nil {
			if err := validateIP(ip); err != nil {
				sendReply(clientConn, ReplyConnectionNotAllowed, nil, 0)
				return nil, err
			}
		}
	}

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
	errc := make(chan error, 2)

	// Client -> Target
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errc <- err
	}()

	// Target -> Client
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errc <- err
	}()

	// When one direction finishes, close both connections
	// so the other direction unblocks and finishes too
	err := <-errc
	clientConn.Close()
	targetConn.Close()
	<-errc // wait for the other goroutine to finish

	return err
}
