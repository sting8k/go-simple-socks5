package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandleHandshake(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		config     *Config
		wantMethod byte
		wantError  bool
	}{
		{
			name:       "NoAuth Method",
			input:      []byte{socks5Version, 1, AuthMethodNoAuthRequired},
			config:     &Config{},
			wantMethod: AuthMethodNoAuthRequired,
			wantError:  false,
		},
		{
			name:       "Auth Required but NoAuth Offered",
			input:      []byte{socks5Version, 1, AuthMethodNoAuthRequired},
			config:     &Config{Username: "user", Password: "pass"},
			wantMethod: AuthMethodNoAcceptable,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			done := make(chan struct{})
			go func() {
				client.Write(tt.input)
				// Read response before closing
				response := make([]byte, 2)
				client.Read(response)
				close(done)
				client.Close()
			}()

			method, err := handleHandshake(server, tt.config)
			if (err != nil) != tt.wantError {
				t.Errorf("handleHandshake() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError && method != tt.wantMethod {
				t.Errorf("handleHandshake() = %v, want %v", method, tt.wantMethod)
			}
			<-done
		})
	}
}

func TestHandleUserPassAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		config  *Config
		wantErr bool
	}{
		{
			name: "Valid Credentials",
			input: []byte{
				userPassAuthVersion,
				4,                  // username length
				'u', 's', 'e', 'r', // username
				4,                  // password length
				'p', 'a', 's', 's', // password
			},
			config: &Config{
				Username:    "user",
				Password:    "pass",
				AuthTracker: NewAuthTracker(), // Initialize AuthTracker
			},
			wantErr: false,
		},
		{
			name: "Invalid Credentials",
			input: []byte{
				userPassAuthVersion,
				4,                  // username length
				'u', 's', 'e', 'r', // username
				4,                  // password length
				'w', 'r', 'o', 'n', // wrong password
			},
			config: &Config{
				Username:    "user",
				Password:    "pass",
				AuthTracker: NewAuthTracker(), // Initialize AuthTracker
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			go func() {
				client.Write(tt.input)
				// Read response to prevent blocking
				response := make([]byte, 2)
				client.Read(response)
				client.Close()
			}()

			err := handleUserPassAuthentication(server, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleUserPassAuthentication() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticationRateLimiting(t *testing.T) {
	tests := []struct {
		name            string
		attempts        int
		shouldBeBlocked bool
	}{
		{
			name:            "Under Max Attempts",
			attempts:        3,
			shouldBeBlocked: false,
		},
		{
			name:            "Exactly Max Attempts",
			attempts:        5,
			shouldBeBlocked: false,
		},
		{
			name:            "Exceeds Max Attempts",
			attempts:        6,
			shouldBeBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Username:    "user",
				Password:    "pass",
				AuthTracker: NewAuthTracker(),
			}

			// Mock client IP address
			mockClientAddr := &net.TCPAddr{
				IP:   net.ParseIP("192.0.2.1"), // Test IP address
				Port: 12345,
			}

			// Invalid credentials for testing
			badAuth := []byte{
				userPassAuthVersion,
				4,                  // username length
				'u', 's', 'e', 'r', // username
				4,                  // password length
				'w', 'r', 'o', 'n', // wrong password
			}

			var lastErr error
			// Simulate multiple authentication attempts
			for i := 0; i < tt.attempts; i++ {
				client, server := net.Pipe()

				// Create a wrapped connection with mock remote address
				wrappedServer := &connWithAddr{
					Conn:       server,
					remoteAddr: mockClientAddr,
				}

				go func() {
					client.Write(badAuth)
					response := make([]byte, 2)
					client.Read(response)
					client.Close()
				}()

				lastErr = handleUserPassAuthentication(wrappedServer, config)
				server.Close()
			}

			if tt.shouldBeBlocked {
				if lastErr == nil || !strings.Contains(lastErr.Error(), "temporarily blocked") {
					t.Errorf("Expected client to be blocked after %d attempts, but got error: %v",
						tt.attempts, lastErr)
				}
			} else {
				if strings.Contains(lastErr.Error(), "temporarily blocked") {
					t.Errorf("Client should not be blocked after %d attempts, but was blocked",
						tt.attempts)
				}
			}
		})
	}
}

// Helper function to check if error is a blocking error
func isBlockedError(err error) bool {
	return err != nil && err.Error() == "client  is temporarily blocked"
}

// Add a helper type for mocking connection with remote address
type connWithAddr struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connWithAddr) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Override validateIP for testing
var originalValidateIP = validateIP

func TestHandleRequest(t *testing.T) {
	// Temporarily override validateIP to allow private IPs in tests
	validateIP = func(ip net.IP) error {
		return nil
	}
	// Restore original function after test
	defer func() {
		validateIP = originalValidateIP
	}()

	// Mock dialer for testing
	origDialTimeout := dialTimeout
	defer func() { dialTimeout = origDialTimeout }()

	// Create a mock dialer that returns a real TCP connection for testing
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		// Create a local TCP listener
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer listener.Close()

		// Connect to it
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}

		// Accept the connection and discard it
		go func() {
			c, _ := listener.Accept()
			if c != nil {
				c.Close()
			}
		}()

		return conn, nil
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Valid IPv4 Connect Request",
			input: []byte{
				socks5Version, // version
				CmdConnect,    // command
				0x00,          // reserved
				AddrTypeIPv4,  // address type
				127, 0, 0, 1,  // IPv4 address
				0x04, 0xD2, // port 1234 in network order
			},
			wantErr: false,
		},
		{
			name: "Valid Domain Connect Request",
			input: []byte{
				socks5Version,  // version
				CmdConnect,     // command
				0x00,           // reserved
				AddrTypeDomain, // address type
				9,              // domain length
				'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
				0x04, 0xD2, // port 1234
			},
			wantErr: false,
		},
		{
			name: "Unsupported Command",
			input: []byte{
				socks5Version,
				CmdBind, // unsupported command
				0x00,
				AddrTypeIPv4,
				127, 0, 0, 1,
				0x04, 0xD2,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			done := make(chan struct{})
			go func() {
				client.Write(tt.input)
				// Read response to prevent blocking
				response := make([]byte, 10)
				client.Read(response)
				close(done)
				client.Close()
			}()

			conn, err := handleRequest(server)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				conn.Close()
			}
			<-done
		})
	}
}

func TestRelayData(t *testing.T) {
	client1, client2 := net.Pipe()
	server1, server2 := net.Pipe()
	defer client1.Close()
	defer client2.Close()
	defer server1.Close()
	defer server2.Close()

	testData := []byte("Hello, World!")
	readDone := make(chan struct{})
	relayDone := make(chan struct{})

	// Start relay
	go func() {
		err := relayData(client1, server1)
		if err != nil && err != io.EOF {
			t.Errorf("relayData() error = %v", err)
		}
		close(relayDone)
	}()

	// Write to client2 and read from server2
	go func() {
		// Write test data
		_, err := client2.Write(testData)
		if err != nil {
			t.Errorf("Failed to write test data: %v", err)
		}
		client2.Close() // Close write end to signal EOF

		// Read and verify data
		received := make([]byte, len(testData))
		n, err := io.ReadFull(server2, received)
		if err != nil {
			t.Errorf("Failed to read data: %v", err)
		}
		if n != len(testData) {
			t.Errorf("Read %d bytes, want %d", n, len(testData))
		}
		if !bytes.Equal(received, testData) {
			t.Errorf("Got %q, want %q", received, testData)
		}

		close(readDone)
	}()

	// Wait for both operations to complete with timeout
	select {
	case <-readDone:
		// Data has been successfully read, now close remaining connections
		server2.Close()
		<-relayDone // Wait for relay to finish
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}
}
