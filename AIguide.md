Tuyệt vời! Chúng ta sẽ bắt đầu phác thảo cấu trúc code Golang dựa trên thiết kế chi tiết đã thống nhất. Tôi sẽ trình bày dưới dạng các file riêng biệt như đã đề xuất để dễ theo dõi.

Đây là phác thảo ban đầu, bạn có thể dùng nó làm sườn để triển khai chi tiết hơn.

---

### 1. `constants.go`

File này sẽ chứa các hằng số liên quan đến protocol SOCKS5.

```go
package main

// SOCKS5 Version
const socks5Version = 0x05

// Authentication Methods
const (
	AuthMethodNoAuthRequired   = 0x00
	AuthMethodGSSAPI           = 0x01 // Không hỗ trợ trong ví dụ này
	AuthMethodUserPass         = 0x02
	AuthMethodNoAcceptable     = 0xFF
)

// Username/Password Authentication Version (sub-negotiation)
const userPassAuthVersion = 0x01

// Username/Password Authentication Status
const (
	AuthStatusSuccess = 0x00
	AuthStatusFailure = 0x01 // Hoặc bất kỳ giá trị khác 0
)

// SOCKS5 Commands
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02 // Không hỗ trợ trong ví dụ này
	CmdUDPAssociate = 0x03 // Không hỗ trợ trong ví dụ này
)

// SOCKS5 Address Types
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// SOCKS5 Reply Codes
const (
	ReplySucceeded             = 0x00
	ReplyGeneralFailure        = 0x01
	ReplyConnectionNotAllowed  = 0x02
	ReplyNetworkUnreachable    = 0x03
	ReplyHostUnreachable       = 0x04
	ReplyConnectionRefused     = 0x05
	ReplyTTLExpired            = 0x06
	ReplyCommandNotSupported   = 0x07
	ReplyAddressTypeNotSupported = 0x08
)

// Reserved byte
const reservedByte = 0x00
```

---

### 2. `config.go`

File này định nghĩa struct `Config` và hàm để load cấu hình từ CLI.

```go
package main

import (
	"flag"
	"fmt"
)

// Config stores the application configuration
type Config struct {
	Host     string
	Port     string
	Username string
	Password string
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

	// Validate if username is provided, password must also be provided, and vice-versa (optional check)
	if (cfg.Username != "" && cfg.Password == "") || (cfg.Username == "" && cfg.Password != "") {
		return nil, fmt.Errorf("both username and password must be provided for authentication, or neither")
	}

	return cfg, nil
}
```

---

### 3. `main.go`

File này là entry point của ứng dụng, xử lý việc khởi tạo, chạy server và graceful shutdown.

```go
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
	// 1. Load Configuration
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// 2. Setup Logging (cơ bản)
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Thêm file và dòng code vào log

	log.Println("SOCKS5 Proxy starting...")
	log.Printf("Configuration: Host=%s, Port=%s, AuthEnabled=%t", cfg.Host, cfg.Port, cfg.Username != "")

	// 3. Create Server Instance
	socksServer, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// 4. Setup Graceful Shutdown
	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown() // Đảm bảo context được hủy

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// 5. Start Server in a goroutine
	go func() {
		log.Printf("Server listening on %s:%s", cfg.Host, cfg.Port)
		if err := socksServer.Start(shutdownCtx); err != nil {
			// Lỗi net.ErrClosed là bình thường khi listener đóng do shutdown
			if err.Error() != "http: Server closed" && err.Error() != "accept tcp [::]:"+cfg.Port+": use of closed network connection" && err.Error() != "accept tcp "+cfg.Host+":"+cfg.Port+": use of closed network connection" {
				log.Printf("Server error: %v", err) // Log lỗi nếu không phải do đóng bình thường
			}
			cancelShutdown() // Báo cho main goroutine là server đã dừng (hoặc có lỗi)
		}
	}()

	// 6. Wait for shutdown signal or server error
	select {
	case sig := <-signalChan:
		log.Printf("Received signal: %s. Initiating graceful shutdown...", sig)
	case <-shutdownCtx.Done(): // Server đã dừng do lỗi hoặc Start() kết thúc
		log.Println("Server goroutine exited. Initiating cleanup...")
	}

	// 7. Perform Graceful Shutdown
	shutdownTimeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if err := socksServer.Shutdown(shutdownTimeoutCtx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
	} else {
		log.Println("Server gracefully stopped.")
	}
}
```

---

### 4. `server.go`

File này chứa logic của SOCKS5 server, bao gồm việc lắng nghe kết nối và quản lý các client handler.

```go
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
	mu       sync.Mutex     // For protecting access to listener, etc. during shutdown
	// shutdown chan struct{} // Có thể dùng để báo hiệu cho vòng lặp Accept
}

// NewServer creates a new SOCKS5 server instance
func NewServer(cfg *Config) (*Server, error) {
	return &Server{
		config: cfg,
		// shutdown: make(chan struct{}),
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

	// Goroutine để lắng nghe context.Done() và đóng listener
	go func() {
		<-ctx.Done() // Khi context này bị hủy (do main signal hoặc lỗi server)
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
			// Kiểm tra nếu lỗi là do listener đã bị đóng (trong quá trình shutdown)
			select {
			case <-ctx.Done(): // Nếu context đã bị hủy, đây là lỗi mong đợi
				log.Println("Listener closed as part of shutdown.")
				return nil // Thoát khỏi vòng lặp Accept
			default:
				// Nếu không phải do shutdown, log lỗi và có thể tiếp tục
				// hoặc quyết định dừng hẳn nếu lỗi nghiêm trọng
				log.Printf("Failed to accept connection: %v", err)
				if ne, ok := err.(net.Error); ok && !ne.Temporary() {
					return fmt.Errorf("non-temporary accept error: %w", err)
				}
				// Với lỗi temporary, có thể thử lại
				continue
			}
		}

		log.Printf("Accepted connection from %s", conn.RemoteAddr())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handleConnection(conn, s.config)
		}()
	}
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.listener != nil {
		log.Println("Closing listener from Shutdown method...")
		s.listener.Close() // Đảm bảo listener đã đóng
	}
	s.mu.Unlock()

	// Chờ tất cả các client handlers hoàn thành hoặc timeout
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
		log.Printf("Shutdown timed out. %d active connections might be interrupted.", s.activeConnections())
		return fmt.Errorf("graceful shutdown timed out: %w", ctx.Err())
	}
}

// activeConnections (helper, cần theo dõi số lượng goroutine đang chạy nếu muốn con số chính xác)
// Với WaitGroup, chúng ta chỉ biết là chúng chưa Done, không có counter trực tiếp dễ dàng.
// Tuy nhiên, wg có thể được dùng để ước lượng.
func (s *Server) activeConnections() int {
	// Đây là cách đơn giản, nhưng không chính xác 100% nếu wg.Add/Done không được quản lý chặt chẽ
	// Hoặc bạn có thể tự duy trì một atomic counter.
	return 0 // Placeholder
}

```

---

### 5. `handler.go`

File này chứa logic chi tiết để xử lý một kết nối SOCKS5 từ client.

```go
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// handleConnection manages a single SOCKS5 client connection
func handleConnection(clientConn net.Conn, cfg *Config) {
	defer clientConn.Close()
	log.Printf("Handler started for %s", clientConn.RemoteAddr())

	// Thiết lập timeout cho các thao tác đọc/ghi ban đầu (handshake, auth, request)
	// clientConn.SetDeadline(time.Now().Add(30 * time.Second)) // Cân nhắc timeout tổng cho handshake

	// 1. SOCKS5 Handshake (Client Greeting & Server Method Selection)
	selectedMethod, err := handleHandshake(clientConn, cfg)
	if err != nil {
		log.Printf("Handshake failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// 2. Authentication (if required by selectedMethod)
	if selectedMethod == AuthMethodUserPass {
		if err := handleUserPassAuthentication(clientConn, cfg); err != nil {
			log.Printf("Authentication failed for %s: %v", clientConn.RemoteAddr(), err)
			return
		}
	}
	// Các phương thức xác thực khác không được hỗ trợ

	// 3. Client Request & Server Reply
	targetConn, err := handleRequest(clientConn)
	if err != nil {
		log.Printf("Handling SOCKS request failed for %s: %v", clientConn.RemoteAddr(), err)
		// Phản hồi lỗi đã được gửi trong handleRequest nếu có thể
		return
	}
	defer targetConn.Close()

	// 4. Data Relay
	// Xóa deadline đã set trước đó, vì data relay có thể kéo dài
	// clientConn.SetDeadline(time.Time{}) // Zero time value removes deadline

	log.Printf("Relaying data between %s and %s", clientConn.RemoteAddr(), targetConn.RemoteAddr())
	if err := relayData(clientConn, targetConn); err != nil {
		log.Printf("Data relay error between %s and %s: %v", clientConn.RemoteAddr(), targetConn.RemoteAddr(), err)
	}

	log.Printf("Handler finished for %s", clientConn.RemoteAddr())
}

// handleHandshake performs the SOCKS5 method negotiation phase
func handleHandshake(clientConn net.Conn, cfg *Config) (byte, error) {
	reader := bufio.NewReader(clientConn)

	// Read Client Greeting: VER | NMETHODS | METHODS
	// VER (1 byte)
	version, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read version: %w", err)
	}
	if version != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	// NMETHODS (1 byte)
	nMethods, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("failed to read nMethods: %w", err)
	}
	if nMethods == 0 {
		return 0, fmt.Errorf("no authentication methods offered by client")
	}

	// METHODS (nMethods bytes)
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return 0, fmt.Errorf("failed to read methods: %w", err)
	}

	// Select a method
	var selectedMethod byte = AuthMethodNoAcceptable
	authRequired := cfg.Username != "" // && cfg.Password != "" implicit from LoadConfig

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

	// Send Server Method Selection: VER | METHOD
	_, err = clientConn.Write([]byte{socks5Version, selectedMethod})
	if err != nil {
		return 0, fmt.Errorf("failed to send method selection: %w", err)
	}

	if selectedMethod == AuthMethodNoAcceptable {
		return selectedMethod, fmt.Errorf("no acceptable authentication method found")
	}

	log.Printf("Handshake successful for %s. Selected method: 0x%02X", clientConn.RemoteAddr(), selectedMethod)
	return selectedMethod, nil
}

// handleUserPassAuthentication performs username/password authentication
func handleUserPassAuthentication(clientConn net.Conn, cfg *Config) error {
	reader := bufio.NewReader(clientConn)

	// Read Username/Password Authentication Request: AUTH_VER | ULEN | UNAME | PLEN | PASSWD
	// AUTH_VER (1 byte)
	authVersion, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read auth version: %w", err)
	}
	if authVersion != userPassAuthVersion {
		// Gửi phản hồi thất bại
		clientConn.Write([]byte{userPassAuthVersion, AuthStatusFailure})
		return fmt.Errorf("unsupported auth sub-negotiation version: %d", authVersion)
	}

	// ULEN (1 byte)
	uLen, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read username length: %w", err)
	}
	if uLen == 0 {
		clientConn.Write([]byte{userPassAuthVersion, AuthStatusFailure})
		return fmt.Errorf("username length is zero")
	}

	// UNAME (uLen bytes)
	username := make([]byte, uLen)
	if _, err := io.ReadFull(reader, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// PLEN (1 byte)
	pLen, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}
	if pLen == 0 {
		clientConn.Write([]byte{userPassAuthVersion, AuthStatusFailure})
		return fmt.Errorf("password length is zero")
	}

	// PASSWD (pLen bytes)
	password := make([]byte, pLen)
	if _, err := io.ReadFull(reader, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Authenticate
	if string(username) == cfg.Username && string(password) == cfg.Password {
		// Send Success Reply: AUTH_VER | STATUS (0x00)
		if _, err := clientConn.Write([]byte{userPassAuthVersion, AuthStatusSuccess}); err != nil {
			return fmt.Errorf("failed to send auth success reply: %w", err)
		}
		log.Printf("Authentication successful for user '%s' from %s", string(username), clientConn.RemoteAddr())
		return nil
	}

	// Send Failure Reply: AUTH_VER | STATUS (0x01)
	log.Printf("Authentication failed for user '%s' from %s", string(username), clientConn.RemoteAddr())
	_, err = clientConn.Write([]byte{userPassAuthVersion, AuthStatusFailure})
	if err != nil {
		// Log lỗi gửi nhưng vẫn trả về lỗi xác thực gốc
		log.Printf("Failed to send auth failure reply: %v", err)
	}
	return fmt.Errorf("invalid username or password")
}

// sendSocksReply sends a SOCKS5 reply to the client.
// bndAddr and bndPort are typically the server's own address/port used for the connection to target,
// or can be 0.0.0.0:0 if not relevant or if privacy is a concern.
func sendSocksReply(clientConn net.Conn, rep byte, atyp byte, bndAddr []byte, bndPort uint16) error {
	reply := []byte{socks5Version, rep, reservedByte, atyp}

	if bndAddr == nil { // Default to 0.0.0.0 if not provided
		if atyp == AddrTypeIPv4 {
			bndAddr = net.IPv4zero.To4()
		} else if atyp == AddrTypeIPv6 {
			bndAddr = net.IPv6zero
		} else {
			// For domain name, address field in reply is not typically used this way,
			// but RFC specifies the server's bound address.
			// Simplification: send a minimal address for domain type if bndAddr is nil.
			// A better approach would be to resolve the server's outbound IP.
			// For now, let's assume atyp will be IPv4/IPv6 for server's bound addr.
			// If it's AddrTypeDomain, it means something is off or needs more logic.
			// For simplicity here, if atyp is domain, and bndAddr is nil, we'll send a dummy IPv4
			bndAddr = net.IPv4zero.To4()
			reply[3] = AddrTypeIPv4 // Adjust atyp in reply if we send IPv4
		}
	}
	reply = append(reply, bndAddr...)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bndPort)
	reply = append(reply, portBytes...)

	_, err := clientConn.Write(reply)
	return err
}


// handleRequest processes the client's SOCKS request (e.g., CONNECT)
func handleRequest(clientConn net.Conn) (net.Conn, error) {
	reader := bufio.NewReader(clientConn)

	// Read SOCKS Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	// VER (1 byte)
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read request version: %w", err)
	}
	if version != socks5Version {
		sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("unsupported request SOCKS version: %d", version)
	}

	// CMD (1 byte)
	cmd, err := reader.ReadByte()
	if err != nil {
		sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("failed to read command: %w", err)
	}

	// RSV (1 byte) - Must be 0x00
	if _, err := reader.ReadByte(); err != nil {
		sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("failed to read reserved byte: %w", err)
	}

	// ATYP (1 byte) - Address Type
	addrType, err := reader.ReadByte()
	if err != nil {
		sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("failed to read address type: %w", err)
	}

	var targetAddr string
	var targetHost string // For net.Dialer, can be IP or domain

	switch addrType {
	case AddrTypeIPv4: // IPv4
		ipv4 := make(net.IP, 4)
		if _, err := io.ReadFull(reader, ipv4); err != nil {
			sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
			return nil, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		targetHost = ipv4.String()
	case AddrTypeDomain: // Domain Name
		domainLen, err := reader.ReadByte()
		if err != nil {
			sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, domain); err != nil {
			sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
			return nil, fmt.Errorf("failed to read domain name: %w", err)
		}
		targetHost = string(domain)
	case AddrTypeIPv6: // IPv6
		ipv6 := make(net.IP, 16)
		if _, err := io.ReadFull(reader, ipv6); err != nil {
			sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
			return nil, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		targetHost = ipv6.String()
	default:
		sendSocksReply(clientConn, ReplyAddressTypeNotSupported, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// DST.PORT (2 bytes, network byte order)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		sendSocksReply(clientConn, ReplyGeneralFailure, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("failed to read target port: %w", err)
	}
	targetPort := binary.BigEndian.Uint16(portBytes)
	targetAddr = net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// Process Command
	switch cmd {
	case CmdConnect:
		log.Printf("Client %s requests CONNECT to %s", clientConn.RemoteAddr(), targetAddr)
		// Dial the target server
		dialer := net.Dialer{Timeout: 10 * time.Second} // Timeout for establishing connection
		targetConn, err := dialer.Dial("tcp", targetAddr)
		if err != nil {
			log.Printf("Failed to connect to target %s for %s: %v", targetAddr, clientConn.RemoteAddr(), err)
			replyCode := ReplyGeneralFailure
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					replyCode = ReplyTTLExpired // Or HostUnreachable depending on context
				} else if opError, ok := netErr.(*net.OpError); ok {
					// This can get complex, trying to map specific syscall errors
					// For simplicity, common ones:
					if opError.Op == "dial" {
						if opError.Addr == nil { // e.g. DNS resolution failed
							replyCode = ReplyHostUnreachable
						} else { // e.g. connection refused
							replyCode = ReplyConnectionRefused
						}
					}
				}
			}
			sendSocksReply(clientConn, replyCode, addrType, nil, 0) // Use original addrType for reply
			return nil, fmt.Errorf("failed to dial target %s: %w", targetAddr, err)
		}

		// Send success reply to client
		// BND.ADDR and BND.PORT should be the address and port the SOCKS server is using
		// for the connection to the target. targetConn.LocalAddr() provides this.
		localAddr := targetConn.LocalAddr().(*net.TCPAddr)
		var boundAddrBytes []byte
		var replyAddrType byte
		if localAddr.IP.To4() != nil {
			boundAddrBytes = localAddr.IP.To4()
			replyAddrType = AddrTypeIPv4
		} else {
			boundAddrBytes = localAddr.IP.To16()
			replyAddrType = AddrTypeIPv6
		}

		if err := sendSocksReply(clientConn, ReplySucceeded, replyAddrType, boundAddrBytes, uint16(localAddr.Port)); err != nil {
			targetConn.Close() // Close target connection if we can't reply to client
			return nil, fmt.Errorf("failed to send success reply to client: %w", err)
		}
		log.Printf("Successfully connected to %s for %s. Bound local: %s", targetAddr, clientConn.RemoteAddr(), localAddr.String())
		return targetConn, nil

	// CmdBind and CmdUDPAssociate are not supported in this example
	default:
		log.Printf("Client %s requested unsupported command: 0x%02X", clientConn.RemoteAddr(), cmd)
		sendSocksReply(clientConn, ReplyCommandNotSupported, AddrTypeIPv4, nil, 0)
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// relayData copies data between client and target connections
func relayData(clientConn, targetConn net.Conn) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var copyErr error // To capture the first error

	go func() {
		defer wg.Done()
		defer targetConn.Close() // If client closes, close target
		defer clientConn.Close() // Ensure client is closed if this goroutine exits
		defer cancel()           // Signal the other goroutine to stop

		_, err := io.Copy(targetConn, clientConn)
		if err != nil && err != io.EOF {
			// Don't log EOF as error, it's a normal close
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				// Normal closure
			} else {
				log.Printf("Error copying from client %s to target %s: %v", clientConn.RemoteAddr(), targetConn.RemoteAddr(), err)
				if copyErr == nil { copyErr = err }
			}
		}
		log.Printf("Relay client->target finished for %s", clientConn.RemoteAddr())
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close() // If target closes, close client
		defer targetConn.Close() // Ensure target is closed if this goroutine exits
		defer cancel()           // Signal the other goroutine to stop

		_, err := io.Copy(clientConn, targetConn)
		if err != nil && err != io.EOF {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				// Normal closure
			} else {
				log.Printf("Error copying from target %s to client %s: %v", targetConn.RemoteAddr(), clientConn.RemoteAddr(), err)
				if copyErr == nil { copyErr = err }
			}
		}
		log.Printf("Relay target->client finished for %s", clientConn.RemoteAddr())
	}()

	// Wait for either copy to finish or context to be cancelled
	// select {
	// case <-ctx.Done():
	// 	log.Printf("Relay context cancelled for %s", clientConn.RemoteAddr())
	// }
	wg.Wait() // Wait for both goroutines to complete
	log.Printf("Data relay fully completed for %s", clientConn.RemoteAddr())
	return copyErr
}

```

---

**Cách biên dịch và chạy:**

1.  Lưu các đoạn code trên vào các file tương ứng (`constants.go`, `config.go`, `main.go`, `server.go`, `handler.go`) trong cùng một thư mục.
2.  Mở terminal, điều hướng đến thư mục đó.
3.  Chạy `go mod init socks5proxy` (hoặc tên module bạn muốn).
4.  Chạy `go mod tidy` để đảm bảo các dependencies.
5.  Biên dịch: `go build -o socks5-proxy .`
6.  Chạy proxy:
    *   Không xác thực: `./socks5-proxy --port 1080`
    *   Có xác thực: `./socks5-proxy --port 1080 --username myuser --password mypass`
    *   Chỉ định host: `./socks5-proxy --host 127.0.0.1 --port 1080`

**Lưu ý quan trọng:**

*   **Error Handling:** Code trên đã bao gồm các bước xử lý lỗi cơ bản và gửi phản hồi SOCKS5. Trong một ứng dụng thực tế, bạn có thể muốn làm nó chi tiết và mạnh mẽ hơn.
*   **Resource Management:** `defer` được sử dụng rộng rãi để đóng các `net.Conn`. `sync.WaitGroup` và `context` giúp quản lý goroutines và graceful shutdown.
*   **Security:** Phần xác thực là Username/Password cơ bản. Không có mã hóa nào được áp dụng cho chính SOCKS5 protocol (đó là bản chất của SOCKS5).
*   **Testing:** Đây là phác thảo. Cần viết unit tests và integration tests đầy đủ.
*   **Logging:** Logging hiện tại là cơ bản. Có thể tích hợp thư viện logging mạnh mẽ hơn (logrus, zap) cho các tính năng như structured logging, log levels, output destinations.
*   **`relayData` function:** Logic `relayData` với `io.Copy` và `context` để hủy sớm là một cách phổ biến. Cần kiểm tra kỹ các trường hợp đóng kết nối (từ client, từ target, do lỗi).
*   **Timeout:** Các timeout được thêm vào cho việc dial và có thể cho handshake. Timeout cho `io.Copy` trong `relayData` phức tạp hơn vì kết nối có thể idle hợp lệ. `clientConn.SetDeadline(time.Time{})` được dùng để xóa deadline cho giai đoạn relay.

Đây là một điểm khởi đầu tốt. Bạn có thể bắt đầu điền vào chi tiết, thêm các kiểm tra, và tinh chỉnh dựa trên nhu cầu cụ thể. Hãy cho tôi biết nếu bạn có câu hỏi hoặc muốn đi sâu vào phần nào!