# go-simple-socks5

A lightweight SOCKS5 proxy server implementation in Go, following RFC 1928 specification.

## Why This Project?

I created this project out of necessity when Telegram was blocked in my country. I needed a quick, reliable SOCKS5 proxy that I could deploy on my server to maintain access to essential communication services. The goal was to build something lightweight and straightforward that just works, without unnecessary complexity.

This project was totally developed by AI assistance, specifically:
- Gemini 2.5 Pro
- Claude 3.5 Sonnet

## Features

- SOCKS5 protocol support
- IPv4, IPv6, and domain name resolution
- Username/password authentication (RFC 1929)
- Connection timeout handling
- Graceful shutdown
- Comprehensive test coverage

## Installation

```sh
go install github.com/sting8k/go-simple-socks5@latest
```

Or clone and build:

```sh
git clone https://github.com/sting8k/go-simple-socks5.git
cd go-simple-socks5
go build
```

## Usage

Basic usage:

```sh
# Start proxy without authentication
./go-simple-socks5 --port 1080

# Start with authentication
./go-simple-socks5 --port 1080 --username user --password pass

# Specify listening interface
./go-simple-socks5 --host 127.0.0.1 --port 1080
```

### Command-line Options

- `--host`: Host address to listen on (default: "0.0.0.0")
- `--port`: Port to listen on (required)
- `--username`: Username for authentication (optional)
- `--password`: Password for authentication (optional)

## Testing

Run the test suite:

```sh
go test -v ./...
```

## License

MIT License