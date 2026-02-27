package main

// SOCKS5 Version
const socks5Version = 0x05

const AppVersion = "1.1.0"

// Authentication Methods
const (
	AuthMethodNoAuthRequired byte = 0x00
	AuthMethodGSSAPI         byte = 0x01
	AuthMethodUserPass       byte = 0x02
	AuthMethodNoAcceptable   byte = 0xFF
)

// Username/Password Authentication Version
const userPassAuthVersion = 0x01

// Authentication Status
const (
	AuthStatusSuccess = 0x00
	AuthStatusFailure = 0x01
)

// SOCKS5 Commands
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// SOCKS5 Address Types
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// SOCKS5 Reply Codes
const (
	ReplySucceeded               = 0x00
	ReplyGeneralFailure          = 0x01
	ReplyConnectionNotAllowed    = 0x02
	ReplyNetworkUnreachable      = 0x03
	ReplyHostUnreachable         = 0x04
	ReplyConnectionRefused       = 0x05
	ReplyTTLExpired              = 0x06
	ReplyCommandNotSupported     = 0x07
	ReplyAddressTypeNotSupported = 0x08
)

// Reserved byte
const reservedByte = 0x00
