package main

import (
	"errors"
	"net"
)

// validateIP holds the function that checks if the given IP is valid
var validateIP = func(ip net.IP) error {
	if ip.IsLoopback() {
		return errors.New("loopback IP addresses are not allowed: " + ip.String())
	}
	if ip.IsPrivate() {
		return errors.New("private IP addresses are not allowed: " + ip.String())
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return errors.New("link-local IP addresses are not allowed: " + ip.String())
	}
	if ip.IsMulticast() {
		return errors.New("multicast IP addresses are not allowed: " + ip.String())
	}
	return nil
}
