package main

import (
	"sync"
	"time"
)

// AuthTracker tracks authentication attempts for rate limiting
type AuthTracker struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

// NewAuthTracker creates a new AuthTracker instance
func NewAuthTracker() *AuthTracker {
	return &AuthTracker{
		attempts: make(map[string][]time.Time),
	}
}

// Track records an authentication attempt for a given IP
func (a *AuthTracker) Track(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.attempts[ip] = append(a.attempts[ip], now)
}

// IsBlocked checks if an IP is temporarily blocked
func (a *AuthTracker) IsBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	attempts := a.attempts[ip]
	threshold := now.Add(-1 * time.Minute) // 1-minute window

	// Filter attempts within the threshold
	var recentAttempts []time.Time
	for _, t := range attempts {
		if t.After(threshold) {
			recentAttempts = append(recentAttempts, t)
		}
	}
	a.attempts[ip] = recentAttempts

	// Block if there are too many attempts
	return len(recentAttempts) > 5
}
