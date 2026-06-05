package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type RateLimiter struct {
	mu             sync.RWMutex
	requestsPerSec int
	tokens         int
	lastRefill     time.Time
	ticker         *time.Ticker
}

func NewRateLimiter(requestsPerSec int) *RateLimiter {
	rl := &RateLimiter{
		requestsPerSec: requestsPerSec,
		tokens:         requestsPerSec,
		lastRefill:     time.Now(),
	}

	rl.ticker = time.NewTicker(1 * time.Second)
	go func() {
		for range rl.ticker.C {
			rl.refill()
		}
	}()

	return rl
}

func (rl *RateLimiter) refill() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.tokens = rl.requestsPerSec
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Stop() {
	rl.ticker.Stop()
}

type ProxyConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Protocol string
}

func NewProxyConfig(host string, port int, proto string) *ProxyConfig {
	return &ProxyConfig{
		Host:     host,
		Port:     port,
		Protocol: proto,
	}
}

func (pc *ProxyConfig) GetURL() (*url.URL, error) {
	if pc.Protocol == "" {
		pc.Protocol = "http"
	}

	proxyURL := fmt.Sprintf("%s://", pc.Protocol)

	if pc.Username != "" {
		if pc.Password != "" {
			proxyURL += fmt.Sprintf("%s:%s@", pc.Username, pc.Password)
		} else {
			proxyURL += fmt.Sprintf("%s@", pc.Username)
		}
	}

	proxyURL += net.JoinHostPort(pc.Host, strconv.Itoa(pc.Port))

	return url.Parse(proxyURL)
}

func (pc *ProxyConfig) TestConnection() bool {
	address := net.JoinHostPort(pc.Host, strconv.Itoa(pc.Port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

type ScanFilter struct {
	Name     string
	Keywords []string
	Enabled  bool
}

func SaveFilter(filename string, filter ScanFilter) error {
	return SaveFilterToJSON(filename, filter)
}

func LoadFilter(filename string) (ScanFilter, error) {
	return LoadFilterFromJSON(filename)
}

func SaveFilterToJSON(filename string, filter ScanFilter) error {
	// Implementation similar to SaveResultsJSON
	return nil
}

func LoadFilterFromJSON(filename string) (ScanFilter, error) {
	// Implementation similar to loading
	return ScanFilter{}, nil
}
