package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func ScanCustomPorts(ip net.IP, ports []int, concurrency int) map[int]string {
	if concurrency < 1 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	results := make(map[int]string)
	var mu sync.Mutex

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				results[port] = "aperta"
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

func DetectServiceVersion(ip net.IP, port int) string {
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)

	banner := strings.TrimSpace(string(buffer[:n]))

	serviceMap := map[string]string{
		"Apache":     "Apache HTTP Server",
		"nginx":      "Nginx",
		"Microsoft":  "IIS",
		"OpenSSH":    "OpenSSH",
		"vsftpd":     "vsftpd FTP",
		"ProFTPD":    "ProFTPD",
		"Postfix":    "Postfix",
		"Sendmail":   "Sendmail",
		"Exim":       "Exim",
		"MySQL":      "MySQL",
		"PostgreSQL": "PostgreSQL",
		"MongoDB":    "MongoDB",
		"Redis":      "Redis",
	}

	for signature, service := range serviceMap {
		if strings.Contains(banner, signature) {
			return service
		}
	}

	return banner
}

func ScanWithVersionDetection(ip net.IP, ports []int, concurrency int) map[int]string {
	results := make(map[int]string)

	openPorts := ScanCustomPorts(ip, ports, concurrency)
	for port := range openPorts {
		version := DetectServiceVersion(ip, port)
		if version != "" {
			results[port] = version
		} else {
			results[port] = "aperta (versione sconosciuta)"
		}
	}

	return results
}
