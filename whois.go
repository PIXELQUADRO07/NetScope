package main

import (
	"fmt"
	"net/http"
	"time"
)

func QueryWhoisIP(ip string) (string, error) {
	url := fmt.Sprintf("https://whois.arin.net/rest/ip/%s", ip)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("whois query fallito: %s", resp.Status)
	}

	buffer := make([]byte, 4096)
	n, _ := resp.Body.Read(buffer)
	return string(buffer[:n]), nil
}

func QueryWhoisDomain(domain string) (string, error) {
	url := fmt.Sprintf("https://whois.arin.net/rest/domain/%s", domain)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("whois query fallito: %s", resp.Status)
	}

	buffer := make([]byte, 4096)
	n, _ := resp.Body.Read(buffer)
	return string(buffer[:n]), nil
}
