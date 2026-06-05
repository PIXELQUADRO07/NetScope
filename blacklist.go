package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type BlacklistChecker struct {
	lists map[string]string
}

func NewBlacklistChecker() *BlacklistChecker {
	return &BlacklistChecker{
		lists: map[string]string{
			"abuseipdb":       "https://api.abuseipdb.com/api/v2/check",
			"projecthoneypot": "http://www.projecthoneypot.org/query.php",
		},
	}
}

func (bc *BlacklistChecker) CheckIP(ip string) (bool, string) {
	client := http.Client{Timeout: 5 * time.Second}

	for source, url := range bc.lists {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "NetScope")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), ip) {
				return true, source
			}
		}
	}

	return false, ""
}

func (bc *BlacklistChecker) CheckIPWithDNSBL(ip string) bool {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return false
	}

	reversedIP := fmt.Sprintf("%s.%s.%s.%s.sbl.spamhaus.net", octets[3], octets[2], octets[1], octets[0])

	_, err := net.LookupHost(reversedIP)
	return err == nil
}

func (bc *BlacklistChecker) CheckMultiple(ips []string) map[string]bool {
	results := make(map[string]bool)
	for _, ip := range ips {
		isBlacklisted, _ := bc.CheckIP(ip)
		results[ip] = isBlacklisted
	}
	return results
}
