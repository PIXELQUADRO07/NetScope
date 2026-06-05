package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CPEMatch struct {
	CPE string `json:"cpe"`
	CVE int    `json:"cve_count"`
}

func DetectCPE(banner string) []string {
	cpeMappings := map[string][]string{
		"Apache":     {"cpe:/a:apache:http_server"},
		"nginx":      {"cpe:/a:nginx:nginx"},
		"IIS":        {"cpe:/a:microsoft:internet_information_services"},
		"OpenSSH":    {"cpe:/a:openbsd:openssh"},
		"vsftpd":     {"cpe:/a:vsftpd:vsftpd"},
		"Postfix":    {"cpe:/a:postfix:postfix"},
		"Dovecot":    {"cpe:/a:dovecot:dovecot"},
		"ProFTPD":    {"cpe:/a:proftpd:proftpd"},
		"Sendmail":   {"cpe:/a:sendmail:sendmail"},
		"MySQL":      {"cpe:/a:mysql:mysql"},
		"PostgreSQL": {"cpe:/a:postgresql:postgresql"},
		"MariaDB":    {"cpe:/a:mariadb:mariadb"},
		"MongoDB":    {"cpe:/a:mongodb:mongodb"},
		"Redis":      {"cpe:/a:redis:redis"},
		"Windows":    {"cpe:/o:microsoft:windows"},
		"Linux":      {"cpe:/o:linux:linux_kernel"},
		"Ubuntu":     {"cpe:/o:canonical:ubuntu_linux"},
		"CentOS":     {"cpe:/o:centos:centos"},
	}

	found := make([]string, 0)
	banner_lower := strings.ToLower(banner)

	for software, cpes := range cpeMappings {
		if strings.Contains(banner_lower, strings.ToLower(software)) {
			found = append(found, cpes...)
		}
	}

	return found
}

type ShodanResponse struct {
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Data      string   `json:"data"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	Title     string   `json:"title"`
	Hostnames []string `json:"hostnames"`
}

func QueryShodanIP(ip string, shodanAPIKey string) (*ShodanResponse, error) {
	if shodanAPIKey == "" {
		return nil, fmt.Errorf("chiave API Shodan non configurata")
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, shodanAPIKey)
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Shodan API ha risposto %s", resp.Status)
	}

	var result ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

type IPInfoResponse struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Region   string `json:"region"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
}

func QueryIPInfo(ip string, ipinfoToken string) (*IPInfoResponse, error) {
	if ipinfoToken == "" {
		return nil, fmt.Errorf("token IPInfo non configurato")
	}

	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ip, ipinfoToken)
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPInfo API ha risposto %s", resp.Status)
	}

	var result IPInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

type CensysResponse struct {
	IP                string `json:"ip"`
	Autonomous_System struct {
		ASN  int    `json:"asn"`
		Name string `json:"name"`
	} `json:"autonomous_system"`
	Location struct {
		Continent string `json:"continent"`
		Country   string `json:"country"`
	} `json:"location"`
}

func QueryCensysIP(ip string, censysID string, censysSecret string) (*CensysResponse, error) {
	if censysID == "" || censysSecret == "" {
		return nil, fmt.Errorf("credenziali Censys non configurate")
	}

	url := fmt.Sprintf("https://api.censys.io/v1/ipv4/%s", ip)
	client := http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(censysID, censysSecret)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Censys API ha risposto %s", resp.Status)
	}

	var result CensysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
