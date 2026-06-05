package main

import (
	"net"
	"strings"
	"testing"
)

func TestGenerateHosts(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	hosts := generateHosts(network)
	if len(hosts) != 254 {
		t.Fatalf("expected 254 hosts, got %d", len(hosts))
	}

	if hosts[0].String() != "192.168.1.1" {
		t.Fatalf("expected first host 192.168.1.1, got %s", hosts[0])
	}

	if hosts[len(hosts)-1].String() != "192.168.1.254" {
		t.Fatalf("expected last host 192.168.1.254, got %s", hosts[len(hosts)-1])
	}
}

func TestFilterBannerLines(t *testing.T) {
	lines := []string{
		"192.168.1.1 - HTTP/1.1 200 | 80: Apache/2.4.41",
		"192.168.1.2 - 22: OpenSSH_7.4",
		"192.168.1.3 - 8080: Hikvision webcam IP Camera",
		"192.168.1.4 - 80: Windows IIS/10.0",
	}

	tests := []struct {
		filter string
		count  int
	}{
		{"webcam", 1},
		{"os", 1},
		{"Apache", 1},
		{"OpenSSH", 1},
	}

	for _, test := range tests {
		result := filterBannerLines(lines, test.filter)
		if len(result) != test.count {
			t.Fatalf("filter '%s': expected %d results, got %d", test.filter, test.count, len(result))
		}
	}
}

func TestBannerMatches(t *testing.T) {
	tests := []struct {
		line   string
		filter string
		match  bool
	}{
		{"192.168.1.1 - Axis webcam", "webcam", true},
		{"192.168.1.1 - Apache/2.4", "webcam", false},
		{"192.168.1.2 - Windows Server 2019", "os", true},
		{"192.168.1.3 - Linux Ubuntu 20.04", "os", true},
	}

	for _, test := range tests {
		result := bannerMatches(test.line, test.filter)
		if result != test.match {
			t.Fatalf("bannerMatches('%s', '%s'): expected %v, got %v", test.line, test.filter, test.match, result)
		}
	}
}

func TestDetectCPE(t *testing.T) {
	tests := []struct {
		banner   string
		count    int
		contains string
	}{
		{"Apache/2.4.41", 1, "apache"},
		{"nginx/1.18", 1, "nginx"},
		{"Windows IIS/10.0", 1, "microsoft"},
	}

	for _, test := range tests {
		cpes := DetectCPE(test.banner)
		if len(cpes) < test.count {
			t.Fatalf("DetectCPE('%s'): expected at least %d CPE, got %d", test.banner, test.count, len(cpes))
		}
		if test.contains != "" {
			found := false
			for _, cpe := range cpes {
				if strings.Contains(cpe, test.contains) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("DetectCPE('%s'): expected CPE containing '%s', got %v", test.banner, test.contains, cpes)
			}
		}
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		text   string
		terms  []string
		result bool
	}{
		{"Apache/2.4.41", []string{"Apache", "nginx"}, true},
		{"nginx/1.18", []string{"Apache", "nginx"}, true},
		{"IIS/10.0", []string{"Apache", "nginx"}, false},
	}

	for _, test := range tests {
		result := containsAny(test.text, test.terms)
		if result != test.result {
			t.Fatalf("containsAny('%s', %v): expected %v, got %v", test.text, test.terms, test.result, result)
		}
	}
}
