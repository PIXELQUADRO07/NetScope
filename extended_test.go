package main

import (
	"net"
	"testing"
	"time"
)

func TestCustomPortScanning(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	ports := []int{80, 443, 22}
	results := ScanCustomPorts(ip, ports, 5)

	if results == nil {
		t.Fatal("ScanCustomPorts returned nil")
	}
}

func TestDayUntilExpiry(t *testing.T) {
	cert := &CertificateInfo{
		NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}
	days := DaysUntilExpiry(cert)
	if days < 29 || days > 31 {
		t.Fatalf("DaysUntilExpiry: expected ~30, got %d", days)
	}
}

func TestIsCertificateExpired(t *testing.T) {
	expiredCert := &CertificateInfo{
		NotAfter: time.Now().Add(-24 * time.Hour),
	}
	if !IsCertificateExpired(expiredCert) {
		t.Fatal("IsCertificateExpired should return true for expired cert")
	}

	validCert := &CertificateInfo{
		NotAfter: time.Now().Add(24 * time.Hour),
	}
	if IsCertificateExpired(validCert) {
		t.Fatal("IsCertificateExpired should return false for valid cert")
	}
}

func TestCheckCPEVulnerabilities(t *testing.T) {
	cpes := []string{"cpe:/a:apache:http_server"}
	vulns := CheckCPEVulnerabilities(cpes)

	if len(vulns) == 0 {
		t.Fatal("CheckCPEVulnerabilities returned no vulnerabilities")
	}

	if vulns[0].CVE == "" {
		t.Fatal("Vulnerability missing CVE")
	}
}

func TestGetVulnerabilityRiskLevel(t *testing.T) {
	tests := []struct {
		cpes     []string
		expected string
	}{
		{[]string{}, "BASSO"},
		{[]string{"cpe:/a:apache:http_server"}, "ALTO"},
	}

	for _, test := range tests {
		risk := GetVulnerabilityRiskLevel(test.cpes)
		if risk != test.expected {
			t.Fatalf("GetVulnerabilityRiskLevel: expected %s, got %s", test.expected, risk)
		}
	}
}

func TestCheckBannerVulnerabilities(t *testing.T) {
	banner := "Apache/2.4.41"
	vulns := CheckBannerVulnerabilities(banner)

	if len(vulns) == 0 {
		t.Fatal("CheckBannerVulnerabilities returned no vulnerabilities")
	}
}

func TestFormatGeoLocation(t *testing.T) {
	geoInfo := &IPStackResponse{
		City:      "Rome",
		Country:   "Italy",
		Latitude:  41.9028,
		Longitude: 12.4964,
	}

	result := FormatGeoLocation(geoInfo)
	if result == "Geolocalizzazione non disponibile" {
		t.Fatal("FormatGeoLocation returned error message")
	}

	if len(result) == 0 {
		t.Fatal("FormatGeoLocation returned empty string")
	}
}

func TestScanWithVersionDetection(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	ports := []int{80, 443}
	results := ScanWithVersionDetection(ip, ports, 5)

	if results == nil {
		t.Fatal("ScanWithVersionDetection returned nil")
	}
}

func TestDetectServiceVersion(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	port := 80
	version := DetectServiceVersion(ip, port)

	if version == "" {
		t.Log("DetectServiceVersion returned empty (localhost might not have services)")
	}
}

func TestGenerateHTMLReport(t *testing.T) {
	report := ScanReport{
		ScanType:  "test",
		Target:    "127.0.0.1/24",
		Results:   []ScanResult{},
		Total:     0,
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Second),
	}

	err := GenerateHTMLReport("/tmp/test_report.html", report)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}
}
