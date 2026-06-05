package main

import (
	"testing"
	"time"
)

func TestI18nItalian(t *testing.T) {
	i18n := NewI18n(Italian)
	result := i18n.T("menu_title")
	if result != "📡 NetScope" {
		t.Fatalf("Italian translation failed: got %s", result)
	}
}

func TestI18nEnglish(t *testing.T) {
	i18n := NewI18n(English)
	result := i18n.T("menu_title")
	if result != "📡 NetScope" {
		t.Fatalf("English translation failed: got %s", result)
	}
}

func TestCacheSetGet(t *testing.T) {
	cache := NewResultsCache("/tmp/test_cache.json")
	cache.Set("192.168.1.1", "Apache", []int{80, 443}, 1*time.Hour)

	entry, exists := cache.Get("192.168.1.1")
	if !exists {
		t.Fatal("Cache entry not found")
	}
	if entry.Banner != "Apache" {
		t.Fatalf("Expected Apache, got %s", entry.Banner)
	}
}

func TestSchedulerAdd(t *testing.T) {
	sched := NewScheduler()
	err := sched.AddScan("test1", "192.168.1.0/24", "local", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to add scan: %v", err)
	}

	scans := sched.GetSchedules()
	if len(scans) != 1 {
		t.Fatalf("Expected 1 scan, got %d", len(scans))
	}
}

func TestBlacklistChecker(t *testing.T) {
	checker := NewBlacklistChecker()
	// Test with a private IP (shouldn't be blacklisted)
	isBlacklisted, _ := checker.CheckIP("192.168.1.1")
	if isBlacklisted {
		t.Fatal("Private IP shouldn't be blacklisted")
	}
}

func TestMetricsRecord(t *testing.T) {
	metrics := NewMetrics()
	metrics.RecordScan(2*time.Second, 10, 5)

	metricsData := metrics.GetMetrics()
	if metricsData["total_scans"] != 1 {
		t.Fatalf("Expected 1 scan, got %d", metricsData["total_scans"])
	}
	if metricsData["total_hosts"] != 10 {
		t.Fatalf("Expected 10 hosts, got %d", metricsData["total_hosts"])
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5)
	defer rl.Stop()

	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("Allow should return true for request %d", i+1)
		}
	}

	if rl.Allow() {
		t.Fatal("Allow should return false when limit reached")
	}
}

func TestAdaptiveConcurrency(t *testing.T) {
	ac := NewAdaptiveConcurrency(2, 16, 500*time.Millisecond)
	level := ac.GetConcurrencyLevel()

	if level != 2 {
		t.Fatalf("Expected initial level 2, got %d", level)
	}

	ac.RecordMetrics(200 * time.Millisecond)
	// Just verify it doesn't crash
}

func TestNotificationManager(t *testing.T) {
	nm := NewNotificationManager(10)

	nm.NotifyVulnerability("192.168.1.1", "CVE-2021-1234", "HIGH")
	unread := nm.GetUnread()

	if len(unread) != 1 {
		t.Fatalf("Expected 1 unread notification, got %d", len(unread))
	}

	if unread[0].Type != "vulnerability" {
		t.Fatalf("Expected vulnerability type, got %s", unread[0].Type)
	}
}

func TestNetworkTopology(t *testing.T) {
	nt := NewNetworkTopology("192.168.1.1")

	node := &NetworkNode{
		IP:       "192.168.1.2",
		Hostname: "web-server",
		Services: []string{"http", "https"},
	}
	nt.AddNode(node)

	retrievedNode, exists := nt.GetNode("192.168.1.2")
	if !exists {
		t.Fatal("Node not found in topology")
	}
	if retrievedNode.Hostname != "web-server" {
		t.Fatalf("Expected web-server, got %s", retrievedNode.Hostname)
	}
}

func TestProxyConfig(t *testing.T) {
	proxy := NewProxyConfig("proxy.local", 8080, "http")
	proxyURL, err := proxy.GetURL()

	if err != nil {
		t.Fatalf("Failed to get proxy URL: %v", err)
	}
	if proxyURL.Host != "proxy.local:8080" {
		t.Fatalf("Expected proxy.local:8080, got %s", proxyURL.Host)
	}
}
