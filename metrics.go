package main

import (
	"sync"
	"time"
)

type Metrics struct {
	mu                   sync.RWMutex
	TotalScans           int
	TotalHosts           int
	TotalServices        int
	TotalVulnerabilities int
	AverageScanTime      time.Duration
	LastScanTime         time.Time
	ScanTimes            []time.Duration
	CacheHitRate         float64
	AverageResponseTime  time.Duration
}

func NewMetrics() *Metrics {
	return &Metrics{
		ScanTimes: make([]time.Duration, 0),
	}
}

func (m *Metrics) RecordScan(duration time.Duration, hostsFound int, servicesFound int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalScans++
	m.TotalHosts += hostsFound
	m.TotalServices += servicesFound
	m.LastScanTime = time.Now()
	m.ScanTimes = append(m.ScanTimes, duration)

	total := time.Duration(0)
	for _, t := range m.ScanTimes {
		total += t
	}
	m.AverageScanTime = total / time.Duration(len(m.ScanTimes))
}

func (m *Metrics) RecordVulnerability() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalVulnerabilities++
}

func (m *Metrics) SetCacheHitRate(rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CacheHitRate = rate
}

func (m *Metrics) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_scans":           m.TotalScans,
		"total_hosts":           m.TotalHosts,
		"total_services":        m.TotalServices,
		"total_vulnerabilities": m.TotalVulnerabilities,
		"average_scan_time":     m.AverageScanTime.String(),
		"last_scan_time":        m.LastScanTime,
		"cache_hit_rate":        m.CacheHitRate,
		"average_response_time": m.AverageResponseTime.String(),
	}
}

func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalScans = 0
	m.TotalHosts = 0
	m.TotalServices = 0
	m.TotalVulnerabilities = 0
	m.ScanTimes = make([]time.Duration, 0)
	m.CacheHitRate = 0
}
