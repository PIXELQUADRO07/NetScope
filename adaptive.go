package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

type AdaptiveConcurrency struct {
	mu                 sync.RWMutex
	currentLevel       int
	minLevel           int
	maxLevel           int
	avgResponseTime    time.Duration
	targetResponseTime time.Duration
	adjustmentInterval time.Duration
	lastAdjustment     time.Time
}

func NewAdaptiveConcurrency(min, max int, targetRT time.Duration) *AdaptiveConcurrency {
	return &AdaptiveConcurrency{
		currentLevel:       min,
		minLevel:           min,
		maxLevel:           max,
		targetResponseTime: targetRT,
		adjustmentInterval: 5 * time.Second,
		lastAdjustment:     time.Now(),
	}
}

func (ac *AdaptiveConcurrency) GetConcurrencyLevel() int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	return ac.currentLevel
}

func (ac *AdaptiveConcurrency) RecordMetrics(avgRT time.Duration) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.avgResponseTime = avgRT

	if time.Since(ac.lastAdjustment) < ac.adjustmentInterval {
		return
	}

	ac.lastAdjustment = time.Now()

	if avgRT > ac.targetResponseTime && ac.currentLevel > ac.minLevel {
		ac.currentLevel--
	} else if avgRT < ac.targetResponseTime && ac.currentLevel < ac.maxLevel {
		ac.currentLevel++
	}
}

func (ac *AdaptiveConcurrency) AutoScale() {
	maxCores := runtime.NumCPU()
	ac.mu.Lock()
	ac.maxLevel = maxCores * 2
	ac.mu.Unlock()
}

type Notification struct {
	ID        string
	Type      string
	Message   string
	Severity  string
	Timestamp time.Time
	Read      bool
}

type NotificationManager struct {
	mu            sync.RWMutex
	notifications []Notification
	maxSize       int
}

func NewNotificationManager(maxSize int) *NotificationManager {
	return &NotificationManager{
		notifications: make([]Notification, 0),
		maxSize:       maxSize,
	}
}

func (nm *NotificationManager) Add(notif Notification) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	notif.Timestamp = time.Now()
	nm.notifications = append(nm.notifications, notif)

	if len(nm.notifications) > nm.maxSize {
		nm.notifications = nm.notifications[1:]
	}
}

func (nm *NotificationManager) GetUnread() []Notification {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	unread := make([]Notification, 0)
	for _, n := range nm.notifications {
		if !n.Read {
			unread = append(unread, n)
		}
	}
	return unread
}

func (nm *NotificationManager) MarkAsRead(id string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for i, n := range nm.notifications {
		if n.ID == id {
			nm.notifications[i].Read = true
			break
		}
	}
}

func (nm *NotificationManager) Clear() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.notifications = make([]Notification, 0)
}

func (nm *NotificationManager) NotifyVulnerability(ip, cve string, severity string) {
	notif := Notification{
		ID:       fmt.Sprintf("vuln_%s_%s", ip, cve),
		Type:     "vulnerability",
		Message:  fmt.Sprintf("Vulnerabilità %s trovata su %s", cve, ip),
		Severity: severity,
	}
	nm.Add(notif)
}

func (nm *NotificationManager) NotifyBlacklist(ip string) {
	notif := Notification{
		ID:       fmt.Sprintf("blacklist_%s", ip),
		Type:     "security",
		Message:  fmt.Sprintf("IP %s trovato in blacklist", ip),
		Severity: "HIGH",
	}
	nm.Add(notif)
}

func (nm *NotificationManager) NotifyScanComplete(target string, hostsFound int) {
	notif := Notification{
		ID:       fmt.Sprintf("scan_%s_%d", target, time.Now().Unix()),
		Type:     "scan",
		Message:  fmt.Sprintf("Scansione %s completata: %d host trovati", target, hostsFound),
		Severity: "INFO",
	}
	nm.Add(notif)
}
