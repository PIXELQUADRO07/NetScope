package main

import (
	"fmt"
	"sync"
	"time"
)

type ScheduledScan struct {
	ID        string
	Target    string
	ScanType  string
	Interval  time.Duration
	NextRun   time.Time
	LastRun   time.Time
	Active    bool
	CreatedAt time.Time
}

type Scheduler struct {
	mu    sync.RWMutex
	scans map[string]*ScheduledScan
	done  chan bool
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		scans: make(map[string]*ScheduledScan),
		done:  make(chan bool),
	}
}

func (s *Scheduler) AddScan(id, target, scanType string, interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.scans[id]; exists {
		return fmt.Errorf("scan con ID %s esiste già", id)
	}

	s.scans[id] = &ScheduledScan{
		ID:        id,
		Target:    target,
		ScanType:  scanType,
		Interval:  interval,
		NextRun:   time.Now().Add(interval),
		Active:    true,
		CreatedAt: time.Now(),
	}

	return nil
}

func (s *Scheduler) RemoveScan(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.scans[id]; !exists {
		return fmt.Errorf("scan con ID %s non trovato", id)
	}

	delete(s.scans, id)
	return nil
}

func (s *Scheduler) Start() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndExecute()
		case <-s.done:
			return
		}
	}
}

func (s *Scheduler) Stop() {
	s.done <- true
}

func (s *Scheduler) checkAndExecute() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, scan := range s.scans {
		if scan.Active && now.After(scan.NextRun) {
			go s.executeScan(scan)
			scan.LastRun = now
			scan.NextRun = now.Add(scan.Interval)
		}
	}
}

func (s *Scheduler) executeScan(scan *ScheduledScan) {
	// Placeholder - verrà integrato con le funzioni di scanner
	fmt.Printf("[Scheduled] Esecuzione scan %s: %s (%s)\n", scan.ID, scan.Target, scan.ScanType)
}

func (s *Scheduler) GetSchedules() map[string]*ScheduledScan {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*ScheduledScan)
	for k, v := range s.scans {
		result[k] = v
	}
	return result
}

func (s *Scheduler) EnableScan(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, exists := s.scans[id]
	if !exists {
		return fmt.Errorf("scan non trovato")
	}

	scan.Active = true
	return nil
}

func (s *Scheduler) DisableScan(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, exists := s.scans[id]
	if !exists {
		return fmt.Errorf("scan non trovato")
	}

	scan.Active = false
	return nil
}
