package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type CacheEntry struct {
	IP        string
	Banner    string
	Ports     []int
	Timestamp time.Time
	TTL       time.Duration
}

type ResultsCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	file    string
}

func NewResultsCache(cacheFile string) *ResultsCache {
	cache := &ResultsCache{
		entries: make(map[string]CacheEntry),
		file:    cacheFile,
	}
	cache.Load()
	return cache
}

func (c *ResultsCache) Set(ip, banner string, ports []int, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = CacheEntry{
		IP:        ip,
		Banner:    banner,
		Ports:     ports,
		Timestamp: time.Now(),
		TTL:       ttl,
	}
	c.Save()
}

func (c *ResultsCache) Get(ip string) (CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[ip]
	if !exists {
		return CacheEntry{}, false
	}

	if time.Since(entry.Timestamp) > entry.TTL {
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.entries, ip)
		c.mu.Unlock()
		c.mu.RLock()
		return CacheEntry{}, false
	}

	return entry, true
}

func (c *ResultsCache) Save() error {
	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.file, data, 0644)
}

func (c *ResultsCache) Load() error {
	data, err := os.ReadFile(c.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &c.entries)
}

func (c *ResultsCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]CacheEntry)
	return c.Save()
}

func (c *ResultsCache) GetAll() map[string]CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]CacheEntry)
	for k, v := range c.entries {
		result[k] = v
	}
	return result
}

func (c *ResultsCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}
