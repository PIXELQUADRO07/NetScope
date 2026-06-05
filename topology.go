package main

import (
	"fmt"
	"net"
	"sync"
)

type NetworkNode struct {
	IP              string
	Hostname        string
	Services        []string
	Vulnerabilities []string
	Depth           int
	LastSeen        string
}

type NetworkTopology struct {
	mu    sync.RWMutex
	nodes map[string]*NetworkNode
	edges map[string][]string
	root  string
}

func NewNetworkTopology(rootIP string) *NetworkTopology {
	return &NetworkTopology{
		nodes: make(map[string]*NetworkNode),
		edges: make(map[string][]string),
		root:  rootIP,
	}
}

func (nt *NetworkTopology) AddNode(node *NetworkNode) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	nt.nodes[node.IP] = node
}

func (nt *NetworkTopology) AddEdge(from, to string) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	if _, exists := nt.edges[from]; !exists {
		nt.edges[from] = make([]string, 0)
	}
	nt.edges[from] = append(nt.edges[from], to)
}

func (nt *NetworkTopology) GetNode(ip string) (*NetworkNode, bool) {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	node, exists := nt.nodes[ip]
	return node, exists
}

func (nt *NetworkTopology) GetConnectedNodes(ip string) []string {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	return nt.edges[ip]
}

func (nt *NetworkTopology) BuildFromScanResults(results []ScanResult) {
	for i, result := range results {
		node := &NetworkNode{
			IP:       result.IP,
			Hostname: result.Banner,
			Depth:    i,
		}
		nt.AddNode(node)

		if i > 0 {
			nt.AddEdge(results[i-1].IP, result.IP)
		}
	}
}

func (nt *NetworkTopology) ExportDOT() string {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	dot := "digraph NetworkTopology {\n"
	dot += "\trankdir=LR;\n"
	dot += "\tnode [shape=box];\n\n"

	for ip, node := range nt.nodes {
		label := fmt.Sprintf("%s\\n%s", ip, node.Hostname)
		dot += fmt.Sprintf("\t\"%s\" [label=\"%s\"];\n", ip, label)
	}

	dot += "\n"
	for from, tos := range nt.edges {
		for _, to := range tos {
			dot += fmt.Sprintf("\t\"%s\" -> \"%s\";\n", from, to)
		}
	}

	dot += "}\n"
	return dot
}

func (nt *NetworkTopology) FindPathToVulnerability() []string {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	var path []string
	for ip, node := range nt.nodes {
		if len(node.Vulnerabilities) > 0 {
			path = append(path, ip)
		}
	}
	return path
}

func (nt *NetworkTopology) AnalyzeRisk() map[string]interface{} {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	totalNodes := len(nt.nodes)
	vulnerableNodes := 0
	criticalServices := 0

	for _, node := range nt.nodes {
		if len(node.Vulnerabilities) > 0 {
			vulnerableNodes++
		}
		for _, svc := range node.Services {
			port, err := net.LookupPort("tcp", svc)
			if err == nil && port > 0 && port < 1024 {
				criticalServices++
			}
		}
	}

	riskLevel := "LOW"
	if vulnerableNodes > 0 {
		riskLevel = "MEDIUM"
	}
	if vulnerableNodes > totalNodes/2 {
		riskLevel = "HIGH"
	}

	return map[string]interface{}{
		"total_nodes":        totalNodes,
		"vulnerable_nodes":   vulnerableNodes,
		"critical_services":  criticalServices,
		"risk_level":         riskLevel,
		"vulnerability_rate": float64(vulnerableNodes) / float64(totalNodes),
	}
}

func (nt *NetworkTopology) ExportJSON() map[string]interface{} {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	nodes := make([]map[string]interface{}, 0)
	for _, node := range nt.nodes {
		nodes = append(nodes, map[string]interface{}{
			"ip":              node.IP,
			"hostname":        node.Hostname,
			"services":        node.Services,
			"vulnerabilities": node.Vulnerabilities,
		})
	}

	return map[string]interface{}{
		"root_node": nt.root,
		"nodes":     nodes,
		"edges":     nt.edges,
	}
}
