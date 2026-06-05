package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func printUsage() {
	fmt.Print(`NetScope CLI

Usage:
	netscope <command> [options]

Commands:
	local [--concurrency N]           Scan local /24 network
	asn <ASN> [--concurrency N]       Scan targets from ASN
	reverse <IP>                      Reverse DNS lookup
	ssl <host:port>                   Extract SSL certificate
	custom <IP> <ports>               Scan custom ports (comma-separated)
	cache list                         List cached results
	html <filename>                    Generate empty HTML report (placeholder)
	help                               Show this help
`)
}

// RunCLI runs CLI with provided args (not including the "cli" token)
func RunCLI(args []string) {
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "help", "-h", "--help":
		printUsage()
	case "local":
		fs := flag.NewFlagSet("local", flag.ExitOnError)
		concurrency := fs.Int("concurrency", 0, "number of concurrent workers")
		fs.Parse(args[1:])
		if *concurrency == 0 {
			hw, _ := DetectHardware()
			*concurrency = hw.MaxRecommended
		}
		fmt.Printf("Starting local scan with concurrency=%d\n", *concurrency)
		hosts, err := ScanLocalNetwork(*concurrency)
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			os.Exit(1)
		}
		for _, h := range hosts {
			fmt.Println(h)
		}
	case "asn":
		if len(args) < 2 {
			fmt.Println("asn requires ASN argument, e.g. AS12345")
			os.Exit(1)
		}
		asn := args[1]
		fs := flag.NewFlagSet("asn", flag.ExitOnError)
		concurrency := fs.Int("concurrency", 0, "number of concurrent workers")
		fs.Parse(args[2:])
		if *concurrency == 0 {
			hw, _ := DetectHardware()
			*concurrency = hw.MaxRecommended
		}
		hosts, err := ScanTargetASN(asn, *concurrency)
		if err != nil {
			fmt.Printf("ASN scan error: %v\n", err)
			os.Exit(1)
		}
		for _, h := range hosts {
			fmt.Println(h)
		}
	case "reverse":
		if len(args) < 2 {
			fmt.Println("reverse requires IP argument")
			os.Exit(1)
		}
		names, err := ReverseDNSLookup(args[1])
		if err != nil {
			fmt.Printf("Reverse lookup error: %v\n", err)
			os.Exit(1)
		}
		for _, n := range names {
			fmt.Println(n)
		}
	case "ssl":
		if len(args) < 2 {
			fmt.Println("ssl requires host:port argument")
			os.Exit(1)
		}
		parts := strings.Split(args[1], ":")
		host := parts[0]
		port := 443
		if len(parts) == 2 {
			p, _ := strconv.Atoi(parts[1])
			if p > 0 {
				port = p
			}
		}
		cert, err := ExtractSSLCertificate(host, port)
		if err != nil {
			fmt.Printf("SSL extraction error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Subject: %s\nIssuer: %s\nValid: %v to %v\nSANs: %v\n", cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter, cert.DNSNames)
	case "custom":
		if len(args) < 3 {
			fmt.Println("custom requires IP and ports (csv)")
			os.Exit(1)
		}
		ip := net.ParseIP(args[1])
		if ip == nil {
			fmt.Println("invalid IP")
			os.Exit(1)
		}
		portsStr := args[2]
		ports := []int{}
		for _, p := range strings.Split(portsStr, ",") {
			if p == "" {
				continue
			}
			pi, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				fmt.Printf("invalid port: %s\n", p)
				os.Exit(1)
			}
			ports = append(ports, pi)
		}
		results := ScanCustomPorts(ip, ports, 10)
		for port, state := range results {
			fmt.Printf("%d: %s\n", port, state)
		}
	case "cache":
		if len(args) >= 2 && args[1] == "list" {
			cache := NewResultsCache("/tmp/netscope-cache.json")
			entries := cache.GetAll()
			for k, v := range entries {
				fmt.Printf("%s -> %s (ports=%v)\n", k, v.Banner, v.Ports)
			}
			return
		}
		printUsage()
	case "html":
		if len(args) < 2 {
			fmt.Println("html requires filename")
			os.Exit(1)
		}
		filename := args[1]
		report := ScanReport{ScanType: "cli-html", Target: "cli", Results: []ScanResult{}, Total: 0, StartTime: time.Now(), EndTime: time.Now()}
		if err := GenerateHTMLReport(filename, report); err != nil {
			fmt.Printf("HTML generate error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", filename)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
	}
}
