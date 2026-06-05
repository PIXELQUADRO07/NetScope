package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func LocalNetworkCIDRv6() (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ipv6 := ipNet.IP.To16()
			if ipv6 == nil || ipNet.IP.To4() != nil {
				continue
			}

			network := net.IPNet{IP: ipv6, Mask: net.CIDRMask(64, 128)}
			return network.String(), ipv6.String(), nil
		}
	}

	return "", "", fmt.Errorf("rete locale IPv6 non trovata")
}

func generateHostsIPv6(network *net.IPNet) []net.IP {
	base := network.IP.To16()
	if base == nil {
		return nil
	}

	maskSize, bits := network.Mask.Size()
	hostCount := 1 << uint(bits-maskSize)
	if hostCount <= 2 || hostCount > 65536 {
		hostCount = min(hostCount, 65536)
	}

	hosts := make([]net.IP, 0, min(hostCount-2, 10000))
	for i := 1; i < min(hostCount-1, 10001); i++ {
		ip := make(net.IP, 16)
		copy(ip, base)
		for j := 15; j >= 0; j-- {
			if i == 0 {
				break
			}
			ip[j] += byte(i & 0xFF)
			i >>= 8
		}
		hosts = append(hosts, ip)
	}

	return hosts
}

func ScanLocalNetworkIPv6(concurrency int) ([]string, error) {
	cidr, _, err := LocalNetworkCIDRv6()
	if err != nil {
		return nil, err
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ips := generateHostsIPv6(network)
	if len(ips) == 0 {
		return nil, fmt.Errorf("nessun host IPv6 generato")
	}

	if concurrency < 1 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	results := make(chan string, len(ips))

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			if scanHostIPv6(ip) {
				results <- ip.String()
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	hosts := make([]string, 0, len(results))
	for host := range results {
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func scanHostIPv6(ip net.IP) bool {
	ports := []int{80, 443, 22}
	timeout := 400 * time.Millisecond

	for _, port := range ports {
		address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}
