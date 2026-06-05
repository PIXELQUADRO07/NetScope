package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type HardwareInfo struct {
	CPUCores       int
	RAMGB          int
	MaxRecommended int
	LocalCIDR      string
	LocalIP        string
}

func DetectHardware() (HardwareInfo, error) {
	cpu := runtime.NumCPU()
	ramGB, err := detectRAMGB()
	if err != nil {
		ramGB = 1
	}

	cidr, ip, err := LocalNetworkCIDR()
	if err != nil {
		return HardwareInfo{
			CPUCores:       cpu,
			RAMGB:          ramGB,
			MaxRecommended: RecommendConcurrency(cpu, ramGB),
		}, nil
	}

	return HardwareInfo{
		CPUCores:       cpu,
		RAMGB:          ramGB,
		MaxRecommended: RecommendConcurrency(cpu, ramGB),
		LocalCIDR:      cidr,
		LocalIP:        ip,
	}, nil
}

func detectRAMGB() (int, error) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return int(vm.Total / (1024 * 1024 * 1024)), nil
}

func RecommendConcurrency(cpu int, ramGB int) int {
	if cpu < 1 {
		cpu = 1
	}

	limit := cpu * 10
	if ramGB > 0 {
		limit = cpu * 5
		if ramGB >= 8 {
			limit = cpu * 10
		}
		if ramGB >= 16 {
			limit = cpu * 15
		}
	}

	if limit > 100 {
		limit = 100
	}
	if limit < 5 {
		limit = 5
	}
	return limit
}

func LocalNetworkCIDR() (string, string, error) {
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

			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			network := net.IPNet{IP: ipv4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
			return network.String(), ipv4.String(), nil
		}
	}

	return "", "", fmt.Errorf("rete locale non trovata")
}

func ScanLocalNetwork(concurrency int) ([]string, error) {
	cidr, _, err := LocalNetworkCIDR()
	if err != nil {
		return nil, err
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ips := generateHosts(network)
	if len(ips) == 0 {
		return nil, nil
	}

	if concurrency < 1 {
		concurrency = 10
	}

	hosts := scanIPs(ips, concurrency)
	return hosts, nil
}

func ScanLocalNetworkRoot(concurrency int) ([]string, error) {
	cidr, _, err := LocalNetworkCIDR()
	if err != nil {
		return nil, err
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ips := generateHosts(network)
	if len(ips) == 0 {
		return nil, nil
	}

	hosts := scanIPsRoot(ips, concurrency)
	return hosts, nil
}

func scanIPsRoot(ips []net.IP, concurrency int) []string {
	if len(ips) == 0 {
		return nil
	}

	if concurrency < 1 {
		concurrency = 20
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
			if scanHostAdvanced(ip) {
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

	return hosts
}

func scanHostAdvanced(ip net.IP) bool {
	if pingHost(ip) {
		return true
	}

	ports := []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5900, 8080}
	return scanHostPorts(ip, ports)
}

func scanHostPorts(ip net.IP, ports []int) bool {
	timeout := 500 * time.Millisecond

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

func pingHost(ip net.IP) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	if _, err := conn.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
		return false
	}

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return false
	}

	resp := make([]byte, 1500)
	n, _, err := conn.ReadFrom(resp)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), resp[:n])
	if err != nil {
		return false
	}

	return rm.Type == ipv4.ICMPTypeEchoReply
}

func generateHosts(network *net.IPNet) []net.IP {
	base := network.IP.Mask(network.Mask).To4()
	if base == nil {
		return nil
	}

	maskSize, bits := network.Mask.Size()
	hostCount := 1 << uint(bits-maskSize)
	if hostCount <= 2 {
		return nil
	}

	hosts := make([]net.IP, 0, hostCount-2)
	for i := 1; i < hostCount-1; i++ {
		ip := make(net.IP, 4)
		for j := 0; j < 4; j++ {
			byteIndex := 3 - j
			ip[j] = base[j] | byte((i>>uint(8*byteIndex))&0xFF)
		}
		hosts = append(hosts, ip)
	}

	return hosts
}

func scanHost(ip net.IP) bool {
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

type BGPViewResponse struct {
	Data struct {
		IPv4Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
	} `json:"data"`
}

func GetIPRangesByASN(asn string) ([]string, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API BGPView ha risposto %s", resp.Status)
	}

	var result BGPViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	prefixes := make([]string, 0, len(result.Data.IPv4Prefixes))
	for _, p := range result.Data.IPv4Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}

	return prefixes, nil
}

func ScanTargetASN(asn string, concurrency int) ([]string, error) {
	prefixes, err := GetIPRangesByASN(asn)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("nessun prefisso IPv4 trovato per %s", asn)
	}

	ips := make([]net.IP, 0)
	maxHosts := 2048

	for _, prefix := range prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}

		hosts := generateHostsLimited(network, maxHosts-len(ips))
		ips = append(ips, hosts...)
		if len(ips) >= maxHosts {
			break
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("nessun host generato per %s", asn)
	}

	hosts := scanIPs(ips, concurrency)
	return hosts, nil
}

func ScanTargetASNRoot(asn string, concurrency int) ([]string, error) {
	prefixes, err := GetIPRangesByASN(asn)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("nessun prefisso IPv4 trovato per %s", asn)
	}

	ips := make([]net.IP, 0)
	maxHosts := 4096

	for _, prefix := range prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}

		hosts := generateHostsLimited(network, maxHosts-len(ips))
		ips = append(ips, hosts...)
		if len(ips) >= maxHosts {
			break
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("nessun host generato per %s", asn)
	}

	hosts := scanIPsRoot(ips, concurrency)
	return hosts, nil
}

func ScanLocalNetworkRootWithFilter(filter string, concurrency int) ([]string, error) {
	hosts, err := ScanLocalNetworkRootWithBanners(concurrency)
	if err != nil {
		return nil, err
	}
	return filterBannerLines(hosts, filter), nil
}

func ScanTargetASNRootWithFilter(asn string, filter string, concurrency int) ([]string, error) {
	hosts, err := ScanTargetASNRootWithBanners(asn, concurrency)
	if err != nil {
		return nil, err
	}
	return filterBannerLines(hosts, filter), nil
}

func filterBannerLines(lines []string, filter string) []string {
	if filter = strings.TrimSpace(strings.ToLower(filter)); filter == "" {
		return lines
	}

	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if bannerMatches(line, filter) {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

func bannerMatches(line, filter string) bool {
	line = strings.ToLower(line)

	switch filter {
	case "webcam":
		return containsAny(line, []string{"webcam", "camera", "axis", "dlink", "rtsp", "mjpg", "video", "hikvision", "ip camera"})
	case "telecamere":
		return containsAny(line, []string{"camera", "telecamera", "webcam", "rtsp", "mjpg", "hikvision", "dahua", "axis", "ipc"})
	case "os", "sistemi operativi", "sistema operativo":
		return containsAny(line, []string{"linux", "ubuntu", "debian", "centos", "red hat", "windows", "microsoft", "iis", "server 2019", "server 2016"})
	default:
		return strings.Contains(line, filter)
	}
}

func containsAny(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func ScanLocalNetworkRootWithBanners(concurrency int) ([]string, error) {
	cidr, _, err := LocalNetworkCIDR()
	if err != nil {
		return nil, err
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ips := generateHosts(network)
	if len(ips) == 0 {
		return nil, nil
	}

	hosts := scanIPsRootWithBanners(ips, concurrency)
	return hosts, nil
}

func ScanTargetASNRootWithBanners(asn string, concurrency int) ([]string, error) {
	prefixes, err := GetIPRangesByASN(asn)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("nessun prefisso IPv4 trovato per %s", asn)
	}

	ips := make([]net.IP, 0)
	maxHosts := 4096

	for _, prefix := range prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}

		hosts := generateHostsLimited(network, maxHosts-len(ips))
		ips = append(ips, hosts...)
		if len(ips) >= maxHosts {
			break
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("nessun host generato per %s", asn)
	}

	hosts := scanIPsRootWithBanners(ips, concurrency)
	return hosts, nil
}

func scanIPsRootWithBanners(ips []net.IP, concurrency int) []string {
	if len(ips) == 0 {
		return nil
	}

	if concurrency < 1 {
		concurrency = 20
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
			line, ok := scanHostAdvancedWithBanner(ip)
			if ok {
				results <- line
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	hosts := make([]string, 0, len(results))
	for host := range results {
		hosts = append(hosts, host)
	}

	return hosts
}

func scanHostAdvancedWithBanner(ip net.IP) (string, bool) {
	if pingHost(ip) {
		return fmt.Sprintf("%s - ICMP raggiungibile", ip.String()), true
	}

	ports := []int{21, 22, 23, 25, 80, 110, 143, 3306, 3389, 5900, 8080}
	banners := make([]string, 0, len(ports))

	for _, port := range ports {
		open, banner := scanPortBanner(ip, port)
		if open {
			if banner != "" {
				banners = append(banners, fmt.Sprintf("%d: %s", port, banner))
			} else {
				banners = append(banners, fmt.Sprintf("%d: aperta", port))
			}
		}
	}

	if len(banners) == 0 {
		return "", false
	}

	return fmt.Sprintf("%s - %s", ip.String(), strings.Join(banners, " | ")), true
}

func scanPortBanner(ip net.IP, port int) (bool, string) {
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return true, ""
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		banner := strings.TrimSpace(string(buffer[:n]))
		return true, strings.Split(banner, "\n")[0]
	}

	// Proviamo con una richiesta HTTP minimale se non otteniamo banner immediato
	if port == 80 || port == 8080 {
		request := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ip.String())
		conn.Write([]byte(request))
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err == nil {
			n, err := conn.Read(buffer)
			if err == nil && n > 0 {
				banner := strings.TrimSpace(string(buffer[:n]))
				return true, strings.Split(banner, "\n")[0]
			}
		}
	}

	return true, "porta aperta"
}

func generateHostsLimited(network *net.IPNet, max int) []net.IP {
	base := network.IP.Mask(network.Mask).To4()
	if base == nil {
		return nil
	}

	maskSize, bits := network.Mask.Size()
	hostCount := 1 << uint(bits-maskSize)
	if hostCount <= 2 || max <= 0 {
		return nil
	}

	if hostCount-2 > max {
		hostCount = max + 2
	}

	hosts := make([]net.IP, 0, min(max, hostCount-2))
	for i := 1; i < hostCount-1 && len(hosts) < max; i++ {
		ip := make(net.IP, 4)
		for j := 0; j < 4; j++ {
			byteIndex := 3 - j
			ip[j] = base[j] | byte((i>>uint(8*byteIndex))&0xFF)
		}
		hosts = append(hosts, ip)
	}

	return hosts
}

func scanIPs(ips []net.IP, concurrency int) []string {
	if len(ips) == 0 {
		return nil
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
			if scanHost(ip) {
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

	return hosts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
