package main

import (
	"net"
	"time"
)

func ScanUDPPort(ip net.IP, port int, timeout time.Duration) bool {
	addr := net.UDPAddr{
		Port: port,
		IP:   ip,
	}
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	_, err = conn.Write([]byte{0x00})
	if err != nil {
		return false
	}

	buffer := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		return false
	}

	return true
}

func ScanUDPCommonPorts(ip net.IP) []int {
	commonUDPPorts := []int{
		53,   // DNS
		67,   // DHCP
		68,   // DHCP
		69,   // TFTP
		123,  // NTP
		161,  // SNMP
		162,  // SNMP Trap
		500,  // IKE
		5353, // mDNS
	}

	openPorts := make([]int, 0)
	timeout := 500 * time.Millisecond

	for _, port := range commonUDPPorts {
		if ScanUDPPort(ip, port, timeout) {
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}
