package main

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

type CertificateInfo struct {
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DNSNames      []string
	SerialNumber  string
	SignatureAlgo string
	PublicKeyAlgo string
	KeySize       int
	Version       int
	Fingerprint   string
}

func ExtractSSLCertificate(host string, port int) (*CertificateInfo, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	return &CertificateInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DNSNames:      cert.DNSNames,
		SerialNumber:  cert.SerialNumber.String(),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		PublicKeyAlgo: cert.PublicKeyAlgorithm.String(),
		Version:       cert.Version,
	}, nil
}

func IsCertificateExpired(cert *CertificateInfo) bool {
	return time.Now().After(cert.NotAfter)
}

func DaysUntilExpiry(cert *CertificateInfo) int {
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return days
}

func CheckCommonPorts(host string) []int {
	ports := []int{443, 8443, 465, 587, 989, 990, 992, 993, 995, 3389}
	openPorts := make([]int, 0)

	for _, port := range ports {
		address := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}
