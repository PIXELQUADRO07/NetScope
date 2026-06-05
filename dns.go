package main

import (
	"net"
)

func ReverseDNSLookup(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

func ResolveDNSName(hostname string) ([]string, error) {
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func ResolveDNSCNAME(hostname string) (string, error) {
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return "", err
	}
	return cname, nil
}

func ResolveDNSSRV(service, proto, name string) (string, []*net.SRV, error) {
	cname, srv, err := net.LookupSRV(service, proto, name)
	if err != nil {
		return "", nil, err
	}
	return cname, srv, nil
}
