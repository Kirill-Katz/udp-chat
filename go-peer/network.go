package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
)

func chooseInterface(name string) (*net.Interface, net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, ifi := range interfaces {
		if name != "" && ifi.Name != name {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 || (name == "" && (ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagMulticast == 0)) {
			continue
		}
		addresses, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil {
				return &ifi, ip.To4(), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no usable IPv4 interface %q; select one with -interface", name)
}

func openSockets(ifi *net.Interface, ip net.IP, group *net.UDPAddr) (*net.UDPConn, *net.UDPConn, error) {
	// All peers share the group port; private sockets deliberately do NOT reuse
	// that port. Multicast packets originate at each peer's private endpoint.
	multicast, err := net.ListenMulticastUDP("udp4", ifi, group)
	if err != nil {
		return nil, nil, fmt.Errorf("join multicast group: %w", err)
	}
	if err = configureMulticastReceiver(multicast); err != nil {
		multicast.Close()
		return nil, nil, err
	}
	unicast, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		multicast.Close()
		return nil, nil, err
	}
	if err = configureMulticastSender(unicast, ip); err != nil {
		multicast.Close()
		unicast.Close()
		return nil, nil, err
	}
	return multicast, unicast, nil
}

// ICMP errors about an earlier send are not evidence that our socket died.
func isICMPError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH)
}

func logDatagram(logger *log.Logger, action string, addr *net.UDPAddr, kind string, n int, reason string) {
	logger.Printf("action=%s endpoint=%s kind=%q size=%d reason=%q", action, addr, kind, n, reason)
}
