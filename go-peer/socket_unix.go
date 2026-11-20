//go:build linux || darwin

package main

import (
	"net"
	"syscall"
)

// Set the outgoing interface explicitly, enable local multicast delivery, and
// limit packets to the local subnet. The receiver's group membership is set by
// net.ListenMulticastUDP, which also enables address reuse for local peers.
func configureMulticastSender(conn *net.UDPConn, ip net.IP) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		var addr [4]byte
		copy(addr[:], ip.To4())
		optionErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr)
		if optionErr == nil {
			optionErr = syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
		}
		if optionErr == nil {
			optionErr = syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1)
		}
	})
	if err != nil {
		return err
	}
	return optionErr
}
