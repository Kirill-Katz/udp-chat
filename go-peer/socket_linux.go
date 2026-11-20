//go:build linux

package main

import (
	"net"
	"syscall"
)

func configureMulticastReceiver(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		// Otherwise Linux may also deliver traffic for multicast groups joined by
		// other sockets on this host when their destination port matches ours.
		optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 49 /* IP_MULTICAST_ALL, Linux uapi/linux/in.h */, 0)
	})
	if err != nil {
		return err
	}
	return optionErr
}
