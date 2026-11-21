//go:build !linux && !darwin && !windows

package main

import (
	"fmt"
	"net"
)

func configureMulticastReceiver(_ *net.UDPConn) error { return nil }

func configureMulticastSender(_ *net.UDPConn, _ net.IP) error {
	return fmt.Errorf("multicast socket options are currently implemented for Linux and macOS only")
}
