//go:build darwin

package main

import "net"

func configureMulticastReceiver(_ *net.UDPConn) error { return nil }
