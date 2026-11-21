//go:build windows

package main

import (
    "net"
    "syscall"
)

func configureMulticastReceiver(_ *net.UDPConn) error { return nil }

func configureMulticastSender(conn *net.UDPConn, ip net.IP) error {
    raw, err := conn.SyscallConn()
    if err != nil { return err }
    var optionErr error
    err = raw.Control(func(fd uintptr) {
        var address [4]byte
        copy(address[:], ip.To4())
        optionErr = syscall.SetsockoptInet4Addr(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, address)
        if optionErr == nil { optionErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1) }
        if optionErr == nil { optionErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1) }
    })
    if err != nil { return err }
    return optionErr
}
