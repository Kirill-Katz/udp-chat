package main

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var errNameInUse = errors.New("name is already in use; choose another -name")

const (
	discoveryTime = 900 * time.Millisecond
	heartbeatTime = 5 * time.Second
	timeoutTime   = 15 * time.Second
)

type member struct {
	id, name string
	addr     *net.UDPAddr
	seen     time.Time
}
type incoming struct {
	packet    Packet
	addr      *net.UDPAddr
	size      int
	multicast bool
	err       error
}

type Peer struct {
	id, name           string
	group              *net.UDPAddr
	multicast, unicast *net.UDPConn
	aead               cipher.AEAD
	logger             *log.Logger
	out                io.Writer
	members            map[string]*member
	seen               map[string]time.Time
	joined             bool
	// Timing fields are configurable internally for fast integration tests.
	discovery, heartbeat, timeout time.Duration
}

func newPeer(name, id string, group *net.UDPAddr, multicast, unicast *net.UDPConn, aead cipher.AEAD, logger *log.Logger, out io.Writer) *Peer {
	return &Peer{id: id, name: name, group: group, multicast: multicast, unicast: unicast, aead: aead, logger: logger, out: out, members: make(map[string]*member), seen: make(map[string]time.Time), discovery: discoveryTime, heartbeat: heartbeatTime, timeout: timeoutTime}
}
func (p *Peer) packet(kind string) (Packet, error) {
	id, err := randomID()
	return Packet{Version: protocolVersion, Type: kind, PeerID: p.id, Name: p.name, MessageID: id}, err
}
func (p *Peer) send(addr *net.UDPAddr, packet Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	if len(data) > maxDatagram {
		return errors.New("packet exceeds datagram limit")
	}
	if err = p.unicast.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		var n int
		n, err = p.unicast.WriteToUDP(data, addr)
		if err == nil {
			logDatagram(p.logger, "send", addr, packet.Type, n, "")
			return nil
		}
	}
	logDatagram(p.logger, "drop", addr, packet.Type, len(data), err.Error())
	return err
}
func (p *Peer) sendControl(kind, to string, addr *net.UDPAddr) error {
	packet, err := p.packet(kind)
	if err != nil {
		return err
	}
	packet.To = to
	return p.send(addr, packet)
}
func (p *Peer) noticeError(err error) {
	if err != nil {
		fmt.Fprintf(p.out, "! %v\n", err)
	}
}

func (p *Peer) readLoop(ctx context.Context, conn *net.UDPConn, multicast bool, ch chan<- incoming, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isICMPError(err) {
				logDatagram(p.logger, "drop", conn.LocalAddr().(*net.UDPAddr), "socket", 0, err.Error())
				continue
			}
			select {
			case ch <- incoming{err: err}:
			case <-ctx.Done():
			}
			return
		}
		packet, err := decodePacket(buf[:n])
		kind := "invalid"
		if err == nil {
			kind = packet.Type
		}
		logDatagram(p.logger, "receive", addr, kind, n, "")
		if err != nil {
			logDatagram(p.logger, "drop", addr, kind, n, err.Error())
			continue
		}
		select {
		case ch <- incoming{packet: packet, addr: addr, size: n, multicast: multicast}:
		case <-ctx.Done():
			return
		}
	}
}

func sameEndpoint(a, b *net.UDPAddr) bool { return a.Port == b.Port && a.IP.Equal(b.IP) }
func (p *Peer) findName(name string) *member {
	for _, m := range p.members {
		if m.name == name {
			return m
		}
	}
	return nil
}
func (p *Peer) remove(m *member) {
	delete(p.members, m.id)
	fmt.Fprintf(p.out, "* %s left the chat\n", m.name)
}
func (p *Peer) remember(packet Packet, addr *net.UDPAddr, now time.Time) error {
	if m := p.members[packet.PeerID]; m != nil {
		if m.name != packet.Name || !sameEndpoint(m.addr, addr) {
			return errors.New("peer identity or endpoint changed")
		}
		m.seen = now
		return nil
	}
	if old := p.findName(packet.Name); old != nil {
		if old.id < packet.PeerID {
			return errors.New("duplicate name; lower peer ID wins")
		}
		p.remove(old)
	}
	if len(p.members) >= 1024 {
		return errors.New("peer table full")
	}
	p.members[packet.PeerID] = &member{id: packet.PeerID, name: packet.Name, addr: addr, seen: now}
	fmt.Fprintf(p.out, "* %s joined the chat\n", packet.Name)
	return nil
}
func (p *Peer) duplicate(packet Packet, now time.Time) bool {
	key := packet.PeerID + packet.MessageID
	if t, ok := p.seen[key]; ok && now.Sub(t) < time.Minute {
		return true
	}
	if len(p.seen) >= 4096 {
		var oldest string
		var at time.Time
		for k, t := range p.seen {
			if oldest == "" || t.Before(at) {
				oldest = k
				at = t
			}
		}
		delete(p.seen, oldest)
	}
	p.seen[key] = now
	return false
}

func (p *Peer) receive(event incoming, now time.Time) error {
	packet := event.packet
	drop := func(reason string) error {
		logDatagram(p.logger, "drop", event.addr, packet.Type, event.size, reason)
		return nil
	}
	// Port separation is part of the protocol, not just an implementation detail.
	onGroup := packet.Type == "claim" || packet.Type == "announce" || packet.Type == "heartbeat" || packet.Type == "general" || packet.Type == "leave"
	if onGroup != event.multicast {
		return drop("wrong receiving socket")
	}
	if packet.To != "" && packet.To != p.id {
		return drop("not addressed to this peer")
	}
	if packet.PeerID == p.id {
		if packet.Name != p.name || packet.Type != "general" || !p.joined {
			return drop("self control packet")
		}
		if p.duplicate(packet, now) {
			return drop("duplicate")
		}
		fmt.Fprintf(p.out, "[general] %s: %s\n", p.name, packet.Text)
		return nil
	}
	if packet.Name == p.name {
		if packet.Type == "claim" {
			// Established names beat claimants. Simultaneous claimants use peer IDs.
			if p.joined || p.id < packet.PeerID {
				p.noticeError(p.sendControl("conflict", packet.PeerID, event.addr))
			} else {
				return errNameInUse
			}
			return nil
		}
		if packet.Type == "conflict" {
			if !p.joined || packet.PeerID < p.id {
				return errNameInUse
			}
			return nil
		}
		if packet.Type == "announce" || packet.Type == "heartbeat" || packet.Type == "general" || packet.Type == "hello" {
			if !p.joined || packet.PeerID < p.id {
				return errNameInUse
			}
			p.noticeError(p.sendControl("conflict", packet.PeerID, event.addr))
			return nil
		}
		return drop("conflicting name")
	}
	if packet.Type == "conflict" {
		return drop("conflict for a different name")
	}
	if packet.Type == "claim" {
		if p.joined {
			p.noticeError(p.sendControl("hello", packet.PeerID, event.addr))
		}
		return nil
	}
	if packet.Type == "leave" {
		m := p.members[packet.PeerID]
		if m == nil || m.name != packet.Name || !sameEndpoint(m.addr, event.addr) {
			return drop("unknown leave")
		}
		if p.duplicate(packet, now) {
			return drop("duplicate")
		}
		p.remove(m)
		return nil
	}
	plaintext := ""
	if packet.Type == "private" {
		if !p.joined {
			return drop("not joined")
		}
		var err error
		plaintext, err = decryptPrivate(p.aead, packet, p.name)
		if err != nil {
			return drop(err.Error())
		}
	}
	if m := p.members[packet.PeerID]; m != nil && (m.name != packet.Name || !sameEndpoint(m.addr, event.addr)) {
		return drop("peer identity or endpoint changed")
	}
	if p.duplicate(packet, now) {
		return drop("duplicate")
	}
	if err := p.remember(packet, event.addr, now); err != nil {
		return drop(err.Error())
	}
	switch packet.Type {
	case "general":
		fmt.Fprintf(p.out, "[general] %s: %s\n", packet.Name, packet.Text)
	case "private":
		fmt.Fprintf(p.out, "[private] %s: %s\n", packet.Name, plaintext)
	}
	return nil
}

func (p *Peer) expire(now time.Time) {
	for _, m := range p.members {
		if now.Sub(m.seen) >= p.timeout {
			p.remove(m)
		}
	}
	for key, at := range p.seen {
		if now.Sub(at) >= time.Minute {
			delete(p.seen, key)
		}
	}
}
func (p *Peer) command(line string) (bool, error) {
	if line == "/quit" {
		return true, nil
	}
	if !p.joined {
		return false, errors.New("still checking the name; wait for the ready message")
	}
	switch {
	case line == "/users":
		users := []string{p.name + " (you)"}
		for _, m := range p.members {
			users = append(users, fmt.Sprintf("%s %s", m.name, m.addr))
		}
		sort.Strings(users)
		for _, user := range users {
			fmt.Fprintln(p.out, user)
		}
		return false, nil
	case strings.HasPrefix(line, "/msg "):
		rest := strings.TrimLeft(strings.TrimPrefix(line, "/msg "), " ")
		name, text, ok := strings.Cut(rest, " ")
		if !ok || !validText(text) {
			return false, errors.New("usage: /msg name text (1-500 characters without controls)")
		}
		target := p.findName(name)
		if name == p.name {
			return false, errors.New("choose another peer for a private message")
		}
		if target == nil {
			return false, fmt.Errorf("%s is not online", name)
		}
		packet, err := p.packet("private")
		if err != nil {
			return false, err
		}
		packet.To = target.id
		if err = encryptPrivate(p.aead, &packet, target.name, text); err != nil {
			return false, err
		}
		if err = p.send(target.addr, packet); err != nil {
			return false, err
		}
		fmt.Fprintf(p.out, "[private -> %s, sent without delivery guarantee] %s: %s\n", name, p.name, text)
		return false, nil
	case line == "/input-line-too-long":
		return false, errors.New("input line too long; messages have at most 500 characters")
	case strings.HasPrefix(line, "/"):
		return false, errors.New("commands: /msg name text, /users, /quit")
	default:
		if !validText(line) {
			return false, errors.New("message must contain 1-500 characters without controls")
		}
		packet, err := p.packet("general")
		if err != nil {
			return false, err
		}
		packet.Text = line
		// Exactly one send; own display is driven only by multicast loopback.
		return false, p.send(p.group, packet)
	}
}

// Run owns all peer state. Only receiver goroutines and the console scanner run
// concurrently; they pass events to this loop, never mutate the membership map.
func (p *Peer) Run(ctx context.Context, commands <-chan string) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); p.multicast.Close(); p.unicast.Close(); wg.Wait() }()
	events := make(chan incoming, 256)
	wg.Add(2)
	go p.readLoop(ctx, p.multicast, true, events, &wg)
	go p.readLoop(ctx, p.unicast, false, events, &wg)
	if err := p.sendControl("claim", "", p.group); err != nil {
		return err
	}
	ready := time.NewTimer(p.discovery)
	defer ready.Stop()
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	heartbeat := time.NewTicker(p.heartbeat)
	defer heartbeat.Stop()
	sweep := time.NewTicker(100 * time.Millisecond)
	defer sweep.Stop()
	readyC := ready.C
	leave := func() {
		if p.joined {
			p.noticeError(p.sendControl("leave", "", p.group))
		}
	}
	for {
		select {
		case <-ctx.Done():
			leave()
			return nil
		case <-readyC:
			p.joined = true
			readyC = nil
			if err := p.sendControl("announce", "", p.group); err != nil {
				return err
			}
			fmt.Fprintf(p.out, "* ready as %s; text, /msg name text, /users, /quit\n", p.name)
		case <-retry.C:
			if !p.joined {
				if err := p.sendControl("claim", "", p.group); err != nil {
					return err
				}
			}
		case <-heartbeat.C:
			if p.joined {
				p.noticeError(p.sendControl("heartbeat", "", p.group))
			}
		case now := <-sweep.C:
			p.expire(now)
		case event := <-events:
			if event.err != nil {
				if ctx.Err() != nil {
					leave()
					return nil
				}
				return event.err
			}
			if err := p.receive(event, time.Now()); err != nil {
				// Never send leave on name rejection: it was not a successful join.
				return err
			}
		case line, ok := <-commands:
			if !ok {
				leave()
				return nil
			}
			p.expire(time.Now())
			quit, err := p.command(line)
			p.noticeError(err)
			if quit {
				leave()
				return nil
			}
		}
	}
}
