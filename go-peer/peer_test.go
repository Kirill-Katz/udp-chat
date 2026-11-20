package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func unitPeer(t *testing.T, name, id string) (*Peer, *bytes.Buffer) {
	t.Helper()
	out := new(bytes.Buffer)
	aead, _ := newCipher(make([]byte, 32))
	multi := listenTestUDP(t)
	uni := listenTestUDP(t)
	return newPeer(name, id, multi.LocalAddr().(*net.UDPAddr), multi, uni, aead, log.New(io.Discard, "", 0), out), out
}
func event(p Packet, multicast bool) incoming {
	return incoming{packet: p, addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30001}, size: 100, multicast: multicast}
}
func TestStateAndDeduplication(t *testing.T) {
	p, out := unitPeer(t, "Ion", ionID)
	p.joined = true
	now := time.Now()
	packet := testPacket("announce")
	if err := p.receive(event(packet, true), now); err != nil {
		t.Fatal(err)
	}
	if len(p.members) != 1 {
		t.Fatal("missing member")
	}
	packet.Type = "general"
	packet.MessageID = "20000000000000000000000000000001"
	packet.Text = "hello"
	p.receive(event(packet, true), now)
	p.receive(event(packet, true), now)
	if strings.Count(out.String(), "[general] Ana: hello") != 1 {
		t.Fatal(out.String())
	}
	bad := event(packet, true)
	bad.addr.Port++
	bad.packet.MessageID = ionID
	p.receive(bad, now)
	if strings.Count(out.String(), "[general] Ana: hello") != 1 {
		t.Fatal("endpoint impersonation accepted")
	}
	p.expire(now.Add(15 * time.Second))
	if len(p.members) != 0 || !strings.Contains(out.String(), "* Ana left the chat") {
		t.Fatal(out.String())
	}
	// Own general message is shown once, not ignored with own control packets.
	own := testPacket("general")
	own.PeerID = ionID
	own.Name = "Ion"
	own.Text = "my text"
	p.receive(event(own, true), now)
	p.receive(event(own, true), now)
	if strings.Count(out.String(), "[general] Ion: my text") != 1 {
		t.Fatal(out.String())
	}
}
func TestNameConflictRules(t *testing.T) {
	low, _ := unitPeer(t, "Ana", anaID)
	high, _ := unitPeer(t, "Ana", ionID)
	packet := testPacket("claim")
	if err := high.receive(event(packet, true), time.Now()); !errors.Is(err, errNameInUse) {
		t.Fatalf("higher claimant should lose: %v", err)
	}
	packet.PeerID = ionID
	if err := low.receive(event(packet, true), time.Now()); err != nil {
		t.Fatal(err)
	}
	high.joined = true // Existing holder beats a lower-ID newcomer by sending conflict.
	packet.PeerID = anaID
	if err := high.receive(event(packet, true), time.Now()); err != nil {
		t.Fatal(err)
	}
	packet.Type = "hello"
	packet.To = ionID
	if err := high.receive(event(packet, false), time.Now()); !errors.Is(err, errNameInUse) {
		t.Fatal("partition merge should converge to lower ID")
	}
}
func readPacket(t *testing.T, conn *net.UDPConn) Packet {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, maxDatagram)
	n, _, err := conn.ReadFromUDP(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodePacket(data[:n])
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestCommandsAndPrivateRouting(t *testing.T) {
	p, out := unitPeer(t, "Ana", anaID)
	p.joined = true
	recipient := listenTestUDP(t)
	p.members[ionID] = &member{id: ionID, name: "Ion", addr: recipient.LocalAddr().(*net.UDPAddr), seen: time.Now()}
	if _, err := p.command("/msg Ion secret text"); err != nil {
		t.Fatal(err)
	}
	packet := readPacket(t, recipient)
	if packet.Type != "private" || packet.To != ionID || packet.Text != "" {
		t.Fatal(packet)
	}
	text, err := decryptPrivate(p.aead, packet, "Ion")
	if err != nil || text != "secret text" {
		t.Fatalf("%s: %v", text, err)
	}
	if _, err := p.command("hello all"); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, p.multicast); packet.Type != "general" || packet.Text != "hello all" {
		t.Fatal(packet)
	}
	// No eager display; general text is only displayed when looped back.
	if strings.Contains(out.String(), "[general]") {
		t.Fatal(out.String())
	}
	for _, line := range []string{"/msg Missing hi", "/msg Ion", strings.Repeat("x", 501), "/unknown"} {
		if _, err := p.command(line); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
	if _, err := p.command("/users"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Ion 127.0.0.1:") {
		t.Fatal(out.String())
	}
	if quit, err := p.command("/quit"); !quit || err != nil {
		t.Fatal("quit failed")
	}
}
func TestPrivateReceiveAndReplay(t *testing.T) {
	p, out := unitPeer(t, "Ion", ionID)
	p.joined = true
	packet := testPacket("private")
	packet.To = ionID
	encryptPrivate(p.aead, &packet, "Ion", "secret")
	p.receive(event(packet, false), time.Now())
	p.receive(event(packet, false), time.Now())
	if strings.Count(out.String(), "[private] Ana: secret") != 1 {
		t.Fatal(out.String())
	}
	packet.MessageID = ionID // AAD authenticates message ID, not only ciphertext.
	p.receive(event(packet, false), time.Now())
	if strings.Count(out.String(), "[private] Ana: secret") != 1 {
		t.Fatal("modified replay accepted")
	}
	packet.To = anaID
	p.receive(event(packet, false), time.Now())
	if strings.Count(out.String(), "[private] Ana: secret") != 1 {
		t.Fatal("wrong recipient accepted")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}
func (b *safeBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func waitFor(t *testing.T, b *safeBuffer, text string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), text) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing %q in output:\n%s", text, b.String())
}

type runningPeer struct {
	p         *Peer
	commands  chan string
	out, logs *safeBuffer
	cancel    context.CancelFunc
	done      chan error
}

func startNetworkPeer(t *testing.T, name, id string, group *net.UDPAddr, ifi *net.Interface, ip net.IP) *runningPeer {
	t.Helper()
	multi, uni, err := openSockets(ifi, ip, group)
	if err != nil {
		t.Fatal(err)
	}
	out, logs := new(safeBuffer), new(safeBuffer)
	aead, _ := newCipher(make([]byte, 32))
	p := newPeer(name, id, group, multi, uni, aead, log.New(logs, "", 0), out)
	p.discovery = 400 * time.Millisecond
	p.heartbeat = 150 * time.Millisecond
	p.timeout = 700 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningPeer{p: p, commands: make(chan string, 8), out: out, logs: logs, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- p.Run(ctx, r.commands) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(3 * time.Second):
			t.Error("peer failed to stop")
		}
	})
	return r
}
func networkGroup(t *testing.T) (*net.Interface, net.IP, *net.UDPAddr) {
	t.Helper()
	if testing.Short() {
		t.Skip("multicast integration test")
	}
	ifi, ip, err := chooseInterface("")
	if err != nil {
		t.Skipf("no multicast interface: %v", err)
	}
	reservation := listenTestUDP(t)
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	reservation.Close()
	return ifi, ip, &net.UDPAddr{IP: net.ParseIP(defaultGroup), Port: port}
}
func TestMulticastPeers(t *testing.T) {
	ifi, ip, group := networkGroup(t)
	ana := startNetworkPeer(t, "Ana", anaID, group, ifi, ip)
	ion := startNetworkPeer(t, "Ion", ionID, group, ifi, ip)
	maria := startNetworkPeer(t, "Maria", "00000000000000000000000000000003", group, ifi, ip)
	for _, r := range []*runningPeer{ana, ion, maria} {
		select {
		case err := <-r.done:
			r.done <- err
			t.Fatalf("%s exited before ready: %v; logs:\n%s", r.p.name, err, r.logs.String())
		case <-time.After(500 * time.Millisecond):
		}
		waitFor(t, r.out, "* ready as")
	}
	waitFor(t, ana.out, "* Ion joined")
	waitFor(t, ion.out, "* Ana joined")
	waitFor(t, maria.out, "* Ana joined")
	ana.commands <- "hello everyone"
	for _, r := range []*runningPeer{ana, ion, maria} {
		waitFor(t, r.out, "[general] Ana: hello everyone")
	}
	ana.commands <- "/msg Ion only Ion can receive this"
	waitFor(t, ion.out, "[private] Ana: only Ion can receive this")
	// Deliberately send malformed and oversized datagrams to the private socket.
	bad := listenTestUDP(t)
	endpoint := &net.UDPAddr{IP: ip, Port: ion.p.unicast.LocalAddr().(*net.UDPAddr).Port}
	for _, data := range [][]byte{[]byte("invalid"), bytes.Repeat([]byte("x"), maxDatagram+1), {0xff}} {
		if _, err := bad.WriteToUDP(data, endpoint); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, ion.logs, "kind=\"invalid\"")
	ion.commands <- "still alive"
	waitFor(t, ana.out, "[general] Ion: still alive")
	if strings.Contains(maria.out.String(), "only Ion can receive this") || strings.Contains(maria.logs.String(), `kind="private"`) {
		t.Fatal("private datagram reached another peer")
	}
	if strings.Count(ana.out.String(), "[general] Ana: hello everyone") != 1 {
		t.Fatal("own general echo duplicated")
	}
	// A later claimant loses even if its ID sorts before the holder's ID.
	duplicate := startNetworkPeer(t, "Ana", "00000000000000000000000000000000", group, ifi, ip)
	select {
	case err := <-duplicate.done:
		if !errors.Is(err, errNameInUse) {
			t.Fatalf("name rejection: %v", err)
		}
		duplicate.done <- err
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate name admitted")
	}
	maria.commands <- "/quit"
	waitFor(t, ana.out, "* Maria left the chat")
	// Simulated process death: close sockets, without executing the leave path.
	ion.p.multicast.Close()
	ion.p.unicast.Close()
	waitFor(t, ana.out, "* Ion left the chat")
}
func TestSimultaneousSameName(t *testing.T) {
	ifi, ip, group := networkGroup(t)
	low := startNetworkPeer(t, "Same", anaID, group, ifi, ip)
	high := startNetworkPeer(t, "Same", ionID, group, ifi, ip)
	waitFor(t, low.out, "* ready as Same")
	select {
	case err := <-high.done:
		if !errors.Is(err, errNameInUse) {
			t.Fatal(err)
		}
		high.done <- err
	case <-time.After(2 * time.Second):
		t.Fatal("higher ID did not reject duplicate name")
	}
}
func TestLoggingDoesNotIncludeContent(t *testing.T) {
	p, _ := unitPeer(t, "Ana", anaID)
	p.joined = true
	var logs bytes.Buffer
	p.logger = log.New(&logs, "", 0)
	p.command("sensitive general content")
	if strings.Contains(logs.String(), "sensitive") || !strings.Contains(logs.String(), "action=send") {
		t.Fatal(logs.String())
	}
}
func TestJSONRoundTrip(t *testing.T) {
	p := testPacket("general")
	p.Text = "<hello> 世界"
	b, _ := json.Marshal(p)
	parsed, err := decodePacket(b)
	if err != nil || parsed != p {
		t.Fatalf("%+v %v", parsed, err)
	}
}
