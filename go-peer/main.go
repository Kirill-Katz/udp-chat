package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unicode/utf8"
)

// readConsole drains oversized lines without allocating unbounded memory.
// stdin is process-owned; a blocked terminal read is abandoned on process exit.
func readConsole(ctx context.Context, in io.Reader, commands chan<- string) {
	defer close(commands)
	reader := bufio.NewReader(in)
	line := make([]byte, 0, 2048)
	tooLong := false
	for {
		fragment, more, err := reader.ReadLine()
		if len(line)+len(fragment) > 4096 {
			tooLong = true
		}
		if !tooLong {
			line = append(line, fragment...)
		}
		if err != nil && len(line) == 0 && !tooLong {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "input: %v\n", err)
			}
			return
		}
		if more {
			continue
		}
		text := string(line)
		if tooLong {
			text = "/input-line-too-long"
		}
		select {
		case commands <- text:
		case <-ctx.Done():
			return
		}
		line = line[:0]
		tooLong = false
		if err != nil {
			return
		}
	}
}

func run() error {
	name := flag.String("name", "", "unique chat name (required)")
	port := flag.Int("port", 9000, "shared UDP chat port")
	groupText := flag.String("group", defaultGroup, "IPv4 multicast group")
	ifaceName := flag.String("interface", "", "LAN interface, e.g. en0 or eth0; auto-select if omitted")
	passphrase := flag.String("passphrase", "", "shared chat passphrase (required)")
	logPath := flag.String("log", "", "datagram log path (default: peer-<name>.log)")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments; use -help")
	}
	if !validName(*name) {
		return fmt.Errorf("-name must contain 1-32 UTF-8 bytes of letters, digits, _ or -")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("-port must be between 1 and 65535")
	}
	groupIP := net.ParseIP(*groupText)
	if groupIP == nil || groupIP.To4() == nil || !groupIP.IsMulticast() {
		return fmt.Errorf("-group must be an IPv4 multicast address")
	}
	if *passphrase == "" || !utf8.ValidString(*passphrase) {
		return fmt.Errorf("-passphrase must be nonempty valid UTF-8")
	}
	ifi, ip, err := chooseInterface(*ifaceName)
	if err != nil {
		return err
	}
	key, err := deriveKey(*passphrase, groupIP.String(), *port)
	if err != nil {
		return err
	}
	aead, err := newCipher(key)
	if err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	if *logPath == "" {
		*logPath = "peer-" + *name + ".log"
	}
	file, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	group := &net.UDPAddr{IP: groupIP, Port: *port}
	multicast, unicast, err := openSockets(ifi, ip, group)
	if err != nil {
		return err
	}
	logger := log.New(file, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC)
	p := newPeer(*name, id, group, multicast, unicast, aead, logger, os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	commands := make(chan string)
	go readConsole(ctx, os.Stdin, commands)
	fmt.Printf("* checking name %s on %s via %s (%s); private port %d; log %s\n", *name, group, ifi.Name, ip, unicast.LocalAddr().(*net.UDPAddr).Port, *logPath)
	return p.Run(ctx, commands)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
