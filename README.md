# Lab 3 — Peer-to-peer LAN chat

The lab requires **no central server**. Every running Go program is a peer that
sends and receives directly over UDP. The previous central-server implementation
has been removed.

- **[`go-peer/`](go-peer/):** runnable Go console peer, implementing tasks 1–4.
- **[`java-peer/`](java-peer/):** Java 21 console peer compatible with the Go peer.
- **[`PROTOCOL.md`](PROTOCOL.md):** standalone implementation guide for the other
  student, including sockets, JSON packets, discovery, name conflicts, presence,
  encryption, and Go/Java-verified compatibility vectors.
- `lab_description.txt` / `lab.pdf`: original assignment.

## Build

Requires **Go 1.24+**. The implementation has no third-party dependencies.
Multicast socket options are currently supported on **macOS and Linux**.

```sh
cd go-peer
go build -o go-peer .
```

For Java 21 or newer, with no external dependencies:

```sh
cd java-peer
javac -d out Chat.java ChatTest.java NetworkTest.java
java -cp out ChatTest
java -cp out NetworkTest
```

## Run

Run each peer in a separate terminal, on the same group, port, and passphrase:

```sh
./go-peer -name Ana -port 9000 -passphrase 'correct horse battery staple'
./go-peer -name Ion -port 9000 -passphrase 'correct horse battery staple'
./go-peer -name Maria -port 9000 -passphrase 'correct horse battery staple'
```

Run the Java peer in another terminal with the same group, port, and passphrase:

```sh
cd java-peer
java -cp out Chat -name Sofia -port 9000 -passphrase 'correct horse battery staple'
```

Use `-interface <network-interface-name>` on Java when automatic selection chooses
the wrong adapter. Java and Go use the same UDP packet format and encryption key.
On Windows, the Java peer can run, while the current Go peer's multicast socket
configuration is supported only on macOS and Linux. For the mixed-language
defense, run the Go peer on macOS/Linux and the Java peer on either machine.

On another computer, use the same commands with a unique name. **Do not supply a
server address:** there is none. Discovery is automatic. Wait for `* ready as ...`
(about one second) before entering chat commands.

Select the correct LAN interface explicitly when a VPN, virtual adapters, or
multiple active interfaces cause automatic selection to choose the wrong one:

```sh
# macOS, commonly en0:
./go-peer -name Ana -port 9000 -interface en0 -passphrase 'correct horse battery staple'

# Linux, replace eth0 with your actual interface:
./go-peer -name Ion -port 9000 -interface eth0 -passphrase 'correct horse battery staple'
```

Use `ifconfig` on macOS or `ip -4 addr` on Linux to identify your interface.
The selected interface/IP and individual private port are printed at startup.

Optional flags:

```text
-group 239.255.42.99   Multicast group (all peers must agree)
-log peer-Ana.log      Datagram log path (default: peer-<name>.log)
-help                 Show all options
```

The passphrase is a required command-line argument, as specified by the lab.
Be aware that command-line arguments can appear in shell history/process lists.
Use a lab-only passphrase, not a personal password.

## Commands

```text
hello everyone           Send one general-channel multicast datagram
/msg Ion see you at five Send one encrypted unicast datagram to Ion
/users                   Show locally known names and private endpoints
/quit                    Announce departure and exit
```

A message contains 1–500 Unicode code points, without control characters. General
messages display once, including at their author. Private senders get a local
**sent, not delivered** notice; only the recipient displays the received private
message. A private message to an unknown/offline user produces an error.

The console continues receiving while waiting for your input. Incoming output
can interrupt a partially typed terminal line; this is a simple console UI, not
a full-screen line editor. Ctrl-C, SIGTERM, or EOF also exits gracefully.

## How it works

Each peer has two sockets:

1. A reusable UDP socket bound to `0.0.0.0:<chat-port>`, joined to the multicast
   group, receives discovery/general/presence packets on all local peers.
2. A distinct UDP socket bound to `0.0.0.0:<ephemeral-port>` sends all packets and
   receives private messages and discovery replies. The source endpoint of a
   received announcement tells others this private address.

Peers claim their names for 900ms before joining. Existing peers reply
immediately; simultaneous same-name claims use a deterministic ID tie-break.
Each joined peer multicasts a heartbeat every 5 seconds; a peer unheard for
15 seconds is removed. Graceful exits multicast a leave packet.

Private text is encrypted locally using **AES-256-GCM**, with fresh random
96-bit nonces and authenticated routing metadata. A shared key is derived with
**PBKDF2-HMAC-SHA256, 600,000 iterations**, from the common passphrase and a public
chat-specific salt. The general channel is plaintext. There is no encryption
server and no external key service. See `PROTOCOL.md` for byte-exact details.

## Logs

Each peer appends datagram records to `peer-<name>.log`, created with mode 0600.
Records include UTC time, send/receive/drop, endpoint, kind, byte size, and drop
reason. Content and passphrases are not logged. Invalid JSON, oversized packets,
wrong-recipient packets, duplicates, and failed authentication are dropped and
logged. They do not crash the program.

## Network troubleshooting

- All peers must choose the same group, port, passphrase, and reachable subnet.
- Allow the application through the host firewall: it needs inbound UDP for
  **both the shared chat port and its individual ephemeral private port**.
- Multiple local peers must use unique names. Multicast loopback is enabled;
  private sockets do not share ports.
- Guest/enterprise Wi-Fi and VPNs may block multicast. Try a phone hotspot or
  another LAN. Binding to `127.0.0.1` is not a substitute for LAN testing.
- A wrong passphrase does not prevent discovery/general chat but private
  authentication fails and is logged. Check every peer's passphrase.
- UDP has no guaranteed delivery/order. No message ACKs or retransmission are
  implemented. A network interruption may cause timeout departures and delayed
  rediscovery. See the protocol's limits and trust model.
- 500 Unicode characters plus encryption/JSON overhead can exceed the
  fragmentation-free MTU. IP fragmentation increases the chance of loss.

## Verify

From `go-peer/`:

```sh
go test -race ./...
go test -race -count=10 ./...
go vet ./...
go test -run='^$' -fuzz=FuzzDecodePacket -fuzztime=5s
```

Tests include three real multicast peers on one host, sender echo suppression,
private routing/isolation, duplicate names, graceful leave, simulated process
death/expiry, malformed packets, cryptographic tampering, and independent crypto
vectors. Network tests use the automatically selected multicast-capable IPv4
interface and are skipped if none exists; `go test -short ./...` skips them
explicitly. Tests shorten internal timers; real CLI defaults remain 900ms/5s/15s.

A defense still needs at least three peers across two physical computers.
The lab's interoperability bonus requires actual Java/Go communication across
the LAN at the defense. Unit crypto vectors alone do not establish that.

## Source map

| File | Responsibility |
| --- | --- |
| `go-peer/main.go` | Flags, bounded console input, log setup, signals |
| `go-peer/protocol.go` | Packet structure and strict validation |
| `go-peer/network.go`, `socket_*.go` | Interface selection and UDP socket options |
| `go-peer/peer.go` | Single-owner event loop, discovery, presence, commands, routing |
| `go-peer/crypto.go` | Key derivation, AES-GCM, authenticated metadata |
| `go-peer/*_test.go` | Unit, integration, fuzz, and crypto compatibility tests |

This is a trusted-LAN teaching protocol: shared-key members can read captured
private messages, discovery/general traffic is not authenticated, and there is
no Internet-facing admission control. Do not use it as a production messenger.
