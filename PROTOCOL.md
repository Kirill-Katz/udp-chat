# LAN Chat Protocol v1 — Go/Java Implementation Guide

This document is the interoperability contract for the chat in `go-peer/` and
for a future implementation by another student. **There is no server.** Every
program is a peer with its own name, membership table, console, and UDP sockets.
`java-peer/` is intentionally empty; this document is the guide for implementing it.

Normative terms: **must** means required for interoperability. All numeric limits
below are part of version 1. All examples use fictitious IDs. Do not copy fixed
IDs or fixed nonces into a running chat.

## 1. Shared configuration

All peers in one chat must agree on:

| Setting | Value/default |
| --- | --- |
| Transport | IPv4 UDP |
| Multicast group | `239.255.42.99` |
| Chat port | `9000` (command-line configurable) |
| Protocol version | integer `1` |
| Passphrase | Same UTF-8 string on every peer |
| Heartbeat interval | 5 seconds |
| Offline timeout | 15 seconds |
| Initial discovery/name-check interval | 900 milliseconds |
| Discovery retry interval | 250 milliseconds during initial discovery |
| Maximum text length | 500 Unicode code points |
| Maximum JSON datagram length | 8192 bytes |

The group and port are configurable, but everyone must use the same values.
Use one group per chat port, a local LAN interface, and multicast TTL **1**.
Enable multicast loopback so multiple peers on the same computer, including the
sender, receive general messages. Some Wi-Fi networks block multicast: use
another network or a phone hotspot if needed.

## 2. Exactly two sockets per peer

### A. Shared multicast receiver

1. Create an IPv4 UDP socket.
2. Enable address reuse **before** binding (`SO_REUSEADDR`; use the OS's multicast
   sharing semantics, not a load-balanced unicast listener).
3. Bind to **`0.0.0.0:<chat-port>`**.
4. Join the multicast group on the chosen LAN interface.
5. Receive `claim`, `announce`, `heartbeat`, `general`, and `leave` here.

All local peers share this receiving port. Multicast copies must reach all of
them. A unicast datagram to this shared port cannot reliably select one peer.
The Go implementation uses `net.ListenMulticastUDP`, which sets up reuse and
membership; on Linux it also disables `IP_MULTICAST_ALL` to avoid other groups.

### B. Individual unicast socket (also the sending socket)

1. Create a separate IPv4 UDP socket, **without port reuse**.
2. Bind to **`0.0.0.0:0`**, letting the OS choose a distinct ephemeral port.
3. Set its multicast outgoing interface, TTL 1, and multicast loopback enabled.
4. Send **all outgoing packets from this socket**, whether their destination is
   multicast or unicast. Never send from the shared multicast receiving socket.
5. Receive `hello`, `conflict`, and `private` here.

**The UDP source IP and source port of any packet are that peer's private
endpoint.** Obtain this from `recvfrom`, not from JSON. For example, receiving
Ana's `announce` from `192.168.1.20:51234` teaches you to send Ana private packets
at `192.168.1.20:51234`, even though her announcement's destination was
`239.255.42.99:9000`.

Keep both sockets open for the entire process. Changing the private port means a
new session, which requires a new peer ID. A peer must reject a packet using a
known peer ID but a different source endpoint or name. There is no automatic
endpoint migration in v1.

**Java suggestion:** use two `DatagramChannel.open(StandardProtocolFamily.INET)`
channels. Set `StandardSocketOptions.SO_REUSEADDR` on the multicast receiver
before `bind(new InetSocketAddress("0.0.0.0", port))`, then `join(group, iface)`.
On the individual channel bind port 0 and set `IP_MULTICAST_IF`,
`IP_MULTICAST_TTL=1`, and `IP_MULTICAST_LOOP=true`. Use `send`/`receive` directly,
with a selector or separate receive threads. `MulticastSocket`/`DatagramSocket`
are also socket APIs, but ensure packets actually leave the individual socket.

## 3. Encoding and validation

- One UTF-8 JSON object per datagram. No newline, length prefix, framing, or
  splitting a message across datagrams. JSON whitespace is allowed.
- JSON keys are **case-sensitive**. Reject duplicate keys (including escaped
  duplicates), unknown keys, null values, trailing JSON values, and fields not
  allowed for that message type.
- All common header fields are required. Integers and strings must have the
  stated JSON types. `v` must be the integer `1`, not `"1"` or `1.0`.
- Omit unused fields entirely. For instance, do not put `"text":""` on a claim.
- A name is 1–32 **UTF-8 bytes**, containing only Unicode letters, Unicode digits,
  `_`, and `-`. Names are case-sensitive, with no normalization. For maximum
  consistency across Java/Go Unicode versions, use ASCII names such as `Ana_2`.
- Text is 1–500 Unicode code points, with no Unicode `Cc` control characters.
  Newlines, tabs, NUL, ESC, and DEL are not allowed. Spaces and non-ASCII text
  are allowed. UTF-8 must be valid; reject unpaired JSON `\uXXXX` surrogate
  escapes rather than replacing them with a substitute character. Do not count
  bytes or Java UTF-16 code units as characters: in Java use
  `text.codePointCount(0, text.length())`.
- Peer IDs and message IDs are **32 lowercase hexadecimal characters**, encoding
  16 cryptographically random bytes. No hyphens, uppercase, or UUID prefixes.
- Base64 is standard RFC 4648 base64 with required padding and **no whitespace
  or line breaks**; URL-safe base64 is not interchangeable.
- Every receiver must use a buffer large enough for a full UDP payload (e.g.
  65535 bytes), then reject datagrams over 8192 bytes. Reading only 8192 bytes
  could silently accept a truncated prefix of an oversized datagram.
- Log all received/sent/dropped datagrams, with time, endpoint, type, and byte
  size. Invalid packets must be dropped without crashing. Do not reply to random
  malformed bytes. Do not log plaintext or passphrases in datagram logs.

## 4. Common header

Every packet contains these fields:

| Field | JSON type | Meaning |
| --- | --- | --- |
| `v` | integer | `1` |
| `type` | string | One type from the table below |
| `peer_id` | string | Sender's random session ID, generated once per process |
| `name` | string | Sender's name |
| `message_id` | string | Fresh random ID for this datagram |

Example header-only announcement:

```json
{"v":1,"type":"announce","peer_id":"00000000000000000000000000000001","name":"Ana","message_id":"10000000000000000000000000000001"}
```

The `to` field, where applicable, is the **recipient's peer ID, not their name**.
Names are used for `/msg` lookup in the local membership table. Never trust an
arbitrary packet's `to` value to tell you who you are: compare it to your own ID.

## 5. Packet types and destinations

Only the common header plus the listed additional fields are allowed:

| Type | Destination | Additional fields | Meaning |
| --- | --- | --- | --- |
| `claim` | Multicast group/chat port | none | Ask to join under this name; not yet online |
| `hello` | Claimant's private endpoint | `to` | Established peer's immediate discovery reply |
| `conflict` | Claimant/conflicting peer's private endpoint | `to` | Reject this name |
| `announce` | Multicast group/chat port | none | Successful join |
| `heartbeat` | Multicast group/chat port | none | Still online |
| `general` | Multicast group/chat port | `text` | General-channel plaintext |
| `private` | Recipient's private endpoint | `to`, `nonce`, `ciphertext` | Encrypted private text |
| `leave` | Multicast group/chat port | none | Graceful departure |

A packet arriving on the wrong receiving socket is dropped. Never multicast
`private` packets. Do not add server-specific types such as `join`, `registered`,
`users`, `ping`, or `pong`: these are **not** part of this peer protocol.

### Example: general

```json
{"v":1,"type":"general","peer_id":"00000000000000000000000000000001","name":"Ana","message_id":"10000000000000000000000000000002","text":"hello everyone"}
```

Send this with **one** UDP send to the multicast destination. Everyone, including
Ana, displays it from their receiver:

```text
[general] Ana: hello everyone
```

The sender must not display an additional eager/local copy. It recognizes its
own multicast echo by `peer_id` and displays it exactly once. Ignore the sender's
own control packets; they must not add the sender to its remote-members table.

### Example: discovery reply

Ion sends this from his individual socket to Ana's observed source endpoint:

```json
{"v":1,"type":"hello","peer_id":"00000000000000000000000000000002","name":"Ion","message_id":"20000000000000000000000000000001","to":"00000000000000000000000000000001"}
```

Ana learns Ion's endpoint from this packet's UDP source. The packet contains
Ion's identity, not Ana's, except for its `to` field.

### Example: private

This is the fully valid cryptographic test vector from section 9:

```json
{"v":1,"type":"private","peer_id":"00000000000000000000000000000001","name":"Ana","message_id":"10000000000000000000000000000001","to":"00000000000000000000000000000002","nonce":"AAECAwQFBgcICQoL","ciphertext":"NWmjMQ7kkUzwSB2AhLYb1I+q8deJM1uwIRaXoQ=="}
```

Send only to Ion's endpoint. Ion authenticates/decrypts before displaying:

```text
[private] Ana: hello 世界
```

No other local peer's socket receives this unicast packet. There is no sender
network echo, acknowledgement, or plaintext `text` field. An optional local
sender notice must be labeled as **sent, not delivered**.

## 6. Discovery, name conflicts, and membership

### Starting a peer

1. Validate configuration, generate a random peer ID, derive the key, open both
   sockets, and start receiving before sending your first packet.
2. Multicast `claim` immediately. Retry at 250ms intervals, each time with a fresh
   `message_id`, until the 900ms discovery interval ends.
3. Established peers respond **immediately**, from their individual sockets:
   - Different name: unicast `hello`, with `to` set to the claimant's peer ID.
   - Same name: unicast `conflict`, with `to` set to the claimant's peer ID.
4. Other peers that are still claiming do not reply for different names. They
   will announce themselves when their discovery interval ends.
5. If no conflict occurs, multicast `announce` at 900ms, mark yourself joined,
   enable normal commands, and begin multicast heartbeats every 5 seconds.
6. Claims alone never add an online member. A valid `hello`, `announce`,
   `heartbeat`, or `general` adds/refreshes the sender. An authenticated `private`
   also adds/refreshes the sender. This recovers from a lost announcement.

The newcomer normally knows existing peers within one second because their
hello replies do not wait for the next heartbeat. UDP can lose all replies;
this is not an absolute delivery guarantee.

### Simultaneous same-name starts

Use bytewise/lexicographic comparison of lowercase peer IDs (equivalent to
comparing the 16 decoded bytes):

- An established holder beats a claimant, regardless of ID.
- While both are claiming, the **smaller ID wins**. On receiving a same-name
  claim, the smaller-ID claimant sends `conflict`; the larger-ID claimant exits.
- A claimant receiving a same-name `hello`, `announce`, `heartbeat`, or `general`
  exits: that peer is already established.
- A claimant receiving a same-name `conflict` addressed to it exits.
- If two same-name peers nevertheless become established because packets were
  lost or network partitions merge, they converge to the **smaller peer ID**.
  An established peer seeing same-name established traffic from a smaller ID
  exits; if the other ID is larger, it sends `conflict`. An established peer
  obeys such a conflict only if the sender has the same name and a smaller ID.
- Do not send `leave` on rejected registration. Display an error and exit with
  a nonzero status; the user can choose another name and restart.

This is deterministic conflict resolution, not distributed consensus: no UDP
protocol can guarantee immediate unique names across a disconnected network.

### Membership table and expiry

For each remote peer store `peer_id`, `name`, observed private endpoint, and the
local time last heard. Use monotonic elapsed time where available, not remote
timestamps. The Go implementation caps its remote table at 1024 entries.
Show a join notice once when first added:

```text
* Maria joined the chat
```

If a different peer ID temporarily claims the same remote name, keep the smaller
ID in your table until the owners resolve their conflict. Known IDs cannot
change their name/endpoint. Ignore duplicate packets rather than refreshing
presence from them. `claim` and `conflict` are not presence traffic.

Remove a member on a valid `leave` from its recorded identity/endpoint, or after
15 seconds without a valid presence/message packet. Check timeouts regularly
(the Go peer checks every 100ms). Display one leave notice:

```text
* Ion left the chat
```

`/users` reads the local table; it does not send a network request. Include your
own name in console output. `/msg name text` resolves the recipient locally.
If the name is not present, print an error and send nothing. `/quit`, EOF, Ctrl-C,
and SIGTERM send a best-effort `leave` if joined and close the sockets.

## 7. Duplicate suppression

Use `(peer_id, message_id)` as the deduplication key. Keep a bounded cache of the
last 4096 keys for up to 60 seconds; when full evict the oldest key. Drop repeated
general/private/presence/leave packets without redisplaying them. Each newly
constructed packet uses a new random message ID. Repeated claim handling may
send fresh hello/conflict replies; this makes discovery retries useful.

For private messages **authenticate before adding to the deduplication cache**.
Otherwise an attacker could poison the cache using a copied ID with an invalid
tag. The message ID is itself authenticated, so changing it invalidates the tag.
This cache is only bounded, short-term replay suppression, not a durable replay
protection guarantee.

## 8. Private encryption: exact cross-language recipe

The general channel and control messages remain plaintext. Private messages
use shared-key authenticated encryption, performed entirely inside each peer.

### Key derivation (once at startup)

1. Password bytes: the passphrase encoded as UTF-8, **without** trimming, Unicode
   normalization, a terminating NUL, or a BOM.
2. Salt bytes: UTF-8 of the exact string
   `lan-chat-v1|<canonical-dotted-IPv4-group>|<decimal-chat-port>`.
   Default: `lan-chat-v1|239.255.42.99|9000`.
3. KDF: **PBKDF2-HMAC-SHA256**, exactly **600,000 iterations**.
4. Output: **32 bytes / 256 bits**.

The salt is public and deterministic so independent peers derive the same key
without a server or handshake. This lab choice does not provide random
per-installation salts; choose a strong passphrase to resist offline guessing.

Java: `PBKDF2WithHmacSHA256` with `PBEKeySpec(..., 600000, 256)` is suitable if
your provider uses the specified UTF-8 password encoding. Verify the vector.
For providers with different character handling, implement PBKDF2 using
`Mac.getInstance("HmacSHA256")` over the explicit UTF-8 password bytes. ASCII
passphrases avoid provider-specific encoding ambiguity.

### Encryption

1. Validate plaintext: valid UTF-8, 1–500 code points, no `Cc` control characters.
2. Construct the complete packet header and recipient `to` ID first.
3. Algorithm: **AES-256-GCM**, 12-byte nonce, 16-byte/128-bit authentication tag.
   Java transformation: `AES/GCM/NoPadding`, `new GCMParameterSpec(128, nonce)`.
4. For every encryption, generate a fresh 12-byte nonce with an OS-backed CSPRNG
   (`crypto/rand` in Go; `SecureRandom` in Java). Never intentionally reuse one
   with the same key, including across process restarts or different senders.
5. Associated data is the UTF-8 encoding of these **six strings**, joined with
   exactly one zero byte between them, and **no final zero byte**:

   ```text
   lan-chat-private-v1
   <sender peer_id>
   <sender name>
   <recipient peer_id>
   <recipient name>
   <message_id>
   ```

   Equivalently:
   `UTF8(domain) || 00 || UTF8(peer_id) || 00 || UTF8(name) || 00 || UTF8(to) || 00 || UTF8(recipientName) || 00 || UTF8(message_id)`.

   Here `00` means one byte `0x00`, **not** the two characters `0` and `0`.
   Recipient name comes from your membership table when sending, and from your
   own configured name when receiving. It is not another JSON field.
6. GCM output is **encrypted plaintext followed by its 16-byte tag**. Go `Seal`
   and Java `doFinal` produce this layout. Store standard-base64 output in
   `ciphertext`, and standard-base64 nonce bytes in `nonce`.
7. Send the packet once, only to the recipient's individual endpoint.

### Decryption

- Verify the header/type/recipient/socket/endpoint and base64 before decrypting.
- Require a 12-byte decoded nonce and 17–2016 decoded ciphertext bytes. These
  limits correspond to 1–2000 UTF-8 plaintext bytes plus the 16-byte GCM tag.
- Reconstruct the exact AAD, then authenticate/decrypt. Wrong passphrase,
  altered ciphertext, altered sender/recipient/message ID, or invalid tag means
  **drop and log**. Never display unauthenticated plaintext.
- Validate decrypted UTF-8 and code-point/control limits before display.
- Do not add malformed or unauthenticated senders to the membership table.

GCM authenticates metadata and ciphertext; it does not prove which member sent
it, because **all chat members share the key**. Anyone with the passphrase can
read captured private traffic. Pairwise key exchange would be needed to hide
messages from other members. Random 96-bit nonces have a birthday collision
limit; shared-key usage must stay low-volume, and high-volume systems need key
rotation or stronger coordinated nonce allocation.

## 9. Compatibility test vectors

Verify these **before** attempting network interoperability. They were checked
with Go and independently with Java 21; the KDF was also checked with Python's
`hashlib.pbkdf2_hmac`.

### PBKDF2

```text
passphrase: correct horse battery staple
salt:       lan-chat-v1|239.255.42.99|9000
iterations: 600000
key length: 32 bytes
key hex:    c37b2a13646807667bf8fc9a232df3c0044a5f47e3b8b47b39238d16e2512fa0
```

### AES-GCM

```text
key:            the derived key above
sender peer_id: 00000000000000000000000000000001
sender name:    Ana
recipient ID:   00000000000000000000000000000002
recipient name: Ion
message_id:     10000000000000000000000000000001
plaintext:      hello 世界
nonce hex:      000102030405060708090a0b
nonce base64:   AAECAwQFBgcICQoL
ciphertext base64 (including tag):
NWmjMQ7kkUzwSB2AhLYb1I+q8deJM1uwIRaXoQ==
```

The nonce in this vector is **only for testing**. Production encryption must
never use this fixed value. There is no newline in the plaintext/ciphertext.

## 10. UDP behavior and scope

There are no delivery ACKs, automatic message retries, fragmentation/reassembly
at the application layer, or total ordering. Discovery retries and periodic
heartbeats tolerate some lost control packets. A private message sent just after
a receiver quits may disappear; a successful UDP send does not prove delivery.
A killed process cannot send leave, so others wait for the 15-second timeout.

8192 bytes is a validation limit, not a recommended MTU. A 500-character Unicode
message plus JSON/base64 can exceed about 1400 bytes and undergo IP
fragmentation. Fragment loss loses the entire datagram. Do not silently change
the 500-code-point limit or split messages if you want v1 interoperability.

Control/general messages are **not authenticated**. This is a trusted-LAN lab
protocol, not an Internet-facing secure messenger. A hostile peer can spoof
presence/name claims; a shared passphrase is not individual authentication.
No admission control, rate limiting, or guaranteed uniqueness during partitions
is provided. Do not expose the chat to untrusted networks.

## 11. Implementation/defense checklist

1. Match both crypto vectors.
2. Start Go and the other implementation on the same group, port, passphrase,
   and LAN interface. Check mutual discovery within approximately one second.
3. Add a third peer. Send a general message in both language directions; each
   peer, including the author, displays it once.
4. Run two peers on one computer. Private text to one must not appear in the
   other, and must be ciphertext in a packet capture.
5. Try a duplicate name, then simultaneous duplicate-name starts. Verify a
   single winner. Verify that a different-passphrase peer cannot decrypt.
6. Try `/users`, unknown recipient, 500 characters, 501 characters, malformed
   JSON, oversized bytes, and altered GCM tags.
7. Quit gracefully; then kill another peer and observe timeout departure.
8. Repeat across at least two physical computers. Check firewall rules for both
   multicast chat-port input and individual ephemeral UDP-port input.
