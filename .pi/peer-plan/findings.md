# Findings

- Original assignment requires a serverless UDP peer, a shared chat port, multicast/general fanout, direct private endpoints, discovery, presence and encrypted private traffic.
- User explicitly requested removing server/, creating go-peer/, and leaving java-peer/ empty; also requested standalone Markdown protocol for the other student.
- Go ListenMulticastUDP provides wildcard binding and address reuse; all sends must originate from a distinct private socket to advertise a useful recvfrom endpoint.
- macOS requires multicast-loopback enabled on sender; Linux IP_MULTICAST_ALL is Linux socket option 49 (not exported in this Go syscall package).
- Java 21 independently matches the Go PBKDF2 and AES-GCM vectors in PROTOCOL.md. Temporary vector verification was outside java-peer/.
- Real same-machine multicast tests and CLI smoke tests passed; cross-computer defense testing remains an operator/network task.
