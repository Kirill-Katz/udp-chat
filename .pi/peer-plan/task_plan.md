# Goal
Replace central server with a lab-compliant Go peer; keep java-peer empty.

## Phases
1. Implement multicast/unicast console peer and encrypted private messages — complete.
2. Test protocol, discovery/name conflicts, routing, shutdown; document interoperability — complete.

## Next Step
User can run the Go peer and hand PROTOCOL.md to the other student; verify on two physical computers.

## Decisions
- IPv4 multicast for discovery/general traffic; distinct ephemeral private sockets.
- Direct UDP via Go standard library; AES-GCM and PBKDF2-SHA256 client-side.
- Single owner event loop, buffered receive events, graceful leave.

## Errors Encountered
Planning helper requires a Git repository; this folder has no .git. Planning files kept locally under .pi/peer-plan instead. Initial multicast test startup did not reach ready; repeated diagnostics/tests now pass. Linux socket constant needed numeric uapi value 49. Two documentation exact-match edits were corrected after inspection. Details in progress.md.
