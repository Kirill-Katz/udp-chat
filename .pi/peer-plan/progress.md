# Progress

## Implementation
- Removed server/; created go-peer/ and empty java-peer/.
- Implemented two direct UDP sockets, single-owner peer event loop, 900ms discovery, unique-name conflict handling, 5s heartbeat, 15s expiry, multicast general messages, encrypted direct unicast private messages, console commands, bounded input, signal/EOF handling, strict JSON validation, and datagram logging.
- Added Linux/macOS multicast options; unsupported platforms fail explicitly.
- Reviewed join/name-conflict, source-endpoint pinning, receive validation, message deduplication, encryption AAD, and socket shutdown paths.
- Initial multicast integration run did not reach ready; added early-exit diagnostics and tolerated ordinary ICMP reachability errors from previous UDP sends. Ten subsequent race-enabled suite runs and CLI smoke tests passed.
- Linux cross-compile initially failed because syscall.IP_MULTICAST_ALL is not exported; used Linux uapi constant 49 in the Linux-only file. Cross-compilation now passes.

## Verification
- go test -race -count=10 ./...: passed, including three actual multicast peers and simultaneous same-name starts.
- go vet ./...: passed.
- Native macOS build and Linux amd64 cross-build: passed.
- Parser fuzzing: 706248 executions, no failure.
- Statement coverage: 74.5%.
- Actual CLI smoke with three processes and default 900ms/5s/15s timers: passed discovery, general, 500-code-point encrypted private text, 501-character rejection, duplicate-name rejection, killed-process timeout, and graceful quit.
- Independent Java 21 vector verification and Python PBKDF2 verification: match documented Go vectors.
- server/ absent; java-peer/ exists and contains no files.

## Documentation
- README.md covers build/run, commands, architecture, firewall/multicast setup, source map, tests and limitations.
- PROTOCOL.md is standalone: exact sockets, packet schema, routing, join/conflict rules, expiry, duplicate cache, byte-exact crypto, vectors, Java socket guidance and acceptance checklist.
- Two initial targeted documentation replacements failed to match; inspected exact lines and applied corrected replacements. No content lost.
