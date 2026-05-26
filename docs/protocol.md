# Protocol and transport

## Transport model

Squish uses QUIC bidirectional streams as the substrate for its SSH-like protocol.

Current layout per connection:

- the first bidirectional stream is the control stream,
- each later bidirectional stream carries one logical channel.

The shared `qssh-core` crate contains:

- postcard-based message framing,
- control-stream message types,
- per-channel message types,
- challenge-building helpers,
- shared error types.

## Framing

Messages are:

- postcard-encoded,
- length-prefixed with a 32-bit little-endian size,
- capped at 64 KiB per frame.

That limit is intentionally large enough for current ML-DSA-65 authentication payloads while still bounding allocations.

## Control stream

The control stream is responsible for connection-wide operations.

Current messages include:

- `ClientHello`
- `AuthChallenge`
- `AuthResponse`
- `AuthResult`
- `Disconnect`
- `KeepAlive`
- `KeepAliveAck`
- `TcpForwardRequest`
- `TcpForwardConfirm`
- `TcpForwardFailure`
- `TcpForwardCancel`

### Authentication flow

The current handshake is:

1. client sends `ClientHello` with protocol version and username,
2. server sends `AuthChallenge` with a random nonce,
3. client signs the challenge payload with its ML-DSA-65 key,
4. client sends `AuthResponse` with public key and signature,
5. server verifies both authorization and signature,
6. server replies with `AuthResult`.

The challenge payload binds the proof to:

- the server certificate fingerprint,
- the requested username,
- the challenge nonce,
- the current time.

## Channel model

Each channel lives on its own QUIC bidirectional stream.

Current channel types:

- `session`
- `direct-tcpip`
- `forwarded-tcpip`

Current channel messages include:

- open/open-confirm/open-failure lifecycle messages,
- raw `Data`,
- `ExtendedData` for stderr-like streams,
- request messages such as PTY, shell, exec, signal, and window change,
- `ExitStatus` and `ExitSignal`,
- `Eof` and `Close`.

## Session behavior

A session channel is used for:

- interactive shells,
- exec requests,
- PTY-backed terminal sessions,
- signal delivery,
- exit reporting.

The client keeps stdin/stdout/stderr wired to the channel and propagates local terminal resizes.

## Forwarding behavior

### `direct-tcpip`

Used for client-side local forwarding.

- client accepts a local TCP connection,
- client opens a `direct-tcpip` channel,
- server connects to the requested target,
- data is proxied both ways.

### `forwarded-tcpip`

Used for remote forwarding.

- client asks the server to listen remotely over the control stream,
- server accepts a remote TCP connection,
- server opens a `forwarded-tcpip` channel back to the client,
- client connects to the local target,
- data is proxied both ways.

## Host identity and TOFU

The TLS certificate is not validated against a traditional public CA. Instead the client computes a SHA-256 fingerprint of the presented server certificate and pins it locally on first use.

This produces an SSH-like trust-on-first-use flow while still using TLS for the QUIC transport.

## Mobility

Because the transport is QUIC, the client can rebind its local UDP socket and continue an established connection when the local network changes. Squish currently has explicit migration monitoring to take advantage of that capability.
