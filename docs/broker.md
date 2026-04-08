# Relay Broker Protocol

The `punch.lua` relay broker is a minimal WebSocket server that acts as a transparent pipe between two peers when direct UDP hole punching fails.

## Protocol Specification

The broker handles two types of frames: **JSON Text** for control and **Binary** for data.

### 1. Connection & Identification
Each peer connects via WebSocket and immediately sends a `join` message:

**Client → Broker (Text):**
```json
{"join": "unique_relay_token"}
```

### 2. Matching
The broker maintains a map of active tokens. When a second peer joins with the same `unique_relay_token`, the broker:
1. Links the two connections.
2. Sends a `ready` message to both.

**Broker → Client (Text):**
```json
{"ready": true}
```

### 3. Data Transfer
Once both peers are in the `ready` state, the broker must forward all **Binary** frames from one peer to the other without modification.

**Client A → Broker (Binary) → Client B (Binary)**

### 4. Errors & Disconnect
If a peer tries to join a token that already has two peers, or if an internal error occurs:

**Broker → Client (Text):**
```json
{"error": "reason_string"}
```

Clients can also send a graceful leave:
**Client → Broker (Text):**
```json
{"leave": true}
```

## Security Note
The broker is "dumb" and doesn't see the plaintext. All data flowing through the broker is already encrypted end-to-end (AES-256-GCM) by the peers using keys derived via ECDH. The broker only sees opaque binary frames.
