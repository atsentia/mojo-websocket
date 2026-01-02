# mojo-websocket

Pure Mojo WebSocket protocol library (RFC 6455).

## Features

- **Frame Encoding/Decoding** - Full RFC 6455 compliance
- **HTTP Upgrade Handshake** - Server and client support
- **Message Fragmentation** - Large message handling
- **Ping/Pong Keepalive** - Connection health monitoring
- **SIMD-optimized Masking** - High-performance payload masking

## Installation

```bash
pixi add mojo-websocket
```

## Quick Start

### Server Usage

```mojo
from mojo_websocket import WebSocketConnection

fn main() raises:
    var ws = WebSocketConnection()
    
    # Perform handshake
    var response = ws.handshake(http_request)
    socket.send(response)
    
    # Send/receive messages
    socket.send_bytes(ws.send_text("Hello!"))
    
    var data = socket.recv_bytes(4096)
    ws.receive(data)
    while ws.has_message():
        var msg = ws.next_message()
        print("Received:", msg.text())
```

### Low-level Frames

```mojo
from mojo_websocket import WebSocketFrame, OPCODE_TEXT

# Create frame
var frame = WebSocketFrame.text("Hello!")
var bytes = frame.encode()

# Parse frame
var parsed = WebSocketFrame.parse(bytes)
print("Message:", parsed.payload_string())
```

### Client Handshake

```mojo
from mojo_websocket import create_client_handshake, generate_websocket_key

var key = generate_websocket_key()
var request = create_client_handshake("example.com", "/ws", key)
```

## API Reference

| Component | Description |
|-----------|-------------|
| `WebSocketConnection` | High-level connection handler |
| `WebSocketFrame` | Low-level frame encoding/decoding |
| `HandshakeRequest` | Parse HTTP upgrade request |
| `HandshakeResponse` | Generate HTTP upgrade response |
| `WebSocketProtocol` | Message assembly from frames |

## Close Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 1000 | `CLOSE_NORMAL` | Normal closure |
| 1001 | `CLOSE_GOING_AWAY` | Endpoint going away |
| 1002 | `CLOSE_PROTOCOL_ERROR` | Protocol error |
| 1003 | `CLOSE_UNSUPPORTED_DATA` | Unsupported data type |

## Testing

```bash
mojo run tests/test_websocket.mojo
```

## License

MIT

## Part of mojo-contrib

This library is part of [mojo-contrib](https://github.com/atsentia/mojo-contrib), a collection of pure Mojo libraries.
