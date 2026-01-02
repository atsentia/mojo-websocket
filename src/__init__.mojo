"""
mojo-websocket

Pure Mojo WebSocket protocol library (RFC 6455).

This library provides WebSocket protocol support including:
- Frame encoding/decoding
- HTTP upgrade handshake
- Message fragmentation
- Ping/pong keepalive
- Close handshake

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   mojo-websocket                         │
    ├─────────────────────────────────────────────────────────┤
    │  ┌─────────────────┐  ┌─────────────────────────────┐  │
    │  │  WebSocketFrame │  │  WebSocketConnection        │  │
    │  │  (low-level)    │  │  (high-level API)           │  │
    │  └─────────────────┘  └─────────────────────────────┘  │
    │           │                       │                     │
    │           ▼                       ▼                     │
    │  ┌─────────────────┐  ┌─────────────────────────────┐  │
    │  │  handshake.mojo │  │  protocol.mojo              │  │
    │  │  (HTTP upgrade) │  │  (message handling)         │  │
    │  └─────────────────┘  └─────────────────────────────┘  │
    └─────────────────────────────────────────────────────────┘

Usage (Server):
    from mojo_websocket import WebSocketConnection

    fn main() raises:
        # After accepting TCP connection...
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

Usage (Low-level frames):
    from mojo_websocket import WebSocketFrame, OPCODE_TEXT

    # Create frame
    var frame = WebSocketFrame.text("Hello!")
    var bytes = frame.encode()

    # Parse frame
    var parsed = WebSocketFrame.parse(bytes)
    print("Message:", parsed.payload_string())
"""

# =============================================================================
# Frame Layer (RFC 6455 Section 5)
# =============================================================================

from .frame import (
    # Frame struct
    WebSocketFrame,

    # Opcodes
    OPCODE_CONTINUATION,
    OPCODE_TEXT,
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,

    # Frame flags
    FLAG_FIN,
    FLAG_MASK,

    # Close codes
    CLOSE_NORMAL,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    CLOSE_UNSUPPORTED_DATA,
    CLOSE_NO_STATUS,
    CLOSE_ABNORMAL,
    CLOSE_INVALID_PAYLOAD,
    CLOSE_POLICY_VIOLATION,
    CLOSE_MESSAGE_TOO_BIG,
    CLOSE_EXTENSION_REQUIRED,
    CLOSE_INTERNAL_ERROR,

    # Functions
    validate_frame,
    mask_payload,
    mask_payload_inplace,  # SIMD-optimized in-place masking (PERF-002)
    generate_mask_key,
    opcode_name,
    close_code_name,
)

# =============================================================================
# Handshake Layer (RFC 6455 Section 4)
# =============================================================================

from .handshake import (
    # Request/Response parsing
    HandshakeRequest,
    HandshakeResponse,

    # Response generation
    compute_accept_key,
    create_handshake_response,
    create_handshake_error,

    # Client handshake
    generate_websocket_key,
    create_client_handshake,

    # Crypto (needed for handshake)
    sha1,
    sha1_string,
    base64_encode,

    # Constants
    WEBSOCKET_GUID,
    WEBSOCKET_VERSION,
)

# =============================================================================
# Protocol Layer (Message handling)
# =============================================================================

from .protocol import (
    # Message struct
    WebSocketMessage,

    # Protocol handler
    WebSocketProtocol,

    # Connection states
    STATE_CONNECTING,
    STATE_OPEN,
    STATE_CLOSING,
    STATE_CLOSED,
    state_name,

    # Builder helper
    MessageBuilder,
)

# =============================================================================
# Server Layer (High-level API)
# =============================================================================

from .server import (
    # Main connection class
    WebSocketConnection,

    # Configuration
    WebSocketConfig,

    # Helpers
    broadcast_text,
    broadcast_binary,
)
