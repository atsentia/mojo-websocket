"""
WebSocket Server

High-level WebSocket server implementation that handles:
- HTTP upgrade handshake
- Frame encoding/decoding
- Message reassembly
- Ping/pong keepalive
- Close handshake

Architecture:
    ┌────────────────────────────────────────────────────────┐
    │                  WebSocketServer                        │
    ├────────────────────────────────────────────────────────┤
    │  ┌─────────────────┐    ┌─────────────────────────┐   │
    │  │ WebSocketClient │    │  WebSocketClient        │   │
    │  │ (connection 1)  │    │  (connection 2)  ...    │   │
    │  └────────┬────────┘    └──────────┬──────────────┘   │
    │           │                        │                   │
    │           ▼                        ▼                   │
    │  ┌──────────────────────────────────────────────────┐ │
    │  │               WebSocketProtocol                   │ │
    │  │  (frame parsing, fragmentation, control frames)  │ │
    │  └──────────────────────────────────────────────────┘ │
    │                         │                              │
    │                         ▼                              │
    │  ┌──────────────────────────────────────────────────┐ │
    │  │              Handshake (RFC 6455)                 │ │
    │  │  (HTTP upgrade, Sec-WebSocket-Key/Accept)        │ │
    │  └──────────────────────────────────────────────────┘ │
    └────────────────────────────────────────────────────────┘

Note: This module provides the WebSocket protocol layer.
For TCP networking, use mojo-socket's TcpListener/TcpSocket.
"""

from .frame import (
    WebSocketFrame,
    OPCODE_TEXT,
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,
    CLOSE_NORMAL,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    validate_frame,
)

from .handshake import (
    HandshakeRequest,
    create_handshake_response,
    create_handshake_error,
    compute_accept_key,
)

from .protocol import (
    WebSocketProtocol,
    WebSocketMessage,
    STATE_CONNECTING,
    STATE_OPEN,
    STATE_CLOSING,
    STATE_CLOSED,
)


# =============================================================================
# WebSocket Connection
# =============================================================================

struct WebSocketConnection:
    """
    Represents a single WebSocket connection.

    Wraps the protocol handler and provides a high-level API
    for sending and receiving messages.

    Example:
        # Accept connection (after TCP socket accept)
        var conn = WebSocketConnection()

        # Perform handshake
        var http_request = socket.recv(4096)
        var response = conn.handshake(http_request)
        socket.send(response)

        # Send/receive messages
        socket.send(conn.send_text("Hello!"))

        var data = socket.recv(4096)
        conn.receive(data)
        while conn.has_message():
            var msg = conn.next_message()
            print("Received:", msg.text())
    """
    var protocol: WebSocketProtocol
    var handshake_complete: Bool
    var client_address: String
    var path: String
    var subprotocol: String
    var extensions: String
    var origin: String

    fn __init__(out self, client_address: String = ""):
        """
        Create new WebSocket connection.

        Args:
            client_address: Client IP:port (for logging).
        """
        self.protocol = WebSocketProtocol()
        self.protocol.state = STATE_CONNECTING
        self.handshake_complete = False
        self.client_address = client_address
        self.path = "/"
        self.subprotocol = ""
        self.extensions = ""
        self.origin = ""

    # =========================================================================
    # Handshake
    # =========================================================================

    fn handshake(inout self, request_data: String) raises -> String:
        """
        Process WebSocket handshake request.

        Args:
            request_data: Raw HTTP request from client.

        Returns:
            HTTP response to send to client.

        Raises:
            Error: If handshake is invalid.

        Example:
            var request = socket.recv(4096)
            var response = conn.handshake(request)
            if len(response) > 0:
                socket.send(response)
        """
        # Parse request
        var request = HandshakeRequest.parse(request_data)

        # Validate
        if not request.is_valid_websocket():
            return create_handshake_error(400, "Bad Request")

        # Store request info
        self.path = request.path
        self.origin = request.origin

        # TODO: Protocol negotiation
        # For now, just accept first protocol if any
        if len(request.protocols) > 0:
            var protocols = _split_comma(request.protocols)
            if len(protocols) > 0:
                self.subprotocol = protocols[0]

        # Generate response
        var response = create_handshake_response(
            request.key,
            self.subprotocol,
            self.extensions,
        )

        # Mark handshake complete
        self.handshake_complete = True
        self.protocol.state = STATE_OPEN

        return response

    fn is_handshake_complete(self) -> Bool:
        """Check if handshake is complete."""
        return self.handshake_complete

    # =========================================================================
    # State
    # =========================================================================

    fn is_open(self) -> Bool:
        """Check if connection is open and ready for messages."""
        return self.handshake_complete and self.protocol.is_open()

    fn is_closing(self) -> Bool:
        """Check if connection is in closing state."""
        return self.protocol.is_closing()

    fn is_closed(self) -> Bool:
        """Check if connection is closed."""
        return self.protocol.is_closed()

    fn get_state(self) -> Int:
        """Get current connection state."""
        if not self.handshake_complete:
            return STATE_CONNECTING
        return self.protocol.get_state()

    # =========================================================================
    # Receiving
    # =========================================================================

    fn receive(inout self, data: List[UInt8]) raises:
        """
        Process incoming data from socket.

        Args:
            data: Raw bytes from socket.recv().

        Raises:
            Error: On protocol error.
        """
        self.protocol.receive_data(data)

    fn receive_string(inout self, data: String) raises:
        """
        Process incoming data from socket (string version).

        Args:
            data: String data from socket.recv().
        """
        var bytes = _string_to_bytes(data)
        self.receive(bytes)

    fn has_message(self) -> Bool:
        """Check if complete messages are available."""
        return self.protocol.has_message()

    fn next_message(inout self) -> WebSocketMessage:
        """Get next complete message."""
        return self.protocol.next_message()

    fn message_count(self) -> Int:
        """Get number of pending messages."""
        return self.protocol.message_count()

    # =========================================================================
    # Sending
    # =========================================================================

    fn send_text(self, message: String) -> List[UInt8]:
        """
        Create bytes for sending a text message.

        Args:
            message: Text to send.

        Returns:
            Encoded frame bytes to send via socket.

        Example:
            var data = conn.send_text("Hello!")
            socket.send_bytes(data)
        """
        var frame = self.protocol.create_text_frame(message)
        return frame.encode()

    fn send_binary(self, data: List[UInt8]) -> List[UInt8]:
        """
        Create bytes for sending a binary message.

        Args:
            data: Binary data to send.

        Returns:
            Encoded frame bytes to send via socket.
        """
        var frame = self.protocol.create_binary_frame(data)
        return frame.encode()

    fn send_ping(self, data: List[UInt8] = List[UInt8]()) -> List[UInt8]:
        """
        Create bytes for sending a ping.

        Args:
            data: Optional ping payload.

        Returns:
            Encoded frame bytes to send via socket.
        """
        var frame = self.protocol.create_ping_frame(data)
        return frame.encode()

    fn send_pong(self, data: List[UInt8] = List[UInt8]()) -> List[UInt8]:
        """
        Create bytes for sending a pong.

        Args:
            data: Pong payload (typically echo of ping).

        Returns:
            Encoded frame bytes to send via socket.
        """
        var frame = self.protocol.create_pong_frame(data)
        return frame.encode()

    fn send_close(
        self,
        code: UInt16 = CLOSE_NORMAL,
        reason: String = "",
    ) -> List[UInt8]:
        """
        Create bytes for sending a close frame.

        Args:
            code: Close status code.
            reason: Close reason.

        Returns:
            Encoded frame bytes to send via socket.
        """
        var frame = self.protocol.create_close_frame(code, reason)
        return frame.encode()

    # =========================================================================
    # Control Frame Handling
    # =========================================================================

    fn needs_pong(self) -> Bool:
        """Check if a pong response is needed (ping was received)."""
        return self.protocol.needs_pong

    fn get_pong_response(inout self) -> List[UInt8]:
        """
        Get pong response for received ping.

        Returns:
            Encoded pong frame, or empty if no ping pending.
        """
        if self.protocol.needs_pong:
            var frame = self.protocol.get_pending_pong()
            return frame.encode()
        return List[UInt8]()

    # =========================================================================
    # Close Handling
    # =========================================================================

    fn initiate_close(inout self, code: UInt16 = CLOSE_NORMAL, reason: String = ""):
        """Start closing handshake."""
        self.protocol.initiate_close(code, reason)

    fn complete_close(inout self):
        """Mark connection as fully closed."""
        self.protocol.complete_close()

    fn close_code(self) -> UInt16:
        """Get close status code (after close received)."""
        return self.protocol.close_code

    fn close_reason(self) -> String:
        """Get close reason (after close received)."""
        return self.protocol.close_reason


# =============================================================================
# WebSocket Server Configuration
# =============================================================================

struct WebSocketConfig:
    """
    Configuration for WebSocket server/connection.

    Example:
        var config = WebSocketConfig()
        config.max_message_size = 1024 * 1024  # 1MB
        config.ping_interval = 30  # seconds
    """
    var max_message_size: Int
    var max_frame_size: Int
    var ping_interval: Int  # seconds (0 = no auto-ping)
    var ping_timeout: Int  # seconds
    var allowed_origins: List[String]
    var supported_protocols: List[String]

    fn __init__(out self):
        """Create default configuration."""
        self.max_message_size = 16777216  # 16MB
        self.max_frame_size = 16777216
        self.ping_interval = 30
        self.ping_timeout = 60
        self.allowed_origins = List[String]()
        self.supported_protocols = List[String]()

    fn validate_origin(self, origin: String) -> Bool:
        """
        Check if origin is allowed.

        Args:
            origin: Origin header value.

        Returns:
            True if allowed (empty list = allow all).
        """
        if len(self.allowed_origins) == 0:
            return True  # Allow all

        for i in range(len(self.allowed_origins)):
            if self.allowed_origins[i] == origin:
                return True

        return False

    fn select_protocol(self, requested: String) -> String:
        """
        Select subprotocol from client's list.

        Args:
            requested: Comma-separated list from client.

        Returns:
            Selected protocol or empty string.
        """
        if len(self.supported_protocols) == 0:
            return ""

        var client_protocols = _split_comma(requested)

        for i in range(len(self.supported_protocols)):
            var supported = self.supported_protocols[i]
            for j in range(len(client_protocols)):
                if client_protocols[j] == supported:
                    return supported

        return ""


# =============================================================================
# WebSocket Handler Interface
# =============================================================================

# Note: Mojo doesn't have traits/interfaces yet, so we document the expected
# callback signatures here.

# fn on_connect(conn: WebSocketConnection) -> None
#     Called when a new WebSocket connection is established.

# fn on_message(conn: WebSocketConnection, msg: WebSocketMessage) -> None
#     Called when a complete message is received.

# fn on_close(conn: WebSocketConnection, code: UInt16, reason: String) -> None
#     Called when connection is closed.

# fn on_error(conn: WebSocketConnection, error: String) -> None
#     Called on protocol error.


# =============================================================================
# Helper Functions
# =============================================================================

fn _string_to_bytes(s: String) -> List[UInt8]:
    """Convert string to bytes."""
    var result = List[UInt8]()
    for i in range(len(s)):
        result.append(UInt8(ord(s[i])))
    return result


fn _bytes_to_string(data: List[UInt8]) -> String:
    """Convert bytes to string."""
    var result = String()
    for i in range(len(data)):
        result += chr(Int(data[i]))
    return result


fn _split_comma(s: String) -> List[String]:
    """Split comma-separated string."""
    var result = List[String]()
    var current = String()

    for i in range(len(s)):
        var c = s[i]
        if c == ",":
            var trimmed = _trim(current)
            if len(trimmed) > 0:
                result.append(trimmed)
            current = String()
        else:
            current += c

    var trimmed = _trim(current)
    if len(trimmed) > 0:
        result.append(trimmed)

    return result


fn _trim(s: String) -> String:
    """Trim whitespace."""
    var start = 0
    var end = len(s)

    while start < end and (s[start] == " " or s[start] == "\t"):
        start += 1

    while end > start and (s[end - 1] == " " or s[end - 1] == "\t"):
        end -= 1

    var result = String()
    for i in range(start, end):
        result += s[i]
    return result


# =============================================================================
# Broadcast Helper
# =============================================================================

fn broadcast_text(
    connections: List[WebSocketConnection],
    message: String,
) -> List[List[UInt8]]:
    """
    Create broadcast bytes for all connections.

    Args:
        connections: List of connections.
        message: Text message to broadcast.

    Returns:
        List of encoded frames (one per connection).

    Example:
        var frames = broadcast_text(connections, "Hello everyone!")
        for i in range(len(connections)):
            sockets[i].send_bytes(frames[i])
    """
    var result = List[List[UInt8]]()
    var frame = WebSocketFrame.text(message)
    var encoded = frame.encode()

    for _ in range(len(connections)):
        # All connections get the same frame
        result.append(encoded)

    return result


fn broadcast_binary(
    connections: List[WebSocketConnection],
    data: List[UInt8],
) -> List[List[UInt8]]:
    """
    Create broadcast bytes for binary message.

    Args:
        connections: List of connections.
        data: Binary data to broadcast.

    Returns:
        List of encoded frames.
    """
    var result = List[List[UInt8]]()
    var frame = WebSocketFrame.binary(data)
    var encoded = frame.encode()

    for _ in range(len(connections)):
        result.append(encoded)

    return result


# =============================================================================
# Echo Server Example (Documentation)
# =============================================================================

# Example usage with mojo-socket:
#
#     from mojo_socket import TcpListener, TcpSocket
#     from mojo_websocket import WebSocketConnection
#
#     fn main() raises:
#         var listener = TcpListener.bind(8080)
#         print("WebSocket server listening on ws://localhost:8080")
#
#         while True:
#             # Accept TCP connection
#             var socket = listener.accept()
#
#             # Create WebSocket connection
#             var ws = WebSocketConnection(socket.remote_address.__str__())
#
#             # Read HTTP upgrade request
#             var request = socket.recv(4096)
#
#             # Perform handshake
#             var response = ws.handshake(request)
#             socket.send(response)
#
#             if not ws.is_open():
#                 socket.close()
#                 continue
#
#             print("Client connected:", ws.path)
#
#             # Echo loop
#             while ws.is_open():
#                 var data = socket.recv_bytes(4096)
#                 if len(data) == 0:
#                     break
#
#                 ws.receive(data)
#
#                 # Handle pings
#                 if ws.needs_pong():
#                     socket.send_bytes(ws.get_pong_response())
#
#                 # Echo messages
#                 while ws.has_message():
#                     var msg = ws.next_message()
#                     if msg.is_text():
#                         socket.send_bytes(ws.send_text(msg.text()))
#                     elif msg.is_binary():
#                         socket.send_bytes(ws.send_binary(msg.data()))
#
#                 # Check for close
#                 if ws.is_closing():
#                     socket.send_bytes(ws.send_close(ws.close_code(), ws.close_reason()))
#                     ws.complete_close()
#                     break
#
#             socket.close()
#             print("Client disconnected")
