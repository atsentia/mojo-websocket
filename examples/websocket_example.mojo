"""
Example: WebSocket Protocol (RFC 6455)

Demonstrates:
- WebSocket frame encoding/decoding
- Client handshake generation
- Message handling
- Ping/pong keepalive
"""

from mojo_websocket import WebSocketFrame, WebSocketConnection, WebSocketProtocol
from mojo_websocket import OPCODE_TEXT, OPCODE_PING, OPCODE_PONG
from mojo_websocket import generate_websocket_key, create_client_handshake
from mojo_websocket import compute_accept_key, WEBSOCKET_GUID


fn frame_encoding_example():
    """Demonstrate WebSocket frame encoding."""
    print("=== Frame Encoding Example ===")

    # Create a text frame
    var text = "Hello, WebSocket!"
    var frame = WebSocketFrame.text(text)

    # Encode to bytes
    var encoded = frame.encode()
    print("Original text: " + text)
    print("Encoded frame size: " + String(len(encoded)) + " bytes")

    # Parse the frame back
    var parsed = WebSocketFrame.parse(encoded)
    print("Parsed payload: " + parsed.payload_string())
    print("Is text frame: " + String(parsed.opcode == OPCODE_TEXT))
    print("")


fn handshake_example():
    """Demonstrate WebSocket handshake."""
    print("=== Handshake Example ===")

    # Generate client key
    var client_key = generate_websocket_key()
    print("Client key: " + client_key)

    # Create handshake request
    var request = create_client_handshake("ws://example.com/chat", client_key)
    print("\nClient handshake request:")
    print(request[:200] + "...")

    # Server computes accept key
    var accept_key = compute_accept_key(client_key)
    print("\nServer accept key: " + accept_key)
    print("")


fn protocol_example() raises:
    """Demonstrate high-level WebSocket protocol."""
    print("=== Protocol Example ===")

    # Create WebSocket connection handler
    var ws = WebSocketConnection()

    # Create text message
    var message_bytes = ws.send_text("Hello from Mojo!")
    print("Created text message: " + String(len(message_bytes)) + " bytes")

    # Create ping frame
    var ping_bytes = ws.send_ping()
    print("Created ping frame: " + String(len(ping_bytes)) + " bytes")

    # Create close frame
    var close_bytes = ws.send_close(1000, "Normal closure")
    print("Created close frame: " + String(len(close_bytes)) + " bytes")
    print("")


fn message_builder_example():
    """Demonstrate message fragmentation."""
    print("=== Message Builder Example ===")

    # For large messages, use fragmentation
    var protocol = WebSocketProtocol()

    # Build a multi-part message
    var part1 = "This is part 1 of a "
    var part2 = "fragmented WebSocket message."

    print("Fragment 1: " + part1)
    print("Fragment 2: " + part2)
    print("(In production, these would be sent as continuation frames)")
    print("")


fn main() raises:
    print("mojo-websocket: Pure Mojo WebSocket Protocol (RFC 6455)\n")

    frame_encoding_example()
    handshake_example()
    protocol_example()
    message_builder_example()

    print("=" * 50)
    print("Integration with mojo-socket:")
    print("  1. Use TcpListener to accept connections")
    print("  2. Perform WebSocket handshake")
    print("  3. Use WebSocketConnection for message I/O")
