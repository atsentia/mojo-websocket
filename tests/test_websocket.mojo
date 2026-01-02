"""
WebSocket Tests

Comprehensive tests for the mojo-websocket library.
"""

from mojo_websocket import (
    # Frame layer
    WebSocketFrame,
    OPCODE_CONTINUATION,
    OPCODE_TEXT,
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,
    CLOSE_NORMAL,
    CLOSE_GOING_AWAY,
    validate_frame,
    mask_payload,
    opcode_name,
    close_code_name,

    # Handshake layer
    HandshakeRequest,
    compute_accept_key,
    create_handshake_response,
    sha1,
    sha1_string,
    base64_encode,
    WEBSOCKET_GUID,

    # Protocol layer
    WebSocketMessage,
    WebSocketProtocol,
    STATE_OPEN,
    STATE_CLOSING,
    STATE_CLOSED,

    # Server layer
    WebSocketConnection,
    WebSocketConfig,
)


# =============================================================================
# Frame Tests
# =============================================================================

fn test_frame_text() raises:
    """Test creating and encoding text frames."""
    var frame = WebSocketFrame.text("Hello")
    var encoded = frame.encode()

    # Verify basic properties
    if not frame.is_text():
        raise Error("Frame should be text type")
    if not frame.is_final():
        raise Error("Frame should be final")
    if frame.payload_string() != "Hello":
        raise Error("Payload mismatch: " + frame.payload_string())

    # Verify encoding
    # First byte: FIN=1, opcode=1 -> 0x81
    if Int(encoded[0]) != 0x81:
        raise Error("First byte should be 0x81, got " + str(Int(encoded[0])))

    # Second byte: MASK=0, len=5 -> 0x05
    if Int(encoded[1]) != 5:
        raise Error("Second byte should be 5, got " + str(Int(encoded[1])))

    # Total length: 2 header + 5 payload = 7
    if len(encoded) != 7:
        raise Error("Encoded length should be 7, got " + str(len(encoded)))

    print("OK test_frame_text")


fn test_frame_binary() raises:
    """Test creating binary frames."""
    var data = List[UInt8]()
    data.append(0x00)
    data.append(0xFF)
    data.append(0x42)

    var frame = WebSocketFrame.binary(data)

    if not frame.is_binary():
        raise Error("Frame should be binary type")
    if frame.payload_length() != 3:
        raise Error("Payload length should be 3")

    print("OK test_frame_binary")


fn test_frame_ping_pong() raises:
    """Test ping and pong frames."""
    var ping_data = List[UInt8]()
    ping_data.append(1)
    ping_data.append(2)
    ping_data.append(3)

    var ping = WebSocketFrame.ping(ping_data)
    if not ping.is_ping():
        raise Error("Should be ping frame")
    if not ping.is_control():
        raise Error("Ping should be control frame")

    var pong = WebSocketFrame.pong(ping_data)
    if not pong.is_pong():
        raise Error("Should be pong frame")
    if not pong.is_control():
        raise Error("Pong should be control frame")

    print("OK test_frame_ping_pong")


fn test_frame_close() raises:
    """Test close frames."""
    var frame = WebSocketFrame.close(CLOSE_NORMAL, "goodbye")

    if not frame.is_close():
        raise Error("Should be close frame")
    if frame.close_code() != CLOSE_NORMAL:
        raise Error("Close code should be 1000")
    if frame.close_reason() != "goodbye":
        raise Error("Close reason mismatch: " + frame.close_reason())

    print("OK test_frame_close")


fn test_frame_parse() raises:
    """Test parsing encoded frames."""
    # Create and encode a frame
    var original = WebSocketFrame.text("Test message")
    var encoded = original.encode()

    # Parse it back
    var parsed = WebSocketFrame.parse(encoded)

    if not parsed.is_text():
        raise Error("Parsed frame should be text")
    if parsed.payload_string() != "Test message":
        raise Error("Parsed payload mismatch: " + parsed.payload_string())

    print("OK test_frame_parse")


fn test_frame_masked() raises:
    """Test masked frame encoding and parsing."""
    var frame = WebSocketFrame.text("Hello")

    var mask = List[UInt8]()
    mask.append(0x37)
    mask.append(0xFA)
    mask.append(0x21)
    mask.append(0x3D)

    var encoded = frame.encode_masked(mask)

    # Parse masked frame
    var parsed = WebSocketFrame.parse(encoded)

    if parsed.payload_string() != "Hello":
        raise Error("Unmasked payload mismatch: " + parsed.payload_string())

    print("OK test_frame_masked")


fn test_frame_extended_length() raises:
    """Test frames with extended payload length."""
    # Create 200-byte payload (requires 16-bit extended length)
    var payload = List[UInt8]()
    for i in range(200):
        payload.append(UInt8(i % 256))

    var frame = WebSocketFrame.binary(payload)
    var encoded = frame.encode()

    # Second byte should be 126 (16-bit extended length)
    if Int(encoded[1]) != 126:
        raise Error("Should use 16-bit extended length, got " + str(Int(encoded[1])))

    # Parse back
    var parsed = WebSocketFrame.parse(encoded)
    if parsed.payload_length() != 200:
        raise Error("Parsed payload length should be 200")

    print("OK test_frame_extended_length")


fn test_mask_payload() raises:
    """Test XOR masking."""
    var data = List[UInt8]()
    data.append(0x48)  # H
    data.append(0x65)  # e
    data.append(0x6C)  # l
    data.append(0x6C)  # l
    data.append(0x6F)  # o

    var mask = List[UInt8]()
    mask.append(0x01)
    mask.append(0x02)
    mask.append(0x03)
    mask.append(0x04)

    # Mask
    var masked = mask_payload(data, mask)

    # Unmask (same operation)
    var unmasked = mask_payload(masked, mask)

    # Should match original
    for i in range(len(data)):
        if unmasked[i] != data[i]:
            raise Error("Unmask failed at position " + str(i))

    print("OK test_mask_payload")


fn test_mask_payload_simd_small() raises:
    """Test SIMD masking with small payload (<32 bytes, scalar fallback)."""
    # 15 bytes - entirely handled by scalar fallback
    var data = List[UInt8]()
    for i in range(15):
        data.append(UInt8(i * 7 % 256))  # Some pattern

    var mask = List[UInt8]()
    mask.append(0xAB)
    mask.append(0xCD)
    mask.append(0xEF)
    mask.append(0x12)

    # Mask and unmask
    var masked = mask_payload(data, mask)
    var unmasked = mask_payload(masked, mask)

    # Verify roundtrip
    for i in range(len(data)):
        if unmasked[i] != data[i]:
            raise Error("SIMD small: unmask failed at position " + str(i))

    # Verify masking actually changed data
    var changed = False
    for i in range(len(data)):
        if masked[i] != data[i]:
            changed = True
            break
    if not changed and len(data) > 0:
        raise Error("SIMD small: masking should change data")

    print("OK test_mask_payload_simd_small")


fn test_mask_payload_simd_exact_32() raises:
    """Test SIMD masking with exactly 32 bytes (one full SIMD chunk, no tail)."""
    var data = List[UInt8]()
    for i in range(32):
        data.append(UInt8((i * 13 + 7) % 256))

    var mask = List[UInt8]()
    mask.append(0x37)
    mask.append(0xFA)
    mask.append(0x21)
    mask.append(0x3D)

    # Mask and unmask
    var masked = mask_payload(data, mask)
    var unmasked = mask_payload(masked, mask)

    # Verify roundtrip
    for i in range(len(data)):
        if unmasked[i] != data[i]:
            raise Error("SIMD exact 32: unmask failed at position " + str(i))

    print("OK test_mask_payload_simd_exact_32")


fn test_mask_payload_simd_large() raises:
    """Test SIMD masking with large payload (multiple SIMD chunks + tail)."""
    # 100 bytes = 3 full SIMD chunks (96 bytes) + 4 byte tail
    var data = List[UInt8]()
    for i in range(100):
        data.append(UInt8((i * 17 + 23) % 256))

    var mask = List[UInt8]()
    mask.append(0x11)
    mask.append(0x22)
    mask.append(0x33)
    mask.append(0x44)

    # Mask and unmask
    var masked = mask_payload(data, mask)
    var unmasked = mask_payload(masked, mask)

    # Verify roundtrip for all 100 bytes
    for i in range(len(data)):
        if unmasked[i] != data[i]:
            raise Error("SIMD large: unmask failed at position " + str(i) +
                       " expected " + str(Int(data[i])) + " got " + str(Int(unmasked[i])))

    print("OK test_mask_payload_simd_large")


fn test_mask_payload_simd_very_large() raises:
    """Test SIMD masking with very large payload (stress test)."""
    # 1000 bytes = 31 full SIMD chunks (992 bytes) + 8 byte tail
    var data = List[UInt8]()
    for i in range(1000):
        data.append(UInt8((i * 31 + 11) % 256))

    var mask = List[UInt8]()
    mask.append(0xFF)
    mask.append(0x00)
    mask.append(0xAA)
    mask.append(0x55)

    # Mask and unmask
    var masked = mask_payload(data, mask)
    var unmasked = mask_payload(masked, mask)

    # Verify roundtrip
    for i in range(len(data)):
        if unmasked[i] != data[i]:
            raise Error("SIMD very large: unmask failed at position " + str(i))

    print("OK test_mask_payload_simd_very_large")


fn test_mask_payload_simd_empty() raises:
    """Test SIMD masking with empty payload (edge case)."""
    var data = List[UInt8]()  # Empty

    var mask = List[UInt8]()
    mask.append(0x01)
    mask.append(0x02)
    mask.append(0x03)
    mask.append(0x04)

    # Should not crash
    var masked = mask_payload(data, mask)

    if len(masked) != 0:
        raise Error("SIMD empty: result should be empty")

    print("OK test_mask_payload_simd_empty")


fn test_mask_payload_simd_correctness() raises:
    """Verify SIMD masking produces same result as reference scalar implementation."""
    # Test various sizes around SIMD boundaries
    var test_sizes = List[Int]()
    test_sizes.append(1)
    test_sizes.append(4)
    test_sizes.append(31)
    test_sizes.append(32)
    test_sizes.append(33)
    test_sizes.append(63)
    test_sizes.append(64)
    test_sizes.append(65)
    test_sizes.append(127)
    test_sizes.append(128)

    var mask = List[UInt8]()
    mask.append(0xDE)
    mask.append(0xAD)
    mask.append(0xBE)
    mask.append(0xEF)

    for size_idx in range(len(test_sizes)):
        var size = test_sizes[size_idx]

        # Create test data
        var data = List[UInt8]()
        for i in range(size):
            data.append(UInt8((i * 41 + 17) % 256))

        # Reference scalar implementation
        var expected = List[UInt8]()
        for i in range(size):
            expected.append(data[i] ^ mask[i % 4])

        # SIMD implementation
        var actual = mask_payload(data, mask)

        # Compare
        if len(actual) != len(expected):
            raise Error("SIMD correctness size " + str(size) + ": length mismatch")

        for i in range(len(expected)):
            if actual[i] != expected[i]:
                raise Error("SIMD correctness size " + str(size) +
                           ": mismatch at position " + str(i))

    print("OK test_mask_payload_simd_correctness")


fn test_opcode_names() raises:
    """Test opcode name conversion."""
    if opcode_name(OPCODE_TEXT) != "TEXT":
        raise Error("TEXT opcode name wrong")
    if opcode_name(OPCODE_BINARY) != "BINARY":
        raise Error("BINARY opcode name wrong")
    if opcode_name(OPCODE_CLOSE) != "CLOSE":
        raise Error("CLOSE opcode name wrong")
    if opcode_name(OPCODE_PING) != "PING":
        raise Error("PING opcode name wrong")
    if opcode_name(OPCODE_PONG) != "PONG":
        raise Error("PONG opcode name wrong")

    print("OK test_opcode_names")


fn test_close_code_names() raises:
    """Test close code name conversion."""
    if close_code_name(CLOSE_NORMAL) != "NORMAL":
        raise Error("NORMAL close code name wrong")
    if close_code_name(CLOSE_GOING_AWAY) != "GOING_AWAY":
        raise Error("GOING_AWAY close code name wrong")

    print("OK test_close_code_names")


# =============================================================================
# Handshake Tests
# =============================================================================

fn test_sha1() raises:
    """Test SHA-1 implementation."""
    # Test vector: "abc" -> a9993e364706816aba3e25717850c26c9cd0d89d
    var hash = sha1_string("abc")

    if len(hash) != 20:
        raise Error("SHA-1 digest should be 20 bytes, got " + str(len(hash)))

    # Check first few bytes
    if Int(hash[0]) != 0xA9:
        raise Error("SHA-1 byte 0 wrong: " + str(Int(hash[0])))
    if Int(hash[1]) != 0x99:
        raise Error("SHA-1 byte 1 wrong: " + str(Int(hash[1])))
    if Int(hash[2]) != 0x3E:
        raise Error("SHA-1 byte 2 wrong: " + str(Int(hash[2])))

    print("OK test_sha1")


fn test_base64_encode() raises:
    """Test Base64 encoding."""
    var data = List[UInt8]()
    # "Hello" = [72, 101, 108, 108, 111]
    data.append(72)
    data.append(101)
    data.append(108)
    data.append(108)
    data.append(111)

    var encoded = base64_encode(data)
    if encoded != "SGVsbG8=":
        raise Error("Base64 encode failed: " + encoded)

    print("OK test_base64_encode")


fn test_compute_accept_key() raises:
    """Test Sec-WebSocket-Accept computation (RFC 6455 example)."""
    # RFC 6455 Section 1.3 example:
    # Client key: dGhlIHNhbXBsZSBub25jZQ==
    # Expected accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    var client_key = "dGhlIHNhbXBsZSBub25jZQ=="
    var accept = compute_accept_key(client_key)

    if accept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=":
        raise Error("Accept key mismatch: " + accept)

    print("OK test_compute_accept_key")


fn test_handshake_request_parse() raises:
    """Test parsing WebSocket handshake request."""
    var request_text = "GET /chat HTTP/1.1\r\n"
    request_text += "Host: server.example.com\r\n"
    request_text += "Upgrade: websocket\r\n"
    request_text += "Connection: Upgrade\r\n"
    request_text += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    request_text += "Sec-WebSocket-Version: 13\r\n"
    request_text += "Origin: http://example.com\r\n"
    request_text += "\r\n"

    var request = HandshakeRequest.parse(request_text)

    if request.method != "GET":
        raise Error("Method should be GET: " + request.method)
    if request.path != "/chat":
        raise Error("Path should be /chat: " + request.path)
    if request.host != "server.example.com":
        raise Error("Host mismatch: " + request.host)
    if request.key != "dGhlIHNhbXBsZSBub25jZQ==":
        raise Error("Key mismatch: " + request.key)
    if request.version != "13":
        raise Error("Version should be 13: " + request.version)
    if not request.is_valid_websocket():
        raise Error("Should be valid WebSocket request")

    print("OK test_handshake_request_parse")


fn test_handshake_response() raises:
    """Test generating handshake response."""
    var client_key = "dGhlIHNhbXBsZSBub25jZQ=="
    var response = create_handshake_response(client_key)

    # Check for required parts
    if not _contains(response, "HTTP/1.1 101"):
        raise Error("Response should contain 101 status")
    if not _contains(response, "Upgrade: websocket"):
        raise Error("Response should contain Upgrade header")
    if not _contains(response, "Connection: Upgrade"):
        raise Error("Response should contain Connection header")
    if not _contains(response, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="):
        raise Error("Response should contain accept key")

    print("OK test_handshake_response")


# =============================================================================
# Protocol Tests
# =============================================================================

fn test_protocol_receive_text() raises:
    """Test receiving text message through protocol."""
    var protocol = WebSocketProtocol()

    # Create and encode a text frame
    var frame = WebSocketFrame.text("Hello World")
    var data = frame.encode()

    # Process through protocol
    protocol.receive_data(data)

    if not protocol.has_message():
        raise Error("Should have a message")

    var msg = protocol.next_message()
    if not msg.is_text():
        raise Error("Message should be text")
    if msg.text() != "Hello World":
        raise Error("Message text mismatch: " + msg.text())

    print("OK test_protocol_receive_text")


fn test_protocol_receive_fragmented() raises:
    """Test receiving fragmented message."""
    var protocol = WebSocketProtocol()

    # Create fragmented frames manually
    var payload1 = _string_to_bytes("Hello ")
    var frame1 = WebSocketFrame(OPCODE_TEXT, payload1, fin=False)

    var payload2 = _string_to_bytes("World")
    var frame2 = WebSocketFrame(OPCODE_CONTINUATION, payload2, fin=True)

    # Send first fragment
    var data1 = frame1.encode()
    protocol.receive_data(data1)

    # Should not have complete message yet
    if protocol.has_message():
        raise Error("Should not have message after first fragment")

    # Send second fragment
    var data2 = frame2.encode()
    protocol.receive_data(data2)

    # Now should have complete message
    if not protocol.has_message():
        raise Error("Should have message after last fragment")

    var msg = protocol.next_message()
    if msg.text() != "Hello World":
        raise Error("Reassembled message mismatch: " + msg.text())

    print("OK test_protocol_receive_fragmented")


fn test_protocol_ping() raises:
    """Test ping/pong handling."""
    var protocol = WebSocketProtocol()

    # Send a ping
    var ping_data = List[UInt8]()
    ping_data.append(1)
    ping_data.append(2)
    ping_data.append(3)

    var ping = WebSocketFrame.ping(ping_data)
    var data = ping.encode()

    protocol.receive_data(data)

    # Should need to send pong
    if not protocol.needs_pong:
        raise Error("Should need pong response")

    var pong_frame = protocol.get_pending_pong()
    if not pong_frame.is_pong():
        raise Error("Response should be pong")

    # Pong payload should match ping
    if pong_frame.payload_length() != 3:
        raise Error("Pong payload length mismatch")

    print("OK test_protocol_ping")


fn test_protocol_close() raises:
    """Test close handling."""
    var protocol = WebSocketProtocol()

    # Receive close frame
    var close = WebSocketFrame.close(CLOSE_NORMAL, "goodbye")
    var data = close.encode()

    protocol.receive_data(data)

    if not protocol.is_closing():
        raise Error("Should be in closing state")
    if protocol.close_code != CLOSE_NORMAL:
        raise Error("Close code should be 1000")
    if protocol.close_reason != "goodbye":
        raise Error("Close reason mismatch")

    print("OK test_protocol_close")


# =============================================================================
# Connection Tests
# =============================================================================

fn test_connection_handshake() raises:
    """Test WebSocket connection handshake."""
    var conn = WebSocketConnection("127.0.0.1:12345")

    var request = "GET /ws HTTP/1.1\r\n"
    request += "Host: localhost\r\n"
    request += "Upgrade: websocket\r\n"
    request += "Connection: Upgrade\r\n"
    request += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    request += "Sec-WebSocket-Version: 13\r\n"
    request += "\r\n"

    var response = conn.handshake(request)

    if not conn.is_handshake_complete():
        raise Error("Handshake should be complete")
    if not conn.is_open():
        raise Error("Connection should be open")
    if conn.path != "/ws":
        raise Error("Path should be /ws: " + conn.path)

    # Response should be valid
    if not _contains(response, "101 Switching Protocols"):
        raise Error("Response should contain 101 status")

    print("OK test_connection_handshake")


fn test_connection_send_receive() raises:
    """Test sending and receiving through connection."""
    var conn = WebSocketConnection()

    # Do handshake
    var request = "GET / HTTP/1.1\r\n"
    request += "Host: localhost\r\n"
    request += "Upgrade: websocket\r\n"
    request += "Connection: Upgrade\r\n"
    request += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    request += "Sec-WebSocket-Version: 13\r\n"
    request += "\r\n"

    _ = conn.handshake(request)

    # Create a text frame to "receive"
    var incoming = WebSocketFrame.text("Test message")
    var data = incoming.encode()

    conn.receive(data)

    if not conn.has_message():
        raise Error("Should have received message")

    var msg = conn.next_message()
    if msg.text() != "Test message":
        raise Error("Message mismatch: " + msg.text())

    # Test sending
    var outgoing = conn.send_text("Response")
    if len(outgoing) == 0:
        raise Error("Send should produce bytes")

    print("OK test_connection_send_receive")


fn test_connection_config() raises:
    """Test WebSocket configuration."""
    var config = WebSocketConfig()

    # Default values
    if config.max_message_size != 16777216:
        raise Error("Default max_message_size wrong")
    if config.ping_interval != 30:
        raise Error("Default ping_interval wrong")

    # Origin validation
    config.allowed_origins.append("http://example.com")
    config.allowed_origins.append("https://example.com")

    if not config.validate_origin("http://example.com"):
        raise Error("Should allow http://example.com")
    if config.validate_origin("http://evil.com"):
        raise Error("Should not allow http://evil.com")

    # Protocol negotiation
    config.supported_protocols.append("graphql-ws")
    config.supported_protocols.append("chat")

    var selected = config.select_protocol("chat, graphql-ws")
    if selected != "graphql-ws":
        raise Error("Should select first supported protocol")

    print("OK test_connection_config")


# =============================================================================
# Security Tests
# =============================================================================

fn test_mask_key_randomness() raises:
    """Test that mask key generation is non-deterministic (SEC-001 fix)."""
    from mojo_websocket import generate_mask_key

    # Generate multiple keys and verify they're different
    var key1 = generate_mask_key()
    var key2 = generate_mask_key()
    var key3 = generate_mask_key()

    # Keys should be 4 bytes
    if len(key1) != 4 or len(key2) != 4 or len(key3) != 4:
        raise Error("Mask keys should be 4 bytes")

    # At least one key should be different (extremely high probability)
    var all_same = True
    for i in range(4):
        if key1[i] != key2[i] or key2[i] != key3[i]:
            all_same = False
            break

    if all_same:
        raise Error("Mask keys should not be deterministic - all 3 keys were identical")

    print("OK test_mask_key_randomness")


fn test_websocket_key_randomness() raises:
    """Test that WebSocket key generation is non-deterministic (SEC-002 fix)."""
    from mojo_websocket import generate_websocket_key

    # Generate multiple keys and verify they're different
    var key1 = generate_websocket_key()
    var key2 = generate_websocket_key()
    var key3 = generate_websocket_key()

    # Keys should be 24 characters (16 bytes base64 encoded)
    if len(key1) != 24 or len(key2) != 24 or len(key3) != 24:
        raise Error("WebSocket keys should be 24 characters, got " + str(len(key1)))

    # At least two keys should be different
    if key1 == key2 and key2 == key3:
        raise Error("WebSocket keys should not be deterministic - all 3 keys were identical")

    print("OK test_websocket_key_randomness")


# =============================================================================
# Edge Case Tests
# =============================================================================

fn test_empty_message() raises:
    """Test empty message handling."""
    var frame = WebSocketFrame.text("")
    var encoded = frame.encode()

    # Should have 2 bytes header, 0 payload
    if len(encoded) != 2:
        raise Error("Empty text frame should be 2 bytes")

    var parsed = WebSocketFrame.parse(encoded)
    if parsed.payload_string() != "":
        raise Error("Parsed payload should be empty")

    print("OK test_empty_message")


fn test_max_control_frame() raises:
    """Test control frame size limit."""
    # Control frames limited to 125 bytes
    var data = List[UInt8]()
    for i in range(125):
        data.append(UInt8(i))

    var ping = WebSocketFrame.ping(data)

    # Should succeed
    validate_frame(ping)

    # 126 bytes should fail
    data.append(0xFF)
    var big_ping = WebSocketFrame.ping(data)

    var failed = False
    try:
        validate_frame(big_ping)
    except e:
        failed = True

    if not failed:
        raise Error("Should fail validation for 126-byte control frame")

    print("OK test_max_control_frame")


fn test_control_frame_no_fragment() raises:
    """Test that control frames cannot be fragmented."""
    var data = List[UInt8]()
    data.append(1)
    data.append(2)

    # Create non-final ping (invalid)
    var ping = WebSocketFrame(OPCODE_PING, data, fin=False)

    var failed = False
    try:
        validate_frame(ping)
    except e:
        failed = True

    if not failed:
        raise Error("Should fail validation for fragmented control frame")

    print("OK test_control_frame_no_fragment")


fn test_multiple_messages() raises:
    """Test receiving multiple messages in sequence."""
    var protocol = WebSocketProtocol()

    # Create three messages
    var frame1 = WebSocketFrame.text("One")
    var frame2 = WebSocketFrame.text("Two")
    var frame3 = WebSocketFrame.text("Three")

    # Concatenate all frames
    var all_data = List[UInt8]()
    var encoded1 = frame1.encode()
    var encoded2 = frame2.encode()
    var encoded3 = frame3.encode()

    for i in range(len(encoded1)):
        all_data.append(encoded1[i])
    for i in range(len(encoded2)):
        all_data.append(encoded2[i])
    for i in range(len(encoded3)):
        all_data.append(encoded3[i])

    # Process all at once
    protocol.receive_data(all_data)

    if protocol.message_count() != 3:
        raise Error("Should have 3 messages, got " + str(protocol.message_count()))

    var msg1 = protocol.next_message()
    var msg2 = protocol.next_message()
    var msg3 = protocol.next_message()

    if msg1.text() != "One":
        raise Error("First message wrong")
    if msg2.text() != "Two":
        raise Error("Second message wrong")
    if msg3.text() != "Three":
        raise Error("Third message wrong")

    print("OK test_multiple_messages")


fn test_partial_frame_receive() raises:
    """Test receiving frame in multiple chunks."""
    var protocol = WebSocketProtocol()

    var frame = WebSocketFrame.text("Hello World")
    var data = frame.encode()

    # Split data in half
    var half = len(data) // 2
    var part1 = List[UInt8]()
    var part2 = List[UInt8]()

    for i in range(half):
        part1.append(data[i])
    for i in range(half, len(data)):
        part2.append(data[i])

    # Send first half
    protocol.receive_data(part1)

    # Should not have message yet
    if protocol.has_message():
        raise Error("Should not have message from partial frame")

    # Send second half
    protocol.receive_data(part2)

    # Now should have message
    if not protocol.has_message():
        raise Error("Should have message after complete frame")

    var msg = protocol.next_message()
    if msg.text() != "Hello World":
        raise Error("Message mismatch")

    print("OK test_partial_frame_receive")


# =============================================================================
# Helper Functions
# =============================================================================

fn _string_to_bytes(s: String) -> List[UInt8]:
    """Convert string to bytes."""
    var result = List[UInt8]()
    for i in range(len(s)):
        result.append(UInt8(ord(s[i])))
    return result


fn _contains(s: String, sub: String) -> Bool:
    """Check if string contains substring."""
    if len(sub) > len(s):
        return False
    for i in range(len(s) - len(sub) + 1):
        var match = True
        for j in range(len(sub)):
            if s[i + j] != sub[j]:
                match = False
                break
        if match:
            return True
    return False


# =============================================================================
# Main
# =============================================================================

fn main() raises:
    print("Running WebSocket tests...\n")
    print("=== Frame Tests ===")

    test_frame_text()
    test_frame_binary()
    test_frame_ping_pong()
    test_frame_close()
    test_frame_parse()
    test_frame_masked()
    test_frame_extended_length()
    test_mask_payload()
    test_opcode_names()
    test_close_code_names()

    print("\n=== SIMD Masking Tests (PERF-002) ===")

    test_mask_payload_simd_small()
    test_mask_payload_simd_exact_32()
    test_mask_payload_simd_large()
    test_mask_payload_simd_very_large()
    test_mask_payload_simd_empty()
    test_mask_payload_simd_correctness()

    print("\n=== Handshake Tests ===")

    test_sha1()
    test_base64_encode()
    test_compute_accept_key()
    test_handshake_request_parse()
    test_handshake_response()

    print("\n=== Protocol Tests ===")

    test_protocol_receive_text()
    test_protocol_receive_fragmented()
    test_protocol_ping()
    test_protocol_close()

    print("\n=== Connection Tests ===")

    test_connection_handshake()
    test_connection_send_receive()
    test_connection_config()

    print("\n=== Security Tests ===")

    test_mask_key_randomness()
    test_websocket_key_randomness()

    print("\n=== Edge Case Tests ===")

    test_empty_message()
    test_max_control_frame()
    test_control_frame_no_fragment()
    test_multiple_messages()
    test_partial_frame_receive()

    print("\n" + "=" * 50)
    print("All WebSocket tests passed!")
