"""
WebSocket Handshake (RFC 6455 Section 4)

Implements the HTTP upgrade handshake for WebSocket connections.

Client request:
    GET /chat HTTP/1.1
    Host: server.example.com
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    Sec-WebSocket-Version: 13

Server response:
    HTTP/1.1 101 Switching Protocols
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
"""


# =============================================================================
# Constants
# =============================================================================

# WebSocket magic GUID (RFC 6455 Section 1.3)
alias WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# WebSocket version
alias WEBSOCKET_VERSION = "13"


# =============================================================================
# SHA-1 Implementation (needed for Sec-WebSocket-Accept)
# =============================================================================

# SHA-1 Initial hash values
alias SHA1_H0: UInt32 = 0x67452301
alias SHA1_H1: UInt32 = 0xEFCDAB89
alias SHA1_H2: UInt32 = 0x98BADCFE
alias SHA1_H3: UInt32 = 0x10325476
alias SHA1_H4: UInt32 = 0xC3D2E1F0


fn _sha1_rotl(x: UInt32, n: Int) -> UInt32:
    """Left rotate."""
    return (x << n) | (x >> (32 - n))


fn sha1(data: List[UInt8]) -> List[UInt8]:
    """
    Compute SHA-1 hash.

    Args:
        data: Input bytes.

    Returns:
        20-byte SHA-1 digest.
    """
    # Initialize hash values
    var h0 = SHA1_H0
    var h1 = SHA1_H1
    var h2 = SHA1_H2
    var h3 = SHA1_H3
    var h4 = SHA1_H4

    # Pre-processing: adding padding bits
    var msg = List[UInt8]()
    for i in range(len(data)):
        msg.append(data[i])

    var msg_len = len(data)
    var bit_len = UInt64(msg_len) * 8

    # Append bit '1' (0x80)
    msg.append(0x80)

    # Pad to 56 mod 64 bytes
    while len(msg) % 64 != 56:
        msg.append(0x00)

    # Append original length in bits (big-endian, 64 bits)
    for i in range(8):
        msg.append(UInt8((bit_len >> (56 - i * 8)) & 0xFF))

    # Process message in 64-byte chunks
    var chunk_count = len(msg) // 64

    for chunk_idx in range(chunk_count):
        var chunk_start = chunk_idx * 64

        # Break chunk into sixteen 32-bit big-endian words w[0..15]
        var w = List[UInt32]()
        for _ in range(80):
            w.append(0)

        for i in range(16):
            var idx = chunk_start + i * 4
            w[i] = (UInt32(msg[idx]) << 24) | \
                   (UInt32(msg[idx + 1]) << 16) | \
                   (UInt32(msg[idx + 2]) << 8) | \
                   UInt32(msg[idx + 3])

        # Extend to 80 words
        for i in range(16, 80):
            w[i] = _sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        # Initialize working variables
        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4

        # Main loop
        for i in range(80):
            var f: UInt32
            var k: UInt32

            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            var temp = _sha1_rotl(a, 5) + f + e + k + w[i]
            e = d
            d = c
            c = _sha1_rotl(b, 30)
            b = a
            a = temp

        # Add to hash
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    # Produce final hash value (20 bytes)
    var digest = List[UInt8]()
    for i in range(4):
        digest.append(UInt8((h0 >> (24 - i * 8)) & 0xFF))
    for i in range(4):
        digest.append(UInt8((h1 >> (24 - i * 8)) & 0xFF))
    for i in range(4):
        digest.append(UInt8((h2 >> (24 - i * 8)) & 0xFF))
    for i in range(4):
        digest.append(UInt8((h3 >> (24 - i * 8)) & 0xFF))
    for i in range(4):
        digest.append(UInt8((h4 >> (24 - i * 8)) & 0xFF))

    return digest


fn sha1_string(s: String) -> List[UInt8]:
    """Compute SHA-1 hash of string."""
    var data = List[UInt8]()
    for i in range(len(s)):
        data.append(UInt8(ord(s[i])))
    return sha1(data)


# =============================================================================
# Base64 Encoding (for Sec-WebSocket-Accept)
# =============================================================================

alias BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


fn base64_encode(data: List[UInt8]) -> String:
    """
    Encode bytes to standard Base64 with padding.

    Args:
        data: Bytes to encode.

    Returns:
        Base64-encoded string.
    """
    if len(data) == 0:
        return ""

    var result = String()
    var i = 0
    var n = len(data)

    # Process 3 bytes at a time
    while i + 2 < n:
        var b0 = Int(data[i])
        var b1 = Int(data[i + 1])
        var b2 = Int(data[i + 2])

        result += BASE64_ALPHABET[(b0 >> 2) & 0x3F]
        result += BASE64_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F]
        result += BASE64_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F]
        result += BASE64_ALPHABET[b2 & 0x3F]

        i += 3

    # Handle remaining bytes
    var remaining = n - i

    if remaining == 1:
        var b0 = Int(data[i])
        result += BASE64_ALPHABET[(b0 >> 2) & 0x3F]
        result += BASE64_ALPHABET[(b0 << 4) & 0x3F]
        result += "=="
    elif remaining == 2:
        var b0 = Int(data[i])
        var b1 = Int(data[i + 1])
        result += BASE64_ALPHABET[(b0 >> 2) & 0x3F]
        result += BASE64_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F]
        result += BASE64_ALPHABET[(b1 << 2) & 0x3F]
        result += "="

    return result


# =============================================================================
# Handshake Request Parsing
# =============================================================================

struct HandshakeRequest:
    """
    Parsed WebSocket handshake request.

    Example:
        var request = HandshakeRequest.parse(http_request)
        if request.is_valid_websocket():
            var response = create_handshake_response(request.key)
    """
    var method: String
    var path: String
    var host: String
    var upgrade: String
    var connection: String
    var key: String
    var version: String
    var origin: String
    var protocols: String
    var extensions: String
    var headers: List[String]

    fn __init__(out self):
        """Create empty request."""
        self.method = ""
        self.path = ""
        self.host = ""
        self.upgrade = ""
        self.connection = ""
        self.key = ""
        self.version = ""
        self.origin = ""
        self.protocols = ""
        self.extensions = ""
        self.headers = List[String]()

    @staticmethod
    fn parse(data: String) raises -> HandshakeRequest:
        """
        Parse HTTP upgrade request.

        Args:
            data: Raw HTTP request string.

        Returns:
            Parsed HandshakeRequest.

        Raises:
            Error: If request is malformed.
        """
        var request = HandshakeRequest()

        # Split into lines
        var lines = _split_lines(data)
        if len(lines) < 1:
            raise Error("Empty request")

        # Parse request line: GET /path HTTP/1.1
        var request_line = lines[0]
        var parts = _split_spaces(request_line)
        if len(parts) < 3:
            raise Error("Invalid request line: " + request_line)

        request.method = parts[0]
        request.path = parts[1]

        # Parse headers
        for i in range(1, len(lines)):
            var line = lines[i]
            if len(line) == 0:
                break

            request.headers.append(line)

            # Find colon separator
            var colon_pos = _find_char(line, ":")
            if colon_pos < 0:
                continue

            var name = _trim(_substring(line, 0, colon_pos))
            var value = _trim(_substring(line, colon_pos + 1, len(line)))
            var name_lower = _to_lower(name)

            if name_lower == "host":
                request.host = value
            elif name_lower == "upgrade":
                request.upgrade = value
            elif name_lower == "connection":
                request.connection = value
            elif name_lower == "sec-websocket-key":
                request.key = value
            elif name_lower == "sec-websocket-version":
                request.version = value
            elif name_lower == "origin":
                request.origin = value
            elif name_lower == "sec-websocket-protocol":
                request.protocols = value
            elif name_lower == "sec-websocket-extensions":
                request.extensions = value

        return request

    fn is_valid_websocket(self) -> Bool:
        """
        Check if request is a valid WebSocket upgrade request.

        Returns:
            True if valid WebSocket handshake request.
        """
        # Method must be GET
        if self.method != "GET":
            return False

        # Upgrade header must be "websocket"
        if _to_lower(self.upgrade) != "websocket":
            return False

        # Connection header must contain "Upgrade"
        if _find_substring(_to_lower(self.connection), "upgrade") < 0:
            return False

        # Sec-WebSocket-Key must be present and 24 chars (16 bytes base64)
        if len(self.key) != 24:
            return False

        # Sec-WebSocket-Version must be 13
        if self.version != "13":
            return False

        return True


# =============================================================================
# Handshake Response Generation
# =============================================================================

fn compute_accept_key(client_key: String) -> String:
    """
    Compute Sec-WebSocket-Accept value.

    Per RFC 6455 Section 1.3:
    1. Concatenate client key with GUID
    2. SHA-1 hash
    3. Base64 encode

    Args:
        client_key: Sec-WebSocket-Key from client.

    Returns:
        Sec-WebSocket-Accept value.
    """
    var concat = client_key + WEBSOCKET_GUID
    var hash = sha1_string(concat)
    return base64_encode(hash)


fn create_handshake_response(
    client_key: String,
    protocol: String = "",
    extensions: String = "",
) -> String:
    """
    Create WebSocket handshake response.

    Args:
        client_key: Sec-WebSocket-Key from client request.
        protocol: Optional selected subprotocol.
        extensions: Optional selected extensions.

    Returns:
        Complete HTTP response string.

    Example:
        var response = create_handshake_response(request.key)
        socket.send(response)
    """
    var accept_key = compute_accept_key(client_key)

    var response = "HTTP/1.1 101 Switching Protocols\r\n"
    response += "Upgrade: websocket\r\n"
    response += "Connection: Upgrade\r\n"
    response += "Sec-WebSocket-Accept: " + accept_key + "\r\n"

    if len(protocol) > 0:
        response += "Sec-WebSocket-Protocol: " + protocol + "\r\n"

    if len(extensions) > 0:
        response += "Sec-WebSocket-Extensions: " + extensions + "\r\n"

    response += "\r\n"
    return response


fn create_handshake_error(status_code: Int, reason: String) -> String:
    """
    Create error response for failed handshake.

    Args:
        status_code: HTTP status code (e.g., 400, 403).
        reason: Status reason phrase.

    Returns:
        HTTP error response.
    """
    var response = "HTTP/1.1 " + str(status_code) + " " + reason + "\r\n"
    response += "Content-Length: 0\r\n"
    response += "Connection: close\r\n"
    response += "\r\n"
    return response


# =============================================================================
# Client Handshake Request Generation
# =============================================================================

fn generate_websocket_key() -> String:
    """
    Generate a cryptographically random Sec-WebSocket-Key.

    Per RFC 6455: 16-byte random value, base64-encoded.
    Uses the Mojo standard library's random_ui64() which provides
    cryptographically secure random numbers.

    Returns:
        24-character base64-encoded key with 128 bits of entropy.
    """
    from random import random_ui64

    var bytes = List[UInt8]()

    # Generate 16 random bytes from two 64-bit random values
    var rand1 = random_ui64()
    var rand2 = random_ui64()

    # Extract 8 bytes from each random value
    for i in range(8):
        bytes.append(UInt8((rand1 >> (i * 8)) & 0xFF))
    for i in range(8):
        bytes.append(UInt8((rand2 >> (i * 8)) & 0xFF))

    return base64_encode(bytes)


fn create_client_handshake(
    host: String,
    path: String = "/",
    key: String = "",
    origin: String = "",
    protocols: String = "",
    extensions: String = "",
) -> String:
    """
    Create WebSocket client handshake request.

    Args:
        host: Host header value.
        path: Request path (default "/").
        key: Optional Sec-WebSocket-Key (generated if empty).
        origin: Optional Origin header.
        protocols: Optional Sec-WebSocket-Protocol header.
        extensions: Optional Sec-WebSocket-Extensions header.

    Returns:
        Complete HTTP request string.

    Example:
        var request = create_client_handshake("example.com", "/socket")
        socket.send(request)
    """
    var ws_key = key
    if len(ws_key) == 0:
        ws_key = generate_websocket_key()

    var request = "GET " + path + " HTTP/1.1\r\n"
    request += "Host: " + host + "\r\n"
    request += "Upgrade: websocket\r\n"
    request += "Connection: Upgrade\r\n"
    request += "Sec-WebSocket-Key: " + ws_key + "\r\n"
    request += "Sec-WebSocket-Version: 13\r\n"

    if len(origin) > 0:
        request += "Origin: " + origin + "\r\n"

    if len(protocols) > 0:
        request += "Sec-WebSocket-Protocol: " + protocols + "\r\n"

    if len(extensions) > 0:
        request += "Sec-WebSocket-Extensions: " + extensions + "\r\n"

    request += "\r\n"
    return request


# =============================================================================
# Handshake Response Validation (for clients)
# =============================================================================

struct HandshakeResponse:
    """
    Parsed WebSocket handshake response (for client use).
    """
    var status_code: Int
    var status_reason: String
    var upgrade: String
    var connection: String
    var accept: String
    var protocol: String
    var extensions: String

    fn __init__(out self):
        self.status_code = 0
        self.status_reason = ""
        self.upgrade = ""
        self.connection = ""
        self.accept = ""
        self.protocol = ""
        self.extensions = ""

    @staticmethod
    fn parse(data: String) raises -> HandshakeResponse:
        """Parse HTTP response."""
        var response = HandshakeResponse()

        var lines = _split_lines(data)
        if len(lines) < 1:
            raise Error("Empty response")

        # Parse status line: HTTP/1.1 101 Switching Protocols
        var status_line = lines[0]
        var parts = _split_spaces(status_line)
        if len(parts) < 3:
            raise Error("Invalid status line")

        # Parse status code
        response.status_code = _parse_int(parts[1])
        response.status_reason = parts[2]

        # Parse headers
        for i in range(1, len(lines)):
            var line = lines[i]
            if len(line) == 0:
                break

            var colon_pos = _find_char(line, ":")
            if colon_pos < 0:
                continue

            var name = _trim(_substring(line, 0, colon_pos))
            var value = _trim(_substring(line, colon_pos + 1, len(line)))
            var name_lower = _to_lower(name)

            if name_lower == "upgrade":
                response.upgrade = value
            elif name_lower == "connection":
                response.connection = value
            elif name_lower == "sec-websocket-accept":
                response.accept = value
            elif name_lower == "sec-websocket-protocol":
                response.protocol = value
            elif name_lower == "sec-websocket-extensions":
                response.extensions = value

        return response

    fn validate(self, client_key: String) raises:
        """
        Validate server response against client key.

        Args:
            client_key: The Sec-WebSocket-Key sent in request.

        Raises:
            Error: If response is invalid.
        """
        if self.status_code != 101:
            raise Error("Expected status 101, got " + str(self.status_code))

        if _to_lower(self.upgrade) != "websocket":
            raise Error("Invalid Upgrade header: " + self.upgrade)

        if _find_substring(_to_lower(self.connection), "upgrade") < 0:
            raise Error("Invalid Connection header: " + self.connection)

        var expected_accept = compute_accept_key(client_key)
        if self.accept != expected_accept:
            raise Error("Invalid Sec-WebSocket-Accept")


# =============================================================================
# String Helper Functions
# =============================================================================

fn _split_lines(s: String) -> List[String]:
    """Split string by CRLF."""
    var lines = List[String]()
    var current = String()

    var i = 0
    while i < len(s):
        if i + 1 < len(s) and s[i] == "\r" and s[i + 1] == "\n":
            lines.append(current)
            current = String()
            i += 2
        else:
            current += s[i]
            i += 1

    if len(current) > 0:
        lines.append(current)

    return lines


fn _split_spaces(s: String) -> List[String]:
    """Split string by spaces."""
    var parts = List[String]()
    var current = String()

    for i in range(len(s)):
        if s[i] == " ":
            if len(current) > 0:
                parts.append(current)
                current = String()
        else:
            current += s[i]

    if len(current) > 0:
        parts.append(current)

    return parts


fn _find_char(s: String, c: String) -> Int:
    """Find first occurrence of character."""
    for i in range(len(s)):
        if s[i] == c:
            return i
    return -1


fn _find_substring(s: String, sub: String) -> Int:
    """Find first occurrence of substring."""
    if len(sub) == 0:
        return 0
    if len(sub) > len(s):
        return -1

    for i in range(len(s) - len(sub) + 1):
        var match = True
        for j in range(len(sub)):
            if s[i + j] != sub[j]:
                match = False
                break
        if match:
            return i
    return -1


fn _substring(s: String, start: Int, end: Int) -> String:
    """Extract substring."""
    var result = String()
    for i in range(start, end):
        if i >= 0 and i < len(s):
            result += s[i]
    return result


fn _trim(s: String) -> String:
    """Trim leading and trailing whitespace."""
    var start = 0
    var end = len(s)

    while start < end and (s[start] == " " or s[start] == "\t"):
        start += 1

    while end > start and (s[end - 1] == " " or s[end - 1] == "\t"):
        end -= 1

    return _substring(s, start, end)


fn _to_lower(s: String) -> String:
    """Convert string to lowercase."""
    var result = String()
    for i in range(len(s)):
        var c = s[i]
        var code = ord(c)
        if code >= 65 and code <= 90:  # A-Z
            result += chr(code + 32)
        else:
            result += c
    return result


fn _parse_int(s: String) -> Int:
    """Parse integer from string."""
    var result = 0
    for i in range(len(s)):
        var c = s[i]
        var code = ord(c)
        if code >= 48 and code <= 57:  # 0-9
            result = result * 10 + (code - 48)
    return result
