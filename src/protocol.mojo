"""
WebSocket Protocol Handler

High-level message handling for WebSocket connections.
Handles text, binary, ping, pong, and close messages.
Supports message fragmentation.
"""

from .frame import (
    WebSocketFrame,
    OPCODE_CONTINUATION,
    OPCODE_TEXT,
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,
    CLOSE_NORMAL,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    CLOSE_ABNORMAL,
    validate_frame,
    opcode_name,
)


# =============================================================================
# WebSocket Message
# =============================================================================

struct WebSocketMessage:
    """
    A complete WebSocket message (potentially assembled from fragments).

    Example:
        if message.is_text:
            print("Received:", message.text())
        elif message.is_binary:
            var data = message.data()
    """
    var opcode: UInt8
    var payload: List[UInt8]
    var is_complete: Bool

    fn __init__(out self, opcode: UInt8 = OPCODE_TEXT):
        """Create empty message."""
        self.opcode = opcode
        self.payload = List[UInt8]()
        self.is_complete = False

    fn __init__(out self, opcode: UInt8, payload: List[UInt8]):
        """Create message with data."""
        self.opcode = opcode
        self.payload = payload
        self.is_complete = True

    fn is_text(self) -> Bool:
        """Check if this is a text message."""
        return self.opcode == OPCODE_TEXT

    fn is_binary(self) -> Bool:
        """Check if this is a binary message."""
        return self.opcode == OPCODE_BINARY

    fn text(self) -> String:
        """Get message as text string."""
        var result = String()
        for i in range(len(self.payload)):
            result += chr(Int(self.payload[i]))
        return result

    fn data(self) -> List[UInt8]:
        """Get message payload data."""
        return self.payload

    fn length(self) -> Int:
        """Get payload length."""
        return len(self.payload)

    fn append(inout self, data: List[UInt8]):
        """Append data to payload (for fragmented messages)."""
        for i in range(len(data)):
            self.payload.append(data[i])


# =============================================================================
# WebSocket Connection State
# =============================================================================

alias STATE_CONNECTING: Int = 0
alias STATE_OPEN: Int = 1
alias STATE_CLOSING: Int = 2
alias STATE_CLOSED: Int = 3


fn state_name(state: Int) -> String:
    """Get human-readable state name."""
    if state == STATE_CONNECTING:
        return "CONNECTING"
    if state == STATE_OPEN:
        return "OPEN"
    if state == STATE_CLOSING:
        return "CLOSING"
    if state == STATE_CLOSED:
        return "CLOSED"
    return "UNKNOWN"


# =============================================================================
# WebSocket Protocol Handler
# =============================================================================

struct WebSocketProtocol:
    """
    WebSocket protocol state machine.

    Handles message framing, fragmentation, and control frames.

    Example:
        var protocol = WebSocketProtocol()

        # Process incoming data
        protocol.receive_data(raw_bytes)

        # Get complete messages
        while protocol.has_message():
            var msg = protocol.next_message()
            if msg.is_text():
                print("Text:", msg.text())

        # Send messages
        var frame = protocol.create_text_frame("Hello!")
        socket.send(frame.encode())
    """
    var state: Int
    var current_message: WebSocketMessage
    var message_queue: List[WebSocketMessage]
    var receive_buffer: List[UInt8]
    var close_code: UInt16
    var close_reason: String
    var max_message_size: Int
    var ping_payload: List[UInt8]  # Payload from last ping (for pong)
    var needs_pong: Bool

    fn __init__(out self, max_message_size: Int = 16777216):
        """
        Create protocol handler.

        Args:
            max_message_size: Maximum message size in bytes (default 16MB).
        """
        self.state = STATE_OPEN
        self.current_message = WebSocketMessage()
        self.message_queue = List[WebSocketMessage]()
        self.receive_buffer = List[UInt8]()
        self.close_code = 0
        self.close_reason = ""
        self.max_message_size = max_message_size
        self.ping_payload = List[UInt8]()
        self.needs_pong = False

    # =========================================================================
    # State Management
    # =========================================================================

    fn is_open(self) -> Bool:
        """Check if connection is open."""
        return self.state == STATE_OPEN

    fn is_closing(self) -> Bool:
        """Check if connection is closing."""
        return self.state == STATE_CLOSING

    fn is_closed(self) -> Bool:
        """Check if connection is closed."""
        return self.state == STATE_CLOSED

    fn get_state(self) -> Int:
        """Get current state."""
        return self.state

    # =========================================================================
    # Receiving
    # =========================================================================

    fn receive_data(inout self, data: List[UInt8]) raises:
        """
        Process incoming raw data.

        Args:
            data: Raw bytes from socket.

        Raises:
            Error: On protocol violation.
        """
        # Add to buffer
        for i in range(len(data)):
            self.receive_buffer.append(data[i])

        # Process complete frames
        while self._try_parse_frame():
            pass

    fn _try_parse_frame(inout self) raises -> Bool:
        """
        Try to parse a frame from the buffer.

        Returns:
            True if a frame was parsed.
        """
        if len(self.receive_buffer) < 2:
            return False

        # Check if we have enough data
        var frame_size: Int
        try:
            frame_size = WebSocketFrame.frame_size(self.receive_buffer)
        except e:
            return False  # Need more data

        if len(self.receive_buffer) < frame_size:
            return False

        # Extract frame bytes
        var frame_data = List[UInt8]()
        for i in range(frame_size):
            frame_data.append(self.receive_buffer[i])

        # Remove from buffer
        var remaining = List[UInt8]()
        for i in range(frame_size, len(self.receive_buffer)):
            remaining.append(self.receive_buffer[i])
        self.receive_buffer = remaining

        # Parse frame
        var frame = WebSocketFrame.parse(frame_data)

        # Validate
        validate_frame(frame)

        # Process frame
        self._handle_frame(frame)

        return True

    fn _handle_frame(inout self, frame: WebSocketFrame) raises:
        """Handle a parsed frame."""
        if frame.is_control():
            self._handle_control_frame(frame)
        else:
            self._handle_data_frame(frame)

    fn _handle_control_frame(inout self, frame: WebSocketFrame) raises:
        """Handle control frames (close, ping, pong)."""
        if frame.is_close():
            self.close_code = frame.close_code()
            self.close_reason = frame.close_reason()

            if self.state == STATE_OPEN:
                # Server received close, should send close response
                self.state = STATE_CLOSING
            elif self.state == STATE_CLOSING:
                # We sent close, now received response
                self.state = STATE_CLOSED

        elif frame.is_ping():
            # Store ping payload for pong response
            self.ping_payload = List[UInt8]()
            for i in range(len(frame.payload)):
                self.ping_payload.append(frame.payload[i])
            self.needs_pong = True

        elif frame.is_pong():
            # Pong received - could validate payload matches our ping
            pass

    fn _handle_data_frame(inout self, frame: WebSocketFrame) raises:
        """Handle data frames (text, binary, continuation)."""
        if frame.is_continuation():
            # Continue current message
            if not self.current_message.is_complete:
                # Add to current message
                for i in range(len(frame.payload)):
                    self.current_message.payload.append(frame.payload[i])

                # Check size limit
                if len(self.current_message.payload) > self.max_message_size:
                    raise Error("Message too large: " + str(len(self.current_message.payload)))

                if frame.is_final():
                    self.current_message.is_complete = True
                    self.message_queue.append(self.current_message)
                    self.current_message = WebSocketMessage()
            else:
                raise Error("Unexpected continuation frame")
        else:
            # New message
            if not self.current_message.is_complete and len(self.current_message.payload) > 0:
                raise Error("New message before previous completed")

            self.current_message = WebSocketMessage(frame.opcode)
            for i in range(len(frame.payload)):
                self.current_message.payload.append(frame.payload[i])

            # Check size limit
            if len(self.current_message.payload) > self.max_message_size:
                raise Error("Message too large")

            if frame.is_final():
                self.current_message.is_complete = True
                self.message_queue.append(self.current_message)
                self.current_message = WebSocketMessage()

    # =========================================================================
    # Message Queue
    # =========================================================================

    fn has_message(self) -> Bool:
        """Check if there are complete messages in queue."""
        return len(self.message_queue) > 0

    fn next_message(inout self) -> WebSocketMessage:
        """
        Get next message from queue.

        Returns:
            Next complete message.

        Note:
            Check has_message() first.
        """
        if len(self.message_queue) == 0:
            return WebSocketMessage()

        var msg = self.message_queue[0]

        # Remove from queue
        var new_queue = List[WebSocketMessage]()
        for i in range(1, len(self.message_queue)):
            new_queue.append(self.message_queue[i])
        self.message_queue = new_queue

        return msg

    fn message_count(self) -> Int:
        """Get number of messages in queue."""
        return len(self.message_queue)

    # =========================================================================
    # Sending (Frame Creation)
    # =========================================================================

    fn create_text_frame(self, message: String) -> WebSocketFrame:
        """Create a text message frame."""
        return WebSocketFrame.text(message)

    fn create_binary_frame(self, data: List[UInt8]) -> WebSocketFrame:
        """Create a binary message frame."""
        return WebSocketFrame.binary(data)

    fn create_ping_frame(self, data: List[UInt8] = List[UInt8]()) -> WebSocketFrame:
        """Create a ping frame."""
        return WebSocketFrame.ping(data)

    fn create_pong_frame(self, data: List[UInt8] = List[UInt8]()) -> WebSocketFrame:
        """Create a pong frame."""
        return WebSocketFrame.pong(data)

    fn create_close_frame(
        self,
        code: UInt16 = CLOSE_NORMAL,
        reason: String = "",
    ) -> WebSocketFrame:
        """Create a close frame."""
        return WebSocketFrame.close(code, reason)

    fn get_pending_pong(inout self) -> WebSocketFrame:
        """
        Get pong frame if ping was received.

        Returns:
            Pong frame, or empty frame if no ping pending.

        Note:
            Caller should check needs_pong first.
        """
        if self.needs_pong:
            self.needs_pong = False
            return WebSocketFrame.pong(self.ping_payload)
        return WebSocketFrame()

    # =========================================================================
    # Fragmentation Support
    # =========================================================================

    fn create_fragmented_message(
        self,
        message: String,
        fragment_size: Int,
    ) -> List[WebSocketFrame]:
        """
        Create fragmented text message.

        Args:
            message: Full message text.
            fragment_size: Max bytes per fragment.

        Returns:
            List of frames to send in order.
        """
        var frames = List[WebSocketFrame]()
        var data = _string_to_bytes(message)
        var total = len(data)

        if total <= fragment_size:
            # No fragmentation needed
            frames.append(WebSocketFrame.text(message))
            return frames

        var pos = 0
        var first = True

        while pos < total:
            var end = pos + fragment_size
            if end > total:
                end = total

            var chunk = List[UInt8]()
            for i in range(pos, end):
                chunk.append(data[i])

            var is_final = (end >= total)

            if first:
                frames.append(WebSocketFrame(OPCODE_TEXT, chunk, is_final))
                first = False
            else:
                frames.append(WebSocketFrame.continuation(chunk, is_final))

            pos = end

        return frames

    fn create_fragmented_binary(
        self,
        data: List[UInt8],
        fragment_size: Int,
    ) -> List[WebSocketFrame]:
        """
        Create fragmented binary message.

        Args:
            data: Full binary data.
            fragment_size: Max bytes per fragment.

        Returns:
            List of frames to send in order.
        """
        var frames = List[WebSocketFrame]()
        var total = len(data)

        if total <= fragment_size:
            frames.append(WebSocketFrame.binary(data))
            return frames

        var pos = 0
        var first = True

        while pos < total:
            var end = pos + fragment_size
            if end > total:
                end = total

            var chunk = List[UInt8]()
            for i in range(pos, end):
                chunk.append(data[i])

            var is_final = (end >= total)

            if first:
                frames.append(WebSocketFrame(OPCODE_BINARY, chunk, is_final))
                first = False
            else:
                frames.append(WebSocketFrame.continuation(chunk, is_final))

            pos = end

        return frames

    # =========================================================================
    # Close Handling
    # =========================================================================

    fn initiate_close(inout self, code: UInt16 = CLOSE_NORMAL, reason: String = ""):
        """
        Start closing handshake.

        Args:
            code: Close status code.
            reason: Close reason.
        """
        self.close_code = code
        self.close_reason = reason
        self.state = STATE_CLOSING

    fn complete_close(inout self):
        """Mark connection as fully closed."""
        self.state = STATE_CLOSED


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


# =============================================================================
# Message Builder (for convenience)
# =============================================================================

struct MessageBuilder:
    """
    Helper for building WebSocket messages.

    Example:
        var builder = MessageBuilder()
        builder.append("Hello, ")
        builder.append("World!")
        var frame = builder.finish_text()
    """
    var buffer: List[UInt8]

    fn __init__(out self):
        """Create empty builder."""
        self.buffer = List[UInt8]()

    fn append(inout self, text: String):
        """Append text to message."""
        for i in range(len(text)):
            self.buffer.append(UInt8(ord(text[i])))

    fn append_bytes(inout self, data: List[UInt8]):
        """Append bytes to message."""
        for i in range(len(data)):
            self.buffer.append(data[i])

    fn clear(inout self):
        """Clear buffer."""
        self.buffer = List[UInt8]()

    fn length(self) -> Int:
        """Get current buffer length."""
        return len(self.buffer)

    fn finish_text(inout self) -> WebSocketFrame:
        """Finish as text frame and reset."""
        var frame = WebSocketFrame(OPCODE_TEXT, self.buffer, True)
        self.buffer = List[UInt8]()
        return frame

    fn finish_binary(inout self) -> WebSocketFrame:
        """Finish as binary frame and reset."""
        var frame = WebSocketFrame(OPCODE_BINARY, self.buffer, True)
        self.buffer = List[UInt8]()
        return frame
