"""SLCAN emulation over a binary CAN<->Ethernet converter (Waveshare 2-CH-CAN-TO-ETH,
USR-CANET200 and compatible devices).

The rest of the library talks SLCAN (Lawicel ASCII) to a pyserial object.
This module provides a minimal pyserial-compatible object that:

* accepts SLCAN commands on write() and turns t/T/r/R frames into the
  converter's 13-byte binary TCP frames,
* answers adapter configuration commands (C, O, S<n>, V, v, ...) locally,
  because bitrate/mode are configured in the converter itself,
* receives 13-byte binary frames on a background thread and exposes them on
  read()/in_waiting as SLCAN text lines ("T01FD7FE08....\\r").

Binary frame layout (13 bytes, big-endian ID):
    byte 0     : bit7 = extended (29-bit) ID, bit6 = RTR, bits3..0 = DLC
    bytes 1-4  : CAN ID
    bytes 5-12 : data, zero padded to 8 bytes

Design notes
------------
* read()/in_waiting never cross an SLCAN line boundary. USBtinAdapter._read_frame()
  keeps its parse buffer in a local variable, so any bytes after the first '\\r'
  in a chunk would be silently dropped. TCP delivers many frames per segment,
  so serving one line at a time is required for correctness, not a nicety.
* The RX queue is bounded: between coordinator polls the heat pump keeps
  broadcasting, and nobody reads. Oldest lines are dropped first; the adapter
  flushes the input buffer before every request anyway.
* Any socket failure is latched and re-raised as serial.SerialException, so
  the existing error handling (DeviceDisconnectedError -> coordinator
  reconnect with backoff) applies unchanged.

URLs:
    caneth://<host>:<port>  binary converter, e.g. caneth://192.168.1.60:20001
    slcan://<host>:<port>   SLCAN text passed through unchanged (USBtin/CANable
                            behind ser2net). Config commands (C, S4, O, ...)
                            go to the real adapter in this mode.
"""

from __future__ import annotations

import collections
import logging
import socket
import struct
import threading
import time
from typing import Deque, Optional
from urllib.parse import urlsplit

import serial

_LOGGER = logging.getLogger(__name__)

FRAME_LEN = 13
_FLAG_EXT = 0x80
_FLAG_RTR = 0x40
_DLC_MASK = 0x0F
_RESERVED_MASK = 0x30  # bits 5..4 must be zero; used as a cheap desync check

RX_QUEUE_MAX_LINES = 4096
CONNECT_TIMEOUT = 5.0


def binary_to_slcan(frame: bytes) -> bytes:
    """Convert one 13-byte converter frame to an SLCAN line (with '\\r')."""
    info = frame[0]
    if info & _RESERVED_MASK or (info & _DLC_MASK) > 8:
        raise ValueError(f"Invalid frame info byte 0x{info:02X} (stream desync?)")
    extended = bool(info & _FLAG_EXT)
    rtr = bool(info & _FLAG_RTR)
    dlc = info & _DLC_MASK
    can_id = int.from_bytes(frame[1:5], "big")
    if extended:
        head = f"{'R' if rtr else 'T'}{can_id & 0x1FFFFFFF:08X}{dlc:X}"
    else:
        head = f"{'r' if rtr else 't'}{can_id & 0x7FF:03X}{dlc:X}"
    payload = "" if rtr else frame[5 : 5 + dlc].hex().upper()
    return (head + payload + "\r").encode("ascii")


def slcan_to_binary(cmd: str) -> bytes:
    """Convert one SLCAN transmit command (t/T/r/R, no '\\r') to 13 bytes."""
    kind = cmd[0]
    extended = kind in ("T", "R")
    rtr = kind in ("r", "R")
    id_len = 8 if extended else 3
    can_id = int(cmd[1 : 1 + id_len], 16)
    dlc = int(cmd[1 + id_len], 16)
    if dlc > 8:
        raise ValueError(f"DLC {dlc} > 8 in {cmd!r}")
    data = b"" if rtr else bytes.fromhex(cmd[2 + id_len : 2 + id_len + 2 * dlc])
    if not rtr and len(data) != dlc:
        raise ValueError(f"Data length mismatch in {cmd!r}")
    info = (_FLAG_EXT if extended else 0) | (_FLAG_RTR if rtr else 0) | dlc
    return bytes([info]) + can_id.to_bytes(4, "big") + data.ljust(8, b"\x00")


class CanEthSerial:
    """Duck-typed subset of serial.Serial used by USBtinAdapter."""

    def __init__(
        self,
        url: str,
        timeout: Optional[float] = 1.0,
        write_timeout: Optional[float] = 1.0,
        **_ignored,
    ) -> None:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("caneth", "slcan") or not parts.hostname or not parts.port:
            raise serial.SerialException(
                f"Invalid URL {url!r}, expected caneth://host:port or slcan://host:port"
            )
        self._passthrough = scheme == "slcan"
        self.port = url
        self.timeout = timeout
        self.write_timeout = write_timeout
        self._addr = (parts.hostname, parts.port)
        self._sock: Optional[socket.socket] = None
        self._rx: Deque[bytes] = collections.deque(maxlen=RX_QUEUE_MAX_LINES)
        self._cur = b""  # line currently being handed out by read()
        self._cv = threading.Condition()
        self._error: Optional[BaseException] = None
        self._reader: Optional[threading.Thread] = None
        self._tx_lock = threading.Lock()
        self._dropped_warned = False
        self.open()

    # ------------------------------------------------------------ lifecycle
    @property
    def is_open(self) -> bool:
        return self._sock is not None and self._error is None

    def open(self) -> None:
        try:
            sock = socket.create_connection(self._addr, timeout=CONNECT_TIMEOUT)
        except OSError as exc:
            raise serial.SerialException(f"Cannot connect to {self._addr}: {exc}")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Detect a dead converter / pulled cable within ~30 s (Linux only).
        for opt, val in (("TCP_KEEPIDLE", 10), ("TCP_KEEPINTVL", 5), ("TCP_KEEPCNT", 4)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
        sock.settimeout(None)  # blocking recv in the reader thread
        if self.write_timeout:
            # Send-only timeout; never touch settimeout() later, it would also
            # affect the concurrent blocking recv() in the reader thread.
            secs = int(self.write_timeout)
            usecs = int((self.write_timeout - secs) * 1_000_000)
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", secs, usecs)
            )
        self._sock = sock
        self._error = None
        self._reader = threading.Thread(
            target=self._rx_loop, name=f"caneth-rx-{self._addr[0]}", daemon=True
        )
        self._reader.start()
        _LOGGER.debug("Connected to CAN-ETH converter at %s:%s", *self._addr)

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        with self._cv:
            self._cv.notify_all()
        if self._reader and self._reader is not threading.current_thread():
            self._reader.join(timeout=2.0)
        self._reader = None

    # ------------------------------------------------------------ RX side
    def _rx_loop(self) -> None:
        buf = bytearray()
        sock = self._sock
        try:
            while sock is not None and self._sock is sock:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Converter closed the TCP connection")
                buf += chunk
                for line in self._split(buf):
                    with self._cv:
                        if len(self._rx) == self._rx.maxlen and not self._dropped_warned:
                            _LOGGER.debug("RX queue full, dropping oldest frames")
                            self._dropped_warned = True
                        self._rx.append(line)
                        self._cv.notify_all()
        except Exception as exc:  # noqa: BLE001 - latched and re-raised to caller
            if self._sock is sock:  # not a deliberate close()
                _LOGGER.warning("CAN-ETH link error: %s", exc)
                with self._cv:
                    self._error = exc
                    self._cv.notify_all()

    def _split(self, buf: bytearray):
        """Yield complete SLCAN lines from buf, consuming them."""
        if self._passthrough:
            while True:
                ends = [i for i in (buf.find(b"\r"), buf.find(b"\a")) if i >= 0]
                if not ends:
                    if len(buf) > 256:  # garbage without terminator
                        raise ValueError("SLCAN stream without line terminator")
                    return
                end = min(ends) + 1
                line = bytes(buf[:end])
                del buf[:end]
                yield line
        else:
            while len(buf) >= FRAME_LEN:
                line = binary_to_slcan(bytes(buf[:FRAME_LEN]))
                del buf[:FRAME_LEN]
                yield line

    def _raise_if_failed(self) -> None:
        if self._error is not None:
            raise serial.SerialException(f"CAN-ETH link lost: {self._error}")
        if self._sock is None:
            raise serial.SerialException("CAN-ETH port not open")

    @property
    def in_waiting(self) -> int:
        self._raise_if_failed()
        with self._cv:
            if self._cur:
                return len(self._cur)
            return len(self._rx[0]) if self._rx else 0

    def read(self, size: int = 1) -> bytes:
        """Return up to `size` bytes, never crossing an SLCAN line boundary."""
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        with self._cv:
            while not self._cur:
                self._raise_if_failed()
                if self._rx:
                    self._cur = self._rx.popleft()
                    break
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return b""
                self._cv.wait(remaining)
            out, self._cur = self._cur[:size], self._cur[size:]
            return out

    def reset_input_buffer(self) -> None:
        with self._cv:
            self._rx.clear()
            self._cur = b""
            self._dropped_warned = False

    def reset_output_buffer(self) -> None:  # pragma: no cover - API parity
        pass

    def flush(self) -> None:  # pragma: no cover - API parity
        pass

    # ------------------------------------------------------------ TX side
    def write(self, data: bytes) -> int:
        self._raise_if_failed()
        if self._passthrough:
            self._send(bytes(data))
            return len(data)
        text = data.decode("ascii", errors="strict")
        for cmd in filter(None, (c.strip() for c in text.split("\r"))):
            if cmd[0] in "tTrR":
                try:
                    frame = slcan_to_binary(cmd)
                except (ValueError, IndexError) as exc:
                    raise serial.SerialException(f"Bad SLCAN frame {cmd!r}: {exc}")
                self._send(frame)
            else:
                # Adapter configuration (C, O, S4, V, v, F, ...): the converter is
                # configured via its own web UI, so just acknowledge like USBtin.
                reply = b"V0100\r" if cmd == "V" else b"v0100\r" if cmd == "v" else b"\r"
                with self._cv:
                    self._rx.append(reply)
                    self._cv.notify_all()
        return len(data)

    def _send(self, frame: bytes) -> None:
        sock = self._sock
        if sock is None:
            raise serial.SerialException("CAN-ETH port not open")
        with self._tx_lock:
            try:
                sock.sendall(frame)
            except BlockingIOError:  # SO_SNDTIMEO expired
                raise serial.SerialTimeoutException("CAN-ETH write timeout")
            except OSError as exc:
                self._error = exc
                raise serial.SerialException(f"CAN-ETH write failed: {exc}")
