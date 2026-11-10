"""Minimal XDR (RFC 4506) packer and unpacker.

Replaces the subset of the standard library's xdrlib module (removed in
Python 3.13) that Fireflies uses. The wire format is unchanged.
"""

import struct


class Error(Exception):
    pass


class ConversionError(Error):
    pass


def _pad(n):
    return (4 - n % 4) % 4


class Packer:
    """Pack values into an XDR byte buffer."""

    def __init__(self):
        self.reset()

    def reset(self):
        self._buf = bytearray()

    def get_buffer(self):
        return bytes(self._buf)

    def pack_uint(self, x):
        try:
            self._buf += struct.pack(">I", x)
        except struct.error as e:
            raise ConversionError(e)

    def pack_int(self, x):
        try:
            self._buf += struct.pack(">i", x)
        except struct.error as e:
            raise ConversionError(e)

    def pack_bool(self, x):
        self._buf += b"\x00\x00\x00\x01" if x else b"\x00\x00\x00\x00"

    def pack_fstring(self, n, s):
        if n < 0:
            raise ValueError("fstring size must be nonnegative")
        if isinstance(s, str):
            s = s.encode("utf-8")
        data = bytes(s[:n])
        data += b"\x00" * (n - len(data) + _pad(n))
        self._buf += data

    pack_fopaque = pack_fstring

    def pack_string(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        n = len(s)
        self.pack_uint(n)
        self.pack_fstring(n, s)

    pack_opaque = pack_string
    pack_bytes = pack_string


class Unpacker:
    """Unpack values from an XDR byte buffer."""

    def __init__(self, data):
        self.reset(data)

    def reset(self, data):
        self._buf = bytes(data)
        self._pos = 0

    def get_position(self):
        return self._pos

    def set_position(self, position):
        self._pos = position

    def get_buffer(self):
        return self._buf

    def done(self):
        if self._pos < len(self._buf):
            raise Error("unextracted data remains")

    def _take(self, n):
        i = self._pos
        j = i + n
        if j > len(self._buf):
            raise EOFError
        self._pos = j
        return self._buf[i:j]

    def unpack_uint(self):
        return struct.unpack(">I", self._take(4))[0]

    def unpack_int(self):
        return struct.unpack(">i", self._take(4))[0]

    def unpack_bool(self):
        return bool(self.unpack_int())

    def unpack_fstring(self, n):
        if n < 0:
            raise ValueError("fstring size must be nonnegative")
        data = self._take(n)
        self._take(_pad(n))
        return data

    unpack_fopaque = unpack_fstring

    def unpack_string(self):
        return self.unpack_fstring(self.unpack_uint())

    unpack_opaque = unpack_string
    unpack_bytes = unpack_string
