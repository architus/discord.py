# -*- coding: utf-8 -*-

"""
The MIT License (MIT)

Copyright (c) 2015-2019 Rapptz

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

import struct
import logging

from math import ceil
from collections import namedtuple

log = logging.getLogger(__name__)

__all__ = ['RTPPacket']


def decode(data):
    """Creates an :class:`RTPPacket` or an :class:`RTCPPacket`.

    Parameters
    -----------
    data : bytes
        The raw packet data.
    """

    # While technically unreliable, discord RTP packets (should)
    # always be distinguishable from RTCP packets.  RTCP packets
    # should always have 200-204 as their second byte, while RTP
    # packet are (probably) always 73 (or at least not 200-204).

    assert data[0] >> 6 == 2  # check version bits
    return RTPPacket(data)

def is_rtcp(data):
    return 200 <= data[1] <= 204

def _parse_low(x):
    return x / 2.0 ** x.bit_length()


class _PacketCmpMixin:
    __slots__ = ()

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def __gt__(self, other):
        return self.timestamp > other.timestamp

    def __eq__(self, other):
        return self.timestamp == other.timestamp

class SilencePacket(_PacketCmpMixin):
    __slots__ = ('ssrc', 'timestamp')
    decrypted_data = b'\xF8\xFF\xFE'

    def __init__(self, ssrc, timestamp):
        self.ssrc = ssrc
        self.timestamp = timestamp

    def __repr__(self):
        return '<SilencePacket timestamp={0.timestamp}, ssrc={0.ssrc}>'.format(self)

class FECPacket(_PacketCmpMixin):
    __slots__ = ('ssrc', 'timestamp', 'sequence')
    decrypted_data = b''

    def __init__(self, ssrc, timestamp, sequence):
        self.ssrc = ssrc
        self.timestamp = sequence
        self.sequence = timestamp

    def __repr__(self):
        return '<FECPacket timestamp={0.timestamp}, sequence={0.sequence}, ssrc={0.ssrc}>'.format(self)

# Consider adding silence attribute to differentiate (to skip isinstance)

class RTPPacket(_PacketCmpMixin):
    __slots__ = ('version', 'padding', 'extended', 'cc', 'marker',
                 'payload', 'sequence', 'timestamp', 'ssrc', 'csrcs',
                 'header', 'data', 'decrypted_data', 'extension')

    _hstruct = struct.Struct('>xxHII')
    _ext_header = namedtuple("Extension", 'profile length values')

    def __init__(self, data):
        data = bytearray(data)

        self.version = data[0] >> 6
        self.padding = bool(data[0] & 0b00100000)
        self.extended = bool(data[0] & 0b00010000)
        self.cc = data[0] & 0b00001111

        self.marker = bool(data[1] & 0b10000000)
        self.payload = data[1] & 0b01111111

        self.sequence, self.timestamp, self.ssrc = self._hstruct.unpack_from(data)

        self.csrcs = ()
        self.extension = None

        self.header = data[:12]
        self.data = data[12:]
        self.decrypted_data = None

        if self.cc:
            fmt = '>%sI' % self.cc
            offset = struct.calcsize(fmt) + 12
            self.csrcs = struct.unpack(fmt, data[12:offset])
            self.data = data[offset:]

        # TODO?: impl padding calculations (though discord doesn't seem to use that bit)

    def update_ext_headers(self, data):
        """Adds extended header data to this packet, returns payload offset"""

        profile, length = struct.unpack_from('>HH', data)
        values = struct.unpack('>%sI' % length, data[4:4+length*4])
        self.extension = self._ext_header(profile, length, values)

        # TODO?: Update self.data with new data offset
        # ... (do I need to do this? because it seems to work fine without it)

        return 4 + length * 4

    def _dump_info(self):
        attrs = {name: getattr(self, name) for name in self.__slots__}
        return ''.join((
            "<RTPPacket ",
            *['{}={}, '.format(n, v) for n, v in attrs.items()],
            '>'))

    def __repr__(self):
        return '<RTPPacket ext={0.extended}, ' \
               'timestamp={0.timestamp}, sequence={0.sequence}, ' \
               'ssrc={0.ssrc}, size={1}' \
               '>'.format(self, len(self.data))
