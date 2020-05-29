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

import time
import select
import socket
import logging
import threading
import traceback
import struct

from . import rtp
from .errors import DiscordException

try:
    import nacl.secret
    from nacl.exceptions import CryptoError
except ImportError:
    pass

log = logging.getLogger(__name__)

__all__ = [
    'AudioSink',
    'SinkExit',
    'TCPSink'
]


class SinkExit(DiscordException):
    """A signal type exception (like ``GeneratorExit``) to raise in a Sink's
    write() method to stop it.

    TODO: make better words

    Parameters
    -----------
    drain: :class:`bool`
        ...
    flush: :class:`bool`
        ...
    """

    def __init__(self, *, drain=True, flush=False):
        super().__init__()


class AudioSink:
    """
    Sink for reader to write stuff to.
    """

    def __del__(self):
        self.cleanup()

    def write(self, packet):
        """
        Writes RTP Opus packet to sink
        """
        raise NotImplementedError

    def wants_opus(self):
        """
        Returns whether or not the sink takes Opus data.
        If this returns false, PCM data will be passed instead.
        """
        return False

    def cleanup(self):
        """
        Does any post processing cleanup necessary for the sink.
        """

    def add_ssrc(self, ssrc, uid):
        """
        Adds an SSRC <-> uid relationship from the sink.
        """

    def remove_ssrc(self, ssrc):
        """
        Removes an SSRC <-> uid relationship from the sink.
        """


class TCPSink(AudioSink):
    """
    Writes data to a TCP socket. To be used with the custom
    client written for Architus. Feel free to use this with
    your own client if it implements the same api.
    """

    def __init__(self, s):
        self.connection = s

    def write(self, packet):
        """
        __slots__ = ('version', 'padding', 'extended', 'cc', 'marker',
                     'payload', 'sequence', 'timestamp', 'ssrc', 'csrcs',
                     'header', 'data', 'decrypted_data', 'extension')
        """
        data = bytearray(12)
        struct.pack_into(">BBBHII", data, 0, 0x00, 0x80, 0x78, packet.sequence,
                         packet.timestamp, packet.ssrc)
        for byte in packet.decrypted_data:
            data.append(byte)
        self.connection.send(data)

    def add_ssrc(self, ssrc, uid):
        data = bytearray(13)
        struct.pack_into(">BHIQ", data, 0, 0x01, ssrc, uid)
        self.connection.send(data)

    def remove_ssrc(self, ssrc):
        data = bytearray(5)
        struct.pack_into(">BI", data, 0, ssrc)
        self.connection.send(data)

    def cleanup(self):
        self.connection.send(b"\x04")


# rename 'data' to 'payload'? or 'opus'? something else?
class VoiceData:
    """
    Represents a single packet of opus/pcm data.
    """
    __slots__ = ('data', 'user', 'packet')

    def __init__(self, data, user, packet):
        self.data = data
        self.user = user
        self.packet = packet


class AudioReader(threading.Thread):
    """
    Handles reading packets sent from Discord.
    """
    def __init__(self, sink, client, *, after=None):
        super().__init__(daemon=True)
        self.sink = sink
        self.client = client
        self.after = after

        if after is not None and not callable(after):
            raise TypeError('Expected a callable for the "after" parameter.')

        self.after = after

        self.box = nacl.secret.SecretBox(bytes(client.secret_key))
        self.decrypt_rtp = getattr(self, '_decrypt_rtp_' + client._mode)
        self.decrypt_rtcp = getattr(self, '_decrypt_rtcp_' + client._mode)

        self._current_error = None
        self._end = threading.Event()
        self._decoder_lock = threading.Lock()

    @property
    def connected(self):
        return self.client._connected

    def _decrypt_rtp_xsalsa20_poly1305(self, packet):
        nonce = bytearray(24)
        nonce[:12] = packet.header
        result = self.box.decrypt(bytes(packet.data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305(self, data):
        nonce = bytearray(24)
        nonce[:8] = data[:8]
        result = self.box.decrypt(data[8:], bytes(nonce))

        return data[:8] + result

    def _decrypt_rtp_xsalsa20_poly1305_suffix(self, packet):
        nonce = packet.data[-24:]
        voice_data = packet.data[:-24]
        result = self.box.decrypt(bytes(voice_data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305_suffix(self, data):
        nonce = data[-24:]
        header = data[:8]
        result = self.box.decrypt(data[8:-24], nonce)

        return header + result

    def _decrypt_rtp_xsalsa20_poly1305_lite(self, packet):
        nonce = bytearray(24)
        nonce[:4] = packet.data[-4:]
        voice_data = packet.data[:-4]
        result = self.box.decrypt(bytes(voice_data), bytes(nonce))

        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]

        return result

    def _decrypt_rtcp_xsalsa20_poly1305_lite(self, data):
        nonce = bytearray(24)
        nonce[:4] = data[-4:]
        header = data[:8]
        result = self.box.decrypt(data[8:-4], bytes(nonce))

        return header + result

    def _ssrc_added(self, ssrc, uid):
        """
        Send along info to sink.
        """
        if self.sink:
            self.sink.add_ssrc(ssrc, uid)

    def _ssrc_removed(self, ssrc):
        # An user has disconnected but there still may be
        # packets from them left in the buffer to read
        # For now we're just going to kill the decoder and see how that works
        # out. I *think* this is the correct way to do this
        # Depending on how many leftovers I end up with I may reconsider

        if self.sink:
            self.sink.remove_ssrc(ssrc)

    def _get_user(self, packet):
        _, user_id = self.client._get_ssrc_mapping(ssrc=packet.ssrc)
        # may need to change this for calls or something
        return self.client.guild.get_member(user_id)

    def _do_run(self):
        while not self._end.is_set():
            if not self.connected.is_set():
                self.connected.wait()

            ready, _, err = select.select([self.client.socket], [],
                                          [self.client.socket], 0.01)
            if not ready:
                if err:
                    print("Socket error")
                continue

            try:
                raw_data = self.client.socket.recv(4096)
            except socket.error as e:
                t0 = time.time()

                if e.errno == 10038:  # ENOTSOCK
                    continue

                log.exception("Socket error in reader thread ")
                print(f"Socket error in reader thread: {e} {t0}")

                with self.client._connecting:
                    timed_out = self.client._connecting.wait(20)

                if not timed_out:
                    raise
                elif self.client.is_connected():
                    print(f"Reconnected in {time.time()-t0:.4f}s")
                    continue
                else:
                    raise

            try:
                packet = None
                if not rtp.is_rtcp(raw_data):
                    packet = rtp.decode(raw_data)
                    packet.decrypted_data = self.decrypt_rtp(packet)
                    print(f"Packet from {self._get_user(packet)}")
                else:
                    continue

            except CryptoError:
                log.exception("CryptoError decoding packet %s", packet)
                continue

            except:
                log.exception("Error unpacking packet")
                traceback.print_exc()

            else:
                if packet.ssrc not in self.client._ssrcs:
                    log.debug("Received packet for unknown ssrc %s",
                              packet.ssrc)

                self.sink.write(packet)

    def stop(self):
        self._end.set()

    def run(self):
        try:
            self._do_run()
        except socket.error as exc:
            self._current_error = exc
            self.stop()
        except Exception as exc:
            traceback.print_exc()
            self._current_error = exc
            self.stop()
        finally:
            try:
                self.sink.cleanup()
            except:
                log.exception("Error during sink cleanup")
                # Testing only
                traceback.print_exc()

            self._call_after()

    def _call_after(self):
        if self.after is not None:
            try:
                self.after(self._current_error)
            except Exception:
                log.exception('Calling the after function failed.')

    def is_listening(self):
        return not self._end.is_set()
