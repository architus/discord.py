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
import wave
import select
import socket
import audioop
import logging
import threading
import traceback
from io import BytesIO
from struct import pack

from . import rtp
from .utils import Defaultdict
from .rtp import SilencePacket
from .opus import Decoder, BufferedDecoder
from .errors import DiscordException

try:
    import nacl.secret
    from nacl.exceptions import CryptoError
except ImportError:
    pass

log = logging.getLogger(__name__)

__all__ = [
    'AudioSink',
    'WaveSink',
    'PCMVolumeTransformerFilter',
    'ConditionalFilter',
    'TimedFilter',
    'UserFilter',
    'SinkExit',
    'WavFile'
]

class SinkExit(DiscordException):
    """A signal type exception (like ``GeneratorExit``) to raise in a Sink's write() method to stop it.

    TODO: make better words

    Parameters
    -----------
    drain: :class:`bool`
        ...
    flush: :class:`bool`
        ...
    """

    def __init__(self, *, drain=True, flush=False):
        self.kwargs = kwargs


class AudioSink:
    def __del__(self):
        self.cleanup()

    def write(self, data):
        raise NotImplementedError

    def wants_opus(self):
        return False

    def cleanup(self):
        pass

    def pack_data(self, data, user=None, packet=None):
        return VoiceData(data, user, packet) # is this even necessary?


class WaveSink(AudioSink):
    def __init__(self, destination):
        self._file = wave.open(destination, 'wb')
        self._file.setnchannels(Decoder.CHANNELS)
        self._file.setsampwidth(Decoder.SAMPLE_SIZE//Decoder.CHANNELS)
        self._file.setframerate(Decoder.SAMPLING_RATE)

    def write(self, data):
        self._file.writeframes(data.data)

    def cleanup(self):
        try:
            self._file.close()
        except:
            pass


class WavFile(AudioSink):
    """
    Custom wave file sink to write recorded voice to.

    The discord bot sends 3840 bytes of 16bit PCM data in each packet as soon as possible.
    This class then does its darndest to transform that live real time data into something
    more synchronized.

    The specific WAV file that this rights will have a couple of hard coded values.
    ChunkID: RIFF
    Format: WAVE
    SubChunk1ID: fmt (note: the space needs to be included in the header)
    AudioFormat: 1 (this specifies uncompressed PCM data)
    SampleRate: 48000 (this is the sample rate that discord uses (I think))
    BitsPerSample: 16 (this is definitely the number of bits per sample in the data
                       that discord sends to architus)
    SubChunk2ID: data
    """

    def __init__(self, f, user_list, event, bot_user, excludes):
        """
        :param: f Where to write the wave file to. This should just be a BytesIO object.
        :param: user_list List of users in the voice channel to include in recording
        """
        self.bot_user = bot_user
        self.event = event
        self.f = f
        self.user_list = user_list
        self.buffer = BytesIO()
        self.data_size = 0
        self.num_channels = len(user_list)
        self.channels = [list() for _ in range(self.num_channels)]
        self.packet_count = 0
        self.excludes = excludes

        # this is equivalent to one packet of silence
        self.silence = b"\x00" * 3840

    def write(self, data):
        """
        This method will just properly store the data internally in the class
        so that it can be properly written out later with all of the proper
        header data.
        """

        # Check to see which channel the data should be written to.
        # Each user will get their own channel
        if data.user == self.bot_user:
            # I don't think the bot actually ever sends voice data,
            # but just to make sure.
            return
        if data.user in self.excludes:
            return
        channel = -1
        for i, u in enumerate(self.user_list):
            if u == data.user:
                channel = i
                break
        if channel == -1:
            # If user was not found, then add them and increase number of channels
            self.user_list.append(data.user)
            self.num_channels += 1
            self.channels.append([])

            # To keep audio roughly synced, add silence up until the current time.
            # The current time is taken as the channel with the most amount of
            # audio currently in it.
            longest = max([len(c) for c in self.channels])
            for _ in range(longest):
                self.channels[-1].append(self.silence)

        # The data comes in as two channel audio. Both channels have the same data
        # and we only need one channel so just take every other 16 bit chunk to
        # compress it down to a single channel.
        d = b"".join([data.data[i:i + 2] for i in range(0, len(data.data), 4)])
        self.channels[channel].append(d)
        self.packet_count += 1

        # roughly once a second, see if any of the channels is falling far behind the
        # others. If they are, this means that person has exited the channel and their
        # audio needs to be caught up with the rest of the channels.
        if self.packet_count > 10:
            self.packet_count = 0
            longest = max([len(c) for c in self.channels])
            for i in range(self.num_channels):
                if longest - len(self.channels[i]) > 5:
                    for _ in range(longest - len(self.channels[i])):
                        self.channels[i].append(self.silence)

    def cleanup(self):
        """
        Writing to WAV files is really weird. Sometimes the bytes need to be
        big endian and sometimes they need to be little endian. This weirdness is
        all in the header so it can be mostly just hard coded but needs to be paid
        special attention to.

        Most of my knowledge of how WAV files work comes from:
        http://soundfile.sapp.org/doc/WaveFormat/

        We just need to make sure that all of the header values match the specifics
        of the WAV file that we will be writing. The main thing we have to do on the
        fly is the number of channels, chunk sizes, block align, and byte rate.
        The actual data can mostly just be left alone apart from putting it in the
        right place.
        """

        wav_data = []
        size = max([len(c) for c in self.channels])
        for c in self.channels:
            if len(c) < size:
                c.append(b"\x00" * (size - len(c)))
            wav_data.append(b"".join(c))

        self.channels = None

        # Header values that can't be hardcoded
        data_chunk_size = self.num_channels * len(wav_data[0])
        chunk_size = pack("<L", 36 + data_chunk_size)
        data_chunk_size = pack("<L", data_chunk_size)
        byte_rate = pack("<L", 48000 * self.num_channels * 2)
        block_align = pack("<H", self.num_channels * 2)
        n_chan = pack("<H", self.num_channels)

        # RIFF chunk descriptor
        self.f.write(b"\x52\x49\x46\x46")              # "RIFF", specifies RIFF file type
        self.f.write(chunk_size)                       # Size of the file minus this and "RIFF"
        self.f.write(b"\x57\x41\x56\x45")              # "WAVE", specifies wave subtype

        # fmt sub chunk
        self.f.write(b"\x66\x6d\x74\x20")              # "fmt ", starts format section
        self.f.write(b"\x10\x00\x00\x00")              # 16, size of this part of header
        self.f.write(b"\x01\x00")                      # 1, PCM mode
        self.f.write(n_chan)                           # number of channels
        self.f.write(b"\x80\xBB\x00\x00")              # 48000, sample rate of file
        self.f.write(byte_rate)                        # byte rate
        self.f.write(block_align)                      # number of bytes in an entire sample of all channels
        self.f.write(b"\x10\x00")                      # Bits in a sample of one channel

        # data chunk
        self.f.write(b"\x64\x61\x74\x61")              # "data", in data header now
        self.f.write(data_chunk_size)                  # size of the data chunk

        # write the actual PCM data
        for j in range(0, len(wav_data[0]), 2):
            for i in range(self.num_channels):
                self.f.write(wav_data[i][j:j + 2])     # make sure to write two bytes as sample size is 16 bits

        self.event.set()


class PCMVolumeTransformerFilter(AudioSink):
    def __init__(self, destination, volume=1.0):
        if not isinstance(destination, AudioSink):
            raise TypeError('expected AudioSink not {0.__class__.__name__}.'.format(destination))

        if destination.wants_opus():
            raise ClientException('AudioSink must not request Opus encoding.')

        self.destination = destination
        self.volume = volume

    @property
    def volume(self):
        """Retrieves or sets the volume as a floating point percentage (e.g. 1.0 for 100%)."""
        return self._volume

    @volume.setter
    def volume(self, value):
        self._volume = max(value, 0.0)

    def write(self, data):
        data = audioop.mul(data.data, 2, min(self._volume, 2.0))
        self.destination.write(data)

# I need some sort of filter sink with a predicate or something
# Which means I need to sort out the write() signature issue
# Also need something to indicate a sink is "done", probably
# something like raising an exception and handling that in the write loop
# Maybe should rename some of these to Filter instead of Sink

class ConditionalFilter(AudioSink):
    def __init__(self, destination, predicate):
        self.destination = destination
        self.predicate = predicate

    def write(self, data):
        if self.predicate(data):
            self.destination.write(data)

class TimedFilter(ConditionalFilter):
    def __init__(self, destination, duration, *, start_on_init=False):
        super().__init__(destination, self._predicate)
        self.duration = duration
        if start_on_init:
            self.start_time = self.get_time()
        else:
            self.start_time = None
            self.write = self._write_once

    def _write_once(self, data):
        self.start_time = self.get_time()
        super().write(data)
        self.write = super().write

    def _predicate(self, data):
        return self.start_time and self.get_time() - self.start_time < self.duration

    def get_time(self):
        return time.time()

class UserFilter(ConditionalFilter):
    def __init__(self, destination, user):
        super().__init__(destination, self._predicate)
        self.user = user

    def _predicate(self, data):
        return data.user == self.user

# rename 'data' to 'payload'? or 'opus'? something else?
class VoiceData:
    __slots__ = ('data', 'user', 'packet')

    def __init__(self, data, user, packet):
        self.data = data
        self.user = user
        self.packet = packet

class AudioReader(threading.Thread):
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

        self.decoder = BufferedDecoder(self)
        self.decoder.start()

        # TODO: inject sink functions

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

    def _reset_decoders(self, *ssrcs):
        self.decoder.reset(*ssrcs)

    def _stop_decoders(self, **kwargs):
        self.decoder.stop(**kwargs)

    def _ssrc_removed(self, ssrc):
        # An user has disconnected but there still may be
        # packets from them left in the buffer to read
        # For now we're just going to kill the decoder and see how that works out
        # I *think* this is the correct way to do this
        # Depending on how many leftovers I end up with I may reconsider

        self.decoder.drop_ssrc(ssrc) # flush=True?

    def _get_user(self, packet):
        _, user_id = self.client._get_ssrc_mapping(ssrc=packet.ssrc)
        # may need to change this for calls or something
        return self.client.guild.get_member(user_id)

    def _write_to_sink(self, pcm, opus, packet):
        try:
            data = opus if self.sink.wants_opus() else pcm
            user = self._get_user(packet)
            self.sink.write(VoiceData(data, user, packet))
            # TODO: remove weird error handling in favor of injected functions
        except SinkExit as e:
            log.info("Shutting down reader thread %s", self)
            self.stop()
            self._stop_decoders(**e.kwargs)
        except:
            traceback.print_exc()
            # insert optional error handling here

    def _set_sink(self, sink):
        with self._decoder_lock:
            self.sink = sink
        # if i were to fire a sink change mini-event it would be here

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

                if e.errno == 10038: # ENOTSOCK
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
                else:
                    packet = rtp.decode(self.decrypt_rtcp(raw_data))
                    if not isinstance(packet, rtp.ReceiverReportPacket):
                        print(packet)

                        # TODO: Fabricate and send SenderReports and see what happens

                    self.decoder.feed_rtcp(packet)
                    continue

            except CryptoError:
                log.exception("CryptoError decoding packet %s", packet)
                continue

            except:
                log.exception("Error unpacking packet")
                traceback.print_exc()

            else:
                if packet.ssrc not in self.client._ssrcs:
                    log.debug("Received packet for unknown ssrc %s", packet.ssrc)

                self.decoder.feed_rtp(packet)

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
            self._stop_decoders()
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
