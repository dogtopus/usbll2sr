#!/usr/bin/env python3

import argparse
import configparser
import contextlib
import io
import shutil
import zipfile

from tqdm import tqdm
from scapy.all import rdpcap


USB_SPEED = {
    'ls': 1500000,
    'fs': 12000000,
    #'hs': 480000000,
}


class SimpleSRWriter:
    def __init__(self, filename, channels, sample_rate, overwrite=True, slice_limit=16777216):
        self._channels = channels
        self._sample_rate = sample_rate
        self._capture_file = 'logic-1'
        self._unit_size = -(-len(channels) // 8)
        self._sr = zipfile.ZipFile(filename, ('w' if overwrite else 'x'), compression=zipfile.ZIP_DEFLATED)
        with self._sr.open('version', 'w') as obj:
            obj.write(b'2')
        metadata = configparser.ConfigParser()
        metadata.add_section('global')
        metadata.add_section('device 1')
        metadata.set('global', 'sigrok version', '0.7.1')
        metadata.set('device 1', 'capturefile', self._capture_file)
        metadata.set('device 1', 'total probes', str(len(channels)))
        metadata.set('device 1', 'samplerate', str(sample_rate))
        metadata.set('device 1', 'total analog', '0')
        for i, ch in enumerate(channels):
            metadata.set('device 1', f'probe{i+1}', ch)
        metadata.set('device 1', 'unitsize', str(self._unit_size))
        with self._sr.open('metadata', 'w') as obj:
            with io.TextIOWrapper(obj) as textio:
                metadata.write(textio)
        self._current_slice = 1
        self._slice_limit = slice_limit
        self._slice_buffer = io.BytesIO()
        self._sample_counter = 0

    def _finalize_current_slice(self):
        with self._sr.open(f'{self._capture_file}-{self._current_slice}', 'w') as obj:
            self._slice_buffer.seek(0)
            shutil.copyfileobj(self._slice_buffer, obj)
        self._slice_buffer = io.BytesIO()
        self._current_slice += 1

    def write_samples(self, samples):
        if len(samples) % self._unit_size != 0:
            raise ValueError('Unaligned sample write.')
        samples_mv = memoryview(samples)
        while True:
            remaining = self._slice_limit - self._slice_buffer.tell()
            if len(samples_mv) > remaining:
                self._slice_buffer.write(samples_mv[:remaining])
                samples_mv = samples_mv[remaining:]
                self._finalize_current_slice()
            else:
                self._slice_buffer.write(samples_mv)
                break
        self._sample_counter += len(samples) // self._unit_size

    def fill_sample(self, pattern, count):
        total_length = len(pattern) * count
        if total_length % self._unit_size != 0:
            raise ValueError('Unaligned sample write.')
        self.write_samples(pattern * count)
        self._sample_counter += total_length // self._unit_size

    @property
    def sample_count(self):
        return self._sample_counter

    def close(self):
        self._finalize_current_slice()
        self._sr.close()


class USBSignaling:
    CHIRP_TO_SAMPLE = {
        'ls': {
            'j': 0b01,
            'k': 0b10,
            's': 0b00,
            'S': 0b11,
        },
        'fs': {
            'j': 0b10,
            'k': 0b01,
            's': 0b00,
            'S': 0b11,
        }
    }

    def __init__(self, sr, interpolate, signaling='fs'):
        self._state = 'j'
        self._sr = sr
        self._c2s = self.__class__.CHIRP_TO_SAMPLE[signaling]
        self._interpolate = interpolate

    def emit_chirps(self, seq, update_state=True):
        def _double(seq):
            for c in seq:
                for _ in range(self._interpolate):
                    yield self._c2s[c]
        sr.write_samples(bytes(_double(seq)))
        if update_state:
            self._state = seq[-1]

    def emit_sync(self):
        self.emit_chirps('kjkjkjkk')

    def emit_eop(self):
        self.emit_chirps('ssj')

    def emit_stall(self, cycles):
        if cycles < 0:
            raise ValueError('Cycles must be 0 or positive.')
        elif cycles == 0:
            return
        else:
            self.emit_chirps(self._state * cycles)

    def emit_bytes(self, seq):
        def _to_chirp(seq):
            stuff = 0
            _jk = 'jk'
            tmp = _jk.index(self._state)
            for byte in seq:
                for _ in range(8):
                    if not (byte & 0b1):
                        tmp = ~tmp & 1
                        stuff = 0
                    else:
                        stuff += 1
                    yield _jk[tmp]
                    # Handle bit stuffing
                    if stuff >= 6:
                        tmp = ~tmp & 1
                        yield _jk[tmp]
                    byte >>= 1
            self._state = _jk[tmp]
        self.emit_chirps(_to_chirp(seq), False)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('pcap', help='PCAP file.')
    p.add_argument('sr', help='Sigrok session file.')
    p.add_argument('signaling', help='Type of USB signaling (ls, fs).')
    p.add_argument('-x', '--interpolate',
                   metavar='N',
                   type=int,
                   default=4,
                   help='Interpolate samples to be Nx the clock rate. (default: 4)')
    p.add_argument('-s', '--start-padding',
                   type=int,
                   default=4,
                   help='Idle padding before the first packet, in cycles. (default: 4)')
    p.add_argument('-e', '--end-padding',
                   type=int,
                   default=0,
                   help='Idle padding after the last packet, in cycles. (default: 0)')
    return p, p.parse_args()

if __name__ == '__main__':
    p, args = parse_args()
    speed = USB_SPEED.get(args.signaling)
    if speed is None:
        p.error(f'Unknown signaling {repr(args.signaling)}')
    pcap = rdpcap(args.pcap)
    last_pkt_at = pcap[0].time
    
    with contextlib.closing(SimpleSRWriter(args.sr, ('D-', 'D+'), speed * args.interpolate, slice_limit=16777216)) as sr:
        usb = USBSignaling(args.signaling, args.interpolate)
        usb.emit_stall(args.start_padding)
        begins_at_ticks = sr.sample_count // args.interpolate
        ends_at_ticks = begins_at_ticks
        for pkt in tqdm(pcap):
            delta_interpacket = pkt.time - last_pkt_at
            delta_ticks_interpacket = round(delta_interpacket * speed)
            delta_ticks_intrapacket = ends_at_ticks - begins_at_ticks
            if delta_ticks_intrapacket > delta_ticks_interpacket:
                raise RuntimeError('Previous packet cannot be trasferred on time. Wrong signaling type?')
            stall_ticks = delta_ticks_interpacket - delta_ticks_intrapacket
            usb.emit_stall(stall_ticks)
            begins_at_ticks = sr.sample_count // args.interpolate
            usb.emit_sync()
            usb.emit_bytes(pkt.load)
            usb.emit_eop()
            ends_at_ticks = sr.sample_count // args.interpolate
            last_pkt_at = pkt.time
        usb.emit_stall(args.end_padding)
