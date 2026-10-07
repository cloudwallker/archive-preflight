"""Full wire streams; none of these fixtures use ZipExtFile's size clipping."""
from dataclasses import replace
import importlib
import importlib.util
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from archive_preflight.model import ScanLimits
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip, tlv


def raw_deflate(data):
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def wire_zip(data=b'hello', *, method=8, declared=None, payload=None,
             descriptor=False, signature=True, zip64=False):
    payload = (raw_deflate(data) if method == 8 else data) if payload is None else payload
    declared = len(data) if declared is None else declared
    crc, name, flags = zlib.crc32(data), b'a', 8 if descriptor else 0
    extra = tlv(1, struct.pack('<QQ', declared, len(payload))) if zip64 else b''
    size = 0xffffffff if zip64 else declared
    comp = 0xffffffff if zip64 else len(payload)
    local = struct.pack('<4s5H3I2H', b'PK\x03\x04', 45 if zip64 else 20, flags,
                        method, 0, 33, 0 if descriptor else crc,
                        comp if zip64 or not descriptor else 0,
                        size if zip64 or not descriptor else 0, 1, len(extra)) + name + extra + payload
    if descriptor:
        local += (b'PK\x07\x08' if signature else b'') + struct.pack('<IQQ' if zip64 else '<III', crc, len(payload), declared)
    central = struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 3 << 8 | 45, 45 if zip64 else 20,
                          flags, method, 0, 33, crc, comp, size, 1, len(extra), 0, 0, 0, 0o100600 << 16, 0) + name + extra
    return local + central + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0)


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.content'), 'complete bounded content verifier is required')
        self.content = importlib.import_module('archive_preflight.content')
        self.model = importlib.import_module('archive_preflight.model')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'source.zip'

    def index(self, blob):
        self.path.write_bytes(blob)
        return read_index(self.path, ScanLimits())

    def consume(self, blob, limits=None, budget=None):
        index = self.index(blob)
        stream = io.BytesIO(blob)
        content = self.content.inspect_local(stream, index, index.entries[0])
        limits = limits or self.model.ExtractLimits()
        budget = budget or self.model.OutputBudget()
        return b''.join(self.content.stream_verified(stream, content, limits, budget)), budget

    def test_complete_stored_and_deflate_empty_and_multiblock(self):
        for method in (0, 8):
            for data in (b'', b'hello', b'a' * 200000):
                with self.subTest(method=method, length=len(data)):
                    actual, budget = self.consume(wire_zip(data, method=method))
                    self.assertEqual(actual, data)
                    self.assertEqual(budget.actual_bytes, len(data))

    def test_low_declared_size_cannot_hide_real_stream(self):
        with self.assertRaisesRegex(ValueError, 'SIZE|LIMIT'):
            self.consume(wire_zip(b'x'*65536, declared=1))

    def test_truncated_junk_and_concatenated_streams_rejected(self):
        payload = raw_deflate(b'hello')
        for forged in (payload[:-1], payload+b'junk', payload+raw_deflate(b'x')):
            with self.subTest(payload=forged):
                with self.assertRaises(ValueError):
                    self.consume(wire_zip(payload=forged))

    def test_stored_size_and_crc_rejected(self):
        for blob in (wire_zip(b'abc', method=0, declared=2), wire_zip(payload=raw_deflate(b'other'))):
            with self.assertRaises(ValueError):
                self.consume(blob)

    def test_limits_are_checked_before_yield_and_count_once(self):
        for limit in (4, 5, 6):
            budget = self.model.OutputBudget()
            limits = self.model.ExtractLimits(file_bytes=limit, total_bytes=limit)
            if limit < 5:
                with self.assertRaises(ValueError):
                    self.consume(wire_zip(), limits, budget)
                self.assertLessEqual(budget.actual_bytes, limit)
            else:
                self.assertEqual(self.consume(wire_zip(), limits, budget)[0], b'hello')
                self.assertEqual(budget.actual_bytes, 5)

    def test_two_files_total_and_zero_balance_probe(self):
        for limit in (9, 10, 11):
            limits, budget = self.model.ExtractLimits(total_bytes=limit), self.model.OutputBudget()
            self.consume(wire_zip(), limits, budget)
            if limit == 9:
                with self.assertRaises(ValueError):
                    self.consume(wire_zip(), limits, budget)
            else:
                self.consume(wire_zip(), limits, budget)
                self.assertEqual(budget.actual_bytes, 10)
        budget = self.model.OutputBudget(actual_bytes=5)
        with self.assertRaises(ValueError):
            self.consume(wire_zip(b'x'), self.model.ExtractLimits(total_bytes=5), budget)
        self.assertEqual(budget.actual_bytes, 5)

    def test_local_name_flags_method_and_sizes_match_central(self):
        original = wire_zip()
        for offset in (6, 8, 14, 18, 22, 30):
            blob = bytearray(original)
            blob[offset] ^= 1
            index = self.index(blob)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.content.inspect_local(io.BytesIO(blob), index, index.entries[0])

    def test_descriptors_signed_unsigned_and_zip64(self):
        for signed in (True, False):
            for zip64 in (True, False):
                blob = wire_zip(descriptor=True, signature=signed, zip64=zip64)
                self.assertEqual(self.consume(blob)[0], b'hello')
                index = self.index(blob)
                for offset in (index.central_offset-1, index.central_offset-(20 if zip64 else 12)):
                    bad = bytearray(blob)
                    bad[offset] ^= 1
                    with self.assertRaises(ValueError):
                        self.consume(bad)

    def test_zip64_descriptor_with_local_zero_placeholders(self):
        blob = bytearray(wire_zip(descriptor=True,zip64=True))
        index = self.index(blob)
        del blob[31:51]  # local ZIP64 TLV; bit 3 permits sizes to be placeholders
        struct.pack_into('<II',blob,18,0,0)
        struct.pack_into('<H',blob,28,0)
        struct.pack_into('<I',blob,len(blob)-6,index.central_offset-20)
        self.assertEqual(self.consume(blob)[0],b'hello')

    def test_duplicate_offsets_overlap_and_central_boundary(self):
        blob = make_zip([b'a', {'name': b'b', 'offset': 0}])
        index = self.index(blob)
        with self.assertRaises(ValueError):
            self.content.inspect_ranges(io.BytesIO(blob), index, {e.entry_id for e in index.entries})
        blob = wire_zip()
        index = self.index(blob)
        entry = replace(index.entries[0], compressed_bytes=index.central_offset)
        with self.assertRaises(ValueError):
            self.content.inspect_local(io.BytesIO(blob), index, entry)

    def test_limits_cannot_expand_hard_maxima(self):
        for kwargs in ({'chunk_bytes': 65537}, {'seconds': 61}, {'files': 10001}, {'total_bytes': 2**30+1}, {'file_bytes': 0}):
            with self.assertRaises(ValueError):
                self.model.ExtractLimits(**kwargs)
