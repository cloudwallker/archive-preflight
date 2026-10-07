import hashlib
import importlib
import importlib.util
import io
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch
import zipfile

from tests.helpers_zip import make_zip, tlv, zip64_with_actual_eocd


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sample.zip'

    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.zip_index'), 'read_index not implemented')
        self.mod = importlib.import_module('archive_preflight.zip_index')
        self.model = importlib.import_module('archive_preflight.model')
        return self.mod.read_index

    def scan(self, data, **limits):
        read = self.api()
        self.path.write_bytes(data)
        return read(self.path, self.model.ScanLimits(**limits))

    def test_preflight_reads_only_bounded_metadata_search_and_directory(self):
        read = self.api()
        for comment in (b'', b'ordinary comment'):
            data = make_zip([b'same', b'same'], comment=comment)
            self.path.write_bytes(data)
            before = hashlib.sha256(data).hexdigest()
            calls = []
            original = self.mod._read_at
            def watch(source, offset, size):
                calls.append((offset, size))
                return original(source, offset, size)
            with patch.object(self.mod, '_read_at', watch), patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('payload read')):
                result = read(self.path, self.model.ScanLimits())
            self.assertEqual([e.entry_id for e in result.entries], ['e000001', 'e000002'])
            self.assertEqual(result.structure_state, 'ok')
            for offset, size in calls:
                self.assertTrue((offset == 0 and size == 4) or (offset >= max(0, len(data)-65557) and offset+size <= len(data)) or (result.central_offset <= offset and offset+size <= result.central_offset+result.central_bytes))
            self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), before)

    def test_large_declared_cd_rejected_before_read(self):
        read = self.api()
        self.path.write_bytes(make_zip([b'x'], cd_size=32*1024*1024))
        original = self.mod._read_at
        def bounded(source, offset, size):
            self.assertLessEqual(size, 65557)
            return original(source, offset, size)
        with patch.object(self.mod, '_read_at', bounded):
            result = read(self.path, self.model.ScanLimits())
        self.assertEqual(result.structure_state, 'incomplete')
        self.assertIn('CENTRAL_LIMIT', [d.code for d in result.diagnostics])

    def test_standard_and_zip64_field_differential(self):
        for zip64 in (False, True):
            data = make_zip([b'z', b'a', b'z'], zip64=zip64)
            result = self.scan(data)
            self.assertEqual(result.structure_state, 'ok')
            with zipfile.ZipFile(io.BytesIO(data)) as std:
                for i, (raw, other) in enumerate(zip(result.entries, std.infolist(), strict=True)):
                    self.assertEqual((raw.index, raw.flags, raw.method, raw.crc32, raw.compressed_bytes, raw.declared_bytes, raw.local_offset),
                                     (i, other.flag_bits, other.compress_type, other.CRC, other.compress_size, other.file_size, other.header_offset))

    def test_zip64_maximum_comment(self):
        result = self.scan(make_zip([b'x'], zip64=True, comment=b'c'*65535))
        self.assertEqual(result.structure_state, 'ok')

    def test_zip64_actual_eocd_comment_boundaries(self):
        for length in (65515, 65516, 65535):
            with self.subTest(comment_length=length):
                data = zip64_with_actual_eocd(length)
                result = self.scan(data)
                self.assertEqual(result.structure_state, 'ok')
                with zipfile.ZipFile(io.BytesIO(data)) as std:
                    self.assertEqual(len(std.infolist()), 1)
                    self.assertEqual(result.entries[0].local_offset, std.infolist()[0].header_offset)
                self.assertEqual(hashlib.sha256(data).digest(), hashlib.sha256(self.path.read_bytes()).digest())

    def test_zip64_actual_eocd_invalid_position_and_values(self):
        for defect, code in (('position', 'ZIP64_POSITION'), ('count', 'ZIP64_INCONSISTENT')):
            data = bytearray(zip64_with_actual_eocd(65535))
            end = len(data)-65535-22
            if defect == 'position':
                struct.pack_into('<Q', data, end-12, end-20-56+1)
            else:
                struct.pack_into('<HH', data, end+8, 2, 2)
            result = self.scan(bytes(data))
            self.assertEqual(result.structure_state, 'invalid')
            self.assertIn(code, [d.code for d in result.diagnostics])

    def test_maximum_comment_metadata_probe_ranges(self):
        self.api()
        for kind in ('ordinary', 'sentinel', 'actual'):
            data = (zip64_with_actual_eocd(65535) if kind == 'actual' else make_zip([b'x'], zip64=kind == 'sentinel', comment=b'c'*65535))
            end = len(data)-65535-22
            original, calls = self.mod._read_at, []
            def watched(source, offset, size):
                calls.append((offset, size))
                return original(source, offset, size)
            with patch.object(self.mod, '_read_at', watched):
                result = self.scan(data)
            self.assertEqual(result.structure_state, 'ok')
            regions = [(0, 4), (len(data)-65557, len(data)), (result.central_offset, result.central_offset+result.central_bytes), (end-20, end)]
            if kind != 'ordinary':
                regions.append((end-20-56, end-20))
            for offset, size in calls:
                self.assertTrue(any(start <= offset and offset+size <= finish for start, finish in regions), (kind, offset, size))
            self.assertEqual(hashlib.sha256(data).digest(), hashlib.sha256(self.path.read_bytes()).digest())

    def test_library_mismatch_keeps_raw_records(self):
        self.api()
        real = zipfile.ZipFile.infolist
        def altered(archive):
            result = real(archive)
            result[0].compress_size += 1
            return result
        with patch.object(zipfile.ZipFile, 'infolist', altered):
            result = self.scan(make_zip([b'a', b'a']))
        self.assertEqual(result.structure_state, 'invalid')
        self.assertEqual(len(result.entries), 2)
        self.assertIn('LIBRARY_MISMATCH', [d.code for d in result.diagnostics])

    def test_nul_library_transformation_is_disclosed(self):
        result = self.scan(make_zip([b'a\0b']))
        self.assertEqual(result.entries[0].raw_name, b'a\0b')
        self.assertIn('LIBRARY_NAME_TRANSFORM', [d.code for d in result.diagnostics])

    def test_invalid_utf8_preserves_raw(self):
        result = self.scan(make_zip([{'name': b'\xff', 'flags': 0x800}]))
        self.assertEqual(result.entries[0].raw_name, b'\xff')
        self.assertNotEqual(result.structure_state, 'ok')

    def test_source_changed_mid_scan(self):
        self.api()
        original, changed = self.mod._read_at, False
        def mutate(source, offset, size):
            nonlocal changed
            data = original(source, offset, size)
            if not changed and size > 4:
                changed = True
                import os
                info = self.path.stat()
                os.utime(self.path, ns=(info.st_atime_ns, info.st_mtime_ns+10000000))
            return data
        with patch.object(self.mod, '_read_at', mutate):
            result = self.scan(make_zip([b'x']))
        self.assertEqual(result.structure_state, 'stale')

    def test_eocd_ambiguity_tail_garbage_and_sfx(self):
        ambiguous = make_zip([], comment=make_zip([]))
        for data, code in ((ambiguous, 'EOCD_AMBIGUOUS'), (make_zip([b'x'])+b'junk', 'EOCD_MISSING'), (b'MZ!!'+make_zip([b'x']), 'SFX_OR_NOT_ZIP')):
            result = self.scan(data)
            self.assertIn(code, [d.code for d in result.diagnostics])
            self.assertNotEqual(result.structure_state, 'ok')

    def test_extra_truncation_and_zip64_placeholders(self):
        for extra in (b'\x75', tlv(1, b'\0'*8), tlv(1, b'')+tlv(1, b'')):
            result = self.scan(make_zip([{'name': b'x', 'extra': extra}]))
            self.assertEqual(result.structure_state, 'invalid')
        # Each required field consumes exactly its prescribed position, even when earlier fields are not placeholders.
        data = bytearray(make_zip([b'x'], zip64=True))
        central = data.index(b'PK\x01\x02')
        struct.pack_into('<I', data, central+24, 1)  # declared size no longer needs ZIP64
        result = self.scan(bytes(data))
        self.assertIn('ZIP64_EXTRA', [d.code for d in result.diagnostics])
        missing = self.scan(make_zip([{'name': b'x', 'size': 0xffffffff}]))
        self.assertIn('ZIP64_EXTRA', [d.code for d in missing.diagnostics])

    def test_zip64_conditional_field_order(self):
        for values in ({'size': 0xffffffff, 'extra': tlv(1, struct.pack('<Q', 1))},
                       {'compressed': 0xffffffff, 'extra': tlv(1, struct.pack('<Q', 1))},
                       {'offset': 0xffffffff, 'extra': tlv(1, struct.pack('<Q', 0))},
                       {'disk': 0xffff, 'extra': tlv(1, struct.pack('<I', 0))},
                       {'size': 0xffffffff, 'offset': 0xffffffff, 'extra': tlv(1, struct.pack('<QQ', 1, 0))}):
            result = self.scan(make_zip([{'name': b'x', **values}]))
            self.assertEqual(result.structure_state, 'ok')
            entry = result.entries[0]
            self.assertEqual((entry.declared_bytes, entry.compressed_bytes, entry.local_offset), (1, 1, 0))

    def test_actual_count_and_name_boundaries(self):
        for n, expected in ((4095, 'ok'), (4096, 'ok'), (4097, 'incomplete')):
            self.assertEqual(self.scan(make_zip([b'x'*n])).structure_state, expected)
        for count in (49999, 50000, 50001):
            data = make_zip([b'x']*count)
            result = self.scan(data)
            self.assertEqual(result.structure_state, 'ok' if count <= 50000 else 'incomplete')
        result = self.scan(make_zip([b'x']*4, eocd_count=3), entries=3)
        self.assertEqual(result.structure_state, 'incomplete')
        result = self.scan(make_zip([b'x'], eocd_count=2))
        self.assertIn('ENTRY_COUNT', [d.code for d in result.diagnostics])

    def test_lowered_archive_and_central_boundaries(self):
        data = make_zip([b'x'])
        for limit, expected in ((len(data)-1, 'incomplete'), (len(data), 'ok'), (len(data)+1, 'ok')):
            self.assertEqual(self.scan(data, archive_bytes=limit).structure_state, expected)
        for limit, expected in ((46, 'incomplete'), (47, 'ok'), (48, 'ok')):
            self.assertEqual(self.scan(data, central_bytes=limit).structure_state, expected)
        for kwargs in ({'entries': 50001}, {'depth': 65}, {'name_bytes': True}, {'seconds': 31}):
            with self.assertRaises(ValueError):
                self.model.ScanLimits(**kwargs)

    def test_unsupported_metadata_still_listed(self):
        for entry in ({'name': b'x', 'flags': 1}, {'name': b'x', 'method': 99}):
            result = self.scan(make_zip([entry]))
            self.assertEqual(result.structure_state, 'unsupported')
            self.assertEqual(len(result.entries), 1)
        result = self.scan(make_zip([{'name': b'x', 'disk': 1}]))
        self.assertEqual(result.structure_state, 'unsupported')

    def test_large_payload_read_window(self):
        self.api()
        payload = b'P'*(256*1024)
        data = make_zip([{'name': b'large', 'data': payload}], comment=b'normal')
        original, calls = self.mod._read_at, []
        def observed(source, offset, size):
            calls.append((offset, size))
            return original(source, offset, size)
        with patch.object(self.mod, '_read_at', observed):
            result = self.scan(data)
        self.assertEqual(result.structure_state, 'ok')
        for offset, size in calls:
            self.assertTrue((offset == 0 and size == 4) or (offset >= len(data)-65557 and offset+size <= len(data)))

    def test_empty_archive(self):
        for z64 in (False, True):
            result = self.scan(make_zip([], zip64=z64))
            self.assertEqual(result.structure_state, 'ok')

    def test_modified_source_overrides_parse_failure(self):
        self.api()
        original, changed = self.mod._read_at, False
        def mutate(source, offset, size):
            nonlocal changed
            data = original(source, offset, size)
            if not changed and size > 4:
                changed = True
                import os
                info = self.path.stat()
                os.utime(self.path, ns=(info.st_atime_ns, info.st_mtime_ns+10000000))
            return data
        with patch.object(self.mod, '_read_at', mutate):
            result = self.scan(make_zip([b'x'], cd_size=32*1024**2))
        self.assertEqual(result.structure_state, 'stale')

    def test_source_symlink_and_reparse_rejected(self):
        read = self.api()
        target = self.path.parent/'real.zip'
        target.write_bytes(make_zip([b'x']))
        try:
            self.path.symlink_to(target)
        except OSError as error:
            self.skipTest('Native symlink creation unavailable: '+str(error.winerror or error.errno))
        result = read(self.path, self.model.ScanLimits())
        self.assertEqual(result.structure_state, 'unsupported')
        self.assertEqual(result.entries, ())
        with self.assertRaises((self.mod._Reject, OSError)):
            self.mod._open_regular(self.path)

    def test_opened_regular_handle_and_directory_rejection(self):
        read = self.api()
        self.assertTrue(hasattr(self.mod, '_open_regular'), 'Native no-follow source handle missing')
        result = read(self.path.parent, self.model.ScanLimits())
        self.assertEqual(result.structure_state, 'unsupported')

    def test_central_hard_limit_checked_before_range(self):
        for declared in (16*1024**2-1, 16*1024**2, 16*1024**2+1):
            result = self.scan(make_zip([b'x'], cd_size=declared))
            self.assertEqual('CENTRAL_LIMIT' in [d.code for d in result.diagnostics], declared > 16*1024**2)

    def test_actual_central_directory_sixteen_mib_boundary(self):
        maximum = 16*1024**2
        record_size = 46+1+65535
        count, remaining = divmod(maximum, record_size)
        common = {'name': b'x', 'extra': tlv(0xcafe, b'\0'*65531)}
        for delta in (-1, 0, 1):
            tail_extra_size = remaining+delta-47
            entries = [common]*count+[{'name': b'x', 'extra': tlv(0xcafe, b'\0'*(tail_extra_size-4))}]
            result = self.scan(make_zip(entries))
            self.assertEqual(result.central_bytes, maximum+delta)
            self.assertEqual(result.structure_state, 'ok' if delta <= 0 else 'incomplete')
            if delta > 0:
                self.assertEqual(result.entries, ())

    def test_actual_eight_gib_sparse_file_boundary(self):
        import os
        read = self.api()
        template = make_zip([b'x'], zip64=True)
        central = template.index(b'PK\x01\x02')
        for total in (8*1024**3-1, 8*1024**3, 8*1024**3+1):
            ending = bytearray(template[central:])
            central_offset = total-len(ending)
            z64 = ending.index(b'PK\x06\x06')
            locator = ending.index(b'PK\x06\x07')
            struct.pack_into('<Q', ending, z64+48, central_offset)
            struct.pack_into('<Q', ending, locator+8, central_offset+z64)
            with self.path.open('wb') as source:
                if os.name == 'nt':
                    import ctypes
                    from ctypes import wintypes
                    import msvcrt
                    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                    ioctl = kernel.DeviceIoControl
                    ioctl.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
                    ioctl.restype = wintypes.BOOL
                    returned = wintypes.DWORD()
                    if not ioctl(msvcrt.get_osfhandle(source.fileno()), 0x900c4, None, 0, None, 0, ctypes.byref(returned), None):
                        self.skipTest('Filesystem does not support sparse files')
                source.write(template[:central])
                source.seek(central_offset)
                source.write(ending)
            self.assertEqual(self.path.stat().st_size, total)
            result = read(self.path, self.model.ScanLimits())
            self.assertEqual(result.structure_state, 'ok' if total <= 8*1024**3 else 'incomplete')


if __name__ == '__main__':
    unittest.main()
