"""Strict, bounded single-disk ZIP central directory reader. Never opens members."""
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import zipfile

from .model import ArchiveIndex, Diagnostic, RawEntry, ScanLimits


class _Reject(Exception):
    def __init__(self, code, state='invalid'):
        self.code, self.state = code, state


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _open_regular(path, *, share_read_only=False):
    """Open the input itself without following a final symlink/reparse point."""
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        create.restype = wintypes.HANDLE
        close = kernel.CloseHandle
        close.argtypes, close.restype = (wintypes.HANDLE,), wintypes.BOOL
        handle = create(str(path.absolute()), 0x80000000, 1 if share_read_only else 7, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            class AttributeTag(ctypes.Structure):
                _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]
            info = AttributeTag()
            query = kernel.GetFileInformationByHandleEx
            query.argtypes, query.restype = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD), wintypes.BOOL
            if not query(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & (0x400 | 0x10):
                raise _Reject('INPUT_NOT_REGULAR', 'unsupported')
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None  # CRT now owns the handle.
        finally:
            if handle is not None:
                close(handle)
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    source = os.fdopen(fd, 'rb')
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
        source.close()
        raise _Reject('INPUT_NOT_REGULAR', 'unsupported')
    return source


def _read_at(source, offset, size):
    if offset < 0 or size < 0:
        raise _Reject('INVALID_RANGE')
    source.seek(offset)
    data = source.read(size)
    if len(data) != size:
        raise _Reject('TRUNCATED')
    return data


def extra_fields(data):
    result, pos = [], 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise _Reject('EXTRA_TRUNCATED')
        kind, length = struct.unpack_from('<HH', data, pos)
        pos += 4
        if pos + length > len(data):
            raise _Reject('EXTRA_TRUNCATED')
        result.append((kind, data[pos:pos+length]))
        pos += length
    return tuple(result)


class _MetadataView(io.RawIOBase):
    """A defensive view used only after raw bounds and central count validation."""
    def __init__(self, source, length, regions):
        self.source, self.length, self.regions, self.pos = source, length, regions, 0

    def seek(self, offset, whence=0):
        self.pos = offset if whence == 0 else (self.pos if whence == 1 else self.length) + offset
        return self.pos

    def tell(self):
        return self.pos

    def read(self, size=-1):
        if size < 0:
            size = self.length - self.pos
        size = min(size, max(0, self.length-self.pos))
        if not any(a <= self.pos and self.pos+size <= b for a, b in self.regions):
            raise _Reject('LIBRARY_READ_OUTSIDE_METADATA')
        result = _read_at(self.source, self.pos, size)
        self.pos += size
        return result

    def seekable(self):
        return True


def _compare_stdlib(source, length, regions, entries):
    diagnostics = []
    with zipfile.ZipFile(_MetadataView(source, length, regions)) as archive:
        infos = archive.infolist()
        if len(infos) != len(entries):
            raise _Reject('LIBRARY_MISMATCH')
        for entry, info in zip(entries, infos, strict=True):
            raw = (entry.flags, entry.method, entry.crc32, entry.compressed_bytes, entry.declared_bytes, entry.local_offset, entry.create_system, entry.external_attr)
            other = (info.flag_bits, info.compress_type, info.CRC, info.compress_size, info.file_size, info.header_offset, info.create_system, info.external_attr)
            if raw != other:
                raise _Reject('LIBRARY_MISMATCH')
            text = entry.raw_name.decode('utf-8' if entry.flags & 0x800 else 'cp437', 'strict')
            if info.orig_filename != text:
                raise _Reject('LIBRARY_MISMATCH')
            if info.filename != text:
                diagnostics.append(Diagnostic('LIBRARY_NAME_TRANSFORM', 'warning', (entry.entry_id,),
                                              {'evidence': 'Original raw name retained; library display name differs'}, 'advisory'))
    return tuple(diagnostics)


def read_index(path: Path, limits: ScanLimits) -> ArchiveIndex:
    path = Path(path)
    entries, diagnostics = [], []
    length = cd_offset = cd_size = 0
    fingerprint, archive_id, state = (), '', 'ok'
    try:
        before = path.lstat()
        fingerprint, length = _fingerprint(before), before.st_size
        if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400:
            raise _Reject('INPUT_NOT_REGULAR', 'unsupported')
        if length > limits.archive_bytes:
            raise _Reject('ARCHIVE_LIMIT', 'incomplete')
        with _open_regular(path) as source:
            if _fingerprint(os.fstat(source.fileno())) != fingerprint:
                raise _Reject('SOURCE_CHANGED', 'stale')
            if length < 22:
                raise _Reject('NOT_ZIP', 'unsupported')
            first = _read_at(source, 0, 4)
            if first not in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x06\x06'):
                raise _Reject('SFX_OR_NOT_ZIP', 'unsupported')
            start = max(0, length - 65557)
            tail = _read_at(source, start, length-start)
            candidates = []
            pos = tail.find(b'PK\x05\x06')
            while pos >= 0:
                if pos+22 <= len(tail) and pos+22+struct.unpack_from('<H', tail, pos+20)[0] == len(tail):
                    candidates.append(pos)
                pos = tail.find(b'PK\x05\x06', pos+1)
            if len(candidates) != 1:
                raise _Reject('EOCD_AMBIGUOUS' if candidates else 'EOCD_MISSING')
            end_pos = start+candidates[0]
            end = tail[candidates[0]:]
            _, disk, cd_disk, disk_count, count, cd_size, cd_offset, _ = struct.unpack_from('<4s4H2IH', end)
            if disk or cd_disk or disk_count != count:
                raise _Reject('MULTI_DISK', 'unsupported')
            metadata_start, z64 = end_pos, b''
            needs64 = count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff
            # Probe only the standard locator position adjacent to the verified
            # EOCD. A legal ZIP64 may retain real (non-sentinel) EOCD fields.
            locator = _read_at(source, end_pos-20, 20) if end_pos >= 20 else b''
            if locator[:4] == b'PK\x06\x07':
                _, z_disk, z_offset, disks = struct.unpack('<4sIQI', locator)
                if z_disk or disks != 1:
                    raise _Reject('MULTI_DISK', 'unsupported')
                if z_offset < 0 or z_offset+56 != end_pos-20:
                    raise _Reject('ZIP64_POSITION')
                # Fixed standard ZIP64 EOCD only; no extensible sectors or allocation by untrusted length.
                z64 = _read_at(source, z_offset, 56)
                signature, record_size, made, needed, disk64, cd_disk64, n_disk, n, size64, off64 = struct.unpack('<4sQ2H2I4Q', z64)
                if signature != b'PK\x06\x06' or record_size != 44:
                    raise _Reject('ZIP64_RECORD')
                if disk64 or cd_disk64 or n_disk != n:
                    raise _Reject('MULTI_DISK', 'unsupported')
                if (count != 0xffff and count != n) or (cd_size != 0xffffffff and cd_size != size64) or (cd_offset != 0xffffffff and cd_offset != off64):
                    raise _Reject('ZIP64_INCONSISTENT')
                count, cd_size, cd_offset = n, size64, off64
                metadata_start = z_offset
            elif needs64:
                raise _Reject('ZIP64_MISSING')
            if cd_size > limits.central_bytes:
                raise _Reject('CENTRAL_LIMIT', 'incomplete')
            if count > limits.entries:
                raise _Reject('ENTRY_LIMIT', 'incomplete')
            if cd_offset+cd_size != metadata_start or cd_offset > length:
                raise _Reject('CENTRAL_RANGE')
            digest = hashlib.sha256(str(length).encode('ascii') + b'\x00' + end + z64 + (locator if z64 else b''))
            cursor, finish = cd_offset, cd_offset+cd_size
            while cursor < finish:
                if len(entries) >= limits.entries:
                    raise _Reject('ENTRY_LIMIT', 'incomplete')
                if finish-cursor < 46:
                    raise _Reject('CENTRAL_TRUNCATED')
                fixed = _read_at(source, cursor, 46)
                values = struct.unpack('<4s6H3I5H2I', fixed)
                sig, made, needed, flags, method, time, date, crc, compressed, declared, nlen, xlen, clen, disk_start, internal, external, local_offset = values
                if sig != b'PK\x01\x02':
                    raise _Reject('CENTRAL_SIGNATURE')
                if nlen > limits.name_bytes:
                    raise _Reject('NAME_LIMIT', 'incomplete')
                size = nlen+xlen+clen
                if cursor+46+size > finish:
                    raise _Reject('CENTRAL_TRUNCATED')
                variable = _read_at(source, cursor+46, size)
                name, extra = variable[:nlen], variable[nlen:nlen+xlen]
                tlvs = extra_fields(extra)
                zip_fields = [data for kind, data in tlvs if kind == 1]
                required = ((declared == 0xffffffff, 8), (compressed == 0xffffffff, 8), (local_offset == 0xffffffff, 8), (disk_start == 0xffff, 4))
                required_length = sum(n for flag, n in required if flag)
                if len(zip_fields) > 1 or (required_length and not zip_fields) or (zip_fields and len(zip_fields[0]) != required_length):
                    raise _Reject('ZIP64_EXTRA')
                if zip_fields:
                    values64, at = [], 0
                    for flag, width in required:
                        if flag:
                            values64.append(int.from_bytes(zip_fields[0][at:at+width], 'little'))
                            at += width
                        else:
                            values64.append(None)
                    declared, compressed, local_offset, disk_start = tuple(new if new is not None else old for old, new in zip((declared, compressed, local_offset, disk_start), values64))
                if disk_start:
                    raise _Reject('MULTI_DISK', 'unsupported')
                if local_offset+30 > cd_offset or compressed > cd_offset-local_offset:
                    raise _Reject('LOCAL_RANGE')
                entry = RawEntry(f'e{len(entries)+1:06d}', len(entries), cursor, name, extra, flags, method, crc, compressed, declared, local_offset, made >> 8, external)
                entries.append(entry)
                digest.update(fixed+variable)
                cursor += 46+size
                if flags & (1 | 0x40 | 0x2000):
                    diagnostics.append(Diagnostic('ENCRYPTED', entry_ids=(entry.entry_id,)))
                    state = 'unsupported'
                if method not in (0, 8):
                    diagnostics.append(Diagnostic('METHOD_UNSUPPORTED', entry_ids=(entry.entry_id,)))
                    state = 'unsupported'
            if len(entries) != count:
                raise _Reject('ENTRY_COUNT')
            if entries and min(e.local_offset for e in entries) != 0:
                raise _Reject('SFX_PREFIX', 'unsupported')
            if not entries and cd_offset != 0:
                raise _Reject('SFX_PREFIX', 'unsupported')
            archive_id = digest.hexdigest()
            try:
                differences = _compare_stdlib(source, length, ((start, length), (cd_offset, length)), entries)
                diagnostics.extend(differences)
                if differences and state == 'ok':
                    state = 'findings'
            except (UnicodeDecodeError, zipfile.BadZipFile, NotImplementedError):
                diagnostics.append(Diagnostic('LIBRARY_UNAVAILABLE', 'warning', details={'evidence': 'Raw central metadata preserved; standard library rejected decoding'}, certainty='advisory'))
                if state == 'ok':
                    state = 'findings'
            if _fingerprint(os.fstat(source.fileno())) != fingerprint or _fingerprint(path.lstat()) != fingerprint:
                raise _Reject('SOURCE_CHANGED', 'stale')
    except _Reject as error:
        state = error.state
        diagnostics.append(Diagnostic(error.code))
    except OSError:
        state = 'invalid'
        diagnostics.append(Diagnostic('INPUT_IO_ERROR'))
    if fingerprint and state != 'stale':
        try:
            changed = _fingerprint(path.lstat()) != fingerprint
        except OSError:
            changed = True
        if changed:
            state = 'stale'
            diagnostics.append(Diagnostic('SOURCE_CHANGED'))
    return ArchiveIndex(archive_id, path.name, length, tuple(entries), state, tuple(diagnostics), fingerprint=fingerprint,
                        central_offset=cd_offset, central_bytes=cd_size, limits=limits)
