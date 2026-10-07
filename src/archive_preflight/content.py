"""Bounded local-record validation and complete raw ZIP member streams."""
import struct
import zlib

from .model import ContentRange, ExtractLimits, OutputBudget
from .zip_index import extra_fields, _Reject


def _read(source, offset, count, boundary):
    if offset < 0 or count < 0 or offset + count > boundary:
        raise ValueError('LOCAL_RANGE')
    source.seek(offset)
    data = source.read(count)
    if len(data) != count:
        raise ValueError('CONTENT_TRUNCATED')
    return data


def inspect_local(source, index, entry) -> ContentRange:
    boundary = index.central_offset
    fixed = _read(source, entry.local_offset, 30, boundary)
    sig, version, flags, method, _, _, crc, compressed, declared, nlen, xlen = struct.unpack('<4s5H3I2H', fixed)
    if sig != b'PK\x03\x04' or flags != entry.flags or method != entry.method:
        raise ValueError('LOCAL_HEADER_MISMATCH')
    if nlen != len(entry.raw_name) or nlen > index.limits.name_bytes:
        raise ValueError('LOCAL_NAME_MISMATCH')
    variable = _read(source, entry.local_offset+30, nlen+xlen, boundary)
    if variable[:nlen] != entry.raw_name:
        raise ValueError('LOCAL_NAME_MISMATCH')
    try:
        extras = [value for kind, value in extra_fields(variable[nlen:]) if kind == 1]
    except _Reject as error:
        raise ValueError(error.code) from None
    required = (declared == 0xffffffff, compressed == 0xffffffff)
    width = 8 * sum(required)
    if len(extras) > 1 or (width and not extras) or (extras and len(extras[0]) != width):
        raise ValueError('LOCAL_ZIP64_EXTRA')
    zip64 = bool(width)
    if zip64:
        if version < 45:
            raise ValueError('LOCAL_ZIP64_VERSION')
        pos = 0
        values = []
        for needed, value in zip(required, (declared, compressed)):
            values.append(int.from_bytes(extras[0][pos:pos+8], 'little') if needed else value)
            pos += 8 if needed else 0
        declared, compressed = values
    expected = (entry.crc32, entry.compressed_bytes, entry.declared_bytes)
    actual = (crc, compressed, declared)
    if flags & 8:
        if any(value not in (0, wanted) for value, wanted in zip(actual, expected)):
            raise ValueError('LOCAL_DESCRIPTOR_PLACEHOLDER')
    elif actual != expected:
        raise ValueError('LOCAL_SIZE_CRC_MISMATCH')
    data_offset = entry.local_offset + 30 + nlen + xlen
    end = data_offset + entry.compressed_bytes
    if end > boundary:
        raise ValueError('CONTENT_RANGE')
    descriptor_start = descriptor_end = None
    if flags & 8:
        descriptor_start = end
        # A streaming ZIP64 writer may leave ordinary local sizes at zero. The
        # indexed central record's sentinel fields still unambiguously select
        # 64-bit descriptor sizes; an offset-only ZIP64 extra does not.
        central = _read(source,entry.central_offset,46,index.central_offset+index.central_bytes)
        central_compressed,central_declared = struct.unpack_from('<II',central,20)
        zip64 = zip64 or central_compressed==0xffffffff or central_declared==0xffffffff
        # CRC may itself equal the optional signature: accept only a unique
        # layout matching all central values and the next known record boundary.
        candidates = []
        for signed in (False, True):
            length = (20 if zip64 else 12) + (4 if signed else 0)
            if end+length > boundary:
                continue
            data = _read(source, end, length, boundary)
            if signed and data[:4] != b'PK\x07\x08':
                continue
            decoded = struct.unpack('<IQQ' if zip64 else '<III', data[4:] if signed else data)
            if decoded == expected:
                candidates.append(end+length)
        if len(candidates) != 1:
            raise ValueError('DESCRIPTOR_MISMATCH')
        descriptor_end = candidates[0]
    return ContentRange(entry.entry_id, data_offset, entry.compressed_bytes, entry.declared_bytes,
                        entry.crc32, entry.method, descriptor_start, descriptor_end)


def inspect_ranges(source, index, included):
    """Skipped bodies/headers are never read; their central offsets still fence ranges."""
    entries = sorted(index.entries, key=lambda entry: entry.local_offset)
    if len({entry.local_offset for entry in entries}) != len(entries):
        raise ValueError('DUPLICATE_LOCAL_OFFSET')
    ranges = {}
    for position, entry in enumerate(entries):
        next_offset = entries[position+1].local_offset if position+1 < len(entries) else index.central_offset
        if entry.local_offset < 0 or entry.local_offset+30+len(entry.raw_name)+entry.compressed_bytes > next_offset:
            raise ValueError('OVERLAPPING_LOCAL_RANGE')
        if entry.entry_id in included:
            content = inspect_local(source, index, entry)
            if (content.descriptor_end or content.data_offset+content.compressed_bytes) > next_offset:
                raise ValueError('OVERLAPPING_CONTENT_RANGE')
            ranges[entry.entry_id] = content
    return ranges


def stream_verified(source, content: ContentRange, limits: ExtractLimits, budget: OutputBudget):
    """Charge before yield exactly once. No caller may refund this budget on failure."""
    source.seek(content.data_offset)
    remaining, actual, crc = content.compressed_bytes, 0, 0
    decoder = zlib.decompressobj(-15) if content.method == 8 else None
    if content.method not in (0, 8):
        raise ValueError('METHOD_UNSUPPORTED')
    pending = b''
    while remaining or pending or (decoder is not None and not decoder.eof):
        if not pending and remaining:
            size = min(remaining, limits.chunk_bytes)
            pending = source.read(size)
            if len(pending) != size:
                raise ValueError('CONTENT_TRUNCATED')
            remaining -= size
        allowance = min(limits.chunk_bytes, limits.file_bytes-actual, limits.total_bytes-budget.actual_bytes,
                        content.declared_bytes-actual)
        probe = max(1, allowance)
        if decoder is None:
            output, pending = pending[:probe], pending[probe:]
        else:
            try:
                output = decoder.decompress(pending, probe)
            except zlib.error:
                raise ValueError('DEFLATE_INVALID') from None
            pending = decoder.unconsumed_tail
            if decoder.unused_data or (decoder.eof and (pending or remaining)):
                raise ValueError('DEFLATE_TRAILING_DATA')
            if not output and not pending and not remaining and not decoder.eof:
                raise ValueError('DEFLATE_TRUNCATED')
        if output:
            if len(output) > allowance:
                raise ValueError('ACTUAL_SIZE_LIMIT')
            actual += len(output)
            budget.actual_bytes += len(output)
            crc = zlib.crc32(output, crc)
            yield output
        if decoder is not None and decoder.eof:
            break
    if actual != content.declared_bytes or crc != content.crc32:
        raise ValueError('CONTENT_SIZE_CRC_MISMATCH')
