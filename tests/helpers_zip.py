"""Independent, deterministic ZIP wire-format fixtures (original synthetic bytes)."""
import struct
import zlib


def tlv(kind, data):
    return struct.pack('<HH', kind, len(data)) + data


def unicode_path(raw, text, crc=None):
    return tlv(0x7075, b'\x01' + struct.pack('<I', zlib.crc32(raw) if crc is None else crc) + text.encode('utf-8'))


def make_zip(entries, *, zip64=False, comment=b'', eocd_count=None, cd_size=None):
    """Each entry is bytes or a dict; overrides deliberately allow malformed metadata."""
    local = bytearray()
    central = bytearray()
    for value in entries:
        v = {'name': value} if isinstance(value, bytes) else value
        name, data = v['name'], v.get('data', b'x')
        flags, method = v.get('flags', 0), v.get('method', 0)
        crc = v.get('crc', zlib.crc32(data))
        size, compressed = v.get('size', len(data)), v.get('compressed', len(data))
        offset = v.get('offset', len(local))
        local += struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flags, method, 0, 33, crc, len(data), len(data), len(name), 0) + name + data
        extra = v.get('extra', b'')
        if zip64:
            extra = tlv(1, struct.pack('<QQQ', size, compressed, offset)) + extra
        central += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', (v.get('system', 3) << 8) | 45, 45 if zip64 else 20, flags, method, 0, 33, crc,
                               0xffffffff if zip64 else compressed, 0xffffffff if zip64 else size,
                               len(name), len(extra), 0, v.get('disk', 0), 0, v.get('attr', 0), 0xffffffff if zip64 else offset) + name + extra
    count = len(entries) if eocd_count is None else eocd_count
    size = len(central) if cd_size is None else cd_size
    trailer = b''
    if zip64:
        trailer = struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, count, count, size, len(local))
        trailer += struct.pack('<4sIQI', b'PK\x06\x07', 0, len(local) + len(central), 1)
    end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 0xffff if zip64 else count, 0xffff if zip64 else count,
                      0xffffffff if zip64 else size, 0xffffffff if zip64 else len(local), len(comment)) + comment
    return bytes(local + central + trailer + end)


def zip64_with_actual_eocd(comment_length):
    """A legal ZIP64 with representable, consistent non-sentinel EOCD values."""
    data = bytearray(make_zip([b'x'], zip64=True, comment=b'c'*comment_length))
    end = len(data)-22-comment_length
    z64 = end-20-56
    central_size, central_offset = struct.unpack_from('<QQ', data, z64+40)
    struct.pack_into('<HHII', data, end+8, 1, 1, central_size, central_offset)
    return bytes(data)
