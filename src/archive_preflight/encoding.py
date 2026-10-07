"""Strict whole-name decoding; byte 0x5c is never treated as a separator."""
import hashlib
import struct
import zlib
from dataclasses import replace

from .model import NameCandidate, RawEntry
from .zip_index import _Reject, extra_fields


def _candidate(source, text, evidence=(), valid=True, certainty='advisory'):
    identity = source + '\x00' + (text if text is not None else '\x00'.join(evidence))
    return NameCandidate('c'+hashlib.sha256(identity.encode('utf-8')).hexdigest(), text, source, valid, tuple(evidence), certainty)


def decode_candidates(entry: RawEntry) -> tuple[NameCandidate, ...]:
    evidence, extras, issues = [], [], []
    try:
        for kind, data in extra_fields(entry.raw_extra):
            evidence.append(f'EXTRA_{kind:04X}_LENGTH_{len(data)}')
            if kind != 0x7075:
                continue
            if len(data) < 5 or data[0] != 1:
                issues.append('UNICODE_EXTRA_VERSION_OR_LENGTH')
            elif struct.unpack_from('<I', data, 1)[0] != zlib.crc32(entry.raw_name):
                issues.append('UNICODE_EXTRA_CRC')
            else:
                try:
                    extras.append(data[5:].decode('utf-8', 'strict'))
                except UnicodeDecodeError:
                    issues.append('UNICODE_EXTRA_UTF8')
    except _Reject:
        return (_candidate('raw', None, ('EXTRA_TRUNCATED',), False),)
    utf8 = None
    if entry.flags & 0x800:
        try:
            utf8 = entry.raw_name.decode('utf-8', 'strict')
        except UnicodeDecodeError:
            return (_candidate('utf-8-bit11', None, ('INVALID_UTF8',)+tuple(evidence), False),)
    if len(set(extras)) > 1 or (utf8 is not None and any(text != utf8 for text in extras)):
        issues.append('UNICODE_EXTRA_CONFLICT')
    if issues:
        # Bad authoritative evidence cannot be repaired with a guessed legacy codec.
        return (_candidate('unicode-extra', utf8, tuple(issues)+tuple(evidence), False),)
    if utf8 is not None:
        return (_candidate('utf-8-bit11', utf8, evidence, certainty='config_rule'),)
    if extras:
        return (_candidate('unicode-extra', extras[0], evidence, certainty='config_rule'),)
    result, seen = [], {}
    for codec in ('cp437', 'utf-8', 'gb18030', 'cp932', 'big5'):
        try:
            text = entry.raw_name.decode(codec, 'strict')
        except UnicodeDecodeError:
            continue
        if text in seen:
            at = seen[text]
            result[at] = replace(result[at], evidence=result[at].evidence+(f'ALSO_{codec}',))
        else:
            seen[text] = len(result)
            result.append(_candidate(codec, text, tuple(evidence)+(('SPEC_DEFAULT_NOT_INTENT',) if codec == 'cp437' else ())))
    return tuple(result)
