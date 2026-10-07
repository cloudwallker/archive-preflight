import importlib
import importlib.util
from dataclasses import replace
import unittest

from archive_preflight.model import RawEntry
from tests.helpers_zip import unicode_path


def raw(name, flags=0, extra=b''):
    return RawEntry('e000001', 0, 0, name, extra, flags, 0, 0, 0, 0, 0, 3, 0)


class EncodingTests(unittest.TestCase):
    def decode(self, entry):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.encoding'), 'strict candidate decoding missing')
        return importlib.import_module('archive_preflight.encoding').decode_candidates(entry)

    def test_nul_not_truncated(self):
        entry = raw(b'a\x00hidden.txt')
        result = self.decode(entry)
        self.assertEqual(entry.raw_name, b'a\x00hidden.txt')
        self.assertTrue(any(c.text == 'a\x00hidden.txt' for c in result))

    def test_invalid_bit11_no_fallback(self):
        result = self.decode(raw(b'\xff', 0x800))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].valid)
        self.assertIn('INVALID_UTF8', result[0].evidence)

    def test_unicode_extra_crc_conflict(self):
        result = self.decode(raw(b'name', extra=unicode_path(b'name', 'other', crc=0)))
        self.assertTrue(any('UNICODE_EXTRA_CRC' in c.evidence for c in result))

    def test_unicode_extra_disagreement(self):
        for entry in (raw(b'name', 0x800, unicode_path(b'name', 'other')),
                      raw(b'name', extra=unicode_path(b'name', 'one')+unicode_path(b'name', 'two'))):
            result = self.decode(entry)
            self.assertTrue(any('UNICODE_EXTRA_CONFLICT' in c.evidence for c in result))
            self.assertFalse(any(c.valid for c in result))

    def test_unicode_extra_authoritative(self):
        result = self.decode(raw(b'name', extra=unicode_path(b'name', '名字')))
        self.assertEqual([(c.text, c.source) for c in result if c.valid], [('名字', 'unicode-extra')])

    def test_cp932_trail_5c_not_separator(self):
        result = self.decode(raw(b'\x95\x5c/file.txt'))
        cp932 = next(c for c in result if c.source == 'cp932')
        self.assertEqual(cp932.text, '表/file.txt')
        self.assertNotIn('\\', cp932.text)

    def test_candidates_strict_deduplicated_and_stable(self):
        ascii_result = self.decode(raw(b'a.txt'))
        self.assertEqual(len([c for c in ascii_result if c.valid]), 1)
        entry = raw('中文'.encode('gb18030'))
        first = self.decode(entry)
        self.assertEqual(first, self.decode(entry))
        self.assertTrue(any(c.text == '中文' and c.source == 'gb18030' for c in first))
        self.assertTrue(all('\ufffd' not in c.text for c in first if c.valid))


if __name__ == '__main__':
    unittest.main()
