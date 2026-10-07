"""Real subprocess CLI flows, safe terminals, and exclusive output files."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.helpers_zip import make_zip


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'synthetic.zip'
        self.source.write_bytes(make_zip([b'Report.txt', b'report.txt', b'Report_e000002.txt']))

    def cli(self, *args):
        return subprocess.run([sys.executable, '-X', 'utf8', '-m', 'archive_preflight', *map(str, args)],
                              capture_output=True, encoding='utf-8', timeout=30)

    def test_json_only_stdout_and_real_inspect_validate(self):
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        mapping, output = self.root/'draft.json', self.root/'validated.json'
        result = self.cli('inspect', self.source, '--target', 'windows', '--target-root', 'X:/hypothetical',
                          '--json', '--plan', mapping)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['profile']['profileId'], 'windows-win32-conservative-v1')
        self.assertTrue(report['transformations'])
        self.assertNotIn('hypothetical', result.stdout)
        self.assertFalse(report['contentVerified'])
        result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
        self.assertEqual(result.returncode, 1, result.stderr)
        plan = json.loads(output.read_text('ascii'))
        self.assertTrue(plan['extractable'])
        self.assertEqual(plan['resolvedPaths']['e000002'], 'report_e000002_2.txt')
        self.assertRegex(plan['planId'], r'^[0-9a-f]{64}$')
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)

    def test_existing_outputs_and_input_equal_output_rejected(self):
        report = self.root/'report.json'
        report.write_text('existing', encoding='ascii')
        result = self.cli('inspect', self.source, '--target', 'linux', '--report-json', report)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report.read_text('ascii'), 'existing')
        before = self.source.read_bytes()
        result = self.cli('inspect', self.source, '--target', 'linux', '--report-json', self.source)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.source.read_bytes(), before)
        output = self.root/'same.json'
        result = self.cli('inspect', self.source, '--target', 'linux', '--report-json', output, '--plan', output)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_unknown_profile_invalid_and_unsupported_priority(self):
        result = self.cli('inspect', self.source, '--target', 'unknown', '--json')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        invalid = self.root/'invalid.zip'
        invalid.write_bytes(make_zip([b'a'], cd_size=999))
        result = self.cli('inspect', invalid, '--target', 'linux', '--json')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['state'], 'invalid')
        unsupported = self.root/'unsupported.zip'
        unsupported.write_bytes(make_zip([{'name': b'CON', 'method': 99}]))
        result = self.cli('inspect', unsupported, '--target', 'windows', '--json')
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['state'], 'unsupported')

    def test_terminal_control_and_bidi_are_visible_escapes(self):
        malicious = self.root/'unsafe.zip'
        malicious.write_bytes(make_zip([{'name': b'escape\x1b[31m.txt'},
                                        {'name': 'bidi\u202e.txt'.encode(), 'flags': 0x800}]))
        for extra in ((), ('--json',)):
            result = self.cli('inspect', malicious, '--target', 'linux', *extra)
            self.assertNotIn('\x1b', result.stdout+result.stderr)
            self.assertNotIn('\u202e', result.stdout+result.stderr)
            self.assertIn('\\u001b', result.stdout)
            self.assertIn('\\u202e', result.stdout)

    def test_locale_does_not_change_semantic_plan(self):
        plans = []
        for locale in ('zh-CN', 'en'):
            mapping = self.root/(locale+'.json')
            result = self.cli('inspect', self.source, '--target', 'windows', '--target-root', 'X:/same',
                              '--locale', locale, '--plan', mapping)
            self.assertEqual(result.returncode, 1)
            plans.append(mapping.read_bytes())
        self.assertEqual(plans[0], plans[1])

    def test_mapping_utf8_duplicate_keys_budget_and_unknown_root(self):
        mapping = self.root/'mapping.json'
        output = self.root/'out.json'
        for data in (b'\xff', b'{"schemaVersion":1,"schemaVersion":1}'):
            mapping.write_bytes(data)
            result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(output.exists())
        mapping.write_bytes(b' '*16777217)
        result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(output.exists())
        result = self.cli('inspect', self.source, '--target', 'windows', '--plan', mapping)
        # Existing malformed mapping is never overwritten.
        self.assertEqual(result.returncode, 2)
        mapping.unlink()
        result = self.cli('inspect', self.source, '--target', 'windows', '--plan', mapping)
        self.assertEqual(result.returncode, 1)
        result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(json.loads(output.read_text('ascii'))['extractable'])

    def test_version_and_clean_inspection(self):
        result = self.cli('--version')
        self.assertEqual(result.returncode, 0)
        self.assertIn('0.1.0', result.stdout)
        self.source.write_bytes(make_zip([b'plain']))
        result = self.cli('inspect', self.source, '--target', 'linux', '--target-root', '/hypothetical', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'ok')

    def test_combined_unknown_encoding_confirmation_before_validated_output(self):
        self.source.write_bytes(make_zip([b'\x82\xa0//b']))
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        mapping, output = self.root/'combined.json', self.root/'combined-validated.json'
        result = self.cli('inspect', self.source, '--target', 'windows', '--target-root', 'X:/hypothetical',
                          '--plan', mapping)
        self.assertEqual(result.returncode, 1, result.stderr)
        value = json.loads(mapping.read_text('ascii'))
        value['decisions'][0].update(action='rename', targetPath='chosen.txt',
                                     encodingCandidateId=None, nameConfirmed=False)
        mapping.write_text(json.dumps(value), encoding='utf-8')
        result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('ENCODING_CONFIRMATION_REQUIRED', result.stderr)
        self.assertFalse(output.exists())
        value['decisions'][0]['nameConfirmed'] = True
        mapping.write_text(json.dumps(value), encoding='utf-8')
        result = self.cli('validate-plan', self.source, '--mapping', mapping, '--output', output)
        self.assertEqual(result.returncode, 1, result.stderr)
        plan = json.loads(output.read_text('ascii'))
        self.assertTrue(plan['extractable'])
        self.assertEqual(plan['resolvedPaths'], {'e000001': 'chosen.txt'})
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)

    def test_real_extract_cli_native_hashes_stem_sibling_and_no_output_alias(self):
        from tests.test_content import wire_zip
        self.source.write_bytes(wire_zip())
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        draft,validated,result_file = (self.root/name for name in ('draft.json','validated.json','result.json'))
        self.assertEqual(self.cli('inspect',self.source,'--target','linux','--target-root','/hypothetical','--plan',draft).returncode,0)
        self.assertEqual(self.cli('validate-plan',self.source,'--mapping',draft,'--output',validated).returncode,0)
        plan = json.loads(validated.read_text('ascii'))
        output = self.source.with_suffix('')
        sentinel = self.root/'sentinel'
        sentinel.write_bytes(b'untouched')
        result = self.cli('extract',self.source,'--plan',validated,'--accept-plan',plan['planId'],'--output',output,'--result-json',result_file)
        self.assertEqual(result.returncode,0,result.stderr)
        exported = json.loads(result_file.read_text('ascii'))
        self.assertEqual(exported['status'],'verified')
        self.assertEqual(exported['actualBytes'],'5')
        self.assertEqual(exported['entries'][0]['sha256'],hashlib.sha256(b'hello').hexdigest())
        self.assertEqual((output/'a').read_bytes(),b'hello')
        self.assertEqual(sentinel.read_bytes(),b'untouched')
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),before)
        for bad_output,bad_result in ((self.source,None),(self.root/'new',self.root/'new'/'result.json')):
            args = ['extract',self.source,'--plan',validated,'--accept-plan',plan['planId'],'--output',bad_output]
            if bad_result: args += ['--result-json',bad_result]
            rejected = self.cli(*args)
            self.assertNotEqual(rejected.returncode,0)
        self.assertFalse((self.root/'new').exists())

    def test_cli_deadline_exit3_has_no_partial_exports(self):
        import contextlib
        import io
        from unittest.mock import patch
        from archive_preflight.cli import main
        from archive_preflight.worker import WorkerFailure
        output = self.root/'timeout.json'
        with patch('archive_preflight.cli.run_worker',side_effect=WorkerFailure('WORKER_TIMEOUT')), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['inspect',str(self.source),'--target','linux','--report-json',str(output)]),3)
        self.assertFalse(output.exists())
