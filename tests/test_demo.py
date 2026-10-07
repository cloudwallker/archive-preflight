"""Demo artifacts run the same engine; fixture expectations are independent assertions."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DemoTests(unittest.TestCase):
    def test_fixture_matrix_preserves_encoding_and_profile_differences(self):
        from fixtures.build_fixtures import fixtures
        from archive_preflight.analyze import analyze
        from archive_preflight.zip_index import read_index
        from archive_preflight.model import ScanLimits,TargetOptions
        from archive_preflight.profiles import load_profile
        blobs=fixtures()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            path=Path(tmp)/'fixture.zip';path.write_bytes(blobs['demo-eight-risks.zip']);index=read_index(path,ScanLimits())
            reports={profile:analyze(index,load_profile(profile),TargetOptions(root_units=100),{}) for profile in ('windows-win32-conservative-v1','macos-apfs-ci-advisory-v1','macos-apfs-cs-advisory-v1','linux-posix-bytes-v1')}
            self.assertIn('ascii-case',{g.rule_id for g in reports['macos-apfs-ci-advisory-v1'].collision_groups})
            self.assertNotIn('ascii-case',{g.rule_id for g in reports['macos-apfs-cs-advisory-v1'].collision_groups})
            self.assertTrue(any(g.rule_id=='nfc' and g.certainty=='approximation' for g in reports['macos-apfs-cs-advisory-v1'].collision_groups))
            self.assertTrue(all(g.certainty=='advisory' for g in reports['linux-posix-bytes-v1'].collision_groups))
            path.write_bytes(blobs['encoding-mixed.zip']);encoding=analyze(read_index(path,ScanLimits()),load_profile('linux-posix-bytes-v1'),TargetOptions(root_units=100),{})
            self.assertEqual(len(encoding.entries),6)
            sources={c.source for e in encoding.entries for c in e.candidates}
            self.assertTrue({'cp437','gb18030','cp932','utf-8-bit11'}<=sources,sources)
    def test_malformed_content_fixtures_fail_real_owned_extraction_source_unchanged(self):
        from fixtures.build_fixtures import fixtures
        from archive_preflight.analyze import analyze
        from archive_preflight.zip_index import read_index
        from archive_preflight.model import ScanLimits,TargetOptions,ExtractLimits
        from archive_preflight.profiles import load_profile
        from archive_preflight.mapping import suggest_plan,validate_plan
        from archive_preflight.extract import _extract_owned
        blobs=fixtures()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp);sentinel=root/'sentinel';sentinel.write_bytes(b'outside')
            for number,(name,blob) in enumerate(blobs.items()):
                if not name.startswith('content-') and name!='safe-extract.zip':continue
                with self.subTest(fixture=name):
                    path=root/(str(number)+'.zip');out=root/('out'+str(number));path.write_bytes(blob)
                    index=read_index(path,ScanLimits());report=analyze(index,load_profile('windows-win32-conservative-v1'),TargetOptions(root_units=100),{})
                    plan=validate_plan(index,suggest_plan(report));result=_extract_owned(path,plan,plan.plan_id,out,ExtractLimits())
                    self.assertEqual(result.status,'verified' if name=='safe-extract.zip' else 'failed',result.diagnostics)
                    if name!='safe-extract.zip':self.assertFalse(out.exists())
                    self.assertEqual(path.read_bytes(),blob);self.assertEqual(sentinel.read_bytes(),b'outside')
    def test_demo_generates_engine_report_draft_and_offline_html_exclusively(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            out=Path(tmp)/'demo'
            run=lambda:subprocess.run([sys.executable,'-B','-X','utf8','-m','archive_preflight','demo','--output',str(out)],capture_output=True,text=True,encoding='utf-8',timeout=30)
            first=run()
            self.assertIn(first.returncode,(0,1),first.stderr)
            report=json.loads((out/'report.json').read_text('ascii'))
            codes={d['code'] for d in report['diagnostics']}
            self.assertTrue({'WINDOWS_DEVICE_NAME','WINDOWS_TRAILING_DOT_SPACE','PATH_LIMIT','PATH_TRAVERSAL','SPECIAL_TYPE','DECLARED_RATIO_RISK'}<=codes,codes)
            self.assertTrue(any(g['ruleId']=='ascii-case' for g in report['collisionGroups']))
            mac=json.loads((out/'macos-apfs-ci-advisory-v1.json').read_text('ascii'))
            self.assertTrue(any(g['ruleId'] in ('nfc','nfc-casefold') for g in mac['collisionGroups']))
            self.assertFalse(report['contentVerified'])
            self.assertNotIn('planId',json.loads((out/'draft.json').read_text('ascii')))
            self.assertIn('validate-plan',(out/'report.html').read_text('utf-8'))
            before={p.name:p.read_bytes() for p in out.iterdir()}
            self.assertEqual(run().returncode,2)
            self.assertEqual({p.name:p.read_bytes() for p in out.iterdir()},before)
    def test_inspect_html_is_exclusive_and_json_stdout_stays_json(self):
        from tests.helpers_zip import make_zip
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp);source=root/'source.zip';html=root/'report.html'
            source.write_bytes(make_zip([b'plain']))
            args=[sys.executable,'-B','-X','utf8','-m','archive_preflight','inspect',str(source),'--target','linux','--target-root','/synthetic','--json','--html',str(html)]
            first=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=30)
            self.assertEqual(first.returncode,0,first.stderr);self.assertFalse(json.loads(first.stdout)['contentVerified'])
            original=html.read_bytes()
            self.assertEqual(subprocess.run(args,capture_output=True,timeout=30).returncode,2)
            self.assertEqual(html.read_bytes(),original)
