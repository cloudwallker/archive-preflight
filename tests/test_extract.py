from dataclasses import replace
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from archive_preflight.analyze import analyze
from archive_preflight.mapping import suggest_plan,validate_plan
from archive_preflight.model import ScanLimits,TargetOptions,dumps
from archive_preflight.profiles import load_profile
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip
from tests.test_content import wire_zip


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.extract'),'verified extraction is required')
        self.extract = importlib.import_module('archive_preflight.extract')
        self.model = importlib.import_module('archive_preflight.model')
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path,self.out = self.base/'source.zip',self.base/'out'

    def plan(self,blob=None):
        self.path.write_bytes(wire_zip() if blob is None else blob)
        index = read_index(self.path,ScanLimits())
        report = analyze(index,load_profile('linux-posix-bytes-v1'),TargetOptions(root_units=100),{})
        return validate_plan(index,suggest_plan(report))

    def run_extract(self,plan,**kwargs):
        return self.extract._extract_owned(self.path,plan,plan.plan_id,self.out,self.model.ExtractLimits(**kwargs))

    def test_accepted_plan_required_before_writes(self):
        plan = self.plan()
        result = self.extract.extract_verified(self.path,plan,'wrong',self.out,self.model.ExtractLimits())
        self.assertEqual(result.status,'failed')
        self.assertFalse(self.out.exists())
        self.assertEqual(result.cleanup.state,'not_created')

    def test_forged_derived_plan_revalidated_before_writes(self):
        plan = self.plan()
        result = self.run_extract(replace(plan,resolved_paths={'e000001':'../escape'}))
        self.assertEqual(result.status,'failed')
        self.assertFalse(self.out.exists())

    def test_verified_output_sha_source_unchanged_and_strict_result_roundtrip(self):
        plan = self.plan()
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = self.run_extract(plan)
        self.assertEqual(result.status,'verified',result.diagnostics)
        self.assertEqual((self.out/'a').read_bytes(),b'hello')
        self.assertEqual((result.actual_files,result.actual_directories,result.actual_bytes),(1,0,5))
        self.assertEqual(result.entries[0].sha256,hashlib.sha256(b'hello').hexdigest())
        self.assertEqual(before,hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(self.model.loads_extraction_result(dumps(result)),result)

    @unittest.skipUnless(os.name=='nt','Windows native host rules')
    def test_host_rules_do_not_change_mapping(self):
        plan = self.plan(make_zip([{'name':b'a<b','attr':0o100600<<16}]))
        self.assertEqual(plan.resolved_paths['e000001'],'a<b')
        result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertIn('HOST_NAME_UNSUPPORTED',[d.code for d in result.diagnostics])
        self.assertFalse(self.out.exists())

    def test_source_stale_fails(self):
        plan = self.plan()
        self.path.write_bytes(wire_zip(b'changed'))
        result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertFalse(self.out.exists())

    @unittest.skipUnless(os.name=='nt','Windows source sharing policy')
    def test_source_handle_denies_write_and_delete_sharing(self):
        from archive_preflight.zip_index import _open_regular
        self.plan()
        before = self.path.read_bytes()
        with _open_regular(self.path,share_read_only=True):
            with self.assertRaises(OSError):
                with self.path.open('wb') as stream: stream.write(b'bad')
            with self.assertRaises(OSError): self.path.unlink()
        self.assertEqual(self.path.read_bytes(),before)

    def test_result_marks_skipped_and_does_not_read_skipped_local(self):
        blob = bytearray(make_zip([{'name':b'../evil','data':b'bad'},{'name':b'good','data':b'yes','attr':0o100600<<16}]))
        blob[30] = 0 # skipped local name differs; it must not be consumed
        plan = self.plan(blob)
        result = self.run_extract(plan)
        self.assertEqual(result.status,'verified',result.diagnostics)
        self.assertEqual(result.skipped_entry_ids,('e000001',))
        self.assertEqual((self.out/'good').read_bytes(),b'yes')

    def test_all_local_ranges_precede_any_output_creation(self):
        blob = bytearray(make_zip([{'name':b'a','attr':0o100600<<16},{'name':b'b','attr':0o100600<<16}]))
        blob[32+30] = ord('c')
        plan = self.plan(blob)
        self.assertEqual(self.run_extract(plan).status,'failed')
        self.assertFalse(self.out.exists())

    def test_implicit_directories_and_duplicate_directory_records_count_once(self):
        plan = self.plan(make_zip([{'name':b'a/b/','data':b'','attr':0o40700<<16},
                                  {'name':b'a/b/','data':b'','attr':0o40700<<16},
                                  {'name':b'a/b/x','data':b'yes','attr':0o100600<<16}]))
        result = self.run_extract(plan)
        self.assertEqual(result.status,'verified',result.diagnostics)
        self.assertEqual((result.actual_directories,result.actual_files,result.actual_bytes),(2,1,3))

    def test_declared_lower_limits_fail_before_root(self):
        plan = self.plan()
        self.assertEqual(self.run_extract(plan,total_bytes=4).status,'failed')
        self.assertFalse(self.out.exists())

    @unittest.skipUnless(os.name=='nt','Windows native ancestor errors')
    def test_unavailable_native_ancestor_is_unsupported_and_not_created(self):
        import archive_preflight.safe_fs_windows as native
        plan = self.plan()
        with patch.object(native,'_open',side_effect=PermissionError('synthetic unavailable ancestor')):
            result = self.run_extract(plan)
        self.assertEqual(result.status,'unsupported_host')
        self.assertEqual(result.cleanup.state,'not_created')
        self.assertFalse(self.out.exists())

    def test_close_failure_never_reports_verified(self):
        import archive_preflight.safe_fs as fs
        plan = self.plan()
        original = fs._Tree.close
        def fail_after_close(tree):
            original(tree)
            raise OSError('synthetic close failure')
        with patch.object(fs._Tree,'close',fail_after_close):
            result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.cleanup.state,'cleanup_failed')
        self.assertEqual((self.out/'a').read_bytes(),b'hello')

    def test_close_failure_preserves_completed_owned_cleanup_counts(self):
        import archive_preflight.safe_fs as fs
        from tests.test_content import raw_deflate
        plan = self.plan(wire_zip(payload=raw_deflate(b'other')))
        sentinel = self.base/'sentinel'
        sentinel.write_bytes(b'outside owned output')
        before = (self.path.read_bytes(),sentinel.read_bytes())
        observed = []
        original_cleanup,original_close = fs._Tree.cleanup_owned,fs._Tree.close
        def track_cleanup(tree):
            cleanup = original_cleanup(tree)
            observed.append(cleanup)
            return cleanup
        def fail_after_cleanup_close(tree):
            original_close(tree)
            if observed:
                raise OSError('synthetic close failure')
        with patch.object(fs._Tree,'cleanup_owned',track_cleanup), patch.object(fs._Tree,'close',fail_after_cleanup_close):
            result = self.run_extract(plan)
        self.assertFalse(self.out.exists())
        self.assertEqual((self.path.read_bytes(),sentinel.read_bytes()),before)
        self.assertEqual(len(observed),1,result.diagnostics)
        self.assertEqual((observed[0].state,observed[0].removed_files,observed[0].removed_directories),('removed',1,1))
        self.assertEqual(result.status,'failed')
        self.assertIn('HANDLE_CLOSE_FAILED',[d.code for d in result.diagnostics])
        self.assertEqual(result.cleanup.state,'cleanup_failed')
        self.assertEqual((result.cleanup.removed_files,result.cleanup.removed_directories),(1,1))
        self.assertEqual(result.cleanup.diagnostics,observed[0].diagnostics)

    def test_close_failure_preserves_partial_owned_cleanup_counts_and_diagnostics(self):
        import archive_preflight.safe_fs as fs
        from tests.test_content import raw_deflate
        if os.name=='nt':
            from archive_preflight.safe_fs_windows import WindowsTree as NativeTree
        else:
            from archive_preflight.safe_fs_posix import PosixTree as NativeTree
        plan = self.plan(wire_zip(payload=raw_deflate(b'other')))
        sentinel = self.base/'sentinel'
        sentinel.write_bytes(b'outside owned output')
        before = (self.path.read_bytes(),sentinel.read_bytes())
        observed = []
        original_cleanup,original_close = fs._Tree.cleanup_owned,fs._Tree.close
        original_remove = NativeTree._remove
        def fail_directory_remove(tree,node):
            if node['kind']=='directory':
                raise OSError('synthetic directory delete failure')
            original_remove(tree,node)
        def track_cleanup(tree):
            cleanup = original_cleanup(tree)
            observed.append(cleanup)
            return cleanup
        def fail_after_cleanup_close(tree):
            original_close(tree)
            if observed:
                raise OSError('synthetic close failure')
        with patch.object(NativeTree,'_remove',fail_directory_remove), patch.object(fs._Tree,'cleanup_owned',track_cleanup), patch.object(fs._Tree,'close',fail_after_cleanup_close):
            result = self.run_extract(plan)
        self.assertTrue(self.out.is_dir())
        self.assertEqual(list(self.out.iterdir()),[])
        self.assertEqual((self.path.read_bytes(),sentinel.read_bytes()),before)
        self.assertEqual(len(observed),1,result.diagnostics)
        self.assertEqual((observed[0].state,observed[0].removed_files,observed[0].removed_directories),('cleanup_failed',1,0))
        self.assertEqual([d.code for d in observed[0].diagnostics],['CLEANUP_IO_ERROR'])
        self.assertEqual(result.status,'failed')
        self.assertIn('HANDLE_CLOSE_FAILED',[d.code for d in result.diagnostics])
        self.assertEqual(result.cleanup.state,'cleanup_failed')
        self.assertEqual((result.cleanup.removed_files,result.cleanup.removed_directories),(1,0))
        self.assertEqual([d.code for d in result.cleanup.diagnostics],['CLEANUP_IO_ERROR'])

    def test_extraction_result_decoder_rejects_unknown_fields_and_invalid_enums(self):
        import json
        result = self.run_extract(self.plan())
        value = json.loads(dumps(result))
        for key,bad in (('status','ok'),('schemaVersion',2),('actualBytes',5),('extra',True)):
            changed = dict(value)
            changed[key] = bad
            with self.assertRaises(ValueError): self.model.loads_extraction_result(json.dumps(changed))
        value['cleanup']['state']='invented'
        with self.assertRaises(ValueError): self.model.loads_extraction_result(json.dumps(value))

    def test_crc_failure_cleans_owned_tree_and_reports_real_written_bytes(self):
        from tests.test_content import raw_deflate
        plan = self.plan(wire_zip(payload=raw_deflate(b'other')))
        result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.actual_bytes,5)
        self.assertEqual(result.cleanup.state,'removed')
        self.assertFalse(self.out.exists())

    def test_partial_write_failure_does_not_report_authorized_unwritten_bytes(self):
        import archive_preflight.safe_fs as fs
        plan = self.plan()
        original = fs._Tree.create_file
        class FailingStream:
            def __init__(self,stream): self.stream=stream
            def write(self,block):
                if self.stream.tell(): raise OSError('synthetic disk full')
                return self.stream.write(block[:2])
            def __enter__(self): return self
            def __exit__(self,*args): self.stream.close()
        with patch.object(fs._Tree,'create_file',lambda tree,parts:FailingStream(original(tree,parts))):
            result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.actual_bytes,2)
        self.assertEqual(result.actual_files,1)
        self.assertEqual(result.cleanup.state,'removed')

    @unittest.skipUnless(os.name=='nt','Windows native handle transfer')
    def test_file_created_then_stream_handle_failure_counts_actual_creation(self):
        import archive_preflight.safe_fs_windows as native
        plan = self.plan()
        original = native._stream
        def fail_writer(node,writing=False):
            if writing: raise OSError('synthetic handle transfer failure')
            return original(node,writing)
        with patch.object(native,'_stream',fail_writer):
            result = self.run_extract(plan)
        self.assertEqual(result.status,'failed')
        self.assertEqual((result.actual_files,result.actual_bytes),(1,0))
        self.assertEqual(result.cleanup.state,'removed')
