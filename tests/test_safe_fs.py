"""Real host filesystem tests. Junction tests use Windows' native mount-point API."""
import importlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def junction(link, target):
    import ctypes
    from ctypes import wintypes
    import struct
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.DeviceIoControl.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    link.mkdir()
    handle = kernel.CreateFileW(str(link), 0x40000000, 7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        substitute = ('\\??\\'+str(target)).encode('utf-16-le')
        printed = str(target).encode('utf-16-le')
        names = substitute+b'\0\0'+printed+b'\0\0'
        payload = struct.pack('<HHHH', 0, len(substitute), len(substitute)+2, len(printed))+names
        data = struct.pack('<IHH', 0xa0000003, len(payload), 0)+payload
        returned = wintypes.DWORD()
        if not kernel.DeviceIoControl(handle, 0x900a4, data, len(data), None, 0, ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


class SafeTreeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.safe_fs'), 'native SafeTree is required')
        self.fs = importlib.import_module('archive_preflight.safe_fs')
        self.model = importlib.import_module('archive_preflight.model')
        # Keep native files on the product's current local volume, not an unknown TEMP share.
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.out = self.base/'new'

    def tree(self):
        tree = self.fs.SafeTree.create(self.out)
        self.addCleanup(tree.close)
        return tree

    def test_existing_empty_and_nonempty_roots_rejected(self):
        self.out.mkdir()
        for nonempty in (False, True):
            if nonempty:
                (self.out/'sentinel').write_bytes(b'original')
            with self.assertRaises((ValueError, OSError)):
                self.fs.SafeTree.create(self.out)
        self.assertEqual((self.out/'sentinel').read_bytes(), b'original')

    def test_exclusive_files_native_listing_and_owned_cleanup(self):
        tree = self.tree()
        tree.mkdir(('a','b'))
        tree.mkdir(('a','b'))
        with tree.create_file(('a','b','hello')) as f:
            f.write(b'hello')
        with self.assertRaises((ValueError, OSError)):
            tree.create_file(('a','b','hello'))
        entries = tree.list_verified()
        self.assertEqual({(e.target_path,e.kind,e.size) for e in entries}, {('a','directory',0),('a/b','directory',0),('a/b/hello','file',5)})
        self.assertEqual(tree.budget.directories, 2)
        result = tree.cleanup_owned()
        self.assertEqual(result.state, 'removed')
        self.assertEqual((result.removed_files,result.removed_directories), (1,3))
        self.assertFalse(self.out.exists())

    def test_directory_budget_counts_unique_actual_creations(self):
        tree = self.tree()
        tree.limits = self.model.ExtractLimits(directories=1)
        tree.mkdir(('a',))
        tree.mkdir(('a',))
        with self.assertRaises(ValueError):
            tree.mkdir(('a','b'))
        self.assertFalse((self.out/'a'/'b').exists())
        self.assertEqual(tree.budget.directories,1)

    def test_unexpected_file_causes_verification_and_cleanup_to_fail_closed(self):
        tree = self.tree()
        (self.out/'intruder').write_bytes(b'keep')
        with self.assertRaises((ValueError,OSError)):
            tree.list_verified()
        self.assertEqual(tree.cleanup_owned().state, 'retained_ownership_unknown')
        self.assertEqual((self.out/'intruder').read_bytes(), b'keep')

    def test_names_cannot_escape_or_invoke_host_aliases(self):
        tree = self.tree()
        names = [('..','outside'), ('a/b',), ('',), ('a\\b',)]
        if os.name == 'nt':
            names += [('con',), ('a:stream',), ('a.',), ('CON .txt',)]
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                with tree.create_file(name): pass
        self.assertEqual(tree.list_verified(), ())

    def test_ancestor_and_injected_directory_links_rejected_sentinel_unchanged(self):
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'sentinel').write_bytes(b'original')
        link = self.base/'linked'
        if os.name == 'nt':
            junction(link, outside)
        else:
            link.symlink_to(outside, target_is_directory=True)
        self.addCleanup(lambda: link.rmdir() if os.name == 'nt' else link.unlink())
        with self.assertRaises((ValueError,OSError)):
            self.fs.SafeTree.create(link/'bad')
        tree = self.tree()
        injected = self.out/'injected'
        if os.name == 'nt':
            junction(injected, outside)
        else:
            injected.symlink_to(outside, target_is_directory=True)
        self.addCleanup(lambda: injected.rmdir() if os.name == 'nt' else injected.unlink())
        with self.assertRaises((ValueError,OSError)):
            tree.create_file(('injected','sentinel'))
        self.assertEqual((outside/'sentinel').read_bytes(), b'original')

    @unittest.skipUnless(os.name == 'nt','Windows native handle sharing')
    def test_held_ancestor_and_created_root_cannot_be_renamed(self):
        tree = self.tree()
        with self.assertRaises(OSError):
            self.out.rename(self.base/'moved')
        with self.assertRaises(OSError):
            self.base.rename(self.base.with_name(self.base.name+'moved'))
        tree.list_verified()

    def test_closed_handles_cannot_authorize_cleanup(self):
        tree = self.tree()
        tree.close()
        self.assertEqual(tree.cleanup_owned().state, 'retained_ownership_unknown')
        self.assertTrue(self.out.exists())

    def test_cleanup_io_failure_retains_tree_and_reports_failure(self):
        tree = self.tree()
        with patch.object(tree,'_remove',side_effect=OSError('synthetic permission error')):
            result = tree.cleanup_owned()
        self.assertEqual(result.state,'cleanup_failed')
        self.assertTrue(self.out.exists())

    def test_root_identity_change_stops_cleanup(self):
        tree = self.tree()
        if os.name=='nt':
            tree._close_node(tree.nodes[()])
        self.out.rename(self.base/'original')
        self.out.mkdir()
        (self.out/'sentinel').write_bytes(b'keep')
        self.assertEqual(tree.cleanup_owned().state,'retained_ownership_unknown')
        self.assertEqual((self.out/'sentinel').read_bytes(),b'keep')

    @unittest.skipUnless(os.name=='nt','Windows native mkdir/open race')
    def test_mkdir_open_race_reparse_rejected_and_outside_unchanged(self):
        import archive_preflight.safe_fs_windows as native
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'sentinel').write_bytes(b'original')
        original = native._open
        def race(path,directory,owned=False,new=False):
            if path==self.out and owned:
                path.rmdir()
                junction(path,outside)
            return original(path,directory,owned,new)
        try:
            with patch.object(native,'_open',race), self.assertRaises(ValueError):
                self.fs.SafeTree.create(self.out)
            self.assertEqual((outside/'sentinel').read_bytes(),b'original')
        finally:
            if self.out.exists(): self.out.rmdir()

    @unittest.skipUnless(os.name=='nt','Windows actual creation accounting')
    def test_created_directory_count_survives_open_permission_failure(self):
        import archive_preflight.safe_fs_windows as native
        tree = self.tree()
        with patch.object(native,'_open',side_effect=PermissionError('synthetic native handle failure')):
            with self.assertRaises(OSError): tree.mkdir(('a',))
        self.assertTrue((self.out/'a').is_dir())
        self.assertEqual(tree.budget.directories,1)
        self.assertEqual(tree.cleanup_owned().state,'retained_ownership_unknown')
