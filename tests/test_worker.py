"""Actual spawned-process deadline, cancellation and bounded transport tests."""
import importlib
import importlib.util
import json
import multiprocessing
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from archive_preflight.model import TargetOptions,to_json_value
from tests.test_content import wire_zip


def slow_child(connection,operation,payload):
    directory = Path(payload['output'])
    directory.mkdir()
    (directory/'sentinel').write_bytes(b'retain')
    time.sleep(120)


def malformed_child(connection,operation,payload):
    connection.send_bytes(b'{"result":{"status":"verified"}}')


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.worker'),'parent-controlled workers are required')
        self.worker = importlib.import_module('archive_preflight.worker')
        self.tmp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base/'source.zip'
        self.path.write_bytes(wire_zip())

    def test_inspect_and_validate_use_current_strict_models(self):
        result = self.worker.run_worker('inspect',{'path':str(self.path),'profile_id':'linux-posix-bytes-v1',
                                                 'options':to_json_value(TargetOptions(root_units=100))})
        self.assertEqual(result['report'].entries[0].entry_id,'e000001')
        validated = self.worker.run_worker('validate',{'path':str(self.path),'mapping':result['draft_text']})
        self.assertTrue(validated['plan'].extractable)

    def test_scan_timeout_has_no_partial_report_and_process_is_joined(self):
        before = {p.pid for p in multiprocessing.active_children()}
        with self.assertRaises(self.worker.WorkerFailure) as raised:
            self.worker.run_worker('inspect',{'path':str(self.path),'profile_id':'linux-posix-bytes-v1',
                                            'options':to_json_value(TargetOptions())},seconds=0.001)
        self.assertEqual(raised.exception.code,'WORKER_TIMEOUT')
        self.assertEqual(raised.exception.exit_code,3)
        self.assertEqual({p.pid for p in multiprocessing.active_children()},before)

    def test_forced_extract_timeout_retains_unknown_tree_and_waits(self):
        output = self.base/'out'
        with patch.object(self.worker,'_child',slow_child):
            result = self.worker.run_worker('extract',{'output':str(output),'plan_id':'p','archive_id':'a'},seconds=1)
        self.assertEqual(result['result'].status,'failed')
        self.assertEqual(result['result'].cleanup.state,'retained_ownership_unknown')
        self.assertEqual((result['result'].actual_files,result['result'].actual_directories,result['result'].actual_bytes),(None,None,None))
        self.assertIn('ACTUAL_COUNTS_UNAVAILABLE',[d.code for d in result['result'].diagnostics])
        self.assertEqual((output/'sentinel').read_bytes(),b'retain')
        self.assertFalse(multiprocessing.active_children())

    def test_cancellation_terminates_live_child(self):
        output = self.base/'out'
        cancel = threading.Event()
        def signal():
            deadline = time.monotonic()+5
            while not (output/'sentinel').exists() and time.monotonic()<deadline:
                cancel.wait(0.01)
            cancel.set()
        thread = threading.Thread(target=signal)
        thread.start()
        try:
            with patch.object(self.worker,'_child',slow_child):
                result = self.worker.run_worker('extract',{'output':str(output),'plan_id':'p','archive_id':'a'},seconds=6,cancel_event=cancel)
        finally:
            thread.join(6)
        self.assertEqual(result['result'].diagnostics[0].code,'WORKER_CANCELLED')
        self.assertEqual(result['result'].cleanup.state,'retained_ownership_unknown')
        self.assertIsNone(result['result'].actual_bytes)
        self.assertFalse(multiprocessing.active_children())

    def test_worker_response_is_not_trusted_because_it_is_ipc(self):
        with patch.object(self.worker,'_child',malformed_child), self.assertRaises(self.worker.WorkerFailure):
            self.worker.run_worker('inspect',{},seconds=5)

    def test_worker_limits_cannot_increase_or_admit_nan(self):
        for value in (0,31,float('nan'),float('inf')):
            with self.assertRaises(ValueError):
                self.worker.run_worker('inspect',{},seconds=value)

    def test_validate_budget_failure_preserves_exit3(self):
        response = self.worker.run_worker('inspect',{'path':str(self.path),'profile_id':'linux-posix-bytes-v1',
                                                    'options':to_json_value(TargetOptions(root_units=100))})
        mapping = json.loads(response['draft_text'])
        mapping['decisions'][0].update(action='rename',targetPath='/'.join(['x']*65))
        with self.assertRaises(self.worker.WorkerFailure) as raised:
            self.worker.run_worker('validate',{'path':str(self.path),'mapping':json.dumps(mapping)})
        self.assertEqual(raised.exception.exit_code,3)

    def test_public_extract_api_has_its_own_parent_deadline(self):
        from archive_preflight.extract import extract_verified
        from archive_preflight.model import ExtractLimits
        report = self.worker.run_worker('inspect',{'path':str(self.path),'profile_id':'linux-posix-bytes-v1',
                                                 'options':to_json_value(TargetOptions(root_units=100))})
        plan = self.worker.run_worker('validate',{'path':str(self.path),'mapping':report['draft_text']})['plan']
        output = self.base/'out'
        with patch.object(self.worker,'_child',slow_child):
            result = extract_verified(self.path,plan,plan.plan_id,output,ExtractLimits(seconds=1))
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.cleanup.state,'retained_ownership_unknown')
        self.assertIsNone(result.actual_bytes)
        self.assertEqual((output/'sentinel').read_bytes(),b'retain')
