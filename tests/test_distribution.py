"""Public deadline options must lower, never enlarge, the real extraction budget."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class DistributionTests(unittest.TestCase):
    def test_seconds_strict_ipc_roundtrip_preserves_fraction_and_integer_limits(self):
        from archive_preflight.model import ExtractLimits,_decode,to_json_value
        for value in (60,60.0,0.5):
            limits=ExtractLimits(seconds=value)
            try:decoded=_decode(to_json_value(limits),ExtractLimits)
            except ValueError as error:self.fail('Valid seconds lost at strict IPC decoder: '+str(error))
            self.assertEqual(decoded,limits)
            self.assertEqual(limits.seconds,value)
        self.assertEqual(ExtractLimits().seconds,60)
        for value in (0,-1,60.01,float('nan'),float('inf'),True,'0.5'):
            with self.assertRaises(ValueError):ExtractLimits(seconds=value)
        with self.assertRaises(ValueError):ExtractLimits(files=1.5)
        with self.assertRaises(ValueError):_decode(dict(to_json_value(ExtractLimits()),seconds=True),ExtractLimits)
        from archive_preflight.model import _schema
        self.assertEqual(_schema(ExtractLimits)['$defs']['ExtractLimits']['properties']['seconds'],{'type':'number','exclusiveMinimum':0,'maximum':60})
    def test_extract_seconds_domain_and_single_public_entry_consumption(self):
        from archive_preflight.cli import _parser,main
        from archive_preflight.model import ExtractLimits
        from tests.test_extract import ExtractTests
        # Real indexed/validated source and strict plan; observer stops before writes.
        fixture=ExtractTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        plan=fixture.plan();path=fixture.base/'plan.json'
        from archive_preflight.model import dumps
        path.write_text(dumps(plan),encoding='ascii')
        args=['extract',str(fixture.path),'--plan',str(path),'--accept-plan',plan.plan_id,'--output',str(fixture.out)]
        def invoke(argv):
            try:return main(argv)
            except SystemExit as error:return error.code
        for value in ('0','-1','61','nan','inf'):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(invoke(args+['--seconds',value]),2)
            self.assertFalse(fixture.out.exists())
        consumed=[]
        from archive_preflight.worker import _failure_result
        def observe(source,validated,accepted,output,limits):
            consumed.append(limits.seconds)
            return _failure_result({'plan_id':plan.plan_id,'archive_id':plan.archive_id},'WORKER_TIMEOUT')
        with patch('archive_preflight.cli.extract_verified',observe),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(invoke(args),4)
            self.assertEqual(invoke(args+['--seconds','0.5']),4)
        self.assertEqual(consumed,[60,0.5])
