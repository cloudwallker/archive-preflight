"""Offline reports preserve engine evidence and export only strict naming drafts."""
from dataclasses import replace
from html.parser import HTMLParser
import importlib
import importlib.util
import json
from html import unescape
from pathlib import Path
import tempfile
import unittest

from archive_preflight.analyze import analyze
from archive_preflight.mapping import suggest_plan
from archive_preflight.model import ScanLimits,TargetOptions,to_json_value
from archive_preflight.profiles import load_profile
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip


class DataParser(HTMLParser):
    def __init__(self):
        super().__init__();self.active=False;self.data='';self.external=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='script' and attrs.get('id')=='report-data':self.active=True
        if 'src' in attrs or 'href' in attrs and not attrs['href'].startswith('#'):self.external.append(attrs)
    def handle_endtag(self,tag):
        if tag=='script':self.active=False
    def handle_data(self,data):
        if self.active:self.data+=data


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.report'),'offline report renderer required')
        self.module=importlib.import_module('archive_preflight.report')
        self.tmp=tempfile.TemporaryDirectory(dir=Path.cwd());self.addCleanup(self.tmp.cleanup)
        path=Path(self.tmp.name)/'synthetic.zip'
        path.write_bytes(make_zip([{'name':b'Report.txt','attr':0o100600<<16},{'name':b'report.txt','attr':0o100600<<16}]))
        self.report=analyze(read_index(path,ScanLimits()),load_profile('windows-win32-conservative-v1'),TargetOptions(root_units=100),{})
        self.draft=suggest_plan(self.report)
        self.report=replace(self.report,transformations=self.draft.transformations)
    def payload(self,html):
        parser=DataParser();parser.feed(html);self.assertEqual(parser.external,[])
        return json.loads(parser.data)
    def test_preserves_raw_candidates_groups_budgets_runtime_and_unique_draft(self):
        html=self.module.render_html(self.report,self.draft,'zh-CN')
        data=self.payload(html)
        self.assertEqual(data['report'],to_json_value(self.report))
        self.assertEqual(data['draft'],to_json_value(self.draft))
        self.assertNotIn('planId',data['draft'])
        self.assertIn('validate-plan',html)
        self.assertIn('Content-Security-Policy',html)
        self.assertIn("connect-src 'none'",unescape(html))
        self.assertNotIn('https://',html.lower())
    def test_untrusted_script_html_controls_bidi_remain_data(self):
        evil='</script><img src=x onerror=alert(1)>\x1b\n\u202e\u2028\u2029'
        candidate=replace(self.report.entries[0].candidates[0],text=evil)
        entry=replace(self.report.entries[0],default_display_name=evil,candidates=(candidate,))
        report=replace(self.report,entries=(entry,)+self.report.entries[1:])
        html=self.module.render_html(report,self.draft,'en')
        self.assertNotIn(evil,html)
        self.assertNotIn('<img src=x',html)
        self.assertEqual(self.payload(html)['report']['entries'][0]['candidates'][0]['text'],evil)
    def test_wrong_locale_or_archive_binding_rejected(self):
        for report,draft,locale in ((self.report,self.draft,'other'),(self.report,replace(self.draft,archive_id='wrong'),'en')):
            with self.assertRaises(ValueError):self.module.render_html(report,draft,locale)
