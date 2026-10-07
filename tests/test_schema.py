"""Independent protocol examples, also consumed by an external development validator."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from archive_preflight.analyze import analyze
from archive_preflight.model import (ScanLimits, TargetOptions, dumps, loads_mapping, loads_validated_plan,
                                    loads_report, report_schema, mapping_schema, validated_plan_schema, to_json_value,
                                    ExtractionResult,CleanupResult,WrittenEntry,Diagnostic,loads_extraction_result,extraction_result_schema)
from archive_preflight.profiles import load_profile
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip


def _report(profile_id):
    data = make_zip([b'a'])
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp)/'schema.zip'
        path.write_bytes(data)
        result = analyze(read_index(path, ScanLimits()), load_profile(profile_id), TargetOptions(root_units=1), {})
        if hashlib.sha256(data).digest() != hashlib.sha256(path.read_bytes()).digest():
            raise AssertionError('Schema fixture source changed')
    return to_json_value(result)


def contract_cases():
    base = _report('windows-win32-conservative-v1')
    yield 'valid-windows-report', base, True
    limits = {'archiveBytes': (8589934592, True), 'centralBytes': (16777216, True), 'entries': (50000, False),
              'nameBytes': (4096, True), 'depth': (64, False), 'groupMembers': (200000, False),
              'planBytes': (16777216, True), 'exportBytes': (67108864, True), 'seconds': (30, False)}
    for key, (maximum, decimal) in limits.items():
        for value in (-1, 0, 1, maximum-1, maximum, maximum+1):
            changed = copy.deepcopy(base)
            changed['limits'][key] = str(value) if decimal else value
            yield f'limit-{key}-{value}', changed, 0 < value <= maximum
        changed = copy.deepcopy(base)
        changed['limits'][key] = True
        yield 'limit-bool-'+key, changed, False
        if decimal:
            for value in ('01', '+1', '1.0', '1e3', '1\n', 1):
                changed = copy.deepcopy(base)
                changed['limits'][key] = value
                yield f'limit-decimal-{key}-{value!r}', changed, False
    profiles = (('windows-win32-conservative-v1', 259, 247), ('macos-apfs-ci-advisory-v1', 1023, 1023),
                ('macos-apfs-cs-advisory-v1', 1023, 1023), ('linux-posix-bytes-v1', 4095, 4095))
    for profile_id, path_max, directory_max in profiles:
        value = _report(profile_id)
        yield 'valid-profile-'+profile_id, value, True
        for key, maximum in (('componentLimit', 255), ('pathLimit', path_max), ('directoryPathLimit', directory_max)):
            for limit in (None, -1, 0, 1, maximum-1, maximum, maximum+1, True):
                changed = copy.deepcopy(value)
                changed['options'][key] = limit
                yield f'option-{profile_id}-{key}-{limit}', changed, limit is None or (type(limit) is int and 0 < limit <= maximum)
        for key, forged in (('profileId', 'unknown'), ('version', 'portability-v2'), ('units', 'forged'),
                            ('rules', [['exact', 'advisory']]), ('componentLimit', 254), ('pathLimit', path_max+1),
                            ('directoryPathLimit', directory_max+1)):
            changed = copy.deepcopy(value)
            changed['profile'][key] = forged
            yield f'profile-forged-{profile_id}-{key}', changed, False
    for key, value, expected in (('rootUnits', '0', True), ('rootUnits', '999999999999999', True),
                                 ('rootUnits', '-1', False), ('rootUnits', True, False), ('rootUnits', '0\n', False),
                                 ('unicodeVersion', 'forged', False)):
        changed = copy.deepcopy(base)
        changed['options'][key] = value
        yield 'option-general-'+key+'-'+repr(value), changed, expected
    for key in ('declaredBytes', 'compressedBytes', 'localOffset', 'centralOffset'):
        for value in ('0', '8589934593'):
            changed = copy.deepcopy(base)
            changed['entries'][0]['raw'][key] = value
            yield f'ordinary-byte-not-a-scan-limit-{key}-{value}', changed, True
    for value, expected in (('YQ==', True), ('', True), ('YR==', False), ('YQ==\n', False), ('!', False)):
        changed = copy.deepcopy(base)
        changed['entries'][0]['raw']['rawNameBase64'] = value
        yield 'canonical-base64-'+repr(value), changed, expected


def plan_contract_cases():
    from archive_preflight.mapping import suggest_plan, validate_plan
    profiles = (('windows-win32-conservative-v1', 259, 247), ('macos-apfs-ci-advisory-v1', 1023, 1023),
                ('macos-apfs-cs-advisory-v1', 1023, 1023), ('linux-posix-bytes-v1', 4095, 4095))
    for profile_id, path_max, dir_max in profiles:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'plan-schema.zip'
            path.write_bytes(make_zip([b'a', b'../skip']))
            index = read_index(path, ScanLimits())
        draft = suggest_plan(analyze(index, load_profile(profile_id), TargetOptions(root_units=1), {}))
        for kind, plan in (('mapping', draft), ('validated', validate_plan(index, draft))):
            base = to_json_value(plan)
            yield kind, profile_id+'-valid', base, True
            for key, maximum in (('componentLimit', 255), ('pathLimit', path_max), ('directoryPathLimit', dir_max)):
                for option in (None, 0, 1, maximum, maximum+1, True):
                    changed = copy.deepcopy(base)
                    changed['targetOptions'][key] = option
                    yield kind, f'{profile_id}-{key}-{option}', changed, option is None or type(option) is int and 0 < option <= maximum
            for key, value in (('extra', 1), ('schemaVersion', 2), ('profileId', 'forged'), ('transformations', [])):
                changed = copy.deepcopy(base)
                changed[key] = value
                yield kind, f'{profile_id}-root-{key}', changed, False
            for field, value in (('unicodeVersion', 'forged'), ('rootUnits', '01'), ('rootUnits', True)):
                changed = copy.deepcopy(base)
                changed['targetOptions'][field] = value
                yield kind, f'{profile_id}-option-{field}', changed, False
            for entry, key, value in ((0, 'targetPath', None), (0, 'targetPath', ''), (0, 'action', 'forged'),
                                      (0, 'nameConfirmed', 1), (1, 'targetPath', 'unsafe')):
                changed = copy.deepcopy(base)
                changed['decisions'][entry][key] = value
                yield kind, f'{profile_id}-decision-{entry}-{key}', changed, False
            changed = copy.deepcopy(base)
            del changed['directoryMappings']
            yield kind, profile_id+'-optional-directories', changed, kind == 'mapping'
            if kind == 'validated':
                for key, value in (('profileVersion', 'forged'), ('unicodeVersion', 'forged'), ('extractable', 1),
                                   ('resolvedPaths', {'e000001': 1})):
                    changed = copy.deepcopy(base)
                    changed[key] = value
                    yield kind, profile_id+'-'+key, changed, False


def extraction_contract_cases():
    base = to_json_value(ExtractionResult('verified','p','a','windows-ntfs-native',1,1,5,
                         (WrittenEntry('e000001','folder/a','file',5,123,'a'*64),WrittenEntry(None,'folder','directory',0)),
                         ('e000002',),(Diagnostic('ENTRY_SKIPPED','info'),),CleanupResult('not_needed')))
    yield 'valid',base,True
    for field,value in (('schemaVersion',2),('schemaVersion',True),('status','ok'),('actualBytes',5),
                         ('actualBytes','01'),('actualBytes','-1'),('actualFiles',True),('actualFiles',-1),('extra',1)):
        item = copy.deepcopy(base)
        item[field] = value
        yield field+'-'+repr(value),item,False
    for state in ('not_created','removed','retained_ownership_unknown','cleanup_failed','not_needed','unknown'):
        item = copy.deepcopy(base)
        item['cleanup']['state'] = state
        yield 'cleanup-'+state,item,state!='unknown'
    unknown = copy.deepcopy(base)
    unknown.update(status='failed',actualFiles=None,actualDirectories=None,actualBytes=None)
    unknown['cleanup']['state']='retained_ownership_unknown'
    unknown['diagnostics']=[to_json_value(Diagnostic('ACTUAL_COUNTS_UNAVAILABLE'))]
    yield 'unavailable-actual-counts',unknown,True
    for kind in ('verified','missing-diagnostic','partial-null'):
        item=copy.deepcopy(unknown)
        if kind=='verified': item['status']='verified'
        elif kind=='missing-diagnostic': item['diagnostics']=[]
        else: item['actualFiles']=0
        yield 'unavailable-invalid-'+kind,item,False
    for field,value in (('kind','link'),('size',1),('entryId',1),('crc32',-1),('sha256',False)):
        item = copy.deepcopy(base)
        item['entries'][0][field] = value
        yield 'entry-'+field,item,False


class SchemaTests(unittest.TestCase):
    def test_extraction_decoder_contract(self):
        for name,value,expected in extraction_contract_cases():
            with self.subTest(name=name):
                try:
                    loads_extraction_result(json.dumps(value))
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted,expected)
    def test_decoder_finite_contract_examples(self):
        for name, value, expected in contract_cases():
            with self.subTest(case=name):
                try:
                    loads_report(json.dumps(value))
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted, expected)

    def test_schema_retains_canonical_decimal_and_byte_field_kinds(self):
        schema = report_schema()
        self.assertEqual(schema['$defs']['ScanLimits']['properties']['archiveBytes']['type'], 'string')
        self.assertEqual(schema['$defs']['RawEntry']['properties']['declaredBytes']['type'], 'string')

    def test_plan_decoder_contract(self):
        for kind, name, value, expected in plan_contract_cases():
            with self.subTest(kind=kind, case=name):
                decoder = loads_mapping if kind == 'mapping' else loads_validated_plan
                try:
                    decoder(json.dumps(value))
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted, expected)

    def test_public_schemas_equal_unique_model_authority(self):
        root = Path(__file__).resolve().parents[1]/'schemas'
        for name, producer in (('report', report_schema), ('mapping', mapping_schema), ('validated-plan', validated_plan_schema),
                               ('extraction-result',extraction_result_schema)):
            with self.subTest(schema=name):
                self.assertEqual(json.loads((root/(name+'-v1.json')).read_text('ascii')), producer())

    def test_plan_raw_integer_syntax_and_duplicate_fields(self):
        for kind, _, value, expected in plan_contract_cases():
            if not expected:
                continue
            decoder = loads_mapping if kind == 'mapping' else loads_validated_plan
            for token in ('-0', '1.0', '1e0', 'true'):
                text = json.dumps(value).replace('"schemaVersion": 1', '"schemaVersion": '+token)
                with self.assertRaises(ValueError):
                    decoder(text)
            text = json.dumps(value).replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1')
            with self.assertRaises(ValueError):
                decoder(text)
            break


if __name__ == '__main__':
    unittest.main()
