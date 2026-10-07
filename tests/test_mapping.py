"""Deterministic drafts and complete validation of untrusted naming plans."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
import copy
import json

from archive_preflight.analyze import analyze
from archive_preflight.mapping import (MappingValidationError, revalidate_imported_plan,
                                     suggest_plan, validate_plan, plan_id_projection)
from archive_preflight.model import (DirectoryMapping, ScanLimits, TargetOptions, dumps,
                                    loads_mapping, loads_validated_plan, to_json_value)
from archive_preflight.profiles import load_profile
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip, unicode_path


class MappingTests(unittest.TestCase):
    def inspect(self, names, profile='windows-win32-conservative-v1', **options):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'mapping.zip'
            path.write_bytes(make_zip(names))
            index = read_index(path, ScanLimits())
        report = analyze(index, load_profile(profile), TargetOptions(root_units=1, **options), {})
        return index, report

    def test_suggestion_deterministic_and_suffix_reserved(self):
        index, report = self.inspect([b'Report.txt', b'report.txt', b'Report_e000002.txt'])
        plan = suggest_plan(report)
        self.assertEqual(plan, suggest_plan(report))
        self.assertEqual([d.target_path for d in plan.decisions],
                         ['Report.txt', 'report_e000002_2.txt', 'Report_e000002.txt'])
        self.assertTrue(validate_plan(index, plan).extractable)

    def test_directory_rename_propagates(self):
        index, report = self.inspect([b'Dir/x', b'dir/y', b'a', b'a/z'])
        plan = suggest_plan(report)
        self.assertEqual([d.target_path for d in plan.decisions],
                         ['Dir/x', 'dir_e000002/y', 'a_e000003', 'a/z'])
        self.assertTrue(validate_plan(index, plan).extractable)

    def test_unknown_encoding_requires_choice(self):
        index, report = self.inspect([b'\x82\xa0.txt'])
        plan = suggest_plan(report)
        decision = plan.decisions[0]
        self.assertIsNone(decision.encoding_candidate_id)
        self.assertFalse(decision.name_confirmed)
        with self.assertRaises(ValueError):
            validate_plan(index, plan)
        selected = next(c for c in report.entries[0].candidates if c.valid)
        chosen = replace(decision, encoding_candidate_id=selected.candidate_id,
                         target_path=selected.text, name_confirmed=True)
        self.assertTrue(validate_plan(index, replace(plan, decisions=(chosen,))).extractable)
        explicit = replace(decision, target_path='chosen.txt', name_confirmed=True, action='rename')
        self.assertTrue(validate_plan(index, replace(plan, decisions=(explicit,))).extractable)

    def test_mapping_rechecks_every_entry(self):
        index, report = self.inspect([b'x', b'y'])
        draft = suggest_plan(report)
        for targets in (('CON', 'y'), ('../x', 'y'), ('a', 'a/x'), ('X', 'x'), ('x', 'x'),
                        ('\u00e9', 'e\u0301')):
            profile = 'macos-apfs-ci-advisory-v1' if targets[0] == '\u00e9' else draft.profile_id
            changed = replace(draft, profile_id=profile, decisions=tuple(
                replace(d, target_path=target, action='rename') for d, target in zip(draft.decisions, targets)))
            with self.subTest(targets=targets), self.assertRaises(MappingValidationError):
                validate_plan(index, changed)
        for decisions in (draft.decisions[:1], draft.decisions+draft.decisions[:1],
                          (replace(draft.decisions[0], entry_id='e999999'), draft.decisions[1])):
            with self.assertRaises(MappingValidationError):
                validate_plan(index, replace(draft, decisions=decisions))
        for field, value in (('archive_id', 'wrong'), ('profile_id', 'unknown')):
            with self.assertRaises(MappingValidationError):
                validate_plan(index, replace(draft, **{field: value}))

    def test_import_derived_tampering_and_recomputed_invalid_id(self):
        import hashlib
        index, report = self.inspect([b'a'])
        validated = validate_plan(index, suggest_plan(report))
        self.assertEqual(revalidate_imported_plan(index, dumps(validated)), validated)
        self.assertEqual(loads_validated_plan(dumps(validated)), validated)
        for field, value in (('resolvedPaths', {'e000001': 'wrong'}), ('extractable', False), ('planId', '0'*64)):
            changed = to_json_value(validated)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                revalidate_imported_plan(index, changed)
        bad = replace(validated, decisions=(replace(validated.decisions[0], action='rename', target_path='../x'),),
                      resolved_paths={'e000001': '../x'})
        bad = replace(bad, plan_id=hashlib.sha256(dumps(plan_id_projection(bad)).encode('ascii')).hexdigest())
        with self.assertRaises(MappingValidationError):
            revalidate_imported_plan(index, bad)

    def test_reason_target_and_options_bind_plan_id(self):
        index, report = self.inspect([b'a'])
        draft = suggest_plan(report)
        original = validate_plan(index, draft)
        for decision in (replace(draft.decisions[0], reason='user explanation'),
                         replace(draft.decisions[0], target_path='b', action='rename')):
            changed = validate_plan(index, replace(draft, decisions=(decision,)))
            self.assertNotEqual(original.plan_id, changed.plan_id)
        changed = validate_plan(index, replace(draft, target_options=replace(draft.target_options, root_units=2)))
        self.assertNotEqual(original.plan_id, changed.plan_id)
        self.assertEqual(original.plan_id, validate_plan(index, loads_mapping(dumps(draft))).plan_id)

    def test_linux_advisories_preserve_original_names(self):
        index, report = self.inspect([{'name': text.encode(), 'flags': 0x800} for text in
                                     ('Dir/x', 'dir/y', '\u00e9', 'e\u0301')], profile='linux-posix-bytes-v1')
        draft = suggest_plan(report)
        self.assertTrue(all(d.action == 'keep' for d in draft.decisions))
        self.assertFalse(draft.directory_mappings)
        result = validate_plan(index, draft)
        self.assertTrue(result.extractable)
        self.assertTrue(any(d.code == 'TARGET_COMPARISON_ADVISORY' for d in result.remaining_advisories))

    def test_multilevel_directory_merge_and_duplicate_directories(self):
        index, report = self.inspect([b'Dir/Sub/x', b'dir/sub/y',
                                     {'name': b'Dir/', 'attr': 0x10}, {'name': b'Dir/', 'attr': 0x10}])
        draft = suggest_plan(report)
        self.assertEqual([d.target_path for d in draft.decisions],
                         ['Dir/Sub/x', 'dir_e000002/sub/y', 'Dir', 'Dir'])
        self.assertTrue(validate_plan(index, draft).extractable)

    def test_directory_mapping_conflict_skip_and_stale_encoding_node(self):
        index, report = self.inspect([b'Dir/x', b'dir/y'])
        draft = suggest_plan(report)
        changed = replace(draft, decisions=(draft.decisions[0], replace(draft.decisions[1], target_path='wrong/y')))
        with self.assertRaises(MappingValidationError):
            validate_plan(index, changed)
        skipped = replace(draft, decisions=(draft.decisions[0], replace(draft.decisions[1], action='skip', target_path=None)))
        result = validate_plan(index, skipped)
        self.assertEqual(dict(result.resolved_paths), {'e000001': 'Dir/x'})
        self.assertIn('ENTRY_SKIPPED', [d.code for d in result.diagnostics])
        index, report = self.inspect([b'\x82\xa0/x'])
        draft = suggest_plan(report)
        node = report.logical_directories[0]
        candidate = next(c for c in report.entries[0].candidates if c.valid and c.text != report.entries[0].default_display_name)
        chosen = replace(draft.decisions[0], encoding_candidate_id=candidate.candidate_id,
                         target_path=candidate.text, name_confirmed=True)
        changed = replace(draft, decisions=(chosen,), directory_mappings=(DirectoryMapping(node.node_id, 'chosen'),))
        with self.assertRaises(MappingValidationError):
            validate_plan(index, changed)

    def test_skip_blocked_and_invalid_utf8_not_repaired(self):
        index, report = self.inspect([b'../bad', {'name': b'\xff', 'flags': 0x800}, b'good'])
        draft = suggest_plan(report)
        self.assertEqual([d.action for d in draft.decisions], ['skip', 'skip', 'keep'])
        self.assertEqual([d.target_path for d in draft.decisions[:2]], [None, None])
        self.assertTrue(validate_plan(index, draft).extractable)
        repaired = replace(draft.decisions[1], action='rename', target_path='repaired', name_confirmed=True,
                           encoding_candidate_id='forged')
        with self.assertRaises(MappingValidationError):
            validate_plan(index, replace(draft, decisions=(draft.decisions[0], repaired, draft.decisions[2])))

    def test_component_boundaries_extension_and_suffix_budget(self):
        index, report = self.inspect([{'name': ('\U0001f600'*20+'.txt').encode(), 'flags': 0x800}], component_limit=15)
        draft = suggest_plan(report)
        self.assertEqual(draft.decisions[0].target_path, '\U0001f600'*5+'.txt')
        self.assertTrue(validate_plan(index, draft).extractable)
        index, report = self.inspect([b'abcdef', b'ABCDEF'], component_limit=3)
        with self.assertRaises(ValueError):
            suggest_plan(report)
        index, report = self.inspect([b'a.'+b'x'*100])
        self.assertEqual(suggest_plan(report).decisions[0].target_path, 'a.'+'x'*100)

    def test_full_path_not_flattened_and_unknown_root_ineligible(self):
        index, report = self.inspect([b'longdirectory/file'], path_limit=10, directory_path_limit=10)
        draft = suggest_plan(report)
        self.assertEqual(draft.decisions[0].target_path, 'longdirectory/file')
        with self.assertRaises(MappingValidationError):
            validate_plan(index, draft)
        index, report = self.inspect([b'a'])
        result = validate_plan(index, replace(suggest_plan(report), target_options=TargetOptions()))
        self.assertFalse(result.extractable)
        self.assertIn('PATH_ROOT_UNKNOWN', [d.code for d in result.diagnostics])

    def test_strict_mapping_json_fields_and_text_budget(self):
        _, report = self.inspect([b'a'])
        value = to_json_value(suggest_plan(report))
        self.assertNotIn('transformations', value)
        for field, bad in (('extra', 1), ('transformations', []), ('schemaVersion', 2)):
            changed = copy.deepcopy(value)
            changed[field] = bad
            with self.assertRaises(ValueError):
                loads_mapping(json.dumps(changed))
        changed = copy.deepcopy(value)
        del changed['decisions'][0]['reason']
        with self.assertRaises(ValueError):
            loads_mapping(json.dumps(changed))
        with self.assertRaises(ValueError):
            loads_mapping('{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises(ValueError):
            loads_mapping(dumps(suggest_plan(report)), max_bytes=10)
        self.assertEqual(loads_mapping(dumps(suggest_plan(report))).transformations, ())

    def test_nonstandard_explicit_mapping_and_directory_decision_conflict(self):
        index, report = self.inspect([b'a//b'])
        draft = suggest_plan(report)
        explicit = replace(draft.decisions[0], action='rename', target_path='a/b', name_confirmed=True)
        self.assertTrue(validate_plan(index, replace(draft, decisions=(explicit,))).extractable)
        index, report = self.inspect([{'name': b'a/', 'attr': 0x10}, b'a/x'])
        draft = suggest_plan(report)
        changed = replace(draft, decisions=(replace(draft.decisions[0], action='rename', target_path='b'), draft.decisions[1]))
        with self.assertRaises(MappingValidationError):
            validate_plan(index, changed)

    def test_explicit_new_parent_and_implicit_directory_budget(self):
        index, report = self.inspect([b'x', b'y'])
        draft = suggest_plan(report)
        changed = replace(draft, decisions=tuple(replace(d, action='rename', target_path='new/'+d.target_path)
                                                 for d in draft.decisions))
        self.assertTrue(validate_plan(index, changed).extractable)
        # A file limit cannot bypass the stricter directory budget of its parent.
        index, report = self.inspect([b'x'], path_limit=40, directory_path_limit=5)
        draft = suggest_plan(report)
        changed = replace(draft, decisions=(replace(draft.decisions[0], action='rename', target_path='longparent/x'),))
        with self.assertRaises(MappingValidationError):
            validate_plan(index, changed)

    def test_method_qualification_and_encryption_cannot_be_renamed(self):
        index, report = self.inspect([{'name': b'a', 'method': 99}])
        draft = suggest_plan(report)
        keep = replace(draft.decisions[0], action='keep', target_path='a')
        result = validate_plan(index, replace(draft, decisions=(keep,)))
        self.assertFalse(result.extractable)
        self.assertIn('SOURCE_METHOD_OR_ENCRYPTION_UNSUPPORTED', [d.code for d in result.diagnostics])
        index, report = self.inspect([{'name': b'a', 'flags': 1}])
        draft = suggest_plan(report)
        keep = replace(draft.decisions[0], action='rename', target_path='renamed')
        with self.assertRaises(MappingValidationError):
            validate_plan(index, replace(draft, decisions=(keep,)))

    def test_import_every_binding_and_array_canonical_order(self):
        index, report = self.inspect([b'a/x', b'A/y'])
        draft = suggest_plan(report)
        validated = validate_plan(index, draft)
        mutations = {'archiveId': '0'*64, 'profileId': 'linux-posix-bytes-v1',
                     'profileVersion': 'wrong', 'unicodeVersion': 'wrong', 'schemaVersion': 2,
                     'targetOptions': {**to_json_value(draft.target_options), 'rootUnits': '2'},
                     'directoryMappings': [], 'decisions': [{**to_json_value(draft.decisions[0]), 'reason': 'changed'},
                                                            to_json_value(draft.decisions[1])]}
        for field, value in mutations.items():
            changed = to_json_value(validated)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                revalidate_imported_plan(index, changed)
        reordered = replace(draft, decisions=tuple(reversed(draft.decisions)), directory_mappings=tuple(reversed(draft.directory_mappings)))
        self.assertEqual(validate_plan(index, reordered).plan_id, validated.plan_id)

    def test_transform_evidence_does_not_come_from_user_reason(self):
        index, report = self.inspect([b'CON'])
        draft = suggest_plan(report)
        self.assertIsNone(draft.decisions[0].reason)
        self.assertIn('WINDOWS_DEVICE_NAME', draft.transformations[0].reason_codes)
        user = replace(draft, decisions=(replace(draft.decisions[0], reason='WINDOWS_DEVICE_NAME'),))
        loaded = loads_mapping(dumps(user))
        self.assertEqual(loaded.transformations, ())
        self.assertTrue(validate_plan(index, loaded).extractable)

    def test_truncation_rechecks_resulting_component_rules(self):
        for name, limit in ((b'CONSTANT', 3), (b'A.long', 2), (b'.hidden', 1)):
            index, report = self.inspect([name], component_limit=limit)
            draft = suggest_plan(report)
            with self.subTest(name=name):
                self.assertTrue(validate_plan(index, draft).extractable)
        index, report = self.inspect([b'abcdefghij', b'ABCDEFGHIJ'], component_limit=10)
        draft = suggest_plan(report)
        self.assertTrue(any('COMPONENT_LIMIT' in t.reason_codes and 'NAME_COLLISION' in t.reason_codes
                            for t in draft.transformations))

    def test_known_metadata_qualification_and_declared_size_boundaries(self):
        file_limit = 256*1024**2
        cases = [([{'name': b'a', 'system': 42}], 'UNKNOWN_CREATE_SYSTEM'),
                 ([{'name': b'd/'}], 'MISSING_DIRECTORY_METADATA'),
                 ([{'name': b'a', 'compressed': 0, 'size': 1}], 'ZERO_COMPRESSED_NONZERO_OUTPUT'),
                 ([{'name': b'a', 'size': file_limit+1}], 'DECLARED_FILE_LIMIT'),
                 ([{'name': str(i).encode(), 'size': file_limit} for i in range(4)]
                  +[{'name': b'last', 'size': 1}], 'DECLARED_TOTAL_LIMIT')]
        for names, expected in cases:
            index, report = self.inspect(names, profile='linux-posix-bytes-v1')
            result = validate_plan(index, suggest_plan(report))
            with self.subTest(code=expected):
                self.assertFalse(result.extractable)
                self.assertIn(expected, [d.code for d in result.diagnostics])
        index, report = self.inspect([{'name': str(i).encode(), 'size': file_limit} for i in range(4)],
                                     profile='linux-posix-bytes-v1')
        draft = suggest_plan(report)
        self.assertTrue(validate_plan(index, draft).extractable)
        skipped = replace(draft, decisions=tuple(replace(d, action='skip', target_path=None) for d in draft.decisions))
        self.assertTrue(validate_plan(index, skipped).extractable)

    def test_file_and_resolved_directory_count_boundaries(self):
        index, report = self.inspect([('f'+str(i)).encode() for i in range(10001)], profile='linux-posix-bytes-v1')
        draft = suggest_plan(report)
        self.assertFalse(validate_plan(index, draft).extractable)
        decisions = tuple(replace(d, action='rename', target_path=f'd{i:05d}/x')
                          for i, d in enumerate(draft.decisions[:-1]))
        skipped = replace(draft.decisions[-1], action='skip', target_path=None)
        below = replace(draft, decisions=decisions+(skipped,))
        self.assertTrue(validate_plan(index, below).extractable)
        above_dirs = replace(below, decisions=(replace(decisions[0], target_path='d00000/sub/x'),)+decisions[1:]+(skipped,))
        result = validate_plan(index, above_dirs)
        self.assertFalse(result.extractable)
        self.assertIn('TARGET_DIRECTORY_COUNT_LIMIT', [d.code for d in result.diagnostics])

    def test_duplicate_directory_records_not_double_counted(self):
        index, report = self.inspect([{'name': b'd/', 'attr': 0x10}, {'name': b'd/', 'attr': 0x10}, b'd/x'])
        result = validate_plan(index, suggest_plan(report))
        self.assertTrue(result.extractable)
        self.assertEqual(len(result.resolved_paths), 3)
        index, report = self.inspect([{'name': b'd/', 'attr': 0x10} for _ in range(10001)],
                                     profile='linux-posix-bytes-v1')
        self.assertTrue(validate_plan(index, suggest_plan(report)).extractable)

    def test_generated_validated_plan_fits_its_import_budget(self):
        index, report = self.inspect([b'a'])
        draft = suggest_plan(report)
        result = validate_plan(index, draft)
        self.assertLess(len(dumps(draft)), len(dumps(result)))
        lowered = replace(index, limits=replace(index.limits, plan_bytes=len(dumps(draft))))
        with self.assertRaises(MappingValidationError):
            validate_plan(lowered, draft)

    def test_unknown_encoding_nonstandard_combinations_require_confirmation(self):
        for raw in (b'\x82\xa0//b', b'\x82\xa0\\b', b'\x82\xa0/'):
            with self.subTest(raw=raw):
                index, report = self.inspect([raw])
                entry = report.entries[0]
                self.assertEqual(entry.name_state, 'nonstandard')
                self.assertIn('ENCODING_AMBIGUOUS', entry.diagnostic_ids)
                draft = suggest_plan(report)
                decision = replace(draft.decisions[0], action='rename', target_path='chosen.txt',
                                   encoding_candidate_id=None, name_confirmed=False)
                with self.assertRaisesRegex(MappingValidationError, 'ENCODING_CONFIRMATION_REQUIRED'):
                    validate_plan(index, replace(draft, decisions=(decision,)))

    def test_unknown_encoding_nonstandard_confirm_choice_and_skip(self):
        for raw in (b'\x82\xa0//b', b'\x82\xa0\\b', b'\x82\xa0/'):
            with self.subTest(raw=raw):
                index, report = self.inspect([raw])
                draft = suggest_plan(report)
                decision = replace(draft.decisions[0], action='rename', target_path='chosen.txt',
                                   encoding_candidate_id=None, name_confirmed=False)
                candidate = next(c for c in report.entries[0].candidates if c.valid)
                for confirmed in (replace(decision, name_confirmed=True),
                                  replace(decision, encoding_candidate_id=candidate.candidate_id)):
                    result = validate_plan(index, replace(draft, decisions=(confirmed,)))
                    self.assertEqual(dict(result.resolved_paths), {'e000001': 'chosen.txt'})
                    # Missing directory metadata still independently prevents extraction.
                    self.assertEqual(result.extractable, not raw.endswith(b'/'))
                skip = replace(decision, action='skip', target_path=None)
                result = validate_plan(index, replace(draft, decisions=(skip,)))
                self.assertTrue(result.extractable)
                self.assertFalse(result.resolved_paths)
                invalid = replace(decision, encoding_candidate_id='unknown')
                with self.assertRaisesRegex(MappingValidationError, 'INVALID_CANDIDATE_CHOICE'):
                    validate_plan(index, replace(draft, decisions=(invalid,)))

    def test_authoritative_and_ascii_nonstandard_names_need_no_confirmation(self):
        raw = b'\x82\xa0//b'
        fixtures = ({'name': '\u00e9//b'.encode(), 'flags': 0x800},
                    {'name': raw, 'extra': unicode_path(raw, '\u65e5//b')},
                    {'name': b'a//b'}, {'name': b'a\\b'})
        for fixture in fixtures:
            with self.subTest(fixture=fixture['name']):
                index, report = self.inspect([fixture])
                self.assertEqual(report.entries[0].name_state, 'nonstandard')
                self.assertNotIn('ENCODING_AMBIGUOUS', report.entries[0].diagnostic_ids)
                draft = suggest_plan(report)
                decision = replace(draft.decisions[0], action='rename', target_path='chosen.txt',
                                   encoding_candidate_id=None, name_confirmed=False)
                self.assertTrue(validate_plan(index, replace(draft, decisions=(decision,))).extractable)
        for fixture in ({'name': b'\xff//b', 'flags': 0x800},
                        {'name': raw, 'extra': unicode_path(raw, 'known', crc=0)},
                        {'name': b'\x82\xa0/../b'}):
            with self.subTest(blocked=fixture['name']):
                index, report = self.inspect([fixture])
                self.assertEqual(report.entries[0].name_state, 'blocked')
                draft = suggest_plan(report)
                decision = replace(draft.decisions[0], action='rename', target_path='chosen.txt',
                                   encoding_candidate_id=None, name_confirmed=True)
                with self.assertRaisesRegex(MappingValidationError, 'SOURCE_ENTRY_BLOCKED'):
                    validate_plan(index, replace(draft, decisions=(decision,)))

    def test_recomputed_import_id_cannot_bypass_combined_encoding_confirmation(self):
        import hashlib
        index, report = self.inspect([b'\x82\xa0//b'])
        draft = suggest_plan(report)
        confirmed = replace(draft.decisions[0], action='rename', target_path='chosen.txt',
                            encoding_candidate_id=None, name_confirmed=True)
        plan = validate_plan(index, replace(draft, decisions=(confirmed,)))
        self.assertEqual(revalidate_imported_plan(index, dumps(plan)), plan)
        unconfirmed = replace(plan, decisions=(replace(confirmed, name_confirmed=False),))
        unconfirmed = replace(unconfirmed, plan_id=hashlib.sha256(
            dumps(plan_id_projection(unconfirmed)).encode('ascii')).hexdigest())
        for value in (unconfirmed, dumps(unconfirmed), to_json_value(unconfirmed)):
            with self.subTest(import_type=type(value).__name__):
                with self.assertRaisesRegex(MappingValidationError, 'ENCODING_CONFIRMATION_REQUIRED'):
                    revalidate_imported_plan(index, value)
