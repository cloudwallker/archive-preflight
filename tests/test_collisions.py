import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

from archive_preflight.model import ScanLimits, TargetOptions, dumps
from archive_preflight.zip_index import read_index
from tests.helpers_zip import make_zip


class CollisionTests(unittest.TestCase):
    def report(self, entries, profile='windows-win32-conservative-v1', choices=None, options=None, **limits):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.analyze'), 'shared tree analysis missing')
        from archive_preflight.analyze import analyze
        from archive_preflight.profiles import load_profile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'sample.zip'
            path.write_bytes(make_zip(entries))
            index = read_index(path, ScanLimits(**limits))
        return analyze(index, load_profile(profile), options or TargetOptions(), choices or {})

    def test_linux_ascii_casefold_advisory_files_and_parent_directories(self):
        for names, impact in (([b'Report.txt', b'report.txt'], 'file-overwrite'), ([b'Dir/x', b'dir/y'], 'directory-merge')):
            with self.subTest(names=names):
                report = self.report(names, 'linux-posix-bytes-v1', options=TargetOptions(root_units=1))
                self.assertEqual(report.state, 'findings')
                self.assertTrue(report.complete)
                groups = [g for g in report.collision_groups if g.rule_id == 'casefold']
                self.assertEqual(len(groups), 1)
                self.assertEqual(groups[0].certainty, 'advisory')
                self.assertEqual(groups[0].impact, impact)
                self.assertEqual(groups[0].entry_ids, ('e000001', 'e000002'))

    def test_existing_ascii_rules_keep_certainty_and_no_duplicate_casefold(self):
        for profile in ('windows-win32-conservative-v1', 'macos-apfs-ci-advisory-v1'):
            for names in ([b'Report.txt', b'report.txt'], [b'Dir/x', b'dir/y']):
                report = self.report(names, profile, options=TargetOptions(root_units=1))
                self.assertEqual([(g.rule_id, g.certainty) for g in report.collision_groups], [('ascii-case', 'config_rule')])

    def test_file_directory_prefix_collision(self):
        report = self.report([b'a', b'a/x'])
        group = next(g for g in report.collision_groups if g.rule_id == 'exact')
        self.assertEqual(group.entry_ids, ('e000001', 'e000002'))
        self.assertEqual(group.impact, 'file-directory')

    def test_casefold_directory_merge(self):
        report = self.report([b'Dir/Sub/x', b'dir/sub/y'])
        groups = [g for g in report.collision_groups if g.rule_id == 'ascii-case' and g.impact == 'directory-merge']
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(g.entry_ids == ('e000001', 'e000002') for g in groups))
        self.assertTrue(all(g.certainty == 'config_rule' for g in groups))

    def test_duplicate_directory_metadata_only(self):
        report = self.report([b'd/', b'd/', b'd/x'])
        self.assertEqual(len(report.logical_directories), 1)
        node = report.logical_directories[0]
        self.assertEqual(node.explicit_entry_ids, ('e000001', 'e000002'))
        self.assertEqual(node.descendant_entry_ids, ('e000003',))
        self.assertFalse(any(g.rule_id == 'exact' for g in report.collision_groups))
        self.assertIn('DUPLICATE_DIRECTORY_METADATA', [d.code for d in report.diagnostics])

    def test_directory_identity_context_changes(self):
        report = self.report([{'name': b'\x95\x5c/x'}, b'fixed/y'])
        cp = next(c for c in report.entries[0].candidates if c.source == 'cp932')
        chosen = self.report([{'name': b'\x95\x5c/x'}, b'fixed/y'], choices={'e000001': cp.candidate_id})
        old = {d.node_id for d in report.logical_directories}
        self.assertTrue(old.isdisjoint(d.node_id for d in chosen.logical_directories))
        self.assertIn(('表',), [d.source_parts for d in chosen.logical_directories])
        self.assertEqual(chosen.logical_directories, self.report([{'name': b'\x95\x5c/x'}, b'fixed/y'], choices={'e000001': cp.candidate_id}).logical_directories)

    def test_mixed_encoding_entry_choices(self):
        entries = [{'name': '中文'.encode('gb18030')}, {'name': b'\x82.txt'}]
        report = self.report(entries)
        choices = {e.entry_id: next(c.candidate_id for c in e.candidates if c.source == source) for e, source in zip(report.entries, ('gb18030', 'cp437'))}
        chosen = self.report(entries, choices=choices)
        self.assertEqual([e.default_display_name for e in chosen.entries], ['中文', 'é.txt'])
        self.assertTrue(all(e.name_state == 'selected' for e in chosen.entries))

    def test_invalid_paths_and_types_blocked(self):
        names = [b'../escape', b'a/../b', b'//server/x', b'/x', b'C:x', b'C:/x', b'\\\\?\\C:\\x', b'a\x00x', b'']
        report = self.report(names+[{'name': b'link', 'attr': 0o120777 << 16}, {'name': b'fifo', 'attr': 0o010600 << 16}, {'name': b'wrong/', 'attr': 0o100644 << 16}])
        self.assertTrue(all(e.name_state == 'blocked' for e in report.entries))
        self.assertNotEqual(report.state, 'ok')

    def test_nonstandard_names_and_unknown_platform(self):
        report = self.report([b'a\\b', b'./x', b'a//x', {'name': b'x', 'system': 42, 'attr': 0o120777 << 16}])
        self.assertTrue(all(e.name_state == 'nonstandard' for e in report.entries[:3]))
        self.assertNotEqual(report.entries[3].entry_type, 'symlink')

    def test_linux_normalization_advisory(self):
        entries = [{'name': s.encode(), 'flags': 0x800} for s in ('é', 'e\u0301')]
        linux = self.report(entries, 'linux-posix-bytes-v1')
        self.assertTrue(all(g.certainty == 'advisory' for g in linux.collision_groups))
        mac = self.report(entries, 'macos-apfs-cs-advisory-v1')
        self.assertIn(('nfc', 'approximation'), [(g.rule_id, g.certainty) for g in mac.collision_groups])

    def test_group_member_limit(self):
        report = self.report([b'a', b'a', b'a'], group_members=2)
        self.assertFalse(report.complete)
        self.assertEqual(report.state, 'incomplete')
        self.assertIn('GROUP_MEMBER_LIMIT', [d.code for d in report.diagnostics])

    def test_depth_boundary_and_root_unknown(self):
        for n in (63, 64, 65):
            report = self.report([b'/'.join([b'x']*n)])
            self.assertEqual(report.complete, n <= 64)
            self.assertEqual('DEPTH_LIMIT' in [d.code for d in report.diagnostics], n > 64)
        report = self.report([b'x'])
        self.assertTrue(report.complete)
        self.assertEqual(report.state, 'findings')
        self.assertIn('PATH_ROOT_UNKNOWN', [d.code for d in report.diagnostics])

    def test_json_preserves_raw_and_large_integer_strings(self):
        import json
        report = self.report([b'a\x00b'])
        value = json.loads(dumps(report))
        self.assertEqual(value['schemaVersion'], 1)
        self.assertEqual(value['entries'][0]['raw']['rawNameBase64'], 'YQBi')
        self.assertEqual(value['entries'][0]['raw']['localOffset'], '0')
        self.assertFalse(value['contentVerified'])
        self.assertNotIn('fingerprint', str(value))
        with self.assertRaises(ValueError):
            dumps(report, max_bytes=10)

    def test_strict_json_roundtrip_and_rejection(self):
        import json
        from archive_preflight import model
        self.assertTrue(hasattr(model, 'loads_report'), 'strict report decoder missing')
        report = self.report([b'd/', b'd/x'])
        encoded = dumps(report)
        self.assertEqual(dumps(model.loads_report(encoded)), encoded)
        for key, value in (('schemaVersion', 2), ('contentVerified', True), ('extra', 'unknown'), ('state', 'invented')):
            altered = json.loads(encoded)
            altered[key] = value
            with self.assertRaises(ValueError):
                model.loads_report(json.dumps(altered))
        for field, value in (('localOffset', 0), ('localOffset', '00'), ('rawNameBase64', '!'), ('flags', True)):
            altered = json.loads(encoded)
            altered['entries'][0]['raw'][field] = value
            with self.assertRaises(ValueError):
                model.loads_report(json.dumps(altered))
        with self.assertRaises(ValueError):
            model.loads_report(encoded, max_bytes=1)

    def test_implicit_directory_owner_and_parent(self):
        report = self.report([b'a/b/x', b'a/b/y'])
        nodes = {d.source_parts: d for d in report.logical_directories}
        self.assertEqual(nodes[('a', 'b')].parent_node_id, nodes[('a',)].node_id)
        self.assertEqual(nodes[('a',)].owner_entry_id, 'e000001')
        self.assertEqual(nodes[('a',)].explicit_entry_ids, ())
        self.assertEqual(nodes[('a',)].descendant_entry_ids, ('e000001', 'e000002'))

    def test_empty_archive_still_discloses_unknown_root(self):
        report = self.report([])
        self.assertIn('PATH_ROOT_UNKNOWN', [d.code for d in report.diagnostics])

    def test_duplicate_files_never_merged(self):
        report = self.report([b'a', b'a'])
        groups = [g for g in report.collision_groups if g.rule_id == 'exact']
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].impact, 'file-overwrite')

    def test_unicode_casefold_and_macos_case_sensitive(self):
        entries = [{'name': t.encode(), 'flags': 0x800} for t in ('ß/x', 'ss/y', 'Dir/a', 'dir/b')]
        ci = self.report(entries, 'macos-apfs-ci-advisory-v1')
        cs = self.report(entries, 'macos-apfs-cs-advisory-v1')
        self.assertTrue(any(g.rule_id == 'casefold' and g.certainty == 'approximation' for g in ci.collision_groups))
        self.assertFalse(cs.collision_groups)

    def test_invalid_choice_is_not_defaulted_silently(self):
        report = self.report([b'x'], choices={'e000001': 'unknown'})
        self.assertEqual(report.entries[0].name_state, 'blocked')
        self.assertIn('INVALID_CANDIDATE_CHOICE', report.entries[0].diagnostic_ids)

    def test_logical_tree_uses_minimum_index_even_for_reordered_input(self):
        from archive_preflight.analyze import build_logical_directories
        report = self.report([b'a/x', b'a/y'])
        self.assertEqual(build_logical_directories(tuple(reversed(report.entries))), report.logical_directories)

    def test_logical_node_id_canonical_projection(self):
        import hashlib
        import json
        report = self.report([b'a/x', b'a/y'])
        projection = {'context': [['e000001', None, report.entries[0].candidates[0].candidate_id],
                                  ['e000002', None, report.entries[1].candidates[0].candidate_id]],
                      'sourceParts': ['a'], 'ownerIndex': 0}
        expected = 'd'+hashlib.sha256(json.dumps(projection, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
        self.assertEqual(report.logical_directories[0].node_id, expected)

    def test_missing_directory_flag_is_disclosed(self):
        report = self.report([{'name': b'd/', 'attr': 0}])
        self.assertIn('MISSING_DIRECTORY_METADATA', report.entries[0].diagnostic_ids)
        self.assertEqual(report.entries[0].name_state, 'nonstandard')
        self.assertEqual(report.logical_directories[0].source_parts, ('d',))

    def test_report_schema_restricts_enums(self):
        from archive_preflight.model import report_schema
        schema = report_schema()
        self.assertEqual(schema['$defs']['PreflightReport']['additionalProperties'], False)
        props = schema['$defs']['EntryReport']['properties']
        self.assertIn('enum', props['nameState'])
        self.assertIn('blocked', props['nameState']['enum'])

    def test_group_member_boundary(self):
        for limit, complete in ((1, False), (2, True), (3, True)):
            self.assertEqual(self.report([b'a', b'a'], group_members=limit).complete, complete)

    def test_known_platform19_special_mode(self):
        report = self.report([{'name': b'link', 'system': 19, 'attr': 0o120777 << 16}])
        self.assertEqual(report.entries[0].entry_type, 'symlink')
        self.assertEqual(report.entries[0].name_state, 'blocked')

    def test_entry_raw_metadata_is_serialized_without_comment_body(self):
        report = self.report([{'name': b'x', 'extra': b'\xfe\xca\x03\x00ABC'}])
        candidate = report.entries[0].candidates[0]
        self.assertIn('EXTRA_CAFE_LENGTH_3', candidate.evidence)
        self.assertEqual(report.entries[0].raw.raw_extra, b'\xfe\xca\x03\x00ABC')


if __name__ == '__main__':
    unittest.main()
