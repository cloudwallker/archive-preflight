import importlib
import importlib.util
import unittest

from archive_preflight.model import TargetOptions


IDS = ('windows-win32-conservative-v1', 'macos-apfs-ci-advisory-v1', 'macos-apfs-cs-advisory-v1', 'linux-posix-bytes-v1')


class ProfileTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('archive_preflight.profiles'), 'profile rules missing')
        return importlib.import_module('archive_preflight.profiles')

    def test_windows_device_names_and_illegal_components(self):
        m = self.api()
        p = m.load_profile(IDS[0])
        for name in ('COM¹.txt', 'COM2', 'LPT³.log', 'CON.txt', 'CON .x', 'x ', 'tail.', 'a:b', 'x\x1f'):
            with self.subTest(name=name):
                self.assertTrue(m.check_path((name,), False, p, TargetOptions(root_units=1)))
        self.assertEqual(m.check_path(('COM10.txt',), False, p, TargetOptions(root_units=1)), ())

    def test_component_budget_boundaries_and_nonbmp(self):
        m = self.api()
        for profile_id in IDS:
            p = m.load_profile(profile_id)
            for n, want in ((254, False), (255, False), (256, True)):
                codes = m.check_path(('a'*n,), False, p, TargetOptions(root_units=1))
                self.assertEqual('COMPONENT_LIMIT' in codes, want)
        self.assertEqual(m.measure('😀', m.load_profile(IDS[0])), 2)
        self.assertEqual(m.measure('😀', m.load_profile(IDS[3])), 4)

    def test_path_budget_boundaries(self):
        m = self.api()
        for profile_id in IDS:
            p = m.load_profile(profile_id)
            for directory in (False, True):
                budget = p.directory_path_limit if directory else p.path_limit
                for n, want in ((budget-1, False), (budget, False), (budget+1, True)):
                    codes = m.check_path(('x',), directory, p, TargetOptions(root_units=n-1))
                    self.assertEqual('PATH_LIMIT' in codes, want)

    def test_root_unknown_and_strict_options(self):
        m = self.api()
        p = m.load_profile(IDS[0])
        self.assertIn('PATH_ROOT_UNKNOWN', m.check_path(('x',), False, p, TargetOptions()))
        for options in (TargetOptions(root_units=-1), TargetOptions(component_limit=256), TargetOptions(path_limit=0), TargetOptions(unicode_version='forged'), TargetOptions(component_limit=True)):
            with self.assertRaises(ValueError):
                m.check_path(('x',), False, p, options)

    def test_profile_comparison_certainty(self):
        m = self.api()
        ci, cs, linux = [m.load_profile(s) for s in IDS[1:]]
        self.assertIn(('ascii-case', 'config_rule'), ci.rules)
        self.assertNotIn(('ascii-case', 'config_rule'), cs.rules)
        self.assertIn(('nfc', 'approximation'), cs.rules)
        self.assertIn(('nfc', 'advisory'), linux.rules)
        self.assertEqual(m.comparison_key('e\u0301', 'nfc'), 'é')


if __name__ == '__main__':
    unittest.main()
