"""Tests for the caching system."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.cache import ScanCache


class TestScanCache(unittest.TestCase):
    """Test the scan cache."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = ScanCache(cache_dir=os.path.join(self.tmpdir, ".shield-cache"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_changed_detection(self):
        # Create a file
        test_file = os.path.join(self.tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("print('hello')")

        # First check - should be "changed" (not in cache)
        self.assertTrue(self.cache.is_file_changed(test_file))

        # Update cache
        self.cache.update_file(test_file, [{"title": "test", "severity": "LOW"}])
        self.cache.save()

        # After caching - should NOT be changed
        self.assertFalse(self.cache.is_file_changed(test_file))

    def test_modified_file_detection(self):
        test_file = os.path.join(self.tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("print('hello')")
        
        self.cache.update_file(test_file, [])
        self.cache.save()

        # Modify the file
        with open(test_file, "w") as f:
            f.write("print('modified')")

        # Should now be detected as changed
        self.assertTrue(self.cache.is_file_changed(test_file))

    def test_get_cached_findings(self):
        test_file = os.path.join(self.tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("x = 1")

        findings = [{"title": "SQL Injection", "severity": "CRITICAL"}]
        self.cache.update_file(test_file, findings)
        self.cache.save()

        cached = self.cache.get_cached_findings(test_file)
        self.assertEqual(len(cached), 1)
        self.assertEqual(cached[0]["title"], "SQL Injection")

    def test_get_changed_files(self):
        f1 = os.path.join(self.tmpdir, "a.py")
        f2 = os.path.join(self.tmpdir, "b.py")

        with open(f1, "w") as f:
            f.write("a = 1")
        with open(f2, "w") as f:
            f.write("b = 2")

        # Cache only f1
        self.cache.update_file(f1, [])
        self.cache.save()

        changed = self.cache.get_changed_files([f1, f2])
        self.assertIn(f2, changed)
        self.assertNotIn(f1, changed)

    def test_clear_cache(self):
        test_file = os.path.join(self.tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("x = 1")

        self.cache.update_file(test_file, [])
        self.cache.save()
        self.cache.clear()

        # After clear, file should be "changed"
        self.assertTrue(self.cache.is_file_changed(test_file))


if __name__ == "__main__":
    unittest.main()
