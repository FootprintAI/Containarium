"""The release gate must scan executable tools, not only SDK source manifests."""
import importlib.util
from pathlib import Path
import unittest


class ScanCoverageTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("validate_scan", Path(__file__).with_name("validate_scan.py"))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_source_only_scan_is_rejected(self):
        report = {"Results": [{"Target": "go/src/go.mod", "Type": "gomod"}]}
        with self.assertRaisesRegex(ValueError, "binary scan"):
            self.module.validate(report)

    def test_all_managed_go_binaries_must_be_scanned(self):
        report = {"Results": [{"Target": path, "Type": "gobinary"} for path in
                               ("go/bin/go", "bin/buf", "staticcheck/staticcheck")]}
        self.module.validate(report)
        report["Results"].pop()
        with self.assertRaisesRegex(ValueError, "staticcheck"):
            self.module.validate(report)
