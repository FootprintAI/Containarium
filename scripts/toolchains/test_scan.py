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

    def test_extra_binaries_must_appear_in_the_report(self):
        report = {"Results": [{"Target": path, "Type": "gobinary"} for path in
                               ("go/bin/go", "bin/buf", "staticcheck/staticcheck")]}
        with self.assertRaisesRegex(ValueError, "extra/cobol/bin/cobc"):
            self.module.validate(report, extra=["extra/cobol/bin/cobc"])
        report["Results"].append({"Target": "extra/cobol/bin/cobc", "Type": "gobinary"})
        self.module.validate(report, extra=["extra/cobol/bin/cobc"])

    def test_extra_paths_come_from_the_manifest(self):
        manifest = {"tools": [{"name": "go"}, {"name": "cobol", "source": "extra", "bin": ["bin/cobc"]}]}
        self.assertEqual(self.module.extra_binaries(manifest), ["extra/cobol/bin/cobc"])
        self.assertEqual(self.module.extra_binaries({"tools": [{"name": "go"}]}), [])


class ExceptionPolicyTest(unittest.TestCase):
    """The only way past the gate is a scoped, explained, expiring entry."""
    root = Path(__file__).resolve().parents[2]

    def entries(self):
        text = (Path(__file__).with_name("trivy-exceptions.yaml")).read_text()
        body = text.split("vulnerabilities:", 1)[1]
        return [e for e in body.split("\n  - id: ")[1:]] if "\n  - id: " in body else \
            [e for e in body.split("- id: ")[1:]]

    def test_every_exception_is_scoped_explained_and_expiring(self):
        import re
        entries = self.entries()
        self.assertTrue(entries, "an empty exceptions file should be deleted with its workflow wiring")
        for e in entries:
            self.assertRegex(e, r"(?m)^\s+paths:\s*\n\s+- \"[^\"*]+\"", "scoped to a concrete tool path, no wildcard")
            self.assertRegex(e, r"(?m)^\s+statement:\s*>-\s*\n", "carries a statement")
            m = re.search(r"(?m)^\s+expired_at:\s*(\d{4}-\d{2}-\d{2})\s*$", e)
            self.assertIsNotNone(m, "carries an expiry date")

    def test_every_managed_tool_scan_reads_the_exceptions_file(self):
        import re
        for wf in ("release.yml", "toolchains.yml"):
            text = (self.root / ".github" / "workflows" / wf).read_text()
            steps = re.findall(r"- name: Scan managed tools[^\n]*\n(.*?)(?=\n      - |\Z)", text, re.S)
            self.assertTrue(steps, wf)
            for s in steps:
                self.assertIn("TRIVY_IGNOREFILE: scripts/toolchains/trivy-exceptions.yaml", s, wf)
