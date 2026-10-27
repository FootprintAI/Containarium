"""Structure checks on release.yml's bundle and signing jobs (#3118).

v0.119.0 stayed unsigned for 46 minutes because sign-release waited on a
build-bundle job whose apt download had stalled, with no job timeout. The
binary and SHA256SUMS.txt are now signed by a job that does not wait on the
bundle; the bundle is signed by its own job; the full-inventory check runs
once both are done; and every one of these jobs has a timeout.
"""
from pathlib import Path
import unittest

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"


def needs(job):
    n = job.get("needs", [])
    return [n] if isinstance(n, str) else list(n)


def run_text(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


class ReleaseWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]

    def closure(self, name):
        seen, todo = set(), needs(self.jobs[name])
        while todo:
            n = todo.pop()
            if n not in seen:
                seen.add(n)
                todo.extend(needs(self.jobs[n]))
        return seen

    def test_build_bundle_times_out_in_30_minutes(self):
        self.assertEqual(self.jobs["build-bundle"].get("timeout-minutes"), 30)

    def test_signing_jobs_are_bounded(self):
        for name in ("sign-release", "sign-bundle", "verify-release"):
            with self.subTest(job=name):
                t = self.jobs[name].get("timeout-minutes")
                self.assertIsInstance(t, int)
                self.assertLessEqual(t, 30)

    def test_binary_signing_does_not_wait_on_the_bundle(self):
        self.assertNotIn("build-bundle", self.closure("sign-release"))
        self.assertNotIn("sign-bundle", self.closure("sign-release"))
        # SHA256SUMS.txt is final only after helm-chart appends the chart.
        self.assertTrue({"build-and-release", "helm-chart"} <= set(needs(self.jobs["sign-release"])))

    def test_binary_signing_leaves_the_bundle_to_its_own_job(self):
        # The bundle may land on the Release while sign-release runs; it must
        # not be signed twice by two jobs racing to upload the same file.
        text = run_text(self.jobs["sign-release"])
        self.assertIn('select(startswith("containarium-bundle-") | not)', text)
        self.assertRegex(text, r"rm -f [^\n]*release-files/containarium-bundle-\*")
        self.assertNotIn("verify_assets.py", run_text(self.jobs["sign-release"]))

    def test_bundle_signed_after_it_is_built(self):
        job = self.jobs["sign-bundle"]
        self.assertIn("build-bundle", needs(job))
        self.assertIn("sign-assets.sh", run_text(job))
        self.assertIn("containarium-bundle-", run_text(job))

    def test_full_inventory_checked_after_both_signing_jobs(self):
        job = self.jobs["verify-release"]
        self.assertTrue({"sign-release", "sign-bundle"} <= set(needs(job)))
        self.assertIn("verify_assets.py", run_text(job))

    def test_verify_release_is_the_documented_gate(self):
        # docs/RELEASE-PROCESS.md tells operators to gate rollout on
        # verify-release (#3156). It must exist, be unskippable by a failed
        # signing job (no always()/failure() override, no continue-on-error),
        # and the docs must name it.
        job = self.jobs["verify-release"]
        self.assertEqual(self.jobs["verify-release"].get("if"), "startsWith(github.ref, 'refs/tags/v')")
        self.assertTrue({"sign-release", "sign-bundle"} <= set(needs(job)))
        self.assertNotIn("continue-on-error", job)
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
        root = WORKFLOW.parents[2]
        for doc in ("docs/RELEASE-PROCESS.md", "docs/security/VERIFYING-RELEASES.md"):
            with self.subTest(doc=doc):
                self.assertIn("`verify-release`", (root / doc).read_text())
        text = (root / "docs/RELEASE-PROCESS.md").read_text()
        self.assertIn("The release gate is the `verify-release` job", text)

    def test_signing_runs_on_tags_only(self):
        for name in ("sign-release", "sign-bundle", "verify-release"):
            with self.subTest(job=name):
                self.assertEqual(self.jobs[name].get("if"), "startsWith(github.ref, 'refs/tags/v')")

    def test_only_signing_jobs_get_an_oidc_token(self):
        for name in ("sign-release", "sign-bundle"):
            with self.subTest(job=name):
                self.assertEqual(self.jobs[name]["permissions"].get("id-token"), "write")
        self.assertNotIn("id-token", self.jobs["verify-release"].get("permissions", {}))


if __name__ == "__main__":
    unittest.main()
