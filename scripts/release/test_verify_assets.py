import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock

from verify_assets import verify_assets


class VerifyAssetsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tag = "v9.8.7-rc.1"
        self.chart = "containarium-k8s-9.8.7-rc.1.tgz"
        self.bundle = "containarium-bundle-v9.8.7-rc.1-linux-amd64.tar.gz"
        self.programs = ("containariumd", "containarium", "mcp-server", "agent-box")
        for name in ("LICENSE", "NOTICE", "agent-runtime-bundle.tar.gz", "sdlc-skills.tar.gz", self.bundle):
            (self.root / name).write_bytes(b"release fixture\n")
        for name in self.programs:
            (self.root / (name + "-linux-amd64")).write_bytes(b"binary fixture\n")
            (self.root / (name + "-linux-amd64.spdx.json")).write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
                    {"name": name, "SPDXID": "SPDXRef-program"},
                    {"name": "dependency", "SPDXID": "SPDXRef-dependency"}]}))
        self.write_chart("9.8.7-rc.1", self.tag)
        for name in (self.chart, self.bundle, "sdlc-skills.tar.gz"):
            (self.root / (name + ".sha256")).write_text(self.sum_line(name))
        (self.root / "SHA256SUMS.txt").write_text("".join(
            self.sum_line(p.name) for p in sorted(self.root.iterdir())
            if p.name != self.bundle and not p.name.endswith(".sha256")))
        for path in list(self.root.iterdir()):
            (self.root / (path.name + ".sigstore.json")).write_text("{}")
        self.metadata = {
            "tag_name": self.tag,
            "body": "Chart version `9.8.7-rc.1` (installs the `v9.8.7-rc.1` daemon image)",
            "assets": [{"name": p.name} for p in self.root.iterdir()],
        }
        # Only the external cryptographic tool is replaced. Inventory, tar,
        # metadata, SPDX parsing and hashing use the real release fixture.
        self.cosign = Mock(return_value=subprocess.CompletedProcess([], 0))

    def write_chart(self, version, app_version):
        content = f'apiVersion: v2\nname: containarium-k8s\nversion: {version}\nappVersion: "{app_version}"\n'.encode()
        with tarfile.open(self.root / self.chart, "w:gz") as archive:
            entry = tarfile.TarInfo("containarium-k8s/Chart.yaml")
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))

    def sum_line(self, name):
        digest = hashlib.sha256((self.root / name).read_bytes()).hexdigest()
        return f"{digest}  {name}\n"

    def verify(self):
        return verify_assets(self.root, self.metadata, "FootprintAI/Containarium", self.tag, runner=self.cosign)

    def test_complete_release_uses_exact_repository_and_tag_identity(self):
        result = self.verify()
        self.assertEqual(result["chart_version"], "9.8.7-rc.1")
        self.assertIn(self.bundle, result["verified_files"])
        self.assertEqual(len(result["sboms"]), 4)
        self.assertEqual(self.cosign.call_count, len(result["verified_files"]))
        for call in self.cosign.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:2], ["cosign", "verify-blob"])
            self.assertEqual(command[command.index("--certificate-identity") + 1],
                             "https://github.com/FootprintAI/Containarium/.github/workflows/release.yml@refs/tags/v9.8.7-rc.1")
            self.assertEqual(command[command.index("--certificate-oidc-issuer") + 1],
                             "https://token.actions.githubusercontent.com")
            self.assertTrue(call.kwargs["check"])

    def test_missing_uploaded_signature_fails(self):
        (self.root / (self.bundle + ".sigstore.json")).unlink()
        with self.assertRaisesRegex(ValueError, "inventory|signature"):
            self.verify()

    def test_incomplete_release_inventory_fails_even_with_paired_signatures(self):
        for name in ("agent-box-linux-amd64.spdx.json", "agent-box-linux-amd64.spdx.json.sigstore.json"):
            (self.root / name).unlink()
            self.metadata["assets"] = [a for a in self.metadata["assets"] if a["name"] != name]
        with self.assertRaisesRegex(ValueError, "missing"):
            self.verify()

    def test_invalid_signature_fails_closed(self):
        self.cosign.side_effect = subprocess.CalledProcessError(1, ["cosign", "verify-blob"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()

    def test_changed_payload_fails_checksum_validation(self):
        (self.root / "containariumd-linux-amd64").write_bytes(b"wrong download")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_floating_app_version_fails_even_with_matching_checksum(self):
        self.write_chart("9.8.7-rc.1", "latest")
        (self.root / "SHA256SUMS.txt").write_text(self.sum_line(self.chart))
        (self.root / (self.chart + ".sha256")).write_text(self.sum_line(self.chart))
        with self.assertRaisesRegex(ValueError, "appVersion"):
            self.verify()

    def test_wrong_release_notes_or_tag_fails(self):
        for field, value in (("body", "No chart version here"), ("tag_name", "v9.8.6")):
            with self.subTest(field=field):
                original = self.metadata[field]
                self.metadata[field] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.metadata[field] = original

    def test_empty_sbom_fails(self):
        (self.root / "agent-box-linux-amd64.spdx.json").write_text('{"spdxVersion":"SPDX-2.3","packages":[]}')
        with self.assertRaisesRegex(ValueError, "SBOM"):
            self.verify()

    def test_malformed_spdx_with_valid_checksums_fails(self):
        name = "agent-box-linux-amd64.spdx.json"
        for document in (
            {"spdxVersion": "SPDX-garbage", "packages": "ab"},
            {"spdxVersion": "SPDX-2.3", "packages": ["a", "b"]},
            {"spdxVersion": "SPDX-2.3", "packages": [{}, {}]},
        ):
            with self.subTest(document=document):
                previous = self.sum_line(name)
                (self.root / name).write_text(json.dumps(document))
                sums = self.root / "SHA256SUMS.txt"
                sums.write_text(sums.read_text().replace(previous, self.sum_line(name)))
                with self.assertRaisesRegex(ValueError, "SBOM"):
                    self.verify()

    def test_unlisted_checksum_payload_fails(self):
        path = self.root / "SHA256SUMS.txt"
        path.write_text("".join(line for line in path.read_text().splitlines(keepends=True)
                                if not line.endswith("  agent-runtime-bundle.tar.gz\n")))
        with self.assertRaisesRegex(ValueError, "missing from checksum"):
            self.verify()

    def test_sidecar_covering_another_artifact_fails(self):
        (self.root / (self.bundle + ".sha256")).write_text(self.sum_line(self.chart))
        with self.assertRaisesRegex(ValueError, "own artifact"):
            self.verify()

    def test_orphan_signature_fails(self):
        (self.root / "missing.sigstore.json").write_text("{}")
        self.metadata["assets"].append({"name": "missing.sigstore.json"})
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
