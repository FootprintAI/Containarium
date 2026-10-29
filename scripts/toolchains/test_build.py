"""Behavioral tests for the release packager; all downloads are local fixtures."""
import hashlib
import importlib.util
import io
import json
import platform
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest import mock
import zipfile


class ToolchainBuildTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location("build", Path(__file__).with_name("build.py"))
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)
        self.lock = {"tools": []}
        layouts = {"go": ["go/bin/go", "go/bin/gofmt"],
                   "node": ["node-v1/bin/node", "node-v1/bin/npm", "node-v1/bin/npx"],
                   "npm": ["package/bin/npm-cli.js", "package/bin/npx-cli.js"],
                   "pnpm": ["pnpm"], "staticcheck": ["staticcheck/staticcheck"]}
        for name in ("go", "node", "npm", "pnpm", "buf", "protoc", "staticcheck"):
            artifact = self.root / (name + ".download")
            if name == "buf":
                artifact.write_bytes(b"#!/bin/sh\necho fixture\n")
                kind = "binary"
            elif name == "protoc":
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("bin/protoc", "#!/bin/sh\necho fixture\n")
                    archive.writestr("include/google/protobuf/any.proto", "syntax='proto3';")
                kind = "zip"
            else:
                with tarfile.open(artifact, "w:gz") as archive:
                    for filename in layouts[name]:
                        content = b"#!/bin/sh\necho fixture\n"
                        entry = tarfile.TarInfo(filename)
                        entry.size, entry.mode = len(content), 0o755
                        archive.addfile(entry, io.BytesIO(content))
                kind = "tar"
            self.lock["tools"].append({"name": name, "version": "1.0.0", "artifacts": {"amd64": {
                "url": artifact.as_uri(), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "format": kind}}})
        self.lock["system_tools"] = ["python3", "make", "git", "gcc"]

    def test_build_contains_complete_inventory_and_relocatable_links(self):
        destination = self.root / "release"
        self.builder.build(self.lock, "amd64", "v0.1.0", destination, self.root / "cache")
        manifest = json.loads((destination / "manifest.json").read_text())
        self.assertEqual(manifest["release"], "v0.1.0")
        self.assertEqual(manifest["system_tools"], ["python3", "make", "git", "gcc"])
        self.assertEqual({t["name"] for t in manifest["tools"]}, {t["name"] for t in self.lock["tools"]})
        for name in ("go", "gofmt", "node", "npm", "npx", "pnpm", "buf", "protoc", "staticcheck"):
            self.assertTrue((destination / "bin" / name).is_file(), name)
        self.assertIn("GOTOOLCHAIN=local", (destination / "bin/go").read_text())
        self.assertTrue((destination / "protoc/include/google/protobuf/any.proto").is_file())
        self.assertTrue((destination / "install.sh").is_file())
        self.assertEqual((destination / "bin/npm").readlink(), Path("../npm/bin/npm-cli.js"))
        self.assertFalse((destination / "node/bin/npm").exists())

    def test_staticcheck_rebuild_uses_verified_source_and_pinned_go(self):
        tool = next(t for t in self.lock["tools"] if t["name"] == "staticcheck")
        tool.update(module="honnef.co/go/tools", module_version="v0.8.2", module_sum="h1:fixture")
        invoked = []

        def compile_tool(args, **kwargs):
            invoked.append((args, kwargs))
            Path(args[args.index("-o") + 1]).write_bytes(b"#!/bin/sh\necho rebuilt\n")

        info = {"Sum": "h1:fixture", "Dir": str(self.root)}
        with mock.patch.object(self.builder.subprocess, "check_output", return_value=json.dumps(info).encode()), \
             mock.patch.object(self.builder.subprocess, "run", side_effect=compile_tool):
            self.builder.build(self.lock, "amd64", "v0.1.0", self.root / "rebuilt", self.root / "cache")
        args, kwargs = invoked[0]
        self.assertIn("go/bin/go", args[0])
        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
        self.assertEqual(kwargs["env"]["GOSUMDB"], "sum.golang.org")
        self.assertEqual(kwargs["env"]["GOARCH"], "amd64")

    def test_staticcheck_source_checksum_mismatch_stops_build(self):
        tool = next(t for t in self.lock["tools"] if t["name"] == "staticcheck")
        tool.update(module="honnef.co/go/tools", module_version="v0.8.2", module_sum="h1:expected")
        info = {"Sum": "h1:wrong", "Dir": str(self.root)}
        with mock.patch.object(self.builder.subprocess, "check_output", return_value=json.dumps(info).encode()), \
             mock.patch.object(self.builder.subprocess, "run") as compiler:
            with self.assertRaisesRegex(ValueError, "source checksum"):
                self.builder.build(self.lock, "amd64", "v0.1.0", self.root / "rebuilt", self.root / "cache")
        compiler.assert_not_called()

    def test_checksum_mismatch_cannot_produce_a_release(self):
        self.lock["tools"][0]["artifacts"]["amd64"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.builder.build(self.lock, "amd64", "v0.1.0", self.root / "release", self.root / "cache")
        self.assertFalse((self.root / "release/manifest.json").exists())

    def test_cached_download_is_verified_again(self):
        cache = self.root / "cache"
        self.builder.build(self.lock, "amd64", "v0.1.0", self.root / "first", cache)
        for path in cache.iterdir():
            path.write_bytes(b"corrupted cache")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.builder.build(self.lock, "amd64", "v0.1.1", self.root / "second", cache)

    def test_install_update_rollback_and_reject_corruption(self):
        # These fixtures describe the native CPU; an incompatible real
        # archive must be refused by the same installer before activation.
        arch = "arm64" if platform.machine() == "aarch64" else "amd64"
        if arch == "arm64":
            for tool in self.lock["tools"]:
                tool["artifacts"]["arm64"] = tool["artifacts"]["amd64"]
        host = self.root / "host"
        for release in ("v0.1.0", "v0.2.0"):
            tree = self.root / release
            self.builder.build(self.lock, arch, release, tree, self.root / "cache")
            subprocess.run(["bash", str(tree / "install.sh"), str(host)], check=True, capture_output=True)
            self.assertEqual((host / "current").readlink(), Path("releases") / release)
        self.assertTrue((host / "releases/v0.1.0/manifest.json").is_file())
        old = self.root / "v0.1.0"
        subprocess.run(["bash", str(old / "install.sh"), str(host)], check=True, capture_output=True)
        self.assertEqual((host / "current").readlink(), Path("releases/v0.1.0"))
        (self.root / "v0.2.0/bin/buf").write_bytes(b"corrupted")
        result = subprocess.run(["bash", str(self.root / "v0.2.0/install.sh"), str(host)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((host / "current").readlink(), Path("releases/v0.1.0"))


if __name__ == "__main__":
    unittest.main()
