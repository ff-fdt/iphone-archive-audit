#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("audit_archive.py")
MODULE_SPEC = importlib.util.spec_from_file_location("audit_archive", SCRIPT)
assert MODULE_SPEC and MODULE_SPEC.loader
AUDIT = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = AUDIT
MODULE_SPEC.loader.exec_module(AUDIT)


class ArchiveAuditTests(unittest.TestCase):
    def test_full_hash_stability_snapshot_runs_after_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Photos_Originals"
            source.mkdir()
            target = source / "IMG_0001.JPG"
            target.write_bytes(b"\xff\xd8\xfforiginal")
            args = AUDIT.parse_args(
                [
                    str(source),
                    "--audit-dir",
                    str(root / "_audit"),
                    "--skip-readability",
                    "--full-sha256",
                ]
            )

            def hash_then_simulate_external_write(path):
                before = path.read_bytes()
                digest = hashlib.sha256(before).hexdigest()
                path.write_bytes(before + b"changed-during-hash")
                return digest

            with mock.patch.object(
                AUDIT, "sha256_file", side_effect=hash_then_simulate_external_write
            ):
                report, _ = AUDIT.run_audit(args)
            self.assertFalse(
                report["integrity"]["source_stability"]["unchanged_during_audit"]
            )
            self.assertEqual(report["audit"]["status"], "attention")

    def test_fast_inventory_magic_naming_and_live_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Photos_Originals"
            first = source / "one"
            second = source / "two"
            first.mkdir(parents=True)
            second.mkdir(parents=True)

            # Header-only fixtures intentionally avoid personal or real media content.
            (first / "IMG_0001.JPG").write_bytes(b"\xff\xd8\xff" + b"x" * 20)
            (first / "IMG_0001.MOV").write_bytes(
                b"\x00\x00\x00\x18ftypqt  \x00\x00\x00\x00qt  "
            )
            (second / "IMG_0001.JPG").write_bytes(b"not-a-jpeg")
            (second / "empty.PNG").write_bytes(b"")

            audit_dir = root / "_audit"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    "--audit-dir",
                    str(audit_dir),
                    "--skip-readability",
                    "--full-sha256",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads((audit_dir / "archive-audit.json").read_text())
            self.assertEqual(report["inventory"]["regular_files"], 4)
            self.assertEqual(report["inventory"]["image_files"], 3)
            self.assertEqual(report["inventory"]["video_files"], 1)
            self.assertEqual(len(report["integrity"]["zero_byte_files"]), 1)
            self.assertEqual(len(report["integrity"]["magic_extension_mismatches"]), 2)
            self.assertEqual(report["naming"]["same_basename_group_count"], 1)
            self.assertEqual(report["live_photos"]["probable_pair_count"], 1)
            self.assertEqual(report["sha256"]["entries"], 4)
            self.assertTrue((audit_dir / "archive-audit.md").is_file())
            self.assertTrue((audit_dir / "sha256-manifest.tsv").is_file())

    def test_aae_pairing_numbered_collision_names_and_exact_duplicates_are_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Photos_Originals"
            source.mkdir()

            heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heic"
            mov_a = b"\x00\x00\x00\x18ftypqt  \x00\x00\x00\x00qt  "
            mov_b = mov_a + b"numbered"
            aae = b'<?xml version="1.0"?><plist><dict/></plist>'

            # Two source assets exported into one flat directory. Image
            # Capture preserves the colliding second basename with `` 1`` and
            # applies the same stem to its AAE and Live Photo component.
            (source / "IMG_0001.HEIC").write_bytes(heic)
            (source / "IMG_0001.MOV").write_bytes(mov_a)
            (source / "IMG_0001.AAE").write_bytes(aae)
            (source / "IMG_0001 1.HEIC").write_bytes(heic)
            (source / "IMG_0001 1.MOV").write_bytes(mov_b)
            (source / "IMG_0001 1.AAE").write_bytes(aae)
            (source / "IMG_0001 9.AAE").write_bytes(aae)
            # A different sidecar role shares the bytes; AAE-only duplicate
            # grouping must still count the AAE subset independently.
            (source / "COPY.plist").write_bytes(aae)

            # A numeric suffix without an unnumbered sibling is not assumed to
            # be an Image Capture rename. An AAE without exact-stem media is a
            # real follow-up item.
            (source / "Chapter 1.JPG").write_bytes(b"\xff\xd8\xfffixture")
            (source / "ORPHAN.AAE").write_bytes(aae)

            audit_dir = root / "_audit"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    "--audit-dir",
                    str(audit_dir),
                    "--skip-readability",
                    "--full-sha256",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads((audit_dir / "archive-audit.json").read_text())

            self.assertEqual(report["inventory"]["main_media_components"], 5)
            self.assertEqual(report["inventory"]["aae_sidecars"], 4)
            self.assertEqual(report["inventory"]["other_sidecars"], 1)

            numbered = report["naming"]["image_capture_numbered_collision_names"]
            self.assertEqual(numbered["confirmed_group_count"], 1)
            self.assertEqual(numbered["confirmed_numbered_main_media_count"], 2)
            self.assertEqual(numbered["confirmed_numbered_aae_count"], 1)
            self.assertEqual(
                numbered["unconfirmed_numeric_suffix_files"],
                ["Chapter 1.JPG", "IMG_0001 9.AAE"],
            )

            aae_report = report["aae_sidecars"]
            self.assertEqual(aae_report["paired"], 2)
            self.assertEqual(aae_report["ambiguous"], 1)
            self.assertEqual(aae_report["unpaired"], 1)
            numbered_pair = next(
                item
                for item in aae_report["pairings"]
                if item["sidecar"] == "IMG_0001 1.AAE"
            )
            self.assertEqual(numbered_pair["status"], "paired")
            self.assertEqual(numbered_pair["collision_ordinal"], 1)
            self.assertEqual(
                numbered_pair["main_media_components"],
                ["IMG_0001 1.HEIC", "IMG_0001 1.MOV"],
            )
            self.assertTrue(numbered_pair["numbered_collision_name_confirmed"])

            # Content duplicates require a full SHA-256 pass. They remain
            # separate from the collision-preservation naming analysis.
            self.assertEqual(
                report["sha256"]["exact_duplicate_main_media_group_count"], 1
            )
            self.assertEqual(report["sha256"]["exact_duplicate_aae_group_count"], 1)
            aae_duplicate_paths = report["sha256"][
                "exact_duplicate_aae_groups_sample_first_100"
            ][0]["paths"]
            self.assertNotIn("COPY.plist", aae_duplicate_paths)
            markdown = (audit_dir / "archive-audit.md").read_text()
            self.assertIn("AAE 编辑侧车配对", markdown)
            self.assertIn("编号防重名组单独统计", markdown)

    def test_avif_jxl_and_cr2_are_main_media_with_matching_magic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "Photos_Originals"
            source.mkdir()
            (source / "fixture.AVIF").write_bytes(
                b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00avif"
            )
            (source / "fixture.JXL").write_bytes(b"\xff\x0afixture")
            (source / "fixture.CR2").write_bytes(b"II*\x00fixture")
            args = AUDIT.parse_args(
                [
                    str(source),
                    "--audit-dir",
                    str(root / "_audit"),
                    "--skip-readability",
                ]
            )
            report, _ = AUDIT.run_audit(args)
            self.assertEqual(report["inventory"]["main_media_components"], 3)
            self.assertEqual(report["inventory"]["image_files"], 3)
            self.assertEqual(report["inventory"]["other_files"], 0)
            self.assertEqual(report["integrity"]["magic_extension_mismatches"], [])

    def test_rejects_report_directory_inside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "Photos_Originals"
            source.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(source),
                    "--audit-dir",
                    str(source / "_audit"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("outside the source archive tree", result.stderr)


if __name__ == "__main__":
    unittest.main()
