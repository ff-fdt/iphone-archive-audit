#!/usr/bin/env python3
"""Read-only integrity inventory for an exported iPhone photo archive.

The archive tree is never modified. Reports are written to a sibling `_audit`
directory by default. The scanner intentionally does not parse EXIF, GPS,
captions, faces, or image/video frames.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Iterable


VERSION = "1.1.1"
READ_BYTES = 64
HASH_CHUNK_BYTES = 8 * 1024 * 1024

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".heic",
    ".heif",
    ".png",
    ".gif",
    ".tif",
    ".tiff",
    ".dng",
    ".cr2",
    ".webp",
    ".bmp",
    ".avif",
    ".jxl",
}
VIDEO_EXTENSIONS = {".mov", ".mp4", ".m4v", ".3gp", ".3g2"}
SIDECAR_EXTENSIONS = {".aae", ".xmp", ".plist"}
AAE_EXTENSION = ".aae"
IMAGE_CAPTURE_NUMBERED_STEM = re.compile(r"^(?P<base>.+) (?P<ordinal>[1-9][0-9]*)$")

HEIF_BRANDS = {
    b"heic",
    b"heix",
    b"hevc",
    b"hevx",
    b"heim",
    b"heis",
    b"hevm",
    b"hevs",
    b"mif1",
    b"msf1",
    b"avif",
    b"avis",
}
VIDEO_BRANDS = {
    b"qt  ",
    b"isom",
    b"iso2",
    b"iso3",
    b"iso4",
    b"iso5",
    b"iso6",
    b"mp41",
    b"mp42",
    b"M4V ",
    b"M4A ",
    b"3gp4",
    b"3gp5",
    b"3g2a",
}

EXPECTED_MAGIC: dict[str, set[str]] = {
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".png": {"png"},
    ".gif": {"gif"},
    ".tif": {"tiff"},
    ".tiff": {"tiff"},
    ".dng": {"tiff"},
    ".cr2": {"tiff"},
    ".webp": {"webp"},
    ".bmp": {"bmp"},
    ".heic": {"isobmff-image", "isobmff-generic"},
    ".heif": {"isobmff-image", "isobmff-generic"},
    ".avif": {"isobmff-image", "isobmff-generic"},
    ".jxl": {"jxl"},
    ".mov": {"isobmff-video", "isobmff-generic"},
    ".mp4": {"isobmff-video", "isobmff-generic"},
    ".m4v": {"isobmff-video", "isobmff-generic"},
    ".3gp": {"isobmff-video", "isobmff-generic"},
    ".3g2": {"isobmff-video", "isobmff-generic"},
    ".aae": {"xml", "binary-plist"},
    ".xmp": {"xml"},
    ".plist": {"xml", "binary-plist"},
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only audit of ordinary photo/video files exported from an iPhone."
    )
    parser.add_argument("source", type=Path, help="Photos_Originals directory to scan")
    parser.add_argument(
        "--audit-dir",
        type=Path,
        help="report directory (default: SOURCE_PARENT/_audit)",
    )
    parser.add_argument(
        "--sample-per-extension",
        type=int,
        default=3,
        help="deterministic readability samples per media extension (default: 3)",
    )
    parser.add_argument(
        "--skip-readability",
        action="store_true",
        help="skip sips/ffprobe readability sampling",
    )
    parser.add_argument(
        "--full-sha256",
        action="store_true",
        help="hash every regular file and write sha256-manifest.tsv (slow)",
    )
    parser.add_argument(
        "--label",
        default="iPhone photo originals",
        help="human-readable archive label used in reports",
    )
    args = parser.parse_args(argv)
    if args.sample_per_extension < 0:
        parser.error("--sample-per-extension must be zero or greater")
    return args


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def normalized_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def split_image_capture_numbered_stem(stem: str) -> tuple[str, int | None]:
    """Split Image Capture's ``NAME 1.ext`` collision suffix.

    A numeric suffix is only a *pattern candidate* here.  It is confirmed as
    an export collision rename later, when the same directory contains the
    unnumbered media component or another component proves the numbered export
    instance.  This avoids treating an ordinary filename such as
    ``Chapter 1.JPG`` as a duplicate by syntax alone.
    """

    match = IMAGE_CAPTURE_NUMBERED_STEM.fullmatch(stem)
    if match is None:
        return stem, None
    return match.group("base"), int(match.group("ordinal"))


def iso_time(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).astimezone().isoformat()


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    number = float(value)
    for unit in units:
        if number < 1024.0 or unit == units[-1]:
            return f"{number:,.2f} {unit}" if unit != "B" else f"{int(number):,} B"
        number /= 1024.0
    raise AssertionError("unreachable")


def detect_magic(header: bytes) -> tuple[str, list[str]]:
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg", []
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", []
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif", []
    if header.startswith((b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")):
        return "tiff", []
    if header.startswith(b"BM"):
        return "bmp", []
    if header.startswith(b"\xff\x0a") or header.startswith(
        b"\x00\x00\x00\x0cJXL \r\n\x87\n"
    ):
        return "jxl", []
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp", []
    if header.startswith(b"bplist00"):
        return "binary-plist", []
    stripped = header.lstrip()
    if stripped.startswith((b"<?xml", b"<plist", b"<x:xmpmeta", b"<rdf:RDF")):
        return "xml", []
    if len(header) >= 12 and header[4:8] == b"ftyp":
        brands = [header[8:12]]
        for offset in range(16, len(header) - 3, 4):
            brands.append(header[offset : offset + 4])
        brand_set = set(brands)
        names = [brand.decode("ascii", errors="replace") for brand in brands]
        if brand_set & HEIF_BRANDS:
            return "isobmff-image", names
        if brand_set & VIDEO_BRANDS:
            return "isobmff-video", names
        return "isobmff-generic", names
    return "unknown", []


def deterministic_sample(paths: Iterable[Path], count: int, source: Path) -> list[Path]:
    """Choose a stable sample without reading file contents."""
    if count <= 0:
        return []
    ranked = []
    for path in paths:
        relative = path.relative_to(source).as_posix().encode("utf-8", errors="surrogateescape")
        ranked.append((hashlib.sha256(relative).digest(), path))
    ranked.sort(key=lambda item: item[0])
    return [item[1] for item in ranked[:count]]


def probe_image(path: Path) -> dict[str, Any]:
    sips = shutil.which("sips")
    if not sips:
        return {"status": "unavailable", "reason": "sips not found"}
    try:
        result = subprocess.run(
            [sips, "-g", "pixelWidth", "-g", "pixelHeight", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "sips timed out after 30 seconds"}
    if result.returncode != 0:
        return {"status": "failed", "reason": f"sips exit code {result.returncode}"}
    width = height = None
    for line in result.stdout.splitlines():
        key, separator, raw_value = line.strip().partition(":")
        if not separator:
            continue
        if key == "pixelWidth":
            width = raw_value.strip()
        elif key == "pixelHeight":
            height = raw_value.strip()
    if not width or not height or width == "<nil>" or height == "<nil>":
        return {"status": "failed", "reason": "sips returned no dimensions"}
    return {"status": "ok", "width": width, "height": height}


def probe_video(path: Path) -> dict[str, Any]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return {"status": "unavailable", "reason": "ffprobe not found"}
    command = [
        ffprobe,
        "-v",
        "error",
        "-select_streams",
        "v:0",
        "-show_entries",
        "stream=codec_type,width,height:format=duration",
        "-of",
        "json",
        str(path),
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "ffprobe timed out after 45 seconds"}
    if result.returncode != 0:
        return {"status": "failed", "reason": f"ffprobe exit code {result.returncode}"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "failed", "reason": "ffprobe returned invalid JSON"}
    streams = payload.get("streams") or []
    if not streams or streams[0].get("codec_type") != "video":
        return {"status": "failed", "reason": "ffprobe found no video stream"}
    stream = streams[0]
    return {
        "status": "ok",
        "width": stream.get("width"),
        "height": stream.get("height"),
        "duration_seconds": (payload.get("format") or {}).get("duration"),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def metadata_snapshot_digest(
    entries: Iterable[tuple[str, int, int]],
) -> tuple[str, int, int]:
    """Hash path, size, and mtime without reading file content."""
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    for relative, size, mtime_ns in sorted(entries):
        path_bytes = relative.encode("utf-8", errors="surrogateescape")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(size.to_bytes(16, "big", signed=False))
        digest.update(mtime_ns.to_bytes(16, "big", signed=True))
        count += 1
        total_bytes += size
    return digest.hexdigest(), count, total_bytes


def take_metadata_snapshot(source: Path) -> tuple[str, int, int, list[dict[str, str]]]:
    entries: list[tuple[str, int, int]] = []
    errors: list[dict[str, str]] = []
    for root, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        dirnames[:] = [
            dirname for dirname in dirnames if not (root_path / dirname).is_symlink()
        ]
        for filename in filenames:
            path = root_path / filename
            relative = path.relative_to(source).as_posix()
            try:
                stat_result = path.lstat()
            except OSError as exc:
                errors.append({"path": relative, "reason": f"stat: {exc}"})
                continue
            if path.is_symlink() or not path.is_file():
                continue
            entries.append((relative, stat_result.st_size, stat_result.st_mtime_ns))
    digest, count, total_bytes = metadata_snapshot_digest(entries)
    return digest, count, total_bytes, errors


def write_atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def run_audit(args: argparse.Namespace) -> tuple[dict[str, Any], str | None]:
    source = args.source.expanduser().resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"source is not a directory: {source}")
    audit_dir = (args.audit_dir or (source.parent / "_audit")).expanduser().resolve()
    if audit_dir == source or is_relative_to(audit_dir, source):
        raise ValueError("audit directory must be outside the source archive tree")

    started = dt.datetime.now().astimezone()
    extensions: collections.Counter[str] = collections.Counter()
    bytes_by_extension: collections.Counter[str] = collections.Counter()
    magic_types: collections.Counter[str] = collections.Counter()
    basename_index: dict[str, list[str]] = collections.defaultdict(list)
    path_index: dict[str, list[str]] = collections.defaultdict(list)
    live_index: dict[tuple[str, str], dict[str, list[str]]] = collections.defaultdict(
        lambda: {"images": [], "videos": []}
    )
    media_by_extension: dict[str, list[Path]] = collections.defaultdict(list)
    component_index: dict[
        tuple[str, str], dict[str, list[dict[str, Any]]]
    ] = collections.defaultdict(lambda: {"media": [], "aae": []})
    file_records: list[dict[str, Any]] = []

    total_bytes = 0
    regular_files = 0
    image_files = 0
    video_files = 0
    sidecar_files = 0
    aae_files = 0
    other_files = 0
    zero_byte_files: list[str] = []
    unreadable_files: list[dict[str, str]] = []
    magic_mismatches: list[dict[str, Any]] = []
    symlinks: list[str] = []
    special_files: list[str] = []
    mtime_min: float | None = None
    mtime_max: float | None = None
    birth_min: float | None = None
    birth_max: float | None = None
    all_files: list[tuple[Path, str, int, int]] = []

    for root, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        retained_dirs = []
        for dirname in dirnames:
            candidate = root_path / dirname
            if candidate.is_symlink():
                symlinks.append(candidate.relative_to(source).as_posix())
            else:
                retained_dirs.append(dirname)
        dirnames[:] = retained_dirs

        for filename in filenames:
            path = root_path / filename
            relative = path.relative_to(source).as_posix()
            try:
                stat_result = path.lstat()
            except OSError as exc:
                unreadable_files.append({"path": relative, "reason": f"stat: {exc}"})
                continue
            if path.is_symlink():
                symlinks.append(relative)
                continue
            if not path.is_file():
                special_files.append(relative)
                continue

            size = stat_result.st_size
            extension = path.suffix.lower() or "<none>"
            parent_relative = path.parent.relative_to(source).as_posix()
            collision_base_stem, collision_ordinal = split_image_capture_numbered_stem(
                path.stem
            )
            regular_files += 1
            total_bytes += size
            extensions[extension] += 1
            bytes_by_extension[extension] += size
            basename_index[normalized_key(path.name)].append(relative)
            path_index[normalized_key(relative)].append(relative)
            all_files.append((path, relative, size, stat_result.st_mtime_ns))

            mtime_min = stat_result.st_mtime if mtime_min is None else min(mtime_min, stat_result.st_mtime)
            mtime_max = stat_result.st_mtime if mtime_max is None else max(mtime_max, stat_result.st_mtime)
            birth = getattr(stat_result, "st_birthtime", None)
            if birth is not None:
                birth_min = birth if birth_min is None else min(birth_min, birth)
                birth_max = birth if birth_max is None else max(birth_max, birth)

            if size == 0:
                zero_byte_files.append(relative)

            if extension in IMAGE_EXTENSIONS:
                image_files += 1
                file_role = "main_media"
                media_by_extension[extension].append(path)
                live_key = (normalized_key(parent_relative), normalized_key(path.stem))
                live_index[live_key]["images"].append(relative)
            elif extension in VIDEO_EXTENSIONS:
                video_files += 1
                file_role = "main_media"
                media_by_extension[extension].append(path)
                live_key = (normalized_key(parent_relative), normalized_key(path.stem))
                live_index[live_key]["videos"].append(relative)
            elif extension in SIDECAR_EXTENSIONS:
                sidecar_files += 1
                if extension == AAE_EXTENSION:
                    aae_files += 1
                    file_role = "aae_sidecar"
                else:
                    file_role = "other_sidecar"
            else:
                other_files += 1
                file_role = "other"

            record = {
                "path": path,
                "relative": relative,
                "parent": parent_relative,
                "parent_key": normalized_key(parent_relative),
                "stem": path.stem,
                "stem_key": normalized_key(path.stem),
                "extension": extension,
                "role": file_role,
                "collision_base_stem": collision_base_stem,
                "collision_base_stem_key": normalized_key(collision_base_stem),
                "collision_ordinal": collision_ordinal,
            }
            file_records.append(record)
            if file_role == "main_media":
                component_index[(record["parent_key"], record["stem_key"])][
                    "media"
                ].append(record)
            elif file_role == "aae_sidecar":
                component_index[(record["parent_key"], record["stem_key"])][
                    "aae"
                ].append(record)

            try:
                with path.open("rb") as handle:
                    header = handle.read(READ_BYTES)
            except OSError as exc:
                unreadable_files.append({"path": relative, "reason": f"read header: {exc}"})
                continue
            detected, brands = detect_magic(header)
            magic_types[detected] += 1
            expected = EXPECTED_MAGIC.get(extension)
            if expected is not None and detected not in expected:
                magic_mismatches.append(
                    {
                        "path": relative,
                        "extension": extension,
                        "detected": detected,
                        "expected": sorted(expected),
                        "isobmff_brands": brands,
                    }
                )

    same_basename_groups = [
        sorted(paths) for paths in basename_index.values() if len(paths) > 1
    ]
    same_basename_groups.sort(key=lambda group: (-len(group), group[0]))
    casefold_path_collisions = [
        sorted(paths) for paths in path_index.values() if len(paths) > 1
    ]
    casefold_path_collisions.sort(key=lambda group: (-len(group), group[0]))

    # Image Capture keeps colliding source basenames by appending `` 1``,
    # `` 2``, ... before the extension.  A suffix alone is not proof: an
    # ordinary user filename may already end in a number.  Confirm a numbered
    # *media instance* only if a sibling unnumbered media component with the
    # reconstructed basename and the same extension exists.  Once one media
    # component confirms the instance, companion media and its AAE sidecar at
    # the exact same stem inherit that classification.
    main_name_index: dict[tuple[str, str], list[dict[str, Any]]] = (
        collections.defaultdict(list)
    )
    family_index: dict[tuple[str, str], list[dict[str, Any]]] = (
        collections.defaultdict(list)
    )
    for record in file_records:
        if record["role"] == "main_media":
            main_name_index[
                (record["parent_key"], normalized_key(Path(record["relative"]).name))
            ].append(record)
        if record["role"] in {"main_media", "aae_sidecar"}:
            family_index[
                (record["parent_key"], record["collision_base_stem_key"])
            ].append(record)

    confirmed_numbered_instance_keys: set[tuple[str, str]] = set()
    for record in file_records:
        if (
            record["role"] != "main_media"
            or record["collision_ordinal"] is None
        ):
            continue
        reconstructed_basename = (
            f"{record['collision_base_stem']}{record['extension']}"
        )
        anchors = main_name_index.get(
            (record["parent_key"], normalized_key(reconstructed_basename)), []
        )
        if any(anchor["collision_ordinal"] is None for anchor in anchors):
            confirmed_numbered_instance_keys.add(
                (record["parent_key"], record["stem_key"])
            )

    confirmed_numbered_records = [
        record
        for record in file_records
        if record["collision_ordinal"] is not None
        and record["role"] in {"main_media", "aae_sidecar"}
        and (record["parent_key"], record["stem_key"])
        in confirmed_numbered_instance_keys
    ]
    unconfirmed_numbered_records = [
        record
        for record in file_records
        if record["collision_ordinal"] is not None
        and record["role"] in {"main_media", "aae_sidecar"}
        and (record["parent_key"], record["stem_key"])
        not in confirmed_numbered_instance_keys
    ]

    collision_groups: list[dict[str, Any]] = []
    confirmed_family_keys = {
        (record["parent_key"], record["collision_base_stem_key"])
        for record in confirmed_numbered_records
    }
    for family_key in sorted(confirmed_family_keys):
        records = family_index[family_key]
        unnumbered = sorted(
            record["relative"]
            for record in records
            if record["collision_ordinal"] is None
        )
        by_ordinal: dict[int, list[str]] = collections.defaultdict(list)
        for record in records:
            ordinal = record["collision_ordinal"]
            if ordinal is not None:
                by_ordinal[int(ordinal)].append(record["relative"])
        exemplar = min(records, key=lambda item: item["relative"])
        collision_groups.append(
            {
                "directory": exemplar["parent"],
                "base_stem": exemplar["collision_base_stem"],
                "unnumbered_files": unnumbered,
                "numbered_instances": [
                    {"ordinal": ordinal, "files": sorted(paths)}
                    for ordinal, paths in sorted(by_ordinal.items())
                    if (
                        exemplar["parent_key"],
                        normalized_key(f"{exemplar['collision_base_stem']} {ordinal}"),
                    )
                    in confirmed_numbered_instance_keys
                ],
            }
        )
    collision_groups.sort(key=lambda group: (group["directory"], group["base_stem"]))

    aae_pairings: list[dict[str, Any]] = []
    for record in sorted(
        (item for item in file_records if item["role"] == "aae_sidecar"),
        key=lambda item: item["relative"],
    ):
        exact_components = component_index[
            (record["parent_key"], record["stem_key"])
        ]["media"]
        possible_family_components = [
            item
            for item in family_index[
                (record["parent_key"], record["collision_base_stem_key"])
            ]
            if item["role"] == "main_media"
        ]
        if exact_components:
            status_value = "paired"
            components = exact_components
            possible_components: list[dict[str, Any]] = []
        else:
            distinct_possible_instances = {
                (item["parent_key"], item["stem_key"])
                for item in possible_family_components
            }
            status_value = (
                "ambiguous" if len(distinct_possible_instances) > 1 else "unpaired"
            )
            components = []
            possible_components = possible_family_components
        aae_pairings.append(
            {
                "sidecar": record["relative"],
                "status": status_value,
                "collision_ordinal": record["collision_ordinal"],
                "numbered_collision_name_confirmed": (
                    record["parent_key"], record["stem_key"]
                )
                in confirmed_numbered_instance_keys,
                "main_media_components": sorted(
                    item["relative"] for item in components
                ),
                "possible_components_when_not_paired": sorted(
                    item["relative"] for item in possible_components
                ),
            }
        )
    paired_aae = [item for item in aae_pairings if item["status"] == "paired"]
    ambiguous_aae = [item for item in aae_pairings if item["status"] == "ambiguous"]
    unpaired_aae = [item for item in aae_pairings if item["status"] == "unpaired"]

    live_photo_candidates = []
    for pair in live_index.values():
        if pair["images"] and pair["videos"]:
            live_photo_candidates.append(
                {"images": sorted(pair["images"]), "videos": sorted(pair["videos"])}
            )
    live_photo_candidates.sort(key=lambda pair: pair["images"][0])

    readability_checks: list[dict[str, Any]] = []
    if not args.skip_readability:
        for extension in sorted(media_by_extension):
            samples = deterministic_sample(
                media_by_extension[extension], args.sample_per_extension, source
            )
            for path in samples:
                result = (
                    probe_image(path)
                    if extension in IMAGE_EXTENSIONS
                    else probe_video(path)
                )
                readability_checks.append(
                    {
                        "path": path.relative_to(source).as_posix(),
                        "extension": extension,
                        **result,
                    }
                )

    first_snapshot_digest, first_snapshot_count, first_snapshot_bytes = metadata_snapshot_digest(
        (relative, size, mtime_ns) for _, relative, size, mtime_ns in all_files
    )

    audit_dir.mkdir(parents=True, exist_ok=True)
    sha_manifest_name: str | None = None
    sha_errors: list[dict[str, str]] = []
    sha_entries = 0
    duplicate_content_sample: list[dict[str, Any]] = []
    duplicate_content_group_count = 0
    duplicate_main_media_sample: list[dict[str, Any]] = []
    duplicate_main_media_group_count = 0
    duplicate_aae_sample: list[dict[str, Any]] = []
    duplicate_aae_group_count = 0
    if args.full_sha256:
        sha_manifest_name = "sha256-manifest.tsv"
        manifest_lines = ["sha256\tbytes\trelative_path_json"]
        digest_index: dict[tuple[str, int], list[str]] = collections.defaultdict(list)
        digest_role_index: dict[
            tuple[str, str, int], list[str]
        ] = collections.defaultdict(list)
        role_by_relative = {
            record["relative"]: record["role"] for record in file_records
        }
        for path, relative, size, _ in sorted(all_files, key=lambda item: item[1]):
            try:
                digest = sha256_file(path)
            except OSError as exc:
                sha_errors.append({"path": relative, "reason": str(exc)})
                continue
            sha_entries += 1
            digest_index[(digest, size)].append(relative)
            digest_role_index[(role_by_relative[relative], digest, size)].append(relative)
            manifest_lines.append(
                f"{digest}\t{size}\t{json.dumps(relative, ensure_ascii=False)}"
            )
        confirmed_numbered_paths = {
            record["relative"] for record in confirmed_numbered_records
        }
        duplicate_groups = [
            {
                "sha256": key[0],
                "bytes_each": key[1],
                "paths": paths,
                "roles": sorted({role_by_relative[path] for path in paths}),
                "contains_confirmed_numbered_collision_name": any(
                    path in confirmed_numbered_paths for path in paths
                ),
            }
            for key, paths in digest_index.items()
            if len(paths) > 1
        ]
        duplicate_groups.sort(key=lambda group: (-len(group["paths"]), group["paths"][0]))
        duplicate_content_group_count = len(duplicate_groups)
        duplicate_content_sample = duplicate_groups[:100]
        duplicate_main_media = [
            {
                "sha256": key[1],
                "bytes_each": key[2],
                "paths": paths,
                "roles": ["main_media"],
                "contains_confirmed_numbered_collision_name": any(
                    path in confirmed_numbered_paths for path in paths
                ),
            }
            for key, paths in digest_role_index.items()
            if key[0] == "main_media" and len(paths) > 1
        ]
        duplicate_main_media.sort(
            key=lambda group: (-len(group["paths"]), group["paths"][0])
        )
        duplicate_main_media_group_count = len(duplicate_main_media)
        duplicate_main_media_sample = duplicate_main_media[:100]
        duplicate_aae = [
            {
                "sha256": key[1],
                "bytes_each": key[2],
                "paths": paths,
                "roles": ["aae_sidecar"],
                "contains_confirmed_numbered_collision_name": any(
                    path in confirmed_numbered_paths for path in paths
                ),
            }
            for key, paths in digest_role_index.items()
            if key[0] == "aae_sidecar" and len(paths) > 1
        ]
        duplicate_aae.sort(
            key=lambda group: (-len(group["paths"]), group["paths"][0])
        )
        duplicate_aae_group_count = len(duplicate_aae)
        duplicate_aae_sample = duplicate_aae[:100]
        write_atomic_text(audit_dir / sha_manifest_name, "\n".join(manifest_lines) + "\n")

    # This is deliberately the final source-tree read. In full mode it runs
    # after every content hash, so a directory that changes during a multi-hour
    # SHA-256 pass cannot inherit an earlier "unchanged" result.
    (
        second_snapshot_digest,
        second_snapshot_count,
        second_snapshot_bytes,
        second_snapshot_errors,
    ) = take_metadata_snapshot(source)
    source_unchanged = (
        not second_snapshot_errors
        and first_snapshot_digest == second_snapshot_digest
        and first_snapshot_count == second_snapshot_count
        and first_snapshot_bytes == second_snapshot_bytes
    )

    readability_failures = [
        item for item in readability_checks if item["status"] == "failed"
    ]
    readability_unavailable = [
        item for item in readability_checks if item["status"] == "unavailable"
    ]
    issue_count = (
        len(zero_byte_files)
        + len(unreadable_files)
        + len(magic_mismatches)
        + len(casefold_path_collisions)
        + len(readability_failures)
        + len(sha_errors)
        + len(ambiguous_aae)
        + len(unpaired_aae)
        + (0 if source_unchanged else 1)
    )
    status = "attention" if issue_count else "pass"
    finished = dt.datetime.now().astimezone()

    extension_rows = [
        {
            "extension": extension,
            "files": extensions[extension],
            "bytes": bytes_by_extension[extension],
        }
        for extension in sorted(extensions)
    ]

    report: dict[str, Any] = {
        "schema_version": 2,
        "tool": {"name": "iphone-photo-archive-audit", "version": VERSION},
        "archive": {"label": args.label, "source": str(source)},
        "audit": {
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round((finished - started).total_seconds(), 3),
            "mode": "full-sha256" if args.full_sha256 else "fast",
            "privacy": {
                "exif_read": False,
                "gps_read": False,
                "captions_or_faces_read": False,
                "frames_or_thumbnails_created": False,
                "read_operations": "filesystem metadata, first 64 bytes of every regular file, sampled decode/container probes",
            },
            "status": status,
        },
        "inventory": {
            "regular_files": regular_files,
            "total_bytes": total_bytes,
            "image_files": image_files,
            "video_files": video_files,
            "main_media_components": image_files + video_files,
            "sidecar_files": sidecar_files,
            "aae_sidecars": aae_files,
            "other_sidecars": sidecar_files - aae_files,
            "other_files": other_files,
            "extensions": extension_rows,
            "filesystem_date_ranges": {
                "modified": {"earliest": iso_time(mtime_min), "latest": iso_time(mtime_max)},
                "created": {"earliest": iso_time(birth_min), "latest": iso_time(birth_max)},
                "note": "Filesystem timestamps only; EXIF capture dates were not read.",
            },
        },
        "integrity": {
            "zero_byte_files": zero_byte_files,
            "unreadable_files": unreadable_files,
            "magic_types": dict(sorted(magic_types.items())),
            "magic_extension_mismatches": magic_mismatches,
            "symlinks_skipped": sorted(symlinks),
            "special_files_skipped": sorted(special_files),
            "source_stability": {
                "unchanged_during_audit": source_unchanged,
                "first_snapshot": {
                    "metadata_sha256": first_snapshot_digest,
                    "regular_files": first_snapshot_count,
                    "total_bytes": first_snapshot_bytes,
                },
                "second_snapshot": {
                    "metadata_sha256": second_snapshot_digest,
                    "regular_files": second_snapshot_count,
                    "total_bytes": second_snapshot_bytes,
                    "errors": second_snapshot_errors,
                },
                "basis": "Relative path, byte size, and filesystem mtime; file content was not reread.",
            },
        },
        "naming": {
            "same_basename_group_count": len(same_basename_groups),
            "same_basename_groups": same_basename_groups,
            "case_insensitive_relative_path_collision_count": len(casefold_path_collisions),
            "case_insensitive_relative_path_collisions": casefold_path_collisions,
            "image_capture_numbered_collision_names": {
                "confirmed_group_count": len(collision_groups),
                "confirmed_numbered_file_count": len(confirmed_numbered_records),
                "confirmed_numbered_main_media_count": sum(
                    record["role"] == "main_media"
                    for record in confirmed_numbered_records
                ),
                "confirmed_numbered_aae_count": sum(
                    record["role"] == "aae_sidecar"
                    for record in confirmed_numbered_records
                ),
                "groups": collision_groups,
                "unconfirmed_numeric_suffix_file_count": len(
                    unconfirmed_numbered_records
                ),
                "unconfirmed_numeric_suffix_files": sorted(
                    record["relative"] for record in unconfirmed_numbered_records
                ),
                "rule": (
                    "NAME N.ext is confirmed only when an unnumbered sibling "
                    "media component with the reconstructed basename and same "
                    "extension anchors that numbered export instance."
                ),
            },
            "note": (
                "Same basenames in different folders are informational; path "
                "collisions need attention. Confirmed Image Capture numbered "
                "names preserve colliding source names and are not content-duplicate proof."
            ),
        },
        "aae_sidecars": {
            "total": aae_files,
            "paired": len(paired_aae),
            "ambiguous": len(ambiguous_aae),
            "unpaired": len(unpaired_aae),
            "pairings": aae_pairings,
            "ambiguous_pairings": ambiguous_aae,
            "unpaired_sidecars": unpaired_aae,
            "note": (
                "AAE is paired only to main media with the exact same directory "
                "and export stem, including any confirmed numeric suffix. Image+MOV "
                "or RAW+JPEG components at one stem are one component set, not ambiguity."
            ),
        },
        "live_photos": {
            "probable_pair_count": len(live_photo_candidates),
            "probable_pairs": live_photo_candidates,
            "note": "Heuristic only: image and video share the same stem in the same directory; metadata asset identifiers were not read.",
        },
        "readability_sampling": {
            "enabled": not args.skip_readability,
            "sample_per_extension": args.sample_per_extension,
            "checks": readability_checks,
            "failed": len(readability_failures),
            "unavailable": len(readability_unavailable),
            "note": "Samples are selected deterministically from relative-path hashes; sampling is not full-media validation.",
        },
        "sha256": {
            "enabled": args.full_sha256,
            "manifest": sha_manifest_name,
            "entries": sha_entries,
            "errors": sha_errors,
            "duplicate_content_group_count": duplicate_content_group_count,
            "duplicate_content_groups_sample_first_100": duplicate_content_sample,
            "exact_duplicate_main_media_group_count": duplicate_main_media_group_count,
            "exact_duplicate_main_media_groups_sample_first_100": duplicate_main_media_sample,
            "exact_duplicate_aae_group_count": duplicate_aae_group_count,
            "exact_duplicate_aae_groups_sample_first_100": duplicate_aae_sample,
            "note": (
                "Exact duplicates are byte-identical SHA-256 groups and are available "
                "only in full mode. A numbered collision-preservation name alone is not "
                "classified as a duplicate."
            ),
        },
        "limits": [
            "This audit checks the exported archive, not completeness against the phone source.",
            "A fast pass does not hash every byte and does not prove every media file decodes.",
            "Probable Live Photo pairing is filename-based and does not prove Apple asset linkage.",
            "AAE pairing and Image Capture collision-name recognition are conservative filename heuristics; the private manifest supplies source-asset evidence later.",
        ],
    }
    return report, sha_manifest_name


def markdown_report(report: dict[str, Any]) -> str:
    inventory = report["inventory"]
    integrity = report["integrity"]
    naming = report["naming"]
    numbered = naming["image_capture_numbered_collision_names"]
    aae = report["aae_sidecars"]
    live = report["live_photos"]
    readability = report["readability_sampling"]
    sha = report["sha256"]
    modified = inventory["filesystem_date_ranges"]["modified"]
    created = inventory["filesystem_date_ranges"]["created"]

    lines = [
        "# iPhone 影像归档只读校验报告",
        "",
        f"- 状态：`{report['audit']['status']}`",
        f"- 模式：`{report['audit']['mode']}`",
        f"- 归档：`{report['archive']['source']}`",
        f"- 开始：{report['audit']['started_at']}",
        f"- 完成：{report['audit']['finished_at']}",
        f"- 耗时：{report['audit']['duration_seconds']:,} 秒",
        "",
        "## 总量",
        "",
        f"- 常规文件：{inventory['regular_files']:,}",
        f"- 总字节：{inventory['total_bytes']:,}（{human_bytes(inventory['total_bytes'])}）",
        f"- 图片：{inventory['image_files']:,}",
        f"- 视频：{inventory['video_files']:,}",
        f"- 主媒体组件（图片+视频）：{inventory['main_media_components']:,}",
        f"- AAE 编辑侧车：{inventory['aae_sidecars']:,}",
        f"- 其他边车：{inventory['other_sidecars']:,}",
        f"- 其他文件：{inventory['other_files']:,}",
        "",
        "## 扩展名",
        "",
        "| 扩展名 | 文件数 | 字节 | 易读大小 |",
        "|---|---:|---:|---:|",
    ]
    for row in inventory["extensions"]:
        lines.append(
            f"| `{row['extension']}` | {row['files']:,} | {row['bytes']:,} | {human_bytes(row['bytes'])} |"
        )
    lines.extend(
        [
            "",
            "## 文件系统日期范围",
            "",
            f"- 修改时间：{modified['earliest'] or '无'} 至 {modified['latest'] or '无'}",
            f"- 创建时间：{created['earliest'] or '无'} 至 {created['latest'] or '无'}",
            "- 未读取 EXIF 拍摄时间或 GPS。",
            "",
            "## 完整性与命名",
            "",
            f"- 零字节文件：{len(integrity['zero_byte_files']):,}",
            f"- 无法读取文件：{len(integrity['unreadable_files']):,}",
            f"- 魔数与扩展名不符：{len(integrity['magic_extension_mismatches']):,}",
            f"- 跳过符号链接：{len(integrity['symlinks_skipped']):,}",
            f"- 同名文件组（可位于不同目录，仅提示）：{naming['same_basename_group_count']:,}",
            f"- 大小写不敏感的相对路径冲突：{naming['case_insensitive_relative_path_collision_count']:,}",
            f"- 已确认的 Image Capture 编号重名族：{numbered['confirmed_group_count']:,}",
            f"- 其中编号后主媒体组件：{numbered['confirmed_numbered_main_media_count']:,}",
            f"- 其中编号后 AAE：{numbered['confirmed_numbered_aae_count']:,}",
            f"- 仅符合数字后缀、尚无锚点确认的文件：{numbered['unconfirmed_numeric_suffix_file_count']:,}",
            f"- 校验期间源目录保持不变：{'是' if integrity['source_stability']['unchanged_during_audit'] else '否'}",
            "- `NAME 1.ext` 只有在同目录存在未编号同扩展名媒体锚点时才认作 Image Capture 防重名；它本身不代表内容重复。",
            "",
            "## AAE 编辑侧车配对",
            "",
            f"- AAE 总数：{aae['total']:,}",
            f"- 已与同目录、同导出主文件名（含编号后缀）的媒体组件配对：{aae['paired']:,}",
            f"- 歧义：{aae['ambiguous']:,}",
            f"- 未配对：{aae['unpaired']:,}",
            "- 同一主文件名下的图片+MOV 或 RAW+JPEG 视为一组媒体组件，不因此判作歧义。",
            "",
            "## Live Photo 可能配对",
            "",
            f"- 图片与 MOV/视频同目录同主文件名的候选配对：{live['probable_pair_count']:,}",
            "- 这是文件名启发式判断，未读取 Apple Asset Identifier 元数据。",
            "",
            "## 图片/视频可读性抽样",
            "",
            f"- 已启用：{'是' if readability['enabled'] else '否'}",
            f"- 每种扩展名抽样：{readability['sample_per_extension']:,}",
            f"- 实际检查：{len(readability['checks']):,}",
            f"- 失败：{readability['failed']:,}",
            f"- 工具不可用：{readability['unavailable']:,}",
            "",
            "## SHA-256",
            "",
            f"- 已启用全量 SHA-256：{'是' if sha['enabled'] else '否'}",
            f"- 清单条目：{sha['entries']:,}",
            f"- 哈希失败：{len(sha['errors']):,}",
            f"- 清单文件：`{sha['manifest'] or '未生成'}`",
            f"- 字节完全相同的主媒体组：{sha['exact_duplicate_main_media_group_count']:,}",
            f"- 字节完全相同的 AAE 组：{sha['exact_duplicate_aae_group_count']:,}",
            "- 以上“完全相同”只在全量模式下按 SHA-256+字节数判定；编号防重名组单独统计，不当作真正重复。",
            "",
            "## 重要边界",
            "",
            "- 这份报告校验 SSD 上已经导出的文件，不能单独证明手机端内容全部导出完毕。",
            "- 快速模式不读取每个文件的全部字节，也不逐个解码全部媒体。",
            "- AAE 配对和 Image Capture 编号防重名识别采用保守文件名规则；之后还要用私有 manifest 做源资产核对。",
            "- 报告未读取 EXIF/GPS、标题、说明、人物或照片画面，也未生成缩略图。",
            "- JSON 报告包含问题文件和配对候选的完整相对路径清单。",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        report, _ = run_audit(args)
        source = args.source.expanduser().resolve(strict=True)
        audit_dir = (args.audit_dir or (source.parent / "_audit")).expanduser().resolve()
        json_path = audit_dir / "archive-audit.json"
        markdown_path = audit_dir / "archive-audit.md"
        write_atomic_text(
            json_path,
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        )
        write_atomic_text(markdown_path, markdown_report(report))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"status={report['audit']['status']}")
    print(f"files={report['inventory']['regular_files']}")
    print(f"bytes={report['inventory']['total_bytes']}")
    print(f"json={json_path}")
    print(f"markdown={markdown_path}")
    if report["sha256"]["manifest"]:
        print(f"sha256={audit_dir / report['sha256']['manifest']}")
    return 1 if report["audit"]["status"] == "attention" else 0


if __name__ == "__main__":
    raise SystemExit(main())
