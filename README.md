# iPhone Archive Audit

[中文说明](README.zh-CN.md) · [MIT License](LICENSE)

Check photo and video files exported from an iPhone before moving an archive
into long-term storage. A single Python script inventories the files, checks
their headers, groups related media, and optionally computes SHA-256 hashes.

## Demo

Run a sample archive containing two identical one-pixel PNGs and an empty JPEG.

```sh
python3 examples/demo.py
```

```text
status=attention
files=3
bytes=138
json=demo-output/_audit/archive-audit.json
markdown=demo-output/_audit/archive-audit.md
sha256=demo-output/_audit/sha256-manifest.tsv
```

The report identifies the empty file and one group of identical images. [Sample report](examples/report.md) · [SHA-256 manifest](examples/sha256-manifest.tsv).

## Quick start

Requires Python 3.10+. The script uses the Python standard library.

```sh
git clone https://github.com/ff-fdt/iphone-archive-audit.git
cd iphone-archive-audit
python3 audit_archive.py /path/to/Photos_Originals --skip-readability
```

Reports are written beside the archive in `_audit/`:

```text
archive/
├── Photos_Originals/
└── _audit/
    ├── archive-audit.json
    └── archive-audit.md
```

For readability samples on macOS, run without `--skip-readability`.
Install FFmpeg to add video probing: `brew install ffmpeg`.
Use `--sample-per-extension 10` to increase the sample count.

For full-content hashes:

```sh
python3 audit_archive.py /path/to/Photos_Originals --skip-readability --full-sha256
```

This also writes `sha256-manifest.tsv`. Choose another report directory with
`--audit-dir /path/to/reports`; reports must be outside the source archive.

## Features

- File counts, exact byte totals, and extension summaries.
- Zero-byte files, read errors, symbolic links, and case-insensitive path collisions.
- Header checks for common image, video, and sidecar formats, including HEIC,
  JPEG, MOV, AVIF, JXL, RAW, and AAE.
- AAE sidecar pairing, filename-based Live Photo candidates, and Image Capture
  numbered-name families such as `IMG_0001 1.HEIC`.
- Deterministic readability samples with macOS `sips` and `ffprobe`.
- Optional full-file SHA-256 manifest and byte-identical duplicate groups.
- Source metadata snapshots before and after scanning to detect concurrent changes.

## Results

| Exit code | Meaning |
| --- | --- |
| `0` | Checks completed with `status=pass`. |
| `1` | Checks completed with `status=attention`; read the report details. |
| `2` | Invalid input or an I/O error prevented completion. |

The check operates on exported files. Compare its counts and sizes with the
exporter's source inventory to reconcile the export. Live Photo candidates use
matching filenames; content duplicate groups require equal SHA-256 and size.

## Data handling

Source media is read in place. The tool reads filesystem metadata and file
headers; full hashing reads all bytes. Readability sampling asks local tools
for media dimensions and duration. Reports contain local paths and file names,
so keep reports with your private archive. No network service is used.

## Development

```sh
python3 -m unittest discover -v
```

Tests create synthetic media headers in temporary directories.

[Contributing](CONTRIBUTING.md)
