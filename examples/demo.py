"""Create a tiny synthetic archive and run the checker against it."""
import binascii
from pathlib import Path
import struct
import subprocess
import sys
import zlib

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo-output")
source = root / "Photos_Originals"
source.mkdir(parents=True, exist_ok=False)
def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xffffffff)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x30\x80\xc0")) + chunk(b"IEND", b"")
(source / "sample.png").write_bytes(png)
(source / "sample-copy.png").write_bytes(png)
(source / "empty.jpg").touch()
result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "audit_archive.py"), str(source), "--skip-readability", "--full-sha256"])
raise SystemExit(result.returncode)
