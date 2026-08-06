#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parent
clip = (root / "src/protocols/rdp/channels/cliprdr.c").read_text()
header = (root / "src/protocols/rdp/channels/cliprdr.h").read_text()
checks = {
    "advertises FileGroupDescriptorW": 'FileGroupDescriptorW' in clip,
    "requests CLIPRDR file contents": 'ClientFileContentsRequest' in clip and 'FILECONTENTS_RANGE' in clip,
    "handles CLIPRDR file contents response": 'ServerFileContentsResponse' in clip,
    "uses bounded file transfer": 'GUAC_RDP_CLIPBOARD_MAX_FILE_SIZE' in header and 'GUAC_RDP_CLIPBOARD_MAX_FILES' in header,
    "sanitizes clipboard filename": 'sanitize_filename' in clip,
    "converts descriptor filename with terminator": "descriptor_filename[characters] = 0" in clip and "(characters + 1) * sizeof(WCHAR)" in clip,
    "sends a Guacamole file instruction": 'guac_protocol_send_file' in clip,
    "cleans temporary clipboard files": 'unlink' in clip,
}
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("clipboard file transfer contract missing: " + ", ".join(failed))
