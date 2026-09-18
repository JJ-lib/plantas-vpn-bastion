from pathlib import Path
import re

_SLUG_RE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')

def plant_artifact_dir(base, slug):
    value = str(slug or '')
    if not _SLUG_RE.fullmatch(value):
        raise ValueError('Slug VPN no válido.')
    base = Path(base).resolve()
    canonical = base / 'plants' / value
    legacy = base / 'sites' / value
    return canonical if canonical.exists() or not legacy.exists() else legacy
