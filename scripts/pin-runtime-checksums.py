#!/usr/bin/env python3
"""Pin immutable GitHub release checksums for github: source installations."""
import json
import pathlib
import re
import sys

lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
checksums = {}
for line in lines:
    digest, filename = line.split(None, 1)
    checksums[pathlib.PurePath(filename.lstrip('*')).name] = digest
runtime = pathlib.Path(__file__).resolve().parent.parent / 'plugin/runtime.mjs'
s = runtime.read_text()
version = json.loads((runtime.parent.parent / 'package.json').read_text())['version']
s = re.sub(r"const RELEASE = '[^']+';", f"const RELEASE = 'v{version}';", s)
s = re.sub(r"const RELEASE_FILE = '[^']+';", f"const RELEASE_FILE = 'magpie-codex-guard-{version}.tgz';", s)
s = re.sub(r"'User-Agent': 'magpie-codex-guard/[^']+'", f"'User-Agent': 'magpie-codex-guard/{version}'", s)
replacements = {
    'ARCHIVE_SHA256': checksums['magpie-codex-guard-' + version + '.tgz'],
    'linux-amd64': checksums['codex-guard-linux-amd64'],
    'linux-arm64': checksums['codex-guard-linux-arm64'],
    'darwin-arm64': checksums['codex-guard-darwin-arm64'],
}
for key, digest in replacements.items():
    if key == 'ARCHIVE_SHA256':
        pattern = r"const ARCHIVE_SHA256 = '[a-f0-9]{64}';"
        value = f"const ARCHIVE_SHA256 = '{digest}';"
    else:
        pattern = rf"'{key}': '[a-f0-9]{{64}}',"
        value = f"'{key}': '{digest}',"
    s, count = re.subn(pattern, lambda _: value, s)
    if count != 1:
        raise SystemExit(f'cannot pin {key}: found {count} occurrences')
runtime.write_text(s)
print('pinned release', version)
