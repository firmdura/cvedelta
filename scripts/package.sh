#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
. build/environment.sh
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS=
export GOEXPERIMENT= GOFIPS140=off GOAMD64=v1
# Cross-built Linux binaries must be executed on Linux as part of packaging.
if [ "$(uname -s):$(uname -m)" != Linux:x86_64 ]; then
    exec sh build/linux.sh package
fi
go_bin=${GO:-go}
[ "$("$go_bin" env GOVERSION)" = "$CVDELTA_GO_VERSION" ] || { echo "package: requires $CVDELTA_GO_VERSION" >&2; exit 1; }
mkdir -p dist/package dist/cache/go-build dist/cache/go-mod
export GOCACHE=${GOCACHE:-"$(pwd)/dist/cache/go-build"}
export GOMODCACHE=${GOMODCACHE:-"$(pwd)/dist/cache/go-mod"}
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" build -buildvcs=false -trimpath -ldflags='-s -w' -o dist/package/cvedelta ./cmd/cvedelta
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" list -deps -json ./cmd/cvedelta > dist/package/dependencies.json
python3 - "$("$go_bin" env GOROOT)" <<'PY'
from pathlib import Path
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

version = 'v1.0.7'
root = Path.cwd()
out = root / 'dist/package'
name = 'cvedelta-' + version + '-linux-amd64'
# Explicit release allowlist. No Git metadata, caches, local instructions,
# private build inputs, development logs or arbitrary workspace files.
files = ['LICENSE', 'README.md', 'build/README.md', 'docs/usage.md', 'docs/provenance.md',
         'docs/library.md', 'docs/limits.md', 'docs/contracts.md',
         'schemas/yocto-v1.schema.json', 'schemas/metadata-v1.schema.json',
         'schemas/report-v1.schema.json', 'examples/ci.sh',
         'examples/provenance.py', 'examples/library/main.go',
         'examples/quickstart/README.md', 'examples/quickstart/baseline.json',
         'examples/quickstart/candidate.json', 'examples/quickstart/baseline.meta.json',
         'examples/quickstart/candidate.meta.json', 'examples/quickstart/candidate-database.meta.json',
         'examples/quickstart/database.json', 'examples/quickstart/database-other.json',
         'examples/quickstart/coverage-source.json', 'examples/quickstart/coverage-policy.json',
         'testdata/provenance/producer/README.md', 'testdata/provenance/producer/SHA256SUMS',
         'testdata/provenance/producer/database.json', 'testdata/provenance/producer/input.json',
         'testdata/provenance/producer/reproduce.py', 'testdata/provenance/producer/coverage-policy.json',
         'testdata/provenance/producer/report.json', 'testdata/provenance/producer/report.meta.json',
         'testdata/provenance/producer/upstream/LICENSE.MIT',
         'testdata/provenance/producer/upstream/cve-check.bbclass',
         'testdata/provenance/producer/upstream/cve_check.py']
contents = {'cvedelta': (out/'cvedelta').read_bytes()}
for file in files:
    path = root/file
    if not path.is_file() or path.is_symlink():
        raise SystemExit('package: missing or nonregular release file: ' + file)
    contents[file] = path.read_bytes()
# Preserve exact notices from the toolchain used to build this static binary.
# Go's root BSD license alone does not contain the additional assembly/math
# notices embedded in selected standard-library source comments.
goroot = Path(sys.argv[1])
contents['third_party/go/LICENSE'] = (goroot/'LICENSE').read_bytes()
contents['third_party/go/PATENTS'] = (goroot/'PATENTS').read_bytes()
decoder = json.JSONDecoder()
remaining = (out/'dependencies.json').read_text()
packages = []
while remaining.strip():
    remaining = remaining.lstrip()
    package, end = decoder.raw_decode(remaining)
    packages.append(package)
    remaining = remaining[end:]
inventory, notices = [], []
comment = re.compile(r'(?m)(?:^[ \t]*//[^\n]*(?:\n|$))+|/\*[\s\S]*?\*/')
notice = re.compile(r'copyright|licen[cs]e|public domain|permission to|all rights reserved', re.I)
for package in sorted(packages, key=lambda value: value['ImportPath']):
    if not package.get('Standard'):
        if not package['ImportPath'].startswith('github.com/firmdura/cvedelta/'):
            raise SystemExit('package: new runtime dependency needs a notice review: ' + package['ImportPath'])
        continue
    inventory.append(package['ImportPath'])
    if 'Dir' not in package:
        continue
    directory = Path(package['Dir'])
    for file in sorted(package.get('GoFiles', []) + package.get('SFiles', [])):
        source = directory/file
        relative = source.relative_to(goroot).as_posix()
        blocks = [match.group() for match in comment.finditer(source.read_text()) if notice.search(match.group())]
        if blocks:
            notices.append('===== ' + relative + ' =====\n' + '\n'.join(blocks))
    # Retain package-tree license/grant files as well as in-source notices.
    for ancestor in (directory, *directory.parents):
        if ancestor == goroot:
            break
        if goroot not in ancestor.parents:
            raise SystemExit('package: stdlib source outside pinned GOROOT')
        for filename in ('LICENSE', 'PATENTS', 'NOTICE', 'COPYING', 'COPYRIGHT'):
            source = ancestor/filename
            if source.is_file():
                contents['third_party/go/'+source.relative_to(goroot).as_posix()] = source.read_bytes()
contents['third_party/go/DEPENDENCIES.txt'] = ('go1.27.4 linux/amd64 CGO_ENABLED=0\n' + '\n'.join(inventory) + '\n').encode()
contents['third_party/go/SOURCE-NOTICES.txt'] = ('Selected Go and assembly source comment notices, preserved verbatim.\n'
    'This is a build-input inventory; linker elimination may omit functions.\n\n' + '\n\n'.join(notices) + '\n').encode()
for marker in (b'Lucent', b'Vita Nuova', b'Sun Microsystems', b'Stephen L. Moshier', b'Vincent Rijmen'):
    if marker not in contents['third_party/go/SOURCE-NOTICES.txt']:
        raise SystemExit('package: expected pinned stdlib attribution missing: ' + marker.decode())
# Every relative Markdown link in bundled guides must resolve in the archive.
for file, data in list(contents.items()):
    if file.endswith('.md'):
        for link in re.findall(r'\]\(([^)]+)\)', data.decode()):
            if '://' in link or link.startswith('#'):
                continue
            target = os.path.normpath(str(Path(file).parent/link.split('#', 1)[0]))
            if target not in contents:
                raise SystemExit('package: broken documentation link: ' + file + ' -> ' + link)
# Check both path privacy and common accidentally embedded credential markers.
for file, data in contents.items():
    if any(part.lower() in ('agents.md', '.git', '.env', '.aws', '.codex') for part in Path(file).parts):
        raise SystemExit('package: forbidden path: ' + file)
    for marker in (b'/Users/', b'-----BEGIN PRIVATE KEY-----', b'ghp_', b'github_pat_'):
        if marker in data:
            raise SystemExit('package: private marker in ' + file)
license_bytes = contents['LICENSE']
if b'Apache License' not in license_bytes or b'Version 2.0' not in license_bytes:
    raise SystemExit('package: Apache-2.0 license missing')
# Product uses only the standard library. Its retained notices and the bundled
# MIT producer fixture's own license/provenance accompany the Apache project.
# The test-only schema validator is not linked or bundled.
manifest = ''.join(hashlib.sha256(data).hexdigest() + '  ' + file + '\n'
                   for file, data in sorted(contents.items())).encode()
contents['MANIFEST.sha256'] = manifest
archives = [out/(name+'.tar.gz'), out/(name+'.zip')]
with archives[0].open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
    with tarfile.open(fileobj=gz, mode='w') as archive:
        for file, data in sorted(contents.items()):
            info = tarfile.TarInfo(name + '/' + file)
            info.size, info.mtime = len(data), 0
            info.mode = 0o755 if file == 'cvedelta' else 0o644
            archive.addfile(info, io.BytesIO(data))
with zipfile.ZipFile(archives[1], 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for file, data in sorted(contents.items()):
        info = zipfile.ZipInfo(name + '/' + file, date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (0o100755 if file == 'cvedelta' else 0o100644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, data)
sums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in archives)
(out/'SHA256SUMS').write_text(sums, encoding='utf-8')
for index, path in enumerate(archives):
    # A new destination on every run prevents an earlier extraction's modes
    # or filesystem metadata for a reused pathname from masking a bad archive.
    target = Path(tempfile.mkdtemp(prefix='check-' + str(index) + '-', dir=out))
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if any(member.create_system != 3 or not stat.S_ISREG(member.external_attr >> 16)
                   for member in archive.infolist()):
                raise SystemExit('package: ZIP contains nonregular or non-Unix member')
            payloads = {member.filename: archive.read(member) for member in archive.infolist()}
            modes = {member.filename: stat.S_IMODE(member.external_attr >> 16) for member in archive.infolist()}
    else:
        with tarfile.open(path) as archive:
            names = archive.getnames()
            if any(not member.isfile() for member in archive.getmembers()):
                raise SystemExit('package: archive contains nonregular member')
            payloads = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
            modes = {member.name: member.mode for member in archive.getmembers()}
    expected = sorted(name+'/'+file for file in contents)
    if sorted(names) != expected:
        raise SystemExit('package: archive members differ from allowlist')
    for file in expected:
        expected_mode = 0o755 if file == name+'/cvedelta' else 0o644
        if modes[file] != expected_mode:
            raise SystemExit('package: archive mode mismatch: ' + file)
    # Write only already-validated allowlisted paths. This also works with
    # Debian's pinned Python without the newer tarfile extraction-filter API.
    for file in expected:
        destination = target/file
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Apply the validated archive mode at creation, not a later repair of
        # a default-0644 binary. fchmod also restores bits masked by umask.
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, modes[file])
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payloads[file])
            os.fchmod(output.fileno(), modes[file])
        if stat.S_IMODE(destination.stat().st_mode) != modes[file]:
            raise SystemExit('package: extracted mode mismatch: ' + file)
    extracted = target/name
    for file, data in contents.items():
        if (extracted/file).read_bytes() != data:
            raise SystemExit('package: extraction checksum mismatch: '+file)
    binary = extracted/'cvedelta'
    reported = subprocess.run([str(binary), '--version'], cwd=extracted, capture_output=True)
    if reported.returncode or reported.stderr or reported.stdout != ('cvedelta ' + version + '\n').encode():
        raise SystemExit('package: extracted binary version check failed')
    fixture = subprocess.run([sys.executable, 'testdata/provenance/producer/reproduce.py', '--check'],
                             cwd=extracted, capture_output=True)
    if fixture.returncode:
        raise SystemExit('package: bundled producer provenance/checksum check failed')
    q = 'examples/quickstart/'
    base = [str(binary), 'compare', '--baseline', q+'baseline.json', '--baseline-meta', q+'baseline.meta.json',
            '--candidate', q+'candidate.json', '--candidate-meta', q+'candidate.meta.json', '--format', 'json']
    for extra, status in (([], 1), (['--fail-on', 'none'], 0)):
        run = subprocess.run(base+extra, cwd=extracted, capture_output=True)
        if run.returncode != status or run.stderr or json.loads(run.stdout)['counts']['new'] != 1:
            raise SystemExit('package: extracted binary comparison failed')
    changed = list(base)
    changed[changed.index('--candidate-meta')+1] = q+'candidate-database.meta.json'
    run = subprocess.run(changed+['--fail-on', 'none'], cwd=extracted, capture_output=True)
    if run.returncode != 3 or run.stderr or json.loads(run.stdout)['decision'] != 'incomparable':
        raise SystemExit('package: extracted binary incomparable check failed')
    bad = subprocess.run([str(binary), 'compare'], cwd=extracted, capture_output=True)
    if bad.returncode != 2 or bad.stdout or not bad.stderr:
        raise SystemExit('package: extracted binary invalid-input check failed')
    print('package: verified contents, checksums and Linux execution:', path.name)
# Independently re-read the checksum manifest after all archive checks.
for line in (out/'SHA256SUMS').read_text().splitlines():
    digest, file = line.split('  ', 1)
    if hashlib.sha256((out/file).read_bytes()).hexdigest() != digest:
        raise SystemExit('package: archive checksum mismatch')
PY
