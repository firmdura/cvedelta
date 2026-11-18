# Build and verification guide

CVEDelta's supported target is Linux amd64 with Go **1.27.4**. The foundation
selected that stable release from [Go's official
downloads](https://go.dev/dl/?mode=json) on 2026-11-15. `go.mod` pins the exact
toolchain, and `build/environment.sh` pins the Linux amd64 manifest of the
official `golang:1.27.4-bookworm` image by SHA-256 digest. The image includes
GCC for Go's race detector.

Run the commands in this guide from the repository root. The container workflow
requires Docker with support for Linux amd64 containers. Other host
architectures need working amd64 emulation; an ARM64 macOS example appears
below. The full source checkout is required for verification and Go examples.

## Prepare the Linux environment

Preparation requires network access. It pulls the pinned image and runs
`go mod download` using the committed module checksums:

```sh
make setup-linux
```

The source is mounted read-only during setup. The module cache is saved in
`dist/cache/linux-amd64/go-mod`. Run setup again after changing dependencies
before trying to verify offline.

The only external Go dependency is
`github.com/santhosh-tekuri/jsonschema/v5` v5.3.1. Tests use it to validate
contract examples and actual CLI output against the versioned schemas. Runtime
code has no external Go dependencies.

## Run verification offline

After setup, run the full suite:

```sh
make verify-linux
```

This runs both `make verify` and `make acceptance` in the pinned container:

| Command | Checks |
| --- | --- |
| `make verify` | Formatting, offline producer fixture reproduction, vet, and fresh race-enabled tests, including schemas, fixture checksums, expected output files and public API tests |
| `make acceptance` | The real CLI's exits 0, 1, 2 and 3; complete JSON schema validation; byte-for-byte agreement with the public library and independent expected outputs in both formats; repeatability; unchanged input bytes; and the CI, provenance and library examples |

To run only `make verify` in the same container, use the foundation target:

```sh
make verify-foundation-linux
```

Verification checks Go's JSON test events as well as the process exit code.
Every package with test sources must complete at least one passing test, every
started test must finish, and the package must pass. A zero exit code without
actual test execution fails verification.

The container has no network access and uses the prepared image and module
cache. Source is mounted read-only; only ignored `dist/` caches and container
`/tmp` are writable. The scripts set `--pull never`, `--network none`,
`GOTOOLCHAIN=local`, `GOPROXY=off` and `GOSUMDB=off`. A missing image or dependency
requires another explicit setup run. Mandatory tools are never silently skipped.

Linux verification always uses the image's Go binary, regardless of a host
`GO` override. It clears caller-supplied `GOFLAGS` and `GORACE` so test filters
or race-detector exit overrides cannot weaken the suite.

## Verify directly on a development host

Direct host verification requires exact Go 1.27.4, Python 3 and a C compiler.
Choose the Go executable with `go_bin` below: use `go` if the correct version
is on `PATH`, or replace it with the executable's absolute path. Prepare the
module cache once with network access, then run the checks offline:

```sh
go_bin=go
mkdir -p dist/cache/go-build dist/cache/go-mod
export GOTOOLCHAIN=local GOENV=off GOWORK=off
export GOCACHE="$PWD/dist/cache/go-build" GOMODCACHE="$PWD/dist/cache/go-mod"
"$go_bin" mod download
GOPROXY=off GOSUMDB=off make GO="$go_bin" verify
GOPROXY=off GOSUMDB=off make GO="$go_bin" acceptance
GOPROXY=off GOSUMDB=off "$go_bin" run ./examples/library
```

Verification rejects other Go versions and automatic toolchain downloads.
Keep generated build outputs and caches in `dist/`.

## ARM64 macOS host example

The ARM64 Linux VM used for verification required an explicit guest base for
QEMU user-mode emulation. Without it, QEMU 10.2.3 could place Go's race-detector
memory outside the allocator's supported address range. The sanitizer aborted
before tests ran with `sanitizer_allocator_primary32.h:292`, even though the
process could exit zero. An `ok` line alone therefore did not establish that
the race tests had run.

Setting `QEMU_GUEST_BASE=0x800000000000` keeps guest mappings in the address
range this runtime requires. The verification script also checks that tests
actually execute. This setting applies to the process; it does not change the
VM or pinned Go image. Native Linux amd64 does not need it.

QEMU 7.0.0 also crashed inside the Go tools on the same host. Go documents
[known issues with QEMU versions before
7.1.0](https://go.dev/wiki/MinimumRequirements#linux) and
[a related memory-corruption issue](https://github.com/golang/go/issues/77572).

On an ARM64 macOS host with Colima installed, the following preparation uses
network access to create a separate VM and install its amd64 emulator. It
leaves the active Docker context and existing VMs unchanged. The 6 GiB memory
allocation accommodates the million-finding race test; 2 GiB was observed to
fail with a kernel out-of-memory kill. The emulator image is pinned to the
Linux arm64 manifest for QEMU 10.2.3.

```sh
colima start cvedelta-proof --arch aarch64 --vm-type vz --binfmt=false --cpu 2 --memory 6 --disk 10 --activate=false --ssh-config=false --mount "$PWD:w"
docker --context colima-cvedelta-proof run --rm --privileged --platform linux/arm64 tonistiigi/binfmt@sha256:b4c6a09270133b3c5b4dff94f83067df4dd27eced195fc6a1dbad102999e24dd --install amd64
DOCKER_CONTEXT=colima-cvedelta-proof make setup-linux
```

Then run the offline checks in that context, using the same pinned Go image
and the process-local guest base. `build/linux.sh` forwards `QEMU_GUEST_BASE`
only when the caller sets it:

```sh
QEMU_GUEST_BASE=0x800000000000 DOCKER_CONTEXT=colima-cvedelta-proof make verify-foundation-linux
QEMU_GUEST_BASE=0x800000000000 DOCKER_CONTEXT=colima-cvedelta-proof make verify-linux
```

## Create local release packages

After source verification, choose the packaging command for your environment.
On native Linux amd64, run:

```sh
make package
```

For the ARM64 macOS workflow above, keep the Colima VM running and use the same
Docker context and QEMU setting:

```sh
QEMU_GUEST_BASE=0x800000000000 DOCKER_CONTEXT=colima-cvedelta-proof make package
```

On Linux amd64, packaging builds a static binary with `-trimpath` and
`-buildvcs=false`, then creates deterministic, versioned `.tar.gz` and `.zip`
archives plus `SHA256SUMS` in `dist/package/`. On other hosts it uses the
already prepared pinned Linux container, offline. If that environment is in a
non-default Docker context, pass `DOCKER_CONTEXT` as in the Colima example.

A fixed file allowlist determines the archive contents: the binary,
Apache-2.0 project license, guides, schemas, original demo files and the complete
pinned producer fixture, including its MIT source, license and provenance.
Test-only Go dependencies are neither linked nor bundled. Each archive also
contains `MANIFEST.sha256` for its payload.

`third_party/go/` retains the exact build toolchain's Go BSD license, PATENTS
grant, package-tree license files, standard-library build-input inventory, and
verbatim copyright and license comment blocks from the selected Go and assembly
files. These include the runtime's Lucent/Vita Nuova notice and math and crypto
attributions. The inventory is produced with `go list -deps -json` under the
same Linux amd64, CGO-disabled build settings. The linker may eliminate some
functions; the inventory does not establish broader legal compliance.

Packaging checks exact archive membership, every extracted byte, the expected
pinned attributions and extracted notices, and the Apache license. It rejects
common private-path and credential markers, checks each extracted binary's
release version, and runs it on Linux amd64 through exits 0, 1, 2 and 3.
These are specific content and behavior
checks, not a general claim that a secret scanner has cleared the archives.
Creating packages does not publish a release, create a tag, change repository
visibility or request Go module indexing.

From the repository root on Linux, independently check the archive checksums:

```sh
(cd dist/package && sha256sum -c SHA256SUMS)
```

Final release acceptance requires a clean checkout of the reviewed commit,
with caches explicitly prepared beforehand. A successful run in a shared
working tree alone does not meet that requirement. Review source, licensing
and archive contents before publication.

If you used the Colima example, stop its VM after all verification and packaging
work is finished:

```sh
colima stop cvedelta-proof
```
