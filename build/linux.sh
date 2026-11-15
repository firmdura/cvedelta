#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
. build/environment.sh

if [ "${1:-}" = setup ]; then
    [ "$#" -eq 1 ] || { echo 'usage: build/linux.sh setup' >&2; exit 2; }
    docker pull --platform "$CVDELTA_LINUX_PLATFORM" "$CVDELTA_LINUX_IMAGE"
    mkdir -p dist/cache/linux-amd64/go-build dist/cache/linux-amd64/go-mod
    exec docker run --rm --pull never --platform "$CVDELTA_LINUX_PLATFORM" \
        --read-only --tmpfs /tmp:exec \
        --user "$(id -u):$(id -g)" \
        --mount "type=bind,src=$(pwd),dst=/src,readonly" \
        --mount "type=bind,src=$(pwd)/dist,dst=/src/dist" \
        --workdir /src \
        --env GOTOOLCHAIN=local --env GOENV=off --env GOWORK=off \
        --env GOPROXY=https://proxy.golang.org --env GOSUMDB=sum.golang.org \
        --env GOCACHE=/src/dist/cache/linux-amd64/go-build \
        --env GOMODCACHE=/src/dist/cache/linux-amd64/go-mod \
        "$CVDELTA_LINUX_IMAGE" go mod download
fi
if [ "$#" -eq 0 ]; then
    echo 'usage: build/linux.sh setup | MAKE_TARGET...' >&2
    exit 2
fi
mkdir -p dist/cache/linux-amd64/go-build dist/cache/linux-amd64/go-mod
exec docker run --rm --pull never --platform "$CVDELTA_LINUX_PLATFORM" \
    --network none --read-only --tmpfs /tmp:exec \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$(pwd),dst=/src,readonly" \
    --mount "type=bind,src=$(pwd)/dist,dst=/src/dist" \
    --workdir /src \
    --env QEMU_GUEST_BASE \
    --env GOTOOLCHAIN=local --env GOENV=off --env GOWORK=off \
    --env GOPROXY=off --env GOSUMDB=off --env CGO_ENABLED=1 --env GO=go \
    --env GOCACHE=/src/dist/cache/linux-amd64/go-build \
    --env GOMODCACHE=/src/dist/cache/linux-amd64/go-mod \
    "$CVDELTA_LINUX_IMAGE" make GO=go "$@"
