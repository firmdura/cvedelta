# SPDX-License-Identifier: Apache-2.0
GO ?= go

.PHONY: verify acceptance setup-linux verify-linux verify-foundation-linux build package

build:
	@mkdir -p dist
	GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off $(GO) build -buildvcs=false -trimpath -o dist/cvedelta ./cmd/cvedelta

# Includes contract/schema/fixture tests and any feature goldens in go test ./....
verify:
	@GO="$(GO)" sh build/verify.sh

acceptance:
	@GO="$(GO)" sh scripts/acceptance.sh

package:
	@GO="$(GO)" sh scripts/package.sh

# Explicit network-enabled image and dependency preparation.
setup-linux:
	@sh build/linux.sh setup

# Full offline release verification.
verify-linux:
	@sh build/linux.sh verify acceptance

# Foundation proof without claiming CLI acceptance.
verify-foundation-linux:
	@sh build/linux.sh verify
