// SPDX-License-Identifier: Apache-2.0

package delta

import (
	"testing"

	"github.com/firmdura/cvedelta/internal/model"
)

func TestUnchangedFieldsDoNotAllocate(t *testing.T) {
	left, right := "same reported detail", "same reported detail"
	before := model.Context{Version: "1", Status: model.Unpatched, Attributes: model.Attributes{Detail: &left}}
	after := before
	after.Attributes.Detail = &right
	var fields []string
	allocs := testing.AllocsPerRun(100, func() {
		fields = changedFields(before, after)
	})
	if fields == nil || len(fields) != 0 {
		t.Fatalf("unchanged fields = %#v, want an empty array", fields)
	}
	if allocs != 0 {
		t.Fatalf("allocations per unchanged finding = %g, want 0", allocs)
	}
}
