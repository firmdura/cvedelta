// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// isOne compares decimal JSON numbers exactly, including integral exponent and
// fraction forms. Float conversion could round a different value to version 1;
// constructing a big rational could allocate excessively for hostile exponents.
func isOne(n json.Number) bool {
	mantissa := string(n)
	var exponent int64
	if i := strings.IndexAny(mantissa, "eE"); i >= 0 {
		var err error
		exponent, err = strconv.ParseInt(mantissa[i+1:], 10, 64)
		if err != nil {
			return false
		}
		mantissa = mantissa[:i]
	}
	fraction := 0
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		fraction = len(mantissa) - i - 1
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	mantissa = strings.TrimLeft(mantissa, "0")
	if strings.TrimRight(mantissa, "0") != "1" {
		return false
	}
	// Compare rather than add the exponent so extreme int64 values cannot wrap.
	return exponent == int64(fraction)-int64(len(mantissa)-1)
}

// Go's JSON decoder replaces invalid UTF-8 and unpaired surrogate escapes with
// U+FFFD. Reject those inputs first so a successful read never silently changes
// source strings. The decoder still owns all other JSON syntax validation.
func validateText(raw []byte, path string) error {
	if !utf8.Valid(raw) {
		// Locate the bad sequence only on failure. A literal U+FFFD is valid.
		for i := 0; i < len(raw); {
			r, size := utf8.DecodeRune(raw[i:])
			if r == utf8.RuneError && size == 1 {
				return fmt.Errorf("%s: invalid UTF-8 JSON at byte %d", path, i+1)
			}
			i += size
		}
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		start := i
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		u, ok := escapedUnit(raw, i)
		if !ok {
			continue // The JSON decoder reports malformed/truncated escapes.
		}
		i += 4
		if u < 0xD800 || u > 0xDFFF {
			continue
		}
		if u <= 0xDBFF && i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
			if low, ok := escapedUnit(raw, i+2); ok && low >= 0xDC00 && low <= 0xDFFF {
				i += 6
				continue
			}
		}
		return fmt.Errorf("%s: unpaired Unicode surrogate at byte %d", path, start+1)
	}
	return nil
}

// i points to the 'u' in a JSON Unicode escape.
func escapedUnit(raw []byte, i int) (uint64, bool) {
	if i+4 >= len(raw) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
	return v, err == nil
}
