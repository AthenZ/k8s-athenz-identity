// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"fmt"
	"sort"
)

// CheckFields checks the map for any true values and returns an error
// that includes the type name and missing attribute names.
func CheckFields(typeName string, failedChecks map[string]bool) error {
	var missing []string
	for k, v := range failedChecks {
		if v {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%s: missing fields %v", typeName, missing)
}
