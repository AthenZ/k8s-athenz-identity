// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvOrDefault(t *testing.T) {
	os.Setenv("FOOBAR", "XXX")
	defer os.Unsetenv("FOOBAR")
	old := os.Getenv("LOGNAME")
	if old != "" {
		defer os.Setenv("LOGNAME", old)
	}
	os.Unsetenv("LOGNAME")

	a := assert.New(t)
	v := EnvOrDefault("FOOBAR", "YYY")
	a.Equal("XXX", v)

	v = EnvOrDefault("LOGNAME", "YYY")
	a.Equal("YYY", v)
}
