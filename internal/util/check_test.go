// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckFail(t *testing.T) {
	a := assert.New(t)
	err := CheckFields("foobar", map[string]bool{
		"name": true,
		"age":  true,
		"ssn":  false,
	})
	require.NotNil(t, err)
	a.Equal("foobar: missing fields [age name]", err.Error())
}

func TestCheckPass(t *testing.T) {
	err := CheckFields("foobar", map[string]bool{
		"name": false,
		"age":  false,
		"ssn":  false,
	})
	require.Nil(t, err)
}
