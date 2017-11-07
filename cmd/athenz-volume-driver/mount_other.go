// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

// +build !linux

package main

import (
	"errors"
)

func bindMount(sourcePath, targetPath string, readOnly bool) error {
	return errors.New("not implemented")
}

func bindUnmount(targetPath string) error {
	return errors.New("not implemented")
}
