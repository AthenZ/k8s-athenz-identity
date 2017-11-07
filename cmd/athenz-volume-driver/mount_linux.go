// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"syscall"
)

func bindMount(sourcePath, targetPath string, readOnly bool) error {
	flags := syscall.MS_BIND | syscall.MS_REC
	if readOnly {
		flags |= syscall.MS_RDONLY
	}
	return syscall.Mount(sourcePath, targetPath, "", uintptr(flags), "")
}

func bindUnmount(targetPath string) error {
	return syscall.Unmount(targetPath, 0)
}
