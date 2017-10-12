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
