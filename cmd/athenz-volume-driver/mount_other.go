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
