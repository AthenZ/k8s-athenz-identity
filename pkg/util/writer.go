// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.

package util

import (
	"bytes"
	"io"
	"os"
)

// Writer writes multiple files with modified suffixes and renames all of them
// to their final names on save.
type Writer struct {
	files []string
}

// NewWriter returns a writer.
func NewWriter() *Writer {
	return &Writer{}
}

func tmpFile(file string) string {
	return file + ".tmp"
}

// AddBytes writes a file with the supplied bytes.
func (w *Writer) AddBytes(target string, perms os.FileMode, content []byte) error {
	return w.AddReader(target, perms, bytes.NewBuffer(content))
}

// AddFile writes a file using the supplied file as source.
func (w *Writer) AddFile(target string, perms os.FileMode, source string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.AddReader(target, perms, f)
}

// AddReader writes a file using the supplied reader as source.
func (w *Writer) AddReader(target string, perms os.FileMode, content io.Reader) error {
	t := tmpFile(target)
	f, err := os.OpenFile(t, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, perms)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, content); err != nil {
		return err
	}
	w.files = append(w.files, target)
	return nil
}

// Save renames all temp files written to their final names. When multiple files are involved,
// this reduces race conditions with inconsistent data but does not completely eliminate it.
func (w *Writer) Save() error {
	for _, f := range w.files {
		if err := os.Rename(tmpFile(f), f); err != nil {
			return err
		}
	}
	return nil
}
