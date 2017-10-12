package util

import (
	"bytes"
	"io"
	"os"
)

type Writer struct {
	files []string
}

func NewWriter() *Writer {
	return &Writer{}
}

func tmpFile(file string) string {
	return file + ".tmp"
}

func (w *Writer) AddBytes(target string, perms os.FileMode, content []byte) error {
	return w.AddReader(target, perms, bytes.NewBuffer(content))
}

func (w *Writer) AddFile(target string, perms os.FileMode, source string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.AddReader(target, perms, f)
}

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

func (w *Writer) Save() error {
	for _, f := range w.files {
		if err := os.Rename(tmpFile(f), f); err != nil {
			return err
		}
	}
	return nil
}
