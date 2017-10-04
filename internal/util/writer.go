package util

import (
	"io/ioutil"
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

func (w *Writer) Add(file string, content []byte, perms os.FileMode) error {
	t := tmpFile(file)
	w.files = append(w.files, file)
	return ioutil.WriteFile(t, content, perms)
}

func (w *Writer) Save() error {
	for _, f := range w.files {
		if err := os.Rename(tmpFile(f), f); err != nil {
			return err
		}
	}
	return nil
}
