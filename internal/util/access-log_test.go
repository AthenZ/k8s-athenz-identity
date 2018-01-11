// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessLogWriter(t *testing.T) {
	a := assert.New(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("no handler for you"))
	})
	var buf bytes.Buffer
	wrapped := NewAccessLogHandler(h, &buf)
	s := httptest.NewServer(wrapped)
	res, err := http.Get(s.URL)
	require.Nil(t, err)
	defer res.Body.Close()
	a.Equal(403, res.StatusCode)
	b, err := ioutil.ReadAll(res.Body)
	require.Nil(t, err)
	a.Equal("no handler for you", string(b))
	log := buf.String()
	a.Contains(log, "403")
	a.Contains(log, "[access]")
}

func TestAccessLogWriterWithNilWriter(t *testing.T) {
	a := assert.New(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("no handler for you"))
	})
	f, err := ioutil.TempFile("", "foo")
	old := os.Stderr
	defer func() {
		os.Stderr = old
	}()
	os.Stderr = f
	require.Nil(t, err)
	wrapped := NewAccessLogHandler(h, nil)
	s := httptest.NewServer(wrapped)
	res, err := http.Get(s.URL)
	require.Nil(t, err)
	defer res.Body.Close()
	f.Close()
	b, err := ioutil.ReadFile(f.Name())
	log := string(b)
	a.Contains(log, "403")
	a.Contains(log, "[access]")
}
