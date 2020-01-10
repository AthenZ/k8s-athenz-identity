// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.

package log

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAccessLogger(t *testing.T) {
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
	wrapped := InitAccessLogger(h, "foo", "debug")
	s := httptest.NewServer(wrapped)
	res, err := http.Get(s.URL)
	require.Nil(t, err)
	defer res.Body.Close()
	f.Close()
	b, err := ioutil.ReadFile("foo")
	log := string(b)
	a.Contains(log, "403")

	os.Remove("foo")
}
