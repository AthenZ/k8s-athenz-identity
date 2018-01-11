// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/mash/go-accesslog"
)

type l struct {
	logger *log.Logger
}

func (l *l) Log(record accesslog.LogRecord) {
	l.logger.Printf("%s %s %d %v %v\n", record.Method, record.Uri, record.Status, record.ElapsedTime, record.CustomRecords)
}

// NewAccessLogHandler returns a handler that wraps the supplied delegate with access logging.
// Access log lines are written to the supplied writer. A nil writer is the same as standard error.
func NewAccessLogHandler(h http.Handler, writer io.Writer) http.Handler {
	if writer == nil {
		writer = os.Stderr
	}
	l := &l{
		logger: log.New(writer, "[access] ", log.LstdFlags),
	}
	return accesslog.NewLoggingHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}), l)

}
