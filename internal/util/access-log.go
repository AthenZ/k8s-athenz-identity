package util

import (
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
// Access log lines are written to stderr.
func NewAccessLogHandler(h http.Handler) http.Handler {
	l := &l{
		logger: log.New(os.Stderr, "[access] ", log.LstdFlags),
	}
	return accesslog.NewLoggingHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}), l)
}
