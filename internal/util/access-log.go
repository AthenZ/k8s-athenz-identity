package util

import (
	"log"
	"net/http"
	"os"

	"github.com/mash/go-accesslog"
)

func NewAccessLogHandler(h http.Handler) http.Handler {
	return NewAccessLogHandlerWithProvider(h, nil)
}

type l struct {
	logger *log.Logger
}

func (l *l) Log(record accesslog.LogRecord) {
	l.logger.Printf("%s %s %d %v %v\n", record.Method, record.Uri, record.Status, record.ElapsedTime, record.CustomRecords)
}

func NewAccessLogHandlerWithProvider(h http.Handler, customProvider func(r *http.Request) map[string]string) http.Handler {
	l := &l{
		logger: log.New(os.Stderr, "[access] ", log.LstdFlags),
	}
	return accesslog.NewLoggingHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if customProvider != nil {
			attrs := customProvider(r)
			if attrs != nil && len(attrs) > 0 {
				lw := w.(*accesslog.LoggingWriter)
				for k, v := range attrs {
					lw.SetCustomLogRecord(k, v)
				}
			}
		}
		h.ServeHTTP(w, r)
	}), l)
}
