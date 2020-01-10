package log

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/mash/go-accesslog"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log, audit *logrus.Logger

func newLogger(logFile, level string, formatter logrus.Formatter, enableStdOut bool) *logrus.Logger {
	var fileWriter io.Writer

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    1, // Mb
		MaxBackups: 5,
		MaxAge:     28, // Days
	}

	if enableStdOut {
		fileWriter = io.MultiWriter(os.Stdout, logger)
	} else {
		fileWriter = logger
	}

	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Warnln("Could not parse log level, defaulting to info. Error:", err.Error())
		logLevel = logrus.InfoLevel
	}

	if formatter == nil {
		formatter = &logrus.TextFormatter{
			ForceColors:            true,
			DisableSorting:         true,
			FullTimestamp:          true,
			DisableLevelTruncation: true,
		}
	}

	l := &logrus.Logger{
		Out:       fileWriter,
		Formatter: formatter,
		Level:     logLevel,
	}
	l.SetNoLock()

	dir := filepath.Dir(logFile)
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		logrus.Errorln("Could not mkdir for log file, defaulting to stdout logging. Error:", err.Error())
		l.Out = os.Stdout
	}
	return l
}

// InitLogger initializes a logger object with log rotation
func InitLogger(logFile, level string, enableStdOut bool) {
	log = newLogger(logFile, level, nil, enableStdOut)
}

// InitAuditLogger initializes an audit logger object
func InitAuditLogger(logFile string) {
	audit = newLogger(logFile,
		logrus.InfoLevel.String(),
		&logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyLevel: "audit",
			},
		},
		false)
}

type AccessLogger struct {
	access *logrus.Logger
}

func (l *AccessLogger) Log(record accesslog.LogRecord) {
	l.access.Printf("%s %s %d %v %v", record.Method, record.Uri, record.Status, record.ElapsedTime, record.CustomRecords)
}

// InitAccessLogger returns a handler that wraps the supplied delegate with access logging.
func InitAccessLogger(h http.Handler, logFile, level string) http.Handler {
	l := &AccessLogger{
		access: newLogger(logFile, level, nil, true),
	}
	return accesslog.NewLoggingHandler(h, l)
}

func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

func Warningf(format string, args ...interface{}) {
	log.Warningf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	log.Panicf(format, args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Info(args ...interface{}) {
	log.Info(args...)
}

func Print(args ...interface{}) {
	log.Print(args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}

func Warning(args ...interface{}) {
	log.Warning(args...)
}

func Error(args ...interface{}) {
	log.Error(args...)
}

func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

func Panic(args ...interface{}) {
	log.Panic(args...)
}

func Debugln(args ...interface{}) {
	log.Debugln(args...)
}

func Infoln(args ...interface{}) {
	log.Infoln(args...)
}

func Println(args ...interface{}) {
	log.Println(args...)
}

func Warnln(args ...interface{}) {
	log.Warnln(args...)
}

func Warningln(args ...interface{}) {
	log.Warningln(args...)
}

func Errorln(args ...interface{}) {
	log.Errorln(args...)
}

func Fatalln(args ...interface{}) {
	log.Fatalln(args...)
}

func Panicln(args ...interface{}) {
	log.Panicln(args...)
}

func Audit(fields map[string]interface{}, args ...interface{}) {
	audit.WithFields(fields).Info(args...)
}

func Auditln(fields map[string]interface{}, args ...interface{}) {
	audit.WithFields(fields).Infoln(args...)
}
