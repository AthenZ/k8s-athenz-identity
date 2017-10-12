package config

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var defaultPollInterval = 5 * time.Minute // default that can be customized in tests

type LogFn func(format string, args ...interface{})

// certReloader reloads the (key, cert) pair from the filesystem when
// the cert file is updated.
type certReloader struct {
	l        sync.RWMutex
	certFile string
	keyFile  string
	cert     *tls.Certificate
	mtime    time.Time
	logger   LogFn
	stop     chan struct{}
}

// GetLatestCertificate returns the latest known certificate.
func (w *certReloader) GetLatestCertificate() (*tls.Certificate, error) {
	w.l.RLock()
	c := w.cert
	w.l.RUnlock()
	return c, nil
}

// Close stops the background refresh.
func (w *certReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

func (w *certReloader) maybeReload() error {
	st, err := os.Stat(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to stat %s", w.certFile))
	}
	if !st.ModTime().After(w.mtime) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s,%s", w.certFile, w.keyFile))
	}
	w.l.Lock()
	w.cert = &cert
	w.mtime = st.ModTime()
	w.l.Unlock()
	w.logger("certs reloaded at %v", time.Now())
	return nil
}

func (w *certReloader) pollRefresh() error {
	poll := time.NewTicker(time.Duration(defaultPollInterval))
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.maybeReload(); err != nil {
				w.logger("cert reload error: %v\n", err)
			}
		case <-w.stop:
			return nil
		}
	}
}

// reloadConfig contains the config for cert reload.
type reloadConfig struct {
	CertFile string // the cert file
	KeyFile  string // the key file
	Logger   LogFn  // custom log function for errors, optional
}

// newCertReloader returns a certReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func newCertReloader(config reloadConfig) (*certReloader, error) {
	if config.Logger == nil {
		config.Logger = log.Printf
	}
	r := &certReloader{
		certFile: config.CertFile,
		keyFile:  config.KeyFile,
		logger:   config.Logger,
		stop:     make(chan struct{}, 10),
	}
	// load once to ensure files are good.
	if err := r.maybeReload(); err != nil {
		return nil, err
	}
	go r.pollRefresh()
	return r, nil
}
