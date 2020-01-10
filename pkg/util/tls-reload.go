// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var DefaultPollInterval = 1 * time.Second // 1s default interval to allow 1m cert refreshes

// LogFn allows customized logging.
type LogFn func(format string, args ...interface{})

// CertReloader reloads the (key, cert) pair from the filesystem when
// the cert file is updated.
type CertReloader struct {
	l            sync.RWMutex
	certFile     string
	keyFile      string
	cert         *tls.Certificate
	certPEM      []byte
	keyPEM       []byte
	mtime        time.Time
	pollInterval time.Duration
	logger       LogFn
	stop         chan struct{}
}

// GetLatestCertificate returns the latest known certificate.
func (w *CertReloader) GetLatestCertificate() (*tls.Certificate, error) {
	w.l.RLock()
	c := w.cert
	w.l.RUnlock()
	return c, nil
}

// GetLatestKeyAndCert returns the latest known key and certificate in raw bytes.
func (w *CertReloader) GetLatestKeyAndCert() ([]byte, []byte, error) {
	w.l.RLock()
	k := w.keyPEM
	c := w.certPEM
	w.l.RUnlock()
	return k, c, nil
}

// Close stops the background refresh.
func (w *CertReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

func (w *CertReloader) maybeReload() error {
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
	certPEM, err := ioutil.ReadFile(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s", w.certFile))
	}
	keyPEM, err := ioutil.ReadFile(w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load key from %s", w.keyFile))
	}
	w.l.Lock()
	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = st.ModTime()
	w.l.Unlock()
	w.logger("certs reloaded at %v", time.Now())
	return nil
}

func (w *CertReloader) pollRefresh() error {
	poll := time.NewTicker(w.pollInterval)
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

// ReloadConfig contains the config for cert reload.
type ReloadConfig struct {
	CertFile     string // the cert file
	KeyFile      string // the key file
	Logger       LogFn  // custom log function for errors, optional
	PollInterval time.Duration
}

// NewCertReloader returns a CertReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func NewCertReloader(config ReloadConfig) (*CertReloader, error) {
	if config.Logger == nil {
		config.Logger = log.Printf
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Duration(DefaultPollInterval)
	}
	r := &CertReloader{
		certFile:     config.CertFile,
		keyFile:      config.KeyFile,
		logger:       config.Logger,
		pollInterval: config.PollInterval,
		stop:         make(chan struct{}, 10),
	}
	// load once to ensure files are good.
	if err := r.maybeReload(); err != nil {
		return nil, err
	}
	go r.pollRefresh()
	return r, nil
}
