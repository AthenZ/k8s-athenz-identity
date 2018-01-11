// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var errEarlyExit = errors.New("early exit")

const (
	keyInitConfig = "init-config"
)

// Version gets set by the build script via LDFLAGS
var Version string

func getVersion() string {
	if Version == "" {
		return "development version"
	}
	return Version
}

type params struct {
	watcher *watcher
	closers []io.Closer
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func loadConfig(cs *kubernetes.Clientset, namespace string, configMap string) (*initConfig, error) {
	cm, err := cs.CoreV1().ConfigMaps(namespace).Get(configMap, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	configStr := cm.Data[keyInitConfig]
	var c initConfig
	if err := yaml.Unmarshal([]byte(configStr), &c); err != nil {
		return nil, fmt.Errorf("unable to load config from %q, %v", configStr, err)
	}
	return &c, nil
}

func parseFlags(clusterConfig *rest.Config, program string, args []string) (*params, error) {
	var (
		namespace    = util.EnvOrDefault("CONFIG_NAMESPACE", "default")
		configMap    = util.EnvOrDefault("CONFIG_MAP", "athenz-initializer")
		syncInterval = util.EnvOrDefault("SYNC_INTERVAL", "60s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&namespace, "config-namespace", namespace, "configuration namespace")
	f.StringVar(&configMap, "config-map", configMap, "athenz initializer configuration config map")
	f.StringVar(&syncInterval, "sync-interval", syncInterval, "watcher re-sync interval")

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "Show version information")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			err = errEarlyExit
		}
		return nil, err
	}

	if showVersion {
		fmt.Println(getVersion())
		return nil, errEarlyExit
	}

	ri, err := time.ParseDuration(syncInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid resync interval %q, %v", syncInterval, err)
	}

	if clusterConfig == nil {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	cs, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset, %v", err)
	}

	initConfig, err := loadConfig(cs, namespace, configMap)
	if err != nil {
		return nil, err
	}

	initer, err := newInitializer(*initConfig)
	if err != nil {
		return nil, err
	}

	watcher, err := newWatcher(cs, initer, ri)
	if err != nil {
		return nil, err
	}

	return &params{
		watcher: watcher,
		closers: []io.Closer{watcher},
	}, nil
}

func run(config *rest.Config, program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(config, program, args)
	if err != nil {
		return err
	}
	defer params.Close()
	params.watcher.start()
	<-stopChan
	return nil
}

func main() {
	flag.CommandLine.Parse([]string{}) // initialize glog with defaults
	stopChan := make(chan struct{})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-ch
		log.Println("shutting down...")
		close(stopChan)
	}()

	err := run(nil, filepath.Base(os.Args[0]), os.Args[1:], stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln("[FATAL]", err)
	}
}
