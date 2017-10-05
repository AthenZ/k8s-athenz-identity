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

	"github.com/yahoo/k8s-athenz-identity/internal/common"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/keys"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"gopkg.in/yaml.v1"
	"k8s.io/api/core/v1"
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

func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func parseFlags(clusterConfig *rest.Config, program string, args []string) (*params, error) {
	var (
		providerService = envOrDefault("ATHENZ_INIT_PROVIDER_SERVICE", "")
		namespace       = envOrDefault("ATHENZ_INIT_CONFIG_NAMESPACE", "default")
		configMap       = envOrDefault("ATHENZ_INIT_CONFIG_MAP", "athenz-initializer")
		keyDir          = envOrDefault("ATHENZ_INIT_PRIVATE_KEYS_DIR", "/var/keys/private")
		dnsSuffix       = envOrDefault("ATHENZ_INIT_DNS_SUFFIX", "")
		adminDomain     = envOrDefault("ATHENZ_INIT_ADMIN_DOMAIN", "k8s.admin")
		resyncInterval  = envOrDefault("ATHENS_INIT_RESYNC_INTERVAL", "60s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&providerService, "provider", providerService, "fully qualified provider service, required")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS suffix, required")
	f.StringVar(&namespace, "namespace", namespace, "The configuration namespace")
	f.StringVar(&configMap, "configmap", configMap, "The athenz initializer configuration configmap")
	f.StringVar(&keyDir, "sign-key-dir", keyDir, "directory containing private signing keys")
	f.StringVar(&adminDomain, "admin-domain", adminDomain, "athenz admin domain for cluster")
	f.StringVar(&resyncInterval, "sync-interval", resyncInterval, "watcher re-sync interval")

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "Show version information")

	err := f.Parse(args)
	if err != nil {
		return nil, err
	}

	if showVersion {
		fmt.Println(getVersion())
		return nil, errEarlyExit
	}

	if err := util.CheckFields("arguments", map[string]bool{
		"provider":   providerService == "",
		"dns-suffix": dnsSuffix == "",
	}); err != nil {
		return nil, err
	}

	ri, err := time.ParseDuration(resyncInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid resync interval %q, %v", resyncInterval, err)
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

	privateSource := keys.NewPrivateKeySource(keyDir, common.AthensInitSecret)

	attributeSerializer, err := identity.NewSerializer(identity.SerializerConfig{
		TokenExpiry:     15 * time.Minute,
		KeyProvider:     privateSource.SigningKey,
		DNSSuffix:       dnsSuffix,
		ProviderService: providerService,
	})
	if err != nil {
		return nil, err
	}

	a := common.Attributes{AdminDomain: adminDomain}
	initer, err := newInitializer(*initConfig, func(pod *v1.Pod) (map[string]string, error) {
		attrs, err := a.Pod2Attributes(pod)
		if err != nil {
			return nil, err
		}
		return attributeSerializer.Serialize(attrs)
	})
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
