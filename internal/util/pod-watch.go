// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package util

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const ipIndex = "__podIP__"

// PodWatchConfig is the configuration for the watcher. The zero-value is a valid configuration
// that provides a watch on initialized pods and indexes it by IP.
type PodWatchConfig struct {
	EventHandlers        cache.ResourceEventHandler // any resource event handlers to be added
	Indexers             cache.Indexers             // additional indexers. id and ip are always included
	IncludeUninitialized bool                       // include uninitialized objects in the watch
	ResyncInterval       time.Duration              // re-sync caches at this interval when non-zero
}

// PodWatcher watches the k8s API for pod information and returns pods from their IP address.
type PodWatcher struct {
	informer cache.Controller                     // the controller that can be started
	stop     chan struct{}                        // the channel that controls the watch
	once     sync.Once                            // close stop chan exactly once
	ipStore  func(podIP string) (*v1.Pod, error)  // the store that returns pods given IPs
	keyStore func(podKey string) (*v1.Pod, error) // the store that returns pods given the key (namespace<SLASH>name)
}

// NewPodWatcher creates a pod watcher for the supplied namespace (blank for all), client set and watch config.
func NewPodWatcher(ns string, clientset *kubernetes.Clientset, watchConfig PodWatchConfig) (*PodWatcher, error) {
	if ns == "" {
		ns = v1.NamespaceAll
	}

	if watchConfig.EventHandlers == nil {
		watchConfig.EventHandlers = cache.ResourceEventHandlerFuncs{}
	}

	if watchConfig.Indexers == nil {
		watchConfig.Indexers = make(map[string]cache.IndexFunc)
	}

	watchConfig.Indexers[ipIndex] = func(obj interface{}) ([]string, error) {
		var ret []string
		if pod, ok := obj.(*v1.Pod); ok {
			ret = append(ret, pod.Status.PodIP)
		}
		return ret, nil
	}

	watchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", ns, fields.Everything())
	podListWatcher := watchList
	if watchConfig.IncludeUninitialized {
		podListWatcher = &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.IncludeUninitialized = true
				return watchList.List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.IncludeUninitialized = true
				return watchList.Watch(options)
			},
		}
	}

	indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, 0, watchConfig.EventHandlers, watchConfig.Indexers)

	stop := make(chan struct{})
	return &PodWatcher{
		informer: informer,
		ipStore: func(podIP string) (*v1.Pod, error) {
			list, err := indexer.ByIndex(ipIndex, podIP)
			if err != nil {
				return nil, fmt.Errorf("ipStore error, %v", err)
			}
			var pods []*v1.Pod
			var names []string
			for _, r := range list {
				if p, ok := r.(*v1.Pod); ok {
					pods = append(pods, p)
					names = append(names, p.Namespace+"/"+p.Name)
				}
			}
			if len(pods) == 0 {
				return nil, fmt.Errorf("unable to find pod with IP %q", podIP)
			}
			if len(pods) > 1 {
				return nil, fmt.Errorf("more than one pod %v, found with IP %q", names, podIP)
			}
			return pods[0], nil
		},
		keyStore: func(podKey string) (*v1.Pod, error) {
			item, exists, err := indexer.GetByKey(podKey)
			if err != nil {
				return nil, fmt.Errorf("index error: %v", err)
			}
			if !exists {
				return nil, fmt.Errorf("unable to find pod with key %q", podKey)
			}
			pod, ok := item.(*v1.Pod)
			if !ok {
				return nil, fmt.Errorf("internal error, bad object type - not a pod")
			}
			return pod, nil
		},
		stop: stop,
	}, nil
}

// Start starts the pod watcher
func (w *PodWatcher) Start() {
	go w.informer.Run(w.stop)
}

// PodForKey returns a pod that has the specific key. The key is of the form
// [namespace][forward-slash][name].
func (w *PodWatcher) PodForKey(key string) (*v1.Pod, error) {
	return w.keyStore(key)
}

// PodForIP returns a pod that has the specified IP address.
func (w *PodWatcher) PodForIP(ip string) (*v1.Pod, error) {
	return w.ipStore(ip)
}

// Close closes the watcher.
func (w *PodWatcher) Close() error {
	w.once.Do(func() {
		close(w.stop)
	})
	return nil
}
