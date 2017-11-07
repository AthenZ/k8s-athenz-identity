// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/pkg/errors"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodInitializer implements the initializer logic without having to worry about
// posting updates to the API.
type PodInitializer interface {
	Name() string             // initializer name to match in pending list
	Update(pod *v1.Pod) error // update the pod with extra information/ containers
}

type watchConfg struct {
	initializer PodInitializer // the pod initializer
}

type watcher struct {
	initializer PodInitializer        // the initializer implementation
	stop        chan struct{}         // the channel that controls the watch
	once        *sync.Once            // close stop chan exactly once
	cs          *kubernetes.Clientset // pod update interface
	indexer     cache.Indexer         // the indexer to find pods
}

// newWatcher creates a pod watcher.
func newWatcher(clientset *kubernetes.Clientset, initializer PodInitializer, resync time.Duration) (*watcher, error) {
	watchList := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceAll, fields.Everything())
	// Wrap the returned watchlist to include
	// the `IncludeUninitialized` list option when setting up watch clients.
	podListWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.IncludeUninitialized = true
			return watchList.List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.IncludeUninitialized = true
			return watchList.Watch(options)
		},
	}

	stop := make(chan struct{})
	var o sync.Once
	w := &watcher{
		initializer: initializer,
		stop:        stop,
		once:        &o,
		cs:          clientset,
	}

	indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, resync, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			w.maybeInit(obj.(*v1.Pod))
		},
		UpdateFunc: func(old, obj interface{}) {
			w.maybeInit(obj.(*v1.Pod))
		},
	}, cache.Indexers{})

	w.indexer = indexer
	go informer.Run(stop)
	return w, nil
}

func (w *watcher) maybeInit(pod *v1.Pod) (ferr error) {
	defer func() {
		if ferr != nil {
			log.Printf("pod init error %s/%s, %v", pod.Namespace, pod.Name, ferr)
		}
	}()
	name := w.initializer.Name()
	list := pod.ObjectMeta.GetInitializers()
	if list == nil {
		return nil
	}
	pending := list.Pending[:]
	if len(pending) == 0 {
		return nil
	}
	if pending[0].Name != name {
		return nil
	}

	log.Printf("initializing pod %s/%s", pod.Namespace, pod.Name)
	newPod := pod.DeepCopy()

	err := w.initializer.Update(newPod)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("initializer error for %s/%s", newPod.Namespace, newPod.Name))
	}

	pending = pending[1:]
	newPod.ObjectMeta.Initializers.Pending = pending
	if len(pending) == 0 {
		newPod.ObjectMeta.Initializers = nil
	}

	oldData, err := json.Marshal(pod)
	if err != nil {
		return err
	}

	newData, err := json.Marshal(newPod)
	if err != nil {
		return err
	}

	patchData, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Pod{})
	if err != nil {
		return err
	}

	log.Println("patch pod", pod.Name, "bytes:", string(patchData))
	_, err = w.cs.CoreV1().Pods(pod.Namespace).Patch(pod.Name, types.StrategicMergePatchType, patchData)
	if err != nil {
		return err
	}
	return nil
}

func (w *watcher) podByID(id string) (*v1.Pod, error) {
	p, exists, err := w.indexer.GetByKey(id)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("pod %s not found", id)
	}
	return p.(*v1.Pod), nil
}

func (w *watcher) Close() error {
	w.once.Do(func() {
		close(w.stop)
	})
	return nil
}
