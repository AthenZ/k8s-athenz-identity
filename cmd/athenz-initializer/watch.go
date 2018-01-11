// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodInitializer implements the initializer logic without having to worry about
// posting updates to the API.
type PodInitializer interface {
	Name() string             // initializer name to match in pending list
	Update(pod *v1.Pod) error // update the pod with extra information/ containers
}

type watcher struct {
	podWatch    *util.PodWatcher      // the internal watcher
	initializer PodInitializer        // the initializer implementation
	cs          *kubernetes.Clientset // pod update interface
}

// newWatcher creates a pod watcher.
func newWatcher(clientset *kubernetes.Clientset, initializer PodInitializer, resync time.Duration) (*watcher, error) {
	w := &watcher{
		initializer: initializer,
		cs:          clientset,
	}
	watcher, err := util.NewPodWatcher(v1.NamespaceAll, clientset, util.PodWatchConfig{
		IncludeUninitialized: true,
		ResyncInterval:       resync,
		EventHandlers: &cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				w.maybeInit(obj.(*v1.Pod))
			},
			UpdateFunc: func(old, obj interface{}) {
				w.maybeInit(obj.(*v1.Pod))
			},
		},
	})
	if err != nil {
		return nil, err
	}
	w.podWatch = watcher
	return w, nil
}

func (w *watcher) start() {
	w.podWatch.Start()
}

func (w *watcher) maybeInit(pod *v1.Pod) (finalErr error) {
	defer func() {
		if finalErr != nil {
			log.Printf("pod init error %s/%s, %v", pod.Namespace, pod.Name, finalErr)
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

func (w *watcher) Close() error {
	return w.podWatch.Close()
}
