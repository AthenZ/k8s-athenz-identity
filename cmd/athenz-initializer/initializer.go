// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"fmt"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"k8s.io/api/core/v1"
)

type initConfig struct {
	Name              string   `yaml:"name"`              // initializer name, must have at least 2 dots
	AnnotationTrigger string   `yaml:"annotationTrigger"` // the annotation that a pod must have to trigger the initializer
	RemoveImages      []string `yaml:"removeImages"`      // images without versions to remove if found in pod
	InitTemplate      string   `yaml:"initTemplate"`      // template YAML spec for SIA init container
	RefreshTemplate   string   `yaml:"refreshTemplate"`   // template YAML spec for SIA refresh container
	VolumeTemplate    string   `yaml:"volumeTemplate"`    // template for flex volume
}

func (ic *initConfig) assertValid() error {
	return util.CheckFields("initConfig", map[string]bool{
		"Name":            ic.Name == "",
		"InitTemplate":    ic.InitTemplate == "",
		"RefreshTemplate": ic.RefreshTemplate == "",
		"VolumeTemplate":  ic.VolumeTemplate == "",
	})
}

type initializer struct {
	config initConfig
}

func newInitializer(config initConfig) (*initializer, error) {
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	var templateContainer v1.Container
	err := yaml.Unmarshal([]byte(config.InitTemplate), &templateContainer)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("bad init template %q", config.InitTemplate))
	}
	err = yaml.Unmarshal([]byte(config.RefreshTemplate), &templateContainer)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("bad refresh template %q", config.RefreshTemplate))
	}
	var templateVolume v1.Volume
	err = yaml.Unmarshal([]byte(config.VolumeTemplate), &templateVolume)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("bad volume template %q", config.VolumeTemplate))
	}
	return &initializer{
		config: config,
	}, nil
}

func (i *initializer) Name() string {
	return i.config.Name
}

func (i *initializer) Update(pod *v1.Pod) error {
	if i.config.AnnotationTrigger != "" {
		if pod.Annotations == nil || pod.Annotations[i.config.AnnotationTrigger] != "true" {
			return nil // nothing to do
		}
	}

	// filterContainers filters out any containers having the
	// SIA or legacy image from the supplied list
	filterContainers := func(containers []v1.Container) []v1.Container {
		var list []v1.Container
		for _, c := range containers {
			im := c.Image
			// exclude version
			pos := strings.LastIndex(im, ":")
			if pos >= 0 {
				im = im[:pos]
			}
			for _, name := range i.config.RemoveImages {
				if im == name {
					continue
				}
			}
			list = append(list, c)
		}
		return list
	}

	addMissingVolumes := func(containers ...v1.Container) {
		requiredVolumeMap := map[string]bool{}
		for _, c := range containers {
			for _, vm := range c.VolumeMounts {
				requiredVolumeMap[vm.Name] = true
			}
		}

		existingVolumeMap := map[string]bool{}
		for _, v := range pod.Spec.Volumes {
			existingVolumeMap[v.Name] = true
		}

		for k := range requiredVolumeMap {
			if !existingVolumeMap[k] {
				pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
					Name: k,
					VolumeSource: v1.VolumeSource{
						EmptyDir: &v1.EmptyDirVolumeSource{},
					},
				})
			}
		}
	}

	pod.Spec.InitContainers = filterContainers(pod.Spec.InitContainers)
	pod.Spec.Containers = filterContainers(pod.Spec.Containers)

	var siaInitContainer, siaRefreshContainer v1.Container
	var identityVolume v1.Volume

	// errors already checked in newInitializer for unmarshals below
	_ = yaml.Unmarshal([]byte(i.config.InitTemplate), &siaInitContainer)
	_ = yaml.Unmarshal([]byte(i.config.RefreshTemplate), &siaRefreshContainer)
	_ = yaml.Unmarshal([]byte(i.config.VolumeTemplate), &identityVolume)

	pod.Spec.Volumes = append([]v1.Volume{identityVolume}, pod.Spec.Volumes...)
	pod.Spec.InitContainers = append([]v1.Container{siaInitContainer}, pod.Spec.InitContainers...)
	pod.Spec.Containers = append([]v1.Container{siaRefreshContainer}, pod.Spec.Containers...)
	addMissingVolumes(siaInitContainer, siaRefreshContainer)
	return nil
}
