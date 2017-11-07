// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"k8s.io/api/core/v1"
)

type lookup struct {
	podEndpoint string
	mapper      *identity.Mapper
	timeout     time.Duration
}

func (l *lookup) getPodAttributes(podID string) (*identity.PodSubject, error) {
	client := &http.Client{Timeout: l.timeout}
	ep := l.podEndpoint + "/pods"
	res, err := client.Get(ep)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", ep, res.StatusCode)
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s, client read %v", ep, err)
	}
	var list v1.PodList
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("GET %s, JSON unmarshal, %v", ep, err)
	}
	for _, p := range list.Items {
		id := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
		if id == podID {
			return l.mapper.GetSubject(&p)
		}
	}
	return nil, fmt.Errorf("no pods found with id %q", podID)
}
