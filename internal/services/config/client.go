package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"strings"

	"github.com/pkg/errors"
)

type Client interface {
	Config() (*ClusterConfiguration, error)
}

type client struct {
	endpoint string
	c        *http.Client
}

func NewClient(endpoint string, c *http.Client) Client {
	if c == nil {
		c = &http.Client{}
	}
	return &client{
		endpoint: endpoint,
		c:        c,
	}
}

func (c *client) loadConfig(u string) (*ClusterConfiguration, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	res, err := c.c.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("%s %v", req.Method, req.URL))
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "body read")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %v returned %d, %s", req.Method, req.URL, res.StatusCode, b)
	}
	var resp ClusterConfiguration
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("JSON unmarshal, '%s'", b))
	}
	return &resp, nil
}

func (c *client) Config() (*ClusterConfiguration, error) {
	u := c.endpoint
	if !strings.HasSuffix(c.endpoint, configPath) {
		u += configPath
	}
	return c.loadConfig(u)
}
