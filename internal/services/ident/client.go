package ident

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

// Client is a client for identity services.
type Client interface {
	// Init returns an identity object.
	Init() (*Identity, error)
	// Refresh returns an identity object given refresh parameters.
	Refresh(r RefreshRequest) (*Identity, error)
}

type client struct {
	endpoint string
	hashed   string
	c        *http.Client
}

// NewClient returns a client for the specific endpoint and opaque pod id.
// The HTTP client may be nil for simple HTTP endpoints but must be supplied
// for UDS endpoints.
func NewClient(endpoint string, hashedID string, c *http.Client) Client {
	if c == nil {
		c = &http.Client{}
	}
	return &client{
		endpoint: endpoint,
		hashed:   hashedID,
		c:        c,
	}
}

func (c *client) getIdent(req *http.Request) (*Identity, error) {
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
	var resp Identity
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("JSON unmarshal, '%s'", b))
	}
	return &resp, nil
}

func (c *client) Init() (*Identity, error) {
	u := c.endpoint + initPath + "/" + c.hashed
	req, err := http.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	return c.getIdent(req)
}

func (c *client) Refresh(r RefreshRequest) (*Identity, error) {
	u := c.endpoint + refreshPath + "/" + c.hashed
	b, err := json.Marshal(r)
	if err != nil {
		return nil, errors.Wrap(err, "JSON marshal")
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewBuffer(b))
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	return c.getIdent(req)
}
