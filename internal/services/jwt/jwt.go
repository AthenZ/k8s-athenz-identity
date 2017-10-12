package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dimfeld/httptreemux"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
)

const jwtPath = "/jwt"

type signRequest struct {
	Subject identity.PodSubject `json:"subject"`
}

type signResponse struct {
	JWT string `json:"jwt"`
}

func NewHandler(versionPrefix string, serializer func(subject *identity.PodSubject) (string, error)) http.Handler {
	router := httptreemux.New()
	router.POST(versionPrefix+jwtPath, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("body read error, %v", err), http.StatusInternalServerError)
			return
		}
		var req signRequest
		if err := json.Unmarshal(b, &req); err != nil {
			http.Error(w, fmt.Sprintf("JSON error, %v", err), http.StatusBadRequest)
			return
		}
		jwt, err := serializer(&req.Subject)
		if err != nil {
			http.Error(w, fmt.Sprintf("JWT, %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&signResponse{JWT: jwt})
	})
	return router
}

type Client interface {
	GetJWT(subject *identity.PodSubject) (string, error)
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

func (c *client) GetJWT(s *identity.PodSubject) (string, error) {
	u := c.endpoint + jwtPath
	reqBytes, err := json.Marshal(signRequest{Subject: *s})
	if err != nil {
		return "", errors.Wrap(err, "json marshal")
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewBuffer(reqBytes))
	if err != nil {
		return "", errors.Wrap(err, "new request")
	}
	res, err := c.c.Do(req)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("POST %s", u))
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "body read")
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s returned %d, %s", u, res.StatusCode, b)
	}
	var resp signResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("JSON unmarshal, '%s'", b))
	}
	return resp.JWT, nil
}
