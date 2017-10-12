package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/dimfeld/httptreemux"
)

const (
	configPath    = "/cluster"
	trustRootPath = "/trust-root"
)

func NewHandler(versionPrefix string, config *ClusterConfiguration) (http.Handler, error) {
	mux := httptreemux.New()
	mux.GET(versionPrefix+configPath, func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		doJSON(w, config)
	})
	mux.GET(versionPrefix+trustRootPath+"/:name", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		w.Header().Set("Content-Type", "text/plain")
		s, ok := config.TrustRoots[TrustedSource(params["name"])]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, fmt.Sprintf("no trust root found for %q", params["name"]))
		}
		w.Write([]byte(s))
	})
	return mux, nil
}

func doJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
	w.Write([]byte{'\n'})
}
