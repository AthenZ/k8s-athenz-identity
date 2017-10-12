package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type response struct {
	Fields []field `json:"fields"`
}

func main() {
	http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := "/tokens/ntoken"
		b, err := ioutil.ReadFile(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var out []field
		fields := strings.Split(string(b), ";")
		for _, f := range fields {
			parts := strings.SplitN(f, "=", 2)
			if len(parts) == 2 && parts[0] != "s" { // hide sig
				out = append(out, field{Name: parts[0], Value: parts[1]})
			}
		}
		b, err = json.MarshalIndent(response{Fields: out}, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
}
