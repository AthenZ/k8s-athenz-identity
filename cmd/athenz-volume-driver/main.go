package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/services/ident"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const hostSocketDir = "/var/athenz/agent" // the directory that has the agent socket

const (
	opInit    = "init"
	opMount   = "mount"
	opUnmount = "unmount"
)

const (
	statusSuccess     = "Success"
	statusFailure     = "Failure"
	statusUnsupported = "Not supported"
)

type caps struct {
	Attach bool `json:"attach"`
}

type result struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func success() *result {
	return &result{Status: statusSuccess}
}

type initResult struct {
	result
	Capabilities caps `json:"capabilities"`
}

type metadata struct {
	FSType             string `json:"kubernetes.io/fsType"`
	PodName            string `json:"kubernetes.io/pod.name"`
	PodNamespace       string `json:"kubernetes.io/pod.namespace"`
	PodUID             string `json:"kubernetes.io/pod.uid"`
	PVOrVolumeName     string `json:"kubernetes.io/pvOrVolumeName"`
	ReadWrite          string `json:"kubernetes.io/readwrite"`
	ServiceAccountName string `json:"kubernetes.io/serviceAccount.name"`
}

func (m *metadata) assertValid() error {
	return util.CheckFields("driver metadata", map[string]bool{
		"PodName":      m.PodName == "",
		"PodNamespace": m.PodNamespace == "",
	})
}

func usageAndDie() {
	log.Fatalf("Usage: %s <op> <data>\n", filepath.Base(os.Args[0]))
}

// doInit handles the init command
func doInit(_ []string) (interface{}, error) {
	return &initResult{
		result: result{
			Status: statusSuccess,
		},
		Capabilities: caps{
			Attach: false,
		},
	}, nil
}

// doMount handles the mount command
func doMount(args []string) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("insuffient args, want at least %d got %d", 2, len(args))
	}
	path := args[0]

	jsonStr := args[1]
	var meta metadata
	if err := json.Unmarshal([]byte(jsonStr), &meta); err != nil {
		return nil, fmt.Errorf("JSON parse of '%s', %v", jsonStr, err)
	}
	if err := meta.assertValid(); err != nil {
		return nil, err
	}

	vfs := ident.NewIdentityVolume(path)
	// unmount and destroy volume first if somehow present
	doUnmount([]string{path}) // and ignore errors

	if err := vfs.Create(meta.PodNamespace, meta.PodName); err != nil {
		return nil, err
	}

	if err := bindMount(hostSocketDir, vfs.SocketPath(), false); err != nil {
		return nil, errors.Wrap(err, "mount socket path")
	}

	if err := bindMount(vfs.MountRoot(), path, meta.ReadWrite == "ro"); err != nil {
		return nil, errors.Wrap(err, "mount root")
	}
	return success(), nil
}

// doUnmount handles the unmount command
func doUnmount(args []string) (interface{}, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("insuffient args, want at least %d got %d", 1, len(args))
	}
	path := args[0]
	vfs := ident.NewIdentityVolume(path)
	err := bindUnmount(vfs.SocketPath())
	if err != nil {
		return nil, errors.Wrap(err, "unmount socket path")
	}
	err = bindUnmount(path)
	if err != nil {
		return nil, errors.Wrap(err, "unmount root")
	}
	if err := vfs.Destroy(); err != nil {
		return nil, errors.Wrap(err, "vfs.Destroy")
	}
	return success(), nil
}

// doOther handles all unknown commands
func doOther(_ []string) (interface{}, error) {
	return &result{
		Status: statusUnsupported,
	}, nil
}

func main() {
	if len(os.Args) == 1 {
		usageAndDie()
	}
	op := os.Args[1]
	rest := os.Args[2:]

	dispatch := map[string]func([]string) (interface{}, error){
		opInit:    doInit,
		opMount:   doMount,
		opUnmount: doUnmount,
	}
	fn := dispatch[op]
	if fn == nil {
		fn = doOther
	}

	out, err := fn(rest)
	if err != nil {
		out = &result{
			Status:  statusFailure,
			Message: err.Error(),
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		log.Fatalln("JSON serialize", out, err)
	}

	os.Stdout.Write(b)
}
