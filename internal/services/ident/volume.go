package ident

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

// TODO: allow for config file to configure these paths

var (
	hostVolumeSource = "/var/athenz/volumes" // the root directory under which we create flex volumes
)

// podIdentifier identifies a pod for a volume.
type podIdentifier struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (p *podIdentifier) String() string {
	return fmt.Sprintf("%s/%s", p.Namespace, p.Name)
}
func (p *podIdentifier) AssertValid() error {
	return util.CheckFields("volume pod identifier", map[string]bool{
		"Namespace": p.Namespace == "",
		"Name":      p.Name == "",
	})
}

// IdentityVolume encapsulates the machinery behind an Athenz Flex volume.
// This looks as follows:
//
//   host-root
//     + volume-root     <- SHA256 hash of mount-path
//        - data.json    <- contains pod attributes, not visible inside pod
//        - context.json <- contains identity context for ZTS calls, written by agent
//        + mount        <- the directory that is mounted to path
//          + connect    <- bind mount of agent directory containing host socket
//          - id         <- file containing the mount path hash to be used by pod client as identifier
//
// The client in the container where this volume is mounted is expected to POST to the socket
// in the connect directory passing in the opaque ID from the id file.
type IdentityVolume struct {
	root string
}

// NewIdentityVolume returns an identity FS for the supplied mount path.
func NewIdentityVolume(mountPath string) *IdentityVolume {
	hash := sha256.New()
	hash.Write([]byte(mountPath))
	h := hash.Sum(nil)
	root := base64.RawURLEncoding.EncodeToString(h)
	return newVolumeFromHashedPath(root)
}

func newVolumeFromHashedPath(handle string) *IdentityVolume {
	return &IdentityVolume{
		root: handle,
	}
}

func (v *IdentityVolume) rootDir() string {
	return filepath.Join(hostVolumeSource, v.root)
}

// Destroy deletes the identity volume.
func (v *IdentityVolume) Destroy() error {
	return os.RemoveAll(v.rootDir())
}

// MountRoot returns the path that should be mounted into a container.
func (v *IdentityVolume) MountRoot() string {
	return filepath.Join(v.rootDir(), "mount")
}

// SocketPath returns the directory of the agent socket.
func (v *IdentityVolume) SocketPath() string {
	return filepath.Join(v.MountRoot(), "connect")
}

// Create creates the artifacts for the supplied pod namespace and name.
func (v *IdentityVolume) Create(namespace, name string) error {
	id := podIdentifier{Namespace: namespace, Name: name}
	if err := id.AssertValid(); err != nil {
		return err
	}
	if err := os.MkdirAll(v.SocketPath(), 0750); err != nil {
		return errors.Wrap(err, "mkdir -p")
	}
	b, err := json.Marshal(id)
	if err != nil {
		return errors.Wrap(err, "JSON marshal")
	}
	if err := ioutil.WriteFile(v.dataFile(), b, 0640); err != nil {
		return errors.Wrap(err, "write data file")
	}
	if err := ioutil.WriteFile(v.idFile(), []byte(v.root), 0640); err != nil {
		return errors.Wrap(err, "write id file")
	}
	return nil
}

func (v *IdentityVolume) write(what string, file string, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "JSON marshal")
	}
	if err := ioutil.WriteFile(file, b, 0640); err != nil {
		return errors.Wrap(err, fmt.Sprintf("write %s file", what))
	}
	return nil
}

func (v *IdentityVolume) read(what string, file string, data interface{}) error {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("read %s file", what))
	}
	if err := json.Unmarshal(b, data); err != nil {
		return errors.Wrap(err, "JSON unmarshal")
	}
	return nil
}

func (v *IdentityVolume) getID() (*podIdentifier, error) {
	var id podIdentifier
	err := v.read("data", v.dataFile(), &id)
	if err != nil {
		return nil, err
	}
	if err := id.AssertValid(); err != nil {
		return nil, err
	}
	return &id, nil
}

func (v *IdentityVolume) saveContext(ctx interface{}) error {
	return v.write("context", v.contextFile(), ctx)
}

func (v *IdentityVolume) getContext(data interface{}) error {
	return v.read("context", v.contextFile(), data)
}

func (v *IdentityVolume) dataFile() string {
	return filepath.Join(v.rootDir(), "data.json")
}

func (v *IdentityVolume) contextFile() string {
	return filepath.Join(v.rootDir(), "context.json")
}

func (v *IdentityVolume) idFile() string {
	return filepath.Join(v.MountRoot(), "id")
}
