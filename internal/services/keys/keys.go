package keys

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

var regexKeyFileName = regexp.MustCompile(".*\\.v([0-9]+)$")

type versionedFiles struct {
	dir string
}

type fv struct {
	file       string
	version    int
	versionStr string
}

func (f *versionedFiles) list() ([]fv, error) {
	var ret []fv
	seen := map[int]string{}
	if files, err := ioutil.ReadDir(f.dir); err == nil {
		for _, file := range files {
			match := regexKeyFileName.FindStringSubmatch(file.Name())
			if match == nil {
				continue
			}
			if version, err := strconv.Atoi(match[1]); err == nil {
				if seen[version] != "" {
					return nil, fmt.Errorf("multiple files with same version, %s and %s", seen[version], file)
				}
				seen[version] = file.Name()
				ret = append(ret, fv{
					file:       filepath.Join(f.dir, file.Name()),
					version:    version,
					versionStr: fmt.Sprintf("v%d", version),
				})
			} else {
				log.Println("invalid file", file, err)
			}
		}
	} else {
		return nil, errors.Wrap(err, "list files")
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("no versioned files under %s", f.dir)
	}
	return ret, nil
}

func (f *versionedFiles) latestVersionContents() ([]byte, string, error) {
	fvs, err := f.list()
	if err != nil {
		return nil, "", err
	}
	sort.Slice(fvs, func(i, j int) bool {
		return fvs[i].version < fvs[j].version
	})
	fv := fvs[len(fvs)-1]
	content, err := ioutil.ReadFile(fv.file)
	if err != nil {
		return nil, "", err
	}
	return content, fv.versionStr, nil
}

func (f *versionedFiles) contentsForVersion(version string) ([]byte, error) {
	fvs, err := f.list()
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, fv := range fvs {
		if fv.versionStr == version {
			return ioutil.ReadFile(fv.file)
		}
		versions = append(versions, fv.versionStr)
	}
	return nil, fmt.Errorf("no file with version %s, have %v", version, versions)
}

func secretURI(name, version string) string {
	return fmt.Sprintf("secret:%s?version=%s", name, version)
}

func parseSecretURI(uri, expectedName string) (version string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("parseSecretURI: %s", uri))
	}
	if u.Scheme != "secret" {
		return "", fmt.Errorf("parseSecretURI: %s, invalid scheme %s, want 'secret'", uri, u.Scheme)
	}
	if u.Opaque != expectedName {
		return "", fmt.Errorf("parseSecretURI: %s, invalid name %q, want %q", uri, u.Opaque, expectedName)
	}
	v := u.Query().Get("version")
	if v == "" {
		return "", fmt.Errorf("parseSecretURI: %s, no version found", uri)
	}
	return v, nil
}

type PrivateKeySource struct {
	secretName string
	files      *versionedFiles
}

func NewPrivateKeySource(dir string, secretName string) *PrivateKeySource {
	return &PrivateKeySource{
		secretName: secretName,
		files: &versionedFiles{
			dir: dir,
		},
	}
}

func (pks *PrivateKeySource) SigningKey() (*identity.SigningKey, error) {
	contents, version, err := pks.files.latestVersionContents()
	if err != nil {
		return nil, err
	}
	keyType, key, err := util.PrivateKeyFromPEMBytes(contents)
	if err != nil {
		return nil, err
	}
	return &identity.SigningKey{
		URI:     secretURI(pks.secretName, version),
		Type:    keyType,
		Value:   key,
		Version: version,
	}, nil
}

type PublicKeySource struct {
	secretName string
	files      *versionedFiles
}

func NewPublicKeySource(dir string, secretName string) *PublicKeySource {
	return &PublicKeySource{
		secretName: secretName,
		files: &versionedFiles{
			dir: dir,
		},
	}
}

func (pks *PublicKeySource) PublicKey(issuerURI string) (pubKey crypto.PublicKey, err error) {
	version, err := parseSecretURI(issuerURI, pks.secretName)
	if err != nil {
		return nil, err
	}
	contents, err := pks.files.contentsForVersion(version)
	if err != nil {
		return nil, err
	}
	return util.PublicKeyFromPEMBytes(contents)
}
