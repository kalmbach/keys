package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type SSHKey struct {
	Type        string
	Fingerprint string
	Comment     string
	Filename    string
	Path        string
	HasPrivate  bool
}

func LoadSSHKeys() ([]SSHKey, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var out []SSHKey
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".pub") {
			continue
		}
		if strings.HasSuffix(name, "-cert.pub") {
			continue
		}
		path := filepath.Join(dir, name)

		k, err := parseSSHPub(path)
		if err != nil {
			continue
		}
		k.Filename = name
		k.Path = path

		priv := strings.TrimSuffix(path, ".pub")
		if _, err := os.Stat(priv); err == nil {
			k.HasPrivate = true
		}

		out = append(out, k)
	}

	return out, nil
}

func parseSSHPub(path string) (SSHKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return SSHKey{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return SSHKey{}, errors.New("empty file")
	}
	line := strings.TrimSpace(scanner.Text())
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return SSHKey{}, errors.New("malformed pub key")
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return SSHKey{}, err
	}
	sum := sha256.Sum256(blob)
	fp := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")

	comment := ""
	if len(parts) == 3 {
		comment = parts[2]
	}

	return SSHKey{
		Type:        normalizeSSHType(parts[0]),
		Fingerprint: fp,
		Comment:     comment,
	}, nil
}

func normalizeSSHType(t string) string {
	switch {
	case strings.HasPrefix(t, "ssh-ed25519"):
		return "ed25519"
	case strings.HasPrefix(t, "ssh-rsa"):
		return "rsa"
	case strings.HasPrefix(t, "ssh-dss"):
		return "dsa"
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		return "ecdsa"
	case strings.HasPrefix(t, "sk-ecdsa-"):
		return "sk-ecdsa"
	case strings.HasPrefix(t, "sk-ssh-ed25519"):
		return "sk-ed25519"
	}
	return t
}
