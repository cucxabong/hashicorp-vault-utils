package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/consul/api"
)

const recoveryKeySuffix = "core/recovery-key"

type BackendProvider interface {
	// GetRecoveryKey return encrypted Envelop from underlying backend
	GetRecoveryKey() ([]byte, error)
}

type FileBackend struct {
	path string
}

type fileEntry struct {
	Value []byte
}

func NewFileBackend(path string) (BackendProvider, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	be := &FileBackend{
		path: path,
	}
	return be, nil
}

func (b *FileBackend) expandPath(k string) (string, string) {
	path := filepath.Join(b.path, k)
	key := filepath.Base(path)
	path = filepath.Dir(path)
	return path, "_" + key
}

func (b *FileBackend) GetRecoveryKey() ([]byte, error) {
	path, key := b.expandPath(recoveryKeySuffix)
	fullPath := filepath.Join(path, key)
	var entry fileEntry

	if _, err := os.Stat(fullPath); err != nil {
		return nil, err
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	decErr := dec.Decode(&entry)

	return entry.Value, decErr
}

type ConsulBackend struct {
	path   string
	Client *api.Client
}

func NewConsulBackend(url, path string) (BackendProvider, error) {
	config := api.DefaultConfig()
	config.Scheme = "http"
	config.Address = url

	parts := strings.Split(url, "://")
	if len(parts) == 2 {
		config.Scheme = parts[0]
		config.Address = parts[1]
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("consul client setup failed. %v", err)
	}

	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	if strings.HasPrefix(path, "/") {
		path = strings.TrimPrefix(path, "/")
	}

	c := &ConsulBackend{
		Client: client,
		path:   path,
	}

	return c, nil
}

func (c *ConsulBackend) GetRecoveryKey() ([]byte, error) {
	kv := c.Client.KV()
	key := c.path + recoveryKeySuffix
	data, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("key (%s) does not exist.", key)
	}

	return data.Value, nil
}
