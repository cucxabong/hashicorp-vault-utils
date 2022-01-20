package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/consul/api"
)

type ConsulBackend struct {
	path string
	kv   *api.KV
}

// Ensure ConsulBackend implement BackendProvider interface
var _ BackendProvider = (*ConsulBackend)(nil)

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
		kv:   client.KV(),
		path: path,
	}

	return c, nil
}

func (c *ConsulBackend) get(key string) (*api.KVPair, error) {
	data, _, err := c.kv.Get(key, nil)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("key (%s) does not exist.", key)
	}

	return data, nil
}

func (c *ConsulBackend) GetRecoveryKey() ([]byte, error) {
	key := c.path + recoveryKeyPath
	data, err := c.get(key)
	if err != nil {
		return nil, err
	}

	return data.Value, nil
}

func (c *ConsulBackend) RecoveryConfig() (*SealConfig, error) {
	key := c.path + recoverySealConfigPlaintextPath
	conf := &SealConfig{}
	data, _, err := c.kv.Get(key, nil)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("key (%s) does not exist.", key)
	}

	if err := json.Unmarshal(data.Value, conf); err != nil {
		log.Print("failed to decode seal configuration", err)
		return nil, err
	}

	return conf, nil
}
