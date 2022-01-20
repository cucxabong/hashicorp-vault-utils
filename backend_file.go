package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// Ensure FileBackend implement BackendProvider interface
var _ BackendProvider = (*FileBackend)(nil)

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

func (b *FileBackend) expandPath(k string) string {
	path := filepath.Join(b.path, k)
	key := filepath.Base(path)
	path = filepath.Dir(path)

	return filepath.Join(path, "_"+key)
}

func (b *FileBackend) ReadFile(path string) ([]byte, error) {
	var entry fileEntry

	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&entry)

	return entry.Value, err
}

func (b *FileBackend) GetRecoveryKey() ([]byte, error) {
	fullPath := b.expandPath(recoveryKeyPath)

	return b.ReadFile(fullPath)
}

func (b *FileBackend) RecoveryConfig() (*SealConfig, error) {
	fullPath := b.expandPath(recoverySealConfigPlaintextPath)
	data, err := b.ReadFile(fullPath)
	conf := &SealConfig{}
	if err != nil {
		log.Print("unable to read recovery config", err)
		return nil, err
	}

	if err := json.Unmarshal(data, conf); err != nil {
		log.Print("failed to decode seal configuration", err)
		return nil, err
	}

	return conf, nil
}
