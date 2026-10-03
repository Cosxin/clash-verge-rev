// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxJSON = 1024 * 1024

type publishedPolicyError struct{ cause error }

func (err *publishedPolicyError) Error() string {
	return "Native policy was published, but its durability could not be confirmed"
}

func (err *publishedPolicyError) Unwrap() error { return err.cause }

type BanPolicy struct {
	SchemaVersion int      `json:"schemaVersion"`
	Generation    uint64   `json:"generation"`
	ProcessPaths  []string `json:"processPaths"`
}

func validatePaths(paths []string) error {
	if paths == nil || len(paths) > 512 {
		return errors.New("processPaths must be an array of at most 512 executable paths")
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		if len(path) > 2048 || path == "/" || !strings.HasPrefix(path, "/") || filepath.Clean(path) != path {
			return errors.New("process paths must be canonical absolute Linux executable paths without traversal")
		}
		if strings.ContainsAny(path, "\x00\r\n") || strings.Contains(path, " (deleted)") || seen[path] {
			return errors.New("process paths contain control characters, deleted executables or duplicates")
		}
		seen[path] = true
	}
	encoded, err := json.Marshal(paths)
	if err != nil || len(encoded) > maxJSON/2 {
		return errors.New("serialized process paths exceed 512 KiB")
	}
	return nil
}

func decodeJSON(reader io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxJSON+1))
	if err != nil {
		return err
	}
	if len(data) > maxJSON {
		return errors.New("native request exceeds 1 MiB")
	}
	keys := json.NewDecoder(strings.NewReader(string(data)))
	opening, err := keys.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("native JSON must be an object")
	}
	seen := make(map[string]bool)
	allowed := map[string]bool{"schemaVersion": true, "generation": true, "processPaths": true}
	required := []string{"schemaVersion", "generation", "processPaths"}
	if _, request := value.(*Request); request {
		allowed = map[string]bool{"schemaVersion": true, "command": true, "expectedGeneration": true, "processPaths": true, "afterSequence": true, "limit": true}
		required = []string{"schemaVersion", "command"}
	}
	for keys.More() {
		key, err := keys.Token()
		if err != nil || seen[fmt.Sprint(key)] || !allowed[fmt.Sprint(key)] {
			return errors.New("duplicate or invalid native JSON field")
		}
		seen[fmt.Sprint(key)] = true
		var raw json.RawMessage
		if err := keys.Decode(&raw); err != nil || string(raw) == "null" {
			return errors.New("invalid native JSON field")
		}
	}
	for _, key := range required {
		if !seen[key] {
			return errors.New("required native JSON field is missing")
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid native JSON request")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("native request must contain one JSON document")
	}
	return nil
}

func loadPolicy(path string) (BanPolicy, bool, error) {
	policy := BanPolicy{SchemaVersion: 1, ProcessPaths: []string{}}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return policy, false, nil
	}
	if err != nil {
		return policy, false, err
	}
	defer file.Close()
	policy = BanPolicy{}
	if err := decodeJSON(file, &policy); err != nil {
		return policy, false, err
	}
	if policy.SchemaVersion != 1 {
		return policy, false, errors.New("unsupported native policy schema")
	}
	return policy, true, validatePaths(policy.ProcessPaths)
}

func savePolicy(path string, policy BanPolicy) error {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".policy-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return &publishedPolicyError{cause: err}
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return &publishedPolicyError{cause: err}
	}
	return nil
}
