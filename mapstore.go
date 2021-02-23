package smt

import (
	"fmt"
)

// MapStore is a key-value store.
type MapStore interface {
	Get(key []byte) ([]byte, error)     // Get gets the value for a key.
	Set(key []byte, value []byte) error // Set updates the value for a key.
	Delete(key []byte) error            // Delete deletes a key.
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
type InvalidKeyError struct {
	Key []byte
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %x", e.Key)
}

// SimpleMap is a simple in-memory map.
type SimpleMap struct {
	m map[string][]byte
}

// NewSimpleMap creates a new empty SimpleMap.
func NewSimpleMap() *SimpleMap {
	return &SimpleMap{
		m: make(map[string][]byte),
	}
}

// Get gets the value for a key.
func (sm *SimpleMap) Get(key []byte) ([]byte, error) {
	if value, ok := sm.m[string(key)]; ok {
		return value, nil
	}
	return nil, &InvalidKeyError{Key: key}
}

// Set updates the value for a key.
func (sm *SimpleMap) Set(key []byte, value []byte) error {
	sm.m[string(key)] = value
	return nil
}

// Delete deletes a key.
func (sm *SimpleMap) Delete(key []byte) error {
	_, ok := sm.m[string(key)]
	if ok {
		delete(sm.m, string(key))
		return nil
	}
	return &InvalidKeyError{Key: key}
}
