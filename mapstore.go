package smt

import (
	"errors"
	"fmt"
)

// MapStore is a key-value store.
type MapStore interface {
	Get(key []byte) ([]byte, error)     // Get gets the value for a key.
	Set(key []byte, value []byte) error // Set updates the value for a key.
	Delete(key []byte) error            // Delete deletes a key.
	GetKeySize() int                    // Gets the key size for the map store.
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
type InvalidKeyError struct {
	Key []byte
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %x", e.Key)
}

// ErrWrongKeySize is returned when a key has a different size than the key size.
var ErrWrongKeySize = errors.New("wrong key size")

// ErrUnsupportedKeySize is returned when the map store is initialized by a key smaller than 1.
var ErrUnsupportedKeySize = errors.New("key size should be greater or equal to 1")

// SimpleMap is a simple in-memory map.
type SimpleMap struct {
	m       map[string][]byte
	keySize int
}

// NewSimpleMap creates a new empty SimpleMap.
func NewSimpleMap(keySize int) (*SimpleMap, error) {
	if keySize < 1 {
		return nil, ErrUnsupportedKeySize
	}
	return &SimpleMap{
		m:       make(map[string][]byte),
		keySize: keySize,
	}, nil
}

// Get gets the value for a key.
func (sm *SimpleMap) Get(key []byte) ([]byte, error) {
	if err := sm.checkKeySize(key); err != nil {
		return nil, err
	}
	if value, ok := sm.m[string(key)]; ok {
		return value, nil
	}
	return nil, &InvalidKeyError{Key: key}
}

// GetKeySize gets the key size of the map store.
func (sm *SimpleMap) GetKeySize() int {
	return sm.keySize
}

// Set updates the value for a key.
func (sm *SimpleMap) Set(key []byte, value []byte) error {
	if err := sm.checkKeySize(key); err != nil {
		return err
	}
	sm.m[string(key)] = value
	return nil
}

// Delete deletes a key.
func (sm *SimpleMap) Delete(key []byte) error {
	if err := sm.checkKeySize(key); err != nil {
		return err
	}
	_, ok := sm.m[string(key)]
	if ok {
		delete(sm.m, string(key))
		return nil
	}
	return &InvalidKeyError{Key: key}
}

func (sm *SimpleMap) checkKeySize(key []byte) error {
	if len(key) != sm.keySize {
		return ErrWrongKeySize
	}
	return nil
}
