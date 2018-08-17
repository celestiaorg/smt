// Package mapstore contains an interface and a simple in-memory implementation for a key-value store.
package smt

import(
    "fmt"
)

// MapStore is a key-value store.
type MapStore interface {
    Get(key []byte) ([]byte, error) // Get gets the value for a key.
    Put(key []byte, value []byte) error // Put updates the value for a key.
    Del(key []byte) error // Del deletes a key.
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
type InvalidKeyError struct {
    Key []byte
}

func (e *InvalidKeyError) Error() string {
    return fmt.Sprintf("invalid key: %s", e.Key)
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
    } else {
        return nil, &InvalidKeyError{Key: key}
    }
}

// Put updates the value for a key.
func (sm *SimpleMap) Put(key []byte, value []byte) error {
    sm.m[string(key)] = value
    return nil
}

// Del deletes a key.
func (sm *SimpleMap) Del(key []byte) error {
    _, ok := sm.m[string(key)]
    if ok {
        delete(sm.m, string(key))
        return nil
    } else{
        return &InvalidKeyError{Key: key}
    }
}
