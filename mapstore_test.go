package smt

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestMapStoreSimpleMap(t *testing.T) {
	sm := NewSimpleMap()
	h := sha256.New()

	var value []byte
	var err error

	h.Write([]byte("test"))
	key := h.Sum(nil)

	// Tests for Get.
	_, err = sm.Get(key)
	if err == nil {
		t.Error("did not return an error when getting a non-existent key")
	}

	// Tests for Put.
	err = sm.Set(key, []byte("hello"))
	if err != nil {
		t.Error("updating a key returned an error")
	}
	value, err = sm.Get(key)
	if err != nil {
		t.Error("getting a key returned an error")
	}
	if !bytes.Equal(value, []byte("hello")) {
		t.Error("failed to update key")
	}

	// Tests for Del.
	err = sm.Delete(key)
	if err != nil {
		t.Error("deleting a key returned an error")
	}
	_, err = sm.Get(key)
	if err == nil {
		t.Error("failed to delete key")
	}
	err = sm.Delete([]byte("nonexistent"))
	if err == nil {
		t.Error("deleting a key did not return an error on a non-existent key")
	}
}
