package smt

import (
	"bytes"
	"testing"
)

func TestSimpleMap(t *testing.T) {
	sm := NewSimpleMap(len([]byte("test1")))

	// Tests for Get.
	_, err := sm.Get([]byte("test1"))
	if err == nil {
		t.Error("did not return an error when getting a non-existent key")
	}

	// Tests for Put.
	err = sm.Set([]byte("test1"), []byte("hello"))
	if err != nil {
		t.Errorf("updating a key returned an error : %v", err)
	}
	value, err := sm.Get([]byte("test1"))
	if err != nil {
		t.Errorf("getting a key returned an error : %v", err)
	}
	if !bytes.Equal(value, []byte("hello")) {
		t.Error("failed to update key")
	}

	// Tests for Del.
	err = sm.Delete([]byte("test1"))
	if err != nil {
		t.Errorf("deleting a key returned an error : %v", err)
	}
	_, err = sm.Get([]byte("test1"))
	if err == nil {
		t.Error("failed to delete key")
	}
	err = sm.Delete([]byte("test2"))
	if err == nil {
		t.Error("deleting a key did not return an error on a non-existent key")
	}
}

func TestSimpleMapKeySize(t *testing.T) {
	sm := NewSimpleMap(len([]byte("test1")))

	// Tests for setting wrong key size.
	err := sm.Set([]byte("test11"), []byte("hello"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when setting a bigger key size : %v", err)
	}

	err = sm.Set([]byte("test"), []byte("hello"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when setting a smaller key size : %v", err)
	}

	// Tests for getting wrong key size.
	_, err = sm.Get([]byte("test11"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when getting a bigger key size : %v", err)
	}

	_, err = sm.Get([]byte("test"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when getting a smaller key size : %v", err)
	}

	// Tests for getting wrong key size.
	err = sm.Delete([]byte("test11"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when deleting a bigger key size : %v", err)
	}

	err = sm.Delete([]byte("test"))
	if err != ErrWrongKeySize {
		t.Errorf("didn't throw ErrWrongKeySize when deleting a smaller key size : %v", err)
	}
}
