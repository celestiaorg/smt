package smt

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestPath(t *testing.T) {
	th := newTreeHasher(sha256.New())
	chkEq(th.pathSize(), PathLen, t)
	p := th.path(nil)
	chkBytesEq(p, []byte{0, 0, 0, 0}, t)
	p = th.path([]byte{0})
	chkBytesEq(p, []byte{0, 0, 0, 0}, t)
	p = th.path([]byte{1})
	chkBytesEq(p, []byte{0, 0, 0, 1}, t)
	p = th.path([]byte{1, 2, 3, 4})
	chkBytesEq(p, []byte{1, 2, 3, 4}, t)
	p = th.path([]byte{1, 2, 3, 4, 5, 6})
	chkBytesEq(p, []byte{3, 4, 5, 6}, t)
}

func chkEq(v, exp interface{}, t *testing.T) {
	if v != exp {
		t.Errorf("mismatch value exp: %v, got %v", exp, v)
	}
}

func chkBytesEq(v, exp []byte, t *testing.T) {
	if !bytes.Equal(v, exp) {
		t.Errorf("mismatch value exp: %x, got %x", exp, v)
	}
}
