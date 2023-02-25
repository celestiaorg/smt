package smt

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTreeHasherPath(t *testing.T) {
	keyStr := "jellyfish"
	expectedPathEncoded := "a0ea5328f032f1557fbc5d6516c59cc85e7c0fa270c43085f9c994ef2915449b"

	th := newTreeHasher(sha256.New())
	digest := th.digest([]byte(keyStr))

	require.Equal(t, expectedPathEncoded, hex.EncodeToString(digest))
}

func TestTreeHasherLeaf(t *testing.T) {
	path := []byte("i am a leaf")
	data := []byte("i am leaf data")
	expectedHashEncoded := "c8b12b6fd50318a81b6bbfd1f0871c76d957930cd6dbec5436f8e8e237575e6b"
	expectedValueEncoded := "006920616d2061206c6561666920616d206c6561662064617461"

	th := newTreeHasher(sha256.New())
	hash, value := th.digestLeaf(path, data)
	require.Equal(t, []byte{0}, value[:1]) // verify prefix
	require.Equal(t, expectedHashEncoded, hex.EncodeToString(hash))
	require.Equal(t, expectedValueEncoded, hex.EncodeToString(value))
}

func TestTreeHasherNode(t *testing.T) {
	path := []byte("i am a node")
	data := []byte("i am node data")
	expectedHashEncoded := "6435f669879aee1a3426a7f98b242f9efc84de4e1d1f710cfc953795b9bf3a6d"
	expectedValueEncoded := "016920616d2061206e6f64656920616d206e6f64652064617461"

	th := newTreeHasher(sha256.New())
	hash, value := th.digestNode(path, data)
	require.Equal(t, []byte{1}, value[:1]) // verify prefix
	require.Equal(t, expectedHashEncoded, hex.EncodeToString(hash))
	require.Equal(t, expectedValueEncoded, hex.EncodeToString(value))
}

func TestTreeHasherPathSize(t *testing.T) {
	//sha256
	th := newTreeHasher(sha256.New())
	require.Equal(t, 32, th.pathSize())

	//sha512
	th = newTreeHasher(sha512.New())
	require.Equal(t, 64, th.pathSize())
}

func TestTreeHasherPathPlaceholder(t *testing.T) {
	//sha256
	th := newTreeHasher(sha256.New())
	placeholder := th.placeholder()
	require.Len(t, placeholder, 32)
	require.Equal(t, bytes.Repeat([]byte{0}, 32), placeholder)

	//sha512
	th = newTreeHasher(sha512.New())
	placeholder = th.placeholder()
	require.Len(t, placeholder, 64)
	require.Equal(t, bytes.Repeat([]byte{0}, 64), placeholder)
}
