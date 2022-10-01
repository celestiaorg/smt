package smt

import (
	"crypto/sha256"
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
