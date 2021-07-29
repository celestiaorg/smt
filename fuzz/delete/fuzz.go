package delete

import (
	"bytes"
	"crypto/sha256"

	"github.com/celestiaorg/smt"
)

func Fuzz(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	splits := bytes.Split(data, []byte("*"))
	if len(splits) < 3 {
		return -1
	}

	smn, smv := smt.NewSimpleMap(), smt.NewSimpleMap()
	tree := smt.NewSparseMerkleTree(smn, smv, sha256.New())
	for i := 0; i < len(splits)-1; i += 2 {
		key, value := splits[i], splits[i+1]
		tree.Update(key, value)
	}

	deleteKey := splits[len(splits)-1]
	newRoot, err := tree.Delete(deleteKey)
	if err != nil {
		return 0
	}
	if len(newRoot) == 0 {
		panic("newRoot is nil yet err==nil")
	}
	return 1
}
