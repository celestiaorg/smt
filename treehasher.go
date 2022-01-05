package smt

import (
	"bytes"
	"hash"
)

var leafPrefix = []byte{0}
var nodePrefix = []byte{1}

type treeHasher struct {
	hasher    hash.Hash
	zeroValue []byte
}

func newTreeHasher(hasher hash.Hash) *treeHasher {
	th := treeHasher{
		hasher: hasher,
	}
	th.zeroValue = make([]byte, th.hasher.Size())

	return &th
}

func (th *treeHasher) digest(data []byte) []byte {
	th.hasher.Write(data)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) digestLeaf(path []byte, leafData []byte) ([]byte, []byte) {
	value := make([]byte, 0, len(leafPrefix)+len(path)+len(leafData))
	value = append(value, leafPrefix...)
	value = append(value, path...)
	value = append(value, leafData...)

	sum := th.digest(value)

	return sum, value
}

func (th *treeHasher) parseLeaf(data []byte, keySize int) ([]byte, []byte) {
	return data[len(leafPrefix) : keySize+len(leafPrefix)], data[len(leafPrefix)+keySize:]
}

func (th *treeHasher) isLeaf(data []byte) bool {
	return bytes.Equal(data[:len(leafPrefix)], leafPrefix)
}

func (th *treeHasher) digestNode(leftData []byte, rightData []byte) ([]byte, []byte) {
	value := make([]byte, 0, len(nodePrefix)+len(leftData)+len(rightData))
	value = append(value, nodePrefix...)
	value = append(value, leftData...)
	value = append(value, rightData...)

	sum := th.digest(value)

	return sum, value
}

func (th *treeHasher) parseNode(data []byte) ([]byte, []byte) {
	return data[len(nodePrefix) : th.hasher.Size()+len(nodePrefix)], data[len(nodePrefix)+th.hasher.Size():]
}

func (th *treeHasher) placeholder() []byte {
	return th.zeroValue
}
