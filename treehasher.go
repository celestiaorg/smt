package smt

import (
	"hash"
	"bytes"
)

var leafPrefix = []byte{0}
var nodePrefix = []byte{1}

type treeHasher struct {
	hasher hash.Hash
}

func newTreeHasher(hasher hash.Hash) *treeHasher {
	th := treeHasher{
		hasher: hasher,
	}

	return &th
}

func (th *treeHasher) digest(data []byte) []byte {
	th.hasher.Write(data)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) path(key []byte) []byte {
	return th.digest(key)
}

func (th *treeHasher) digestLeaf(path []byte, value []byte) []byte {
	th.hasher.Write(leafPrefix)
	th.hasher.Write(path)
	th.hasher.Write(value)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) parseLeaf(data []byte) ([]byte, []byte) {
	return data[len(leafPrefix):th.pathSize()+len(leafPrefix)], data[len(leafPrefix):th.pathSize()]
}

func (th *treeHasher) isLeaf(data []byte) bool {
	if bytes.Compare(data[:len(leafPrefix)], leafPrefix) == 0 {
		return true
	}

	return false
}

func (th *treeHasher) digestNode(leftData []byte, rightData []byte) []byte {
	th.hasher.Write(nodePrefix)
	th.hasher.Write(leftData)
	th.hasher.Write(rightData)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) parseNode(data []byte) ([]byte, []byte) {
	return data[len(nodePrefix):th.pathSize()+len(nodePrefix)], data[len(nodePrefix)+th.pathSize():]
}

func (th *treeHasher) pathSize() int {
	return th.hasher.Size()
}

func (th *treeHasher) placeholder() []byte {
	return bytes.Repeat([]byte{0}, th.pathSize())
}
