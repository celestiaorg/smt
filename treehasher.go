package smt

import (
	"hash"
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

func (th *treeHasher) digestNode(leftData []byte, rightData []byte) []byte {
	th.hasher.Write(nodePrefix)
	th.hasher.Write(leftData)
	th.hasher.Write(rightData)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) pathSize() int {
	return th.hasher.Size()
}

func (th *treeHasher) defaultNode(height int) []byte {
	return defaultNodes(th.hasher)[height]
}
