package smt

import (
	"bytes"
	"hash"
)

// TODO: Need to document the difference between `data`, `value`, `hash`, and `path`.`
// 	- It seems that `data` is simply `valueHash` determined using the `digest` function.
//
var (
	leafPrefix = []byte{0} // prefix used for the path of each leaf in the three
	nodePrefix = []byte{1} // prefix used for the path of each node in the three
)

type treeHasher struct {
	hasher    hash.Hash
	zeroValue []byte // ASK(reviewer): rename to `emptyNode`?
}

func newTreeHasher(hasher hash.Hash) *treeHasher {
	th := treeHasher{hasher: hasher}
	th.zeroValue = make([]byte, th.pathSize())

	return &th
}

func (th *treeHasher) path(key []byte) []byte {
	return th.digest(key)
}

func (th *treeHasher) digest(data []byte) []byte {
	// TODO: Need to add a lock inside of `treeHasher` to avoid race conditions here.
	th.hasher.Write(data)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) digestLeaf(path, data []byte) (hash, value []byte) {
	value = make([]byte, 0, len(leafPrefix)+len(path)+len(data))
	value = append(value, leafPrefix...)
	value = append(value, path...)
	value = append(value, data...)

	return th.digest(value), value
}

func (th *treeHasher) parseLeaf(value []byte) (path, data []byte) {
	return value[len(leafPrefix) : th.pathSize()+len(leafPrefix)], value[len(leafPrefix)+th.pathSize():]
}

func (th *treeHasher) isLeaf(data []byte) bool {
	return bytes.Equal(data[:len(leafPrefix)], leafPrefix)
}

func (th *treeHasher) digestNode(leftData, rightData []byte) (hash, value []byte) {
	value = make([]byte, 0, len(nodePrefix)+len(leftData)+len(rightData))
	value = append(value, nodePrefix...)
	value = append(value, leftData...)
	value = append(value, rightData...)

	return th.digest(value), value
}

func (th *treeHasher) parseNode(value []byte) (path, data []byte) {
	return value[len(nodePrefix) : th.pathSize()+len(nodePrefix)], value[len(nodePrefix)+th.pathSize():]
}

func (th *treeHasher) pathSize() int {
	return th.hasher.Size()
}

func (th *treeHasher) placeholder() []byte {
	return th.zeroValue
}
