package smt

import (
	"bytes"
	"hash"
)

var (
	leafPrefix = []byte{0}
	nodePrefix = []byte{1}
)

var _ PathHasher = (*treeHasher)(nil)
var _ ValueHasher = (*treeHasher)(nil)

type PathHasher interface {
	Path([]byte) []byte
	PathSize() int
}

type ValueHasher interface {
	digest([]byte) []byte
}

type treeHasher struct {
	hasher    hash.Hash
	zeroValue []byte
}

func newTreeHasher(hasher hash.Hash) *treeHasher {
	th := treeHasher{hasher: hasher}
	th.zeroValue = make([]byte, th.hashSize())
	return &th
}

func (ph *treeHasher) Path(key []byte) []byte {
	th := treeHasher(*ph)
	return th.digest(key)[:ph.PathSize()]
}

func (ph *treeHasher) PathSize() int {
	return ph.hasher.Size()
}

func (th *treeHasher) digest(data []byte) []byte {
	th.hasher.Write(data)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

func (th *treeHasher) digestLeaf(path []byte, leafData []byte) ([]byte, []byte) {
	value := encodeLeaf(path, leafData)
	return th.digest(value), value
}

func (th *treeHasher) digestNode(leftData []byte, rightData []byte) ([]byte, []byte) {
	value := encodeInner(leftData, rightData)
	return th.digest(value), value
}

func (th *treeHasher) parseNode(data []byte) ([]byte, []byte) {
	return data[len(nodePrefix) : th.hashSize()+len(nodePrefix)], data[len(nodePrefix)+th.hashSize():]
}

func (th *treeHasher) hashSize() int {
	return th.hasher.Size()
}

func (th *treeHasher) placeholder() []byte {
	return th.zeroValue
}

func isLeaf(data []byte) bool {
	return bytes.Equal(data[:len(leafPrefix)], leafPrefix)
}

func parseLeaf(data []byte, ph PathHasher) ([]byte, []byte) {
	return data[len(leafPrefix) : ph.PathSize()+len(leafPrefix)], data[len(leafPrefix)+ph.PathSize():]
}

func encodeLeaf(path []byte, leafData []byte) []byte {
	value := make([]byte, 0, len(leafPrefix)+len(path)+len(leafData))
	value = append(value, leafPrefix...)
	value = append(value, path...)
	value = append(value, leafData...)
	return value
}

func encodeInner(leftData []byte, rightData []byte) []byte {
	value := make([]byte, 0, len(nodePrefix)+len(leftData)+len(rightData))
	value = append(value, nodePrefix...)
	value = append(value, leftData...)
	value = append(value, rightData...)
	return value
}
