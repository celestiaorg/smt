package fuzz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/celestiaorg/smt"
)

func Fuzz(input []byte) int {
	if len(input) < 100 {
		return 0
	}
	smn := smt.NewSimpleMap()
	tree := smt.NewSparseMerkleTree(smn, sha256.New())
	r := bytes.NewReader(input)
	var keys [][]byte
	key := func() []byte {
		if readByte(r) < math.MaxUint8/2 {
			k := make([]byte, readByte(r)/2)
			r.Read(k)
			keys = append(keys, k)
			return k
		}
		if len(keys) == 0 {
			return nil
		}
		return keys[int(readByte(r))%len(keys)]
	}
	for i := 0; r.Len() != 0; i++ {
		b, err := r.ReadByte()
		if err != nil {
			continue
		}
		op := op(int(b) % int(Noop))
		switch op {
		case Get:
			tree.Get(key())
		case Update:
			value := make([]byte, 32)
			binary.BigEndian.PutUint64(value, uint64(i))
			tree.Update(key(), value)
		case Delete:
			tree.Delete(key())
		case Prove:
			tree.Prove(key())
		}
	}
	return 1
}

type op int

const (
	Get op = iota
	Update
	Delete
	Prove
	Noop
)

func readByte(r *bytes.Reader) byte {
	b, err := r.ReadByte()
	if err != nil {
		return 0
	}
	return b
}
