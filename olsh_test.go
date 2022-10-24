package smt

// https://igraph.org/python/versions/latest/tutorials/quickstart/quickstart.html
// https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVisualizationHelper(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())
	kv := make(map[string]string)
	bits := make(map[string]string)

	// Populate SMT
	for i := 0; i < 10; i++ {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(i+65))
		fmt.Println(bs, string(bs))
		smt.Update(bs, bs)
		kv[string(bs)] = string(bs)
	}

	// var key string
	for key, value := range kv {
		path := smt.th.path([]byte(key))

		sideNodes, pathNodes, nodeData, _, err := smt.sideNodesForRoot(path, smt.root)
		require.NoError(t, err)

		if smt.th.isLeaf([]byte(nodeData)) {
			fmt.Println(fmt.Sprintf("Leaf: %s (%d side nodes, %d path nodes)", value, len(sideNodes), len(pathNodes)))
		} else {
			fmt.Println(fmt.Sprintf("Not Leaf: %s (%d side nodes, %d path nodes)", value, len(sideNodes), len(pathNodes)))
		}

		largestCommonPrefixLen := getLargestCommonPrefix(t, smt, kv, key)
		fmt.Print("\tLargest common prefix: ", largestCommonPrefixLen)

		var sb strings.Builder
		fmt.Print("\n\tCommon Bits : ")
		for i := 0; i < largestCommonPrefixLen; i++ {
			bit := getBitAtFromMSB(path, i)
			fmt.Print(bit, " ")
			sb.WriteString(strconv.Itoa(bit))
		}
		bits[key] = sb.String()

		// fmt.Print(fmt.Sprintf("bits (%s): ", value))

		sideNodeReadable := make([]string, len(sideNodes))
		for i, sideNode := range sideNodes {
			sideNodeReadable[i] = getLeafValue(t, smt, sideNode)
		}
		fmt.Println("\n\tSIDE NODES: [", strings.Join(sideNodeReadable, ", "), "]")

		pathNodeReadable := make([]string, len(pathNodes))
		for i, pathNode := range pathNodes {
			pathNodeReadable[i] = getLeafValue(t, smt, pathNode)
		}
		fmt.Println("\tPATH NODES: [", strings.Join(pathNodeReadable, ", "), "]")
	}
	writeToCsv(t, bits)
}

func getLeafValue(t *testing.T, smt *SparseMerkleTree, nodeHash []byte) string {
	if bytes.Equal(nodeHash, smt.th.placeholder()) {
		return "ZERO"
	}

	hashOrData, err := smt.nodes.Get(nodeHash)
	require.NoError(t, err)

	if smt.th.isLeaf(hashOrData) {
		leafPath, _ := smt.th.parseLeaf(hashOrData)
		leafUserValue, err := smt.values.Get(leafPath)
		require.NoError(t, err)
		return string(leafUserValue)
	}

	// Node is not a leaf, but is a digest of its children
	// left, right := smt.th.parseNode(hashOrData)
	// l := getLeafValue(t, smt, left)
	// r := getLeafValue(t, smt, right)
	// return fmt.Sprintf("(%s %s)", l, r)
	return "NODE"
}

func writeToCsv(t *testing.T, bits map[string]string) {
	csvFile, err := os.Create("bits.csv")
	require.NoError(t, err)
	csvWriter := csv.NewWriter(csvFile)
	for key, bits := range bits {
		err = csvWriter.Write([]string{string(key), bits})
		require.NoError(t, err)
	}
	csvWriter.Flush()
	csvFile.Close()
}
