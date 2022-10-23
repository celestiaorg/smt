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

func TestOlshansky(t *testing.T) {
	smt, smn, smv, kv := bulkOperations(t, 20, 10, 5, 5)
	fmt.Println("OLSH", len(smn.m), len(smv.m), len(kv), smt.Root())
	/*
		// Loop over nodes map
		for hash, node := range smn.m {
			// smt.th.digest()
			// fmt.Println(hash, " | ", node)
			// value, err := smt.Get([]byte(hash))
			// fmt.Println("OLSH", value, err)
			fmt.Println("OLSH1", hex.EncodeToString([]byte(hash)))
			path, _ := smt.th.parseLeaf([]byte(node))
			// path2, _ := smt.th.parseNode([]byte(node))
			fmt.Println("OLSH11", hex.EncodeToString([]byte(path)))
			fmt.Println("OLSH1", hex.EncodeToString(smt.th.digest([]byte(hash))))
			// break
		}
		fmt.Println()

		// Full matches from OLSH1 -> OLSH11
		// Full matches from OLSH2 -> OLSH11)
		// Full matches from OLSH33 -> OLSH22
		// Full matches from OLSH333 -> OLSH2 (and in turn OLSH11

		// Loop over values map
		for path, value := range smv.m {
			// fmt.Println(path, " | ", value)
			// value, err := smt.Get([]byte(path))
			// fmt.Println("OLSH", value, err)
			fmt.Println("OLSH2", hex.EncodeToString([]byte(path)))
			fmt.Println("OLSH22", hex.EncodeToString([]byte(value)))
			fmt.Println("OLSH222", hex.EncodeToString(smt.th.digest([]byte(value))))
			// break
		}
		fmt.Println()

		// Loop over kv map
		var key string
		for key, value := range kv {
			// fmt.Println(key, " | ", value)
			// value, err := smt.Get([]byte(key))
			// fmt.Println("OLSH", value, err)
			fmt.Println("OLSH3", hex.EncodeToString([]byte(key)))
			fmt.Println("OLSH33", hex.EncodeToString([]byte(value)))
			fmt.Println("OLSH333", hex.EncodeToString(smt.th.path([]byte(key))))

			// break
		}

		sideNodes, pathNodes, nodeData, sideNode, err := smt.sideNodesForRoot(smt.th.path([]byte(key)), smt.root)
		require.NoError(t, err)
		fmt.Println("----------------")
		fmt.Print("OLSH", len(sideNodes), len(pathNodes), "-------", len(nodeData), len(sideNode))
	*/
	var key string
	for key, value := range kv {
		fmt.Println(key, " | ", value)
		break
	}
	sideNodes, pathNodes, nodeData, sideNode, err := smt.sideNodesForRoot(smt.th.path([]byte(key)), smt.root)
	require.NoError(t, err)
	fmt.Println("OLSH", smt.depth(), len(sideNodes), len(pathNodes), "-------", len(nodeData), len(sideNode))

	// for

	// value
	// left
	// right
	// leaf?
	// node?
}

func TestOlshansky2(t *testing.T) {
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
	fmt.Println("OLSH KV", kv)

	// var key string
	for key, value := range kv {
		path := smt.th.path([]byte(key))

		sideNodes, pathNodes, nodeData, _, err := smt.sideNodesForRoot(path, smt.root)
		if smt.th.isLeaf([]byte(nodeData)) {
			// input: (key, value)

			// path = smt.th.digest([]byte(key))
			// valueHash := smt.th.digest(value)
			// currentHash, currentData := smt.th.digestLeaf(path, valueHash)

			// smt.nodes.Set(currentHash, currentData)
			// smt.values.Set(path, value)

			// value = append(value, leafPrefix...)
			// value = append(value, path...)
			// value = append(value, data...)
			// return th.digest(value), value

			// fmt.Println("LEAF: ", value)
			// leafPath, leafData := smt.th.parseLeaf(nodeData)
			// value1, err := smt.Get(leafData)
			// require.NoError(t, err)
			// value2, err := smt.Get(leafPath)
			// require.NoError(t, err)
			// value3, err := smt.Get([]byte(key))
			// require.NoError(t, err)
			// fmt.Println("Leaf data: ", value, string(value3), leafData, leafPath)
			// fmt.Println("Leaf data: ", value)

		} else {
			// fmt.Println("NODE: ", value)
		}

		// How do I map from node to value?

		var sb strings.Builder
		fmt.Print(fmt.Sprintf("OLSH bits (%s): ", value))
		largestCommonPrefixLen := getLargestCommonPrefix(t, smt, kv, key)
		for i := 0; i < largestCommonPrefixLen; i++ {
			bit := getBitAtFromMSB(path, i)
			fmt.Print(bit, " ")
			sb.WriteString(strconv.Itoa(bit))
		}
		fmt.Println("\n\tLargest common prefix:", largestCommonPrefixLen)
		bits[key] = sb.String()

		sideNodeReadable := make([]string, len(sideNodes))
		for i, sideNode := range sideNodes {
			sideNodeReadable[i] = getLeafValue(t, smt, sideNode)
		}
		fmt.Println("\tSIDE NODES: [", strings.Join(sideNodeReadable, ", "), "]")

		pathNodeReadable := make([]string, len(pathNodes))
		for i, pathNode := range pathNodes {
			pathNodeReadable[i] = getLeafValue(t, smt, pathNode)
		}
		fmt.Println("\tPATH NODES: [", strings.Join(pathNodeReadable, ", "), "]")

		require.NoError(t, err)
		fmt.Println("---", smt.depth(), len(sideNodes), len(pathNodes))

		// path := smt.th.path(key)
		// value, err := smt.values.Get(path)

		// fmt.Println("isLeaf: ", smt.th.isLeaf(sideNode), value)
		// nodePath, nodeData := smt.th.parseNode(nodeData)
		// fmt.Println(nodeData)

		// smt.Get([]byte(d1)
		// fmt.Println(key, " | ", value, " | ", d1, " | ")
	}
	fmt.Println("WTF ", bits)
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
	fmt.Println("HOLLA")
	csvWriter := csv.NewWriter(csvFile)
	for key, bits := range bits {
		err = csvWriter.Write([]string{string(key), bits})
		require.NoError(t, err)
	}
	csvWriter.Flush()
	csvFile.Close()
}

// currentHash, currentData = smt.th.digestNode(sideNode, currentData)
// } else {
// 	currentHash, currentData = smt.th.digestNode(currentData, sideNode)
// }

// if err := smt.nodes.Set(currentHash, currentData); err != nil {
// 	return nil, err
// }
// currentData = currentHash
// }

// if err := smt.values.Set(path, value); err != nil {
