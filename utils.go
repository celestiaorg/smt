package smt

// getBitAtFromMSB gets the bit at an offset from the most significant bit
func getBitAtFromMSB(data []byte, position int) int {
	if int(data[position/8])&(1<<(8-1-uint(position)%8)) > 0 {
		return 1
	}
	return 0
}

// setBitAtFromMSB sets the bit at an offset from the most significant bit
func setBitAtFromMSB(data []byte, position int) {
	n := int(data[position/8])
	n |= (1 << (8 - 1 - uint(position)%8))
	data[position/8] = byte(n)
}

func countSetBits(data []byte) int {
	count := 0
	for i := 0; i < len(data)*8; i++ {
		if getBitAtFromMSB(data, i) == 1 {
			count++
		}
	}
	return count
}

func countCommonPrefix(data1 []byte, data2 []byte) int {
	count := 0
	for i := 0; i < len(data1)*8; i++ {
		if getBitAtFromMSB(data1, i) == getBitAtFromMSB(data2, i) {
			count++
		} else {
			break
		}
	}
	return count
}

func emptyBytes(length int) []byte {
	b := make([]byte, length)
	return b
}

func reverseByteSlices(sideNodes [][]byte) [][]byte {
	for left, right := 0, len(sideNodes)-1; left < right; left, right = left+1, right-1 {
		sideNodes[left], sideNodes[right] = sideNodes[right], sideNodes[left]
	}

	return sideNodes
}

func valueKey(key, root []byte) []byte {
	ret := make([]byte, len(root), len(root)+len(key))
	copy(ret, root)
	return append(ret, key...)
}
