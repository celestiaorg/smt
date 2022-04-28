package smt

// getPathBit gets the bit at an offset from the most significant bit
func getPathBit(data []byte, position int) int {
	if int(data[position/8])&(1<<(8-1-uint(position)%8)) > 0 {
		return 1
	}
	return 0
}

// setBitAtFromMSB sets the bit at an offset from the most significant bit
func setBitAtFromMSB(data []byte, position int) {
	n := int(data[position/8])
	n |= 1 << (8 - 1 - uint(position)%8)
	data[position/8] = byte(n)
}

func countSetBits(data []byte) int {
	count := 0
	for i := 0; i < len(data)*8; i++ {
		if getPathBit(data, i) == 1 {
			count++
		}
	}
	return count
}

func countCommonPrefix(data1 []byte, data2 []byte) int {
	count := 0
	for i := 0; i < len(data1)*8; i++ {
		if getPathBit(data1, i) == getPathBit(data2, i) {
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

func reverseByteSlices(slices [][]byte) [][]byte {
	for left, right := 0, len(slices)-1; left < right; left, right = left+1, right-1 {
		slices[left], slices[right] = slices[right], slices[left]
	}

	return slices
}

// Used for verification of serialized proof data
func hashSerialization(smt *BaseSMT, data []byte) []byte {
	if isExtension(data) {
		pathBounds, path, childHash := parseExtension(data, smt.ph)
		ext := extensionNode{path: path, child: &lazyNode{childHash}}
		copy(ext.pathBounds[:], pathBounds)
		return smt.hashNode(&ext)
	} else {
		return smt.th.digest(data)
	}
}
