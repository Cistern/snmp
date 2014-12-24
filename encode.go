package snmp

// TODO: add comment
func encodeHeaderSequence(fieldType byte, length int) []byte {
	result := []byte{fieldType}

	// TODO: add comment - length encoding
	if length <= 0x7f {

		// TODO: return here
		result = append(result, byte(length))

	} else { // TODO: get rid of the else
		result = append(result, 0x80)

		reversed := []byte{}
		for length > 0 {
			reversed = append(reversed, byte(length))
			result = append(result, 0)
			length = length >> 8
		}

		numBytes := len(reversed)
		for i, j := numBytes-1, 2; i >= 0; i, j = i-1, j+1 {
			result[j] = reversed[i]
		}

		result[1] |= byte(numBytes)
	}

	return result
}

func reverseSlice(b []byte) []byte {
	length := len(b)
	result := make([]byte, 0, length)

	for length > 0 {
		result = append(result, b[length-1])
		length--
	}

	return result
}
