package snmp

// encodeHeaderSequence encodes an SNMP data type
// header sequence. The first byte is the field type and
// the remaining bytes are a length-encoded length.
func encodeHeaderSequence(fieldType byte, length int) []byte {
	// Field type is one byte
	result := []byte{fieldType}
	// Encode the length
	if length <= 0x7f {
		// Length fits in one byte
		return append(result, byte(length))
	}
	// Need to length-encode the length
	result = append(result, 0x80)
	// We do little endian first
	reversed := []byte{}
	for length > 0 {
		reversed = append(reversed, byte(length))
		length = length >> 8
	}
	// and then reverse it
	result = append(result, reverseSlice(reversed)...)
	result[1] |= byte(len(reversed))
	return result
}

// reverseSlice returns a []byte in reverse order.
func reverseSlice(b []byte) []byte {
	length := len(b)
	result := make([]byte, 0, length)
	for length > 0 {
		result = append(result, b[length-1])
		length--
	}
	return result
}
