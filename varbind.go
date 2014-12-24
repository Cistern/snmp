package snmp

import (
	"errors"
)

var (
	ErrorIncorrectType = errors.New("snmp: incorrect type")
)

// Varbind represents a single variable binding.
type Varbind struct {
	OID   ObjectIdentifier
	value DataType
}

// NewVarbind returns a new Varbind with the given OID and value.
func NewVarbind(OID ObjectIdentifier, value DataType) Varbind {
	return Varbind{
		OID:   OID,
		value: value,
	}
}

func (v Varbind) GetStringValue() (string, error) {
	str, ok := v.value.(String)

	if !ok {
		return "", ErrorIncorrectType
	}

	return string(str), nil
}

func (v Varbind) GetIntegerValue() (int, error) {
	i, ok := v.value.(Int)

	if !ok {
		return 0, ErrorIncorrectType
	}

	return int(i), nil
}
