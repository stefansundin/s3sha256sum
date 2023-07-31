package main

import (
	"bytes"
	"errors"
	"hash"
	"reflect"
)

const (
	magic256              = "sha\x03"
	expectedMarshaledSize = 108
)

// Internal hash state:
// https://github.com/golang/go/blob/go1.17/src/crypto/sha256/sha256.go#L50-L57
// https://github.com/minio/sha256-simd/blob/v1.0.1/sha256.go#L45-L50
// https://github.com/minio/sha256-simd/blob/v1.0.1/sha256.go#L396-L411

func hashGetLen(h hash.Hash) uint64 {
	if h == nil {
		return 0
	}
	s := reflect.ValueOf(h).Elem()
	return s.FieldByName("len").Uint()
}

func hashMarshalBinary(h hash.Hash) ([]byte, error) {
	if h == nil {
		return nil, nil
	}
	var b []byte
	var err error
	v := reflect.ValueOf(h).MethodByName("MarshalBinary").Call([]reflect.Value{})
	if !v[0].IsNil() {
		b = make([]byte, v[0].Len())
		// Is there a better way to copy these bytes?
		for i := 0; i < v[0].Len(); i++ {
			b[i] = byte(v[0].Index(i).Uint())
		}
	}
	if !v[1].IsNil() {
		err = v[1].Interface().(error)
	}
	if err == nil && len(b) == expectedMarshaledSize && bytes.Equal(b[:4], []byte(magic256)) {
		// Reorganize the data and remove some constant data so that the final string becomes shorter
		// By putting x last we can remove all the 0 bytes at the end
		// As a bonus, we also compute a 1 byte checksum
		// The data is originally stored as: ["sha\x03", h, x, len]
		// We reorganize it to: [checksum, len, h, x]
		b2 := make([]byte, 0, 1+len(b))
		b2 = append(b2, 0) // Checksum temporary placeholder
		b2 = append(b2, b[4+96:]...)
		b2 = append(b2, b[4:4+96]...)
		b2 = bytes.TrimRightFunc(b2, func(r rune) bool { return r == 0 })
		b2[0] = fletcher8(b2[1:])
		b = b2
	}
	return b, err
}

func hashUnmarshalBinary(h *hash.Hash, b []byte) error {
	var err error
	if len(b) != expectedMarshaledSize {
		var checksum byte
		b, checksum = b[1:], b[0]
		actualChecksum := fletcher8(b)
		if checksum != actualChecksum {
			return errors.New("checksum error, the value is corrupted")
		}
		// Unpack the data to what is expected by UnmarshalBinary
		b2 := make([]byte, expectedMarshaledSize)
		copy(b2, magic256)
		copy(b2[4:4+96], b[8:])
		copy(b2[4+96:], b[:8])
		b = b2
	}
	v := reflect.ValueOf(*h).MethodByName("UnmarshalBinary").Call([]reflect.Value{reflect.ValueOf(b)})
	if !v[0].IsNil() {
		err = v[0].Interface().(error)
	}
	return err
}
