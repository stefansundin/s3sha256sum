package main

import (
	"hash"
	"reflect"
)

// Internal hash state:
// https://github.com/golang/go/blob/go1.17/src/crypto/sha256/sha256.go#L50-L57

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
	return b, err
}

func hashUnmarshalBinary(h *hash.Hash, b []byte) error {
	var err error
	v := reflect.ValueOf(*h).MethodByName("UnmarshalBinary").Call([]reflect.Value{reflect.ValueOf(b)})
	if !v[0].IsNil() {
		err = v[0].Interface().(error)
	}
	return err
}
