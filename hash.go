package main

import (
	"encoding/binary"
	"errors"
	"hash"
	"reflect"
	"unsafe"
)

// I am curious if this stuff can be done better.

// Internal hash state:
// https://github.com/minio/sha256-simd/blob/v1.0.0/sha256.go#L47-L52

type digest struct {
	h     [8]uint32
	x     [64]byte
	nx    int
	len   uint64
	is224 bool // for compatibility with crypto/sha256
}

const (
	chunk         = 64
	magic224      = "sha\x02"
	magic256      = "sha\x03"
	marshaledSize = len(magic256) + 8*4 + chunk + 8
)

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
	d := getHashState(h)
	return d.MarshalBinary()
}

func hashUnmarshalBinary(h *hash.Hash, b []byte) error {
	var state digest
	err := state.UnmarshalBinary(b)
	if err != nil {
		return err
	}
	err = restoreHashState(h, state)
	return err
}

func getHashState(hash hash.Hash) *digest {
	var state digest
	s := reflect.ValueOf(hash).Elem()

	h := s.FieldByName("h")
	for i := 0; i < h.Len(); i++ {
		state.h[i] = uint32(h.Index(i).Uint())
	}

	x := s.FieldByName("x")
	for i := 0; i < x.Len(); i++ {
		state.x[i] = byte(x.Index(i).Uint())
	}

	state.nx = int(s.FieldByName("nx").Int())
	state.len = s.FieldByName("len").Uint()

	return &state
}

func restoreHashState(hash *hash.Hash, state digest) error {
	s := reflect.Indirect(reflect.ValueOf(hash).Elem().Elem())

	h := s.FieldByName("h")
	x := s.FieldByName("x")
	nx := s.FieldByName("nx")
	len := s.FieldByName("len")

	reflect.NewAt(h.Type(), unsafe.Pointer(h.UnsafeAddr())).Elem().Set(reflect.ValueOf(state.h))
	reflect.NewAt(x.Type(), unsafe.Pointer(x.UnsafeAddr())).Elem().Set(reflect.ValueOf(state.x))
	reflect.NewAt(nx.Type(), unsafe.Pointer(nx.UnsafeAddr())).Elem().Set(reflect.ValueOf(state.nx))
	reflect.NewAt(len.Type(), unsafe.Pointer(len.UnsafeAddr())).Elem().Set(reflect.ValueOf(state.len))

	return nil
}

// Functions from https://github.com/golang/go/blob/go1.17/src/crypto/sha256/sha256.go

func (d *digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	if d.is224 {
		b = append(b, magic224...)
	} else {
		b = append(b, magic256...)
	}
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.len)
	return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || (d.is224 && string(b[:len(magic224)]) != magic224) || (!d.is224 && string(b[:len(magic256)]) != magic256) {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	b = b[len(magic224):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}
