package main

import (
	"fmt"
	"hash"
	"os"
	"reflect"
	"strings"
)

const kiB = 1024
const MiB = 1024 * kiB
const GiB = 1024 * MiB
const TiB = 1024 * GiB

func parseS3Uri(s string) (string, string) {
	if !strings.HasPrefix(s, "s3://") {
		return "", ""
	}
	parts := strings.SplitN(s[5:], "/", 2)
	if len(parts) == 0 {
		return "", ""
	} else if len(parts) == 1 {
		return parts[0], ""
	} else {
		return parts[0], parts[1]
	}
}

// The S3 docs state GB and TB but they actually mean GiB and TiB
// For consistency, format filesizes in GiB and TiB
func formatFilesize(size uint64) string {
	if size < kiB {
		return fmt.Sprintf("%d bytes", size)
	} else if size < MiB {
		return fmt.Sprintf("%.1f kiB (%d bytes)", float64(size)/float64(kiB), size)
	} else if size < GiB {
		return fmt.Sprintf("%.1f MiB (%d bytes)", float64(size)/float64(MiB), size)
	} else if size < TiB {
		return fmt.Sprintf("%.1f GiB (%d bytes)", float64(size)/float64(GiB), size)
	} else {
		return fmt.Sprintf("%.1f TiB (%d bytes)", float64(size)/float64(TiB), size)
	}
}

func formatResumeCommand(profile, encodedState, bucket, key string) string {
	cmd := []string{os.Args[0]}
	if profile != "" {
		cmd = append(cmd, "-profile", profile)
	}
	cmd = append(cmd, "-resume", encodedState)
	cmd = append(cmd, "s3://"+bucket+"/"+key)
	return strings.Join(cmd, " ")
}

func hashGetLen(h hash.Hash) uint64 {
	s := reflect.ValueOf(h).Elem()
	return s.FieldByName("len").Uint()
}

// Internal hash state:
// https://github.com/golang/go/blob/go1.17/src/crypto/sha256/sha256.go#L50-L57

func hashMarshalBinary(h hash.Hash) ([]byte, error) {
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
