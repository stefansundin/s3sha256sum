package main

import (
	"fmt"
	"os"
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

func formatResumeCommand(encodedState, arg string) string {
	cmd := []string{os.Args[0], "--resume", encodedState}
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--resume" {
			i++
			continue
		}
		if strings.HasPrefix(os.Args[i], "s3://") {
			continue
		}
		cmd = append(cmd, os.Args[i])
	}
	cmd = append(cmd, arg)
	return strings.Join(cmd, " ")
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func mfaTokenProvider() (string, error) {
	for {
		fmt.Printf("Assume Role MFA token code: ")
		var code string
		_, err := fmt.Scanln(&code)
		if len(code) == 6 && isNumeric(code) {
			return code, err
		}
		fmt.Println("Code must consist of 6 digits. Please try again.")
	}
}
