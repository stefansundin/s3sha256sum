package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const version = "0.0.1"

func init() {
	// Do not fail if a region is not specified anywhere
	// This is only used for the first call that looks up the bucket region
	if _, present := os.LookupEnv("AWS_DEFAULT_REGION"); !present {
		os.Setenv("AWS_DEFAULT_REGION", "us-east-1")
	}
}

func main() {
	var profile, resume string
	var versionFlag bool
	flag.StringVar(&profile, "profile", "", "Use a specific profile from your credential file.")
	flag.StringVar(&resume, "resume", "", "Provide a hash state to resume from a specific position.")
	flag.BoolVar(&versionFlag, "version", false, "Print version number.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "s3sha256sum version %s\n", version)
		fmt.Fprintln(os.Stderr, "Copyright (C) 2021 Stefan Sundin")
		fmt.Fprintln(os.Stderr, "Website: https://github.com/stefansundin/s3sha256sum")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "s3sha256sum comes with ABSOLUTELY NO WARRANTY.")
		fmt.Fprintln(os.Stderr, "This is free software, and you are welcome to redistribute it under certain")
		fmt.Fprintln(os.Stderr, "conditions. See the GNU General Public Licence version 3 for details.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [parameters] <S3Uri> [S3Uri]...\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "S3Uri must have the format s3://<bucketname>/<key>.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Parameters:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// Decode the resume state
	var h hash.Hash
	var position uint64
	if resume != "" {
		if flag.NArg() > 1 {
			fmt.Fprintln(os.Stderr, "You can only resume hashing a single object.")
			os.Exit(1)
		}
		state, err := base64.StdEncoding.DecodeString(resume)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		h = sha256.New()
		err = hashUnmarshalBinary(&h, state)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		position = hashGetLen(h)
		fmt.Printf("Resuming from position %s.\n", formatFilesize(position))
	}

	// Trap Ctrl-C signal
	ctx, cancel := context.WithCancel(context.Background())
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		interrupted := false
		for sig := range signalChannel {
			if sig != os.Interrupt {
				continue
			}
			if interrupted {
				os.Exit(1)
			}
			fmt.Println("\nInterrupt received.")
			interrupted = true
			cancel()
		}
	}()

	// Initialize the AWS SDK
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		func(o *config.LoadOptions) error {
			if profile != "" {
				o.SharedConfigProfile = profile
			}
			return nil
		},
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := s3.NewFromConfig(cfg)

	// Cache bucket locations to avoid extra calls
	bucketLocations := make(map[string]string)

	// Loop the provided arguments
	for i, arg := range flag.Args() {
		if i != 0 {
			fmt.Println()
		}

		bucket, key := parseS3Uri(arg)
		if bucket == "" || key == "" {
			fmt.Fprintln(os.Stderr, "Error: The S3Uri must have the format s3://<bucketname>/<key>")
			os.Exit(1)
		}

		// Get the bucket location
		if bucketLocations[bucket] == "" {
			bucketLocationOutput, err := client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{
				Bucket: aws.String(bucket),
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			bucketRegion := string(bucketLocationOutput.LocationConstraint)
			if bucketRegion == "" {
				// This can be updated when aws-sdk-go-v2 supports GetBucketLocation WithNormalizeBucketLocation
				bucketRegion = "us-east-1"
			}
			bucketLocations[bucket] = bucketRegion
		}

		// Create an S3 client for the region
		regionalClient := s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.Region = bucketLocations[bucket]
		})

		// Get the object
		input := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		if position != 0 {
			input.Range = aws.String(fmt.Sprintf("bytes=%d-", position))
		}
		obj, err := regionalClient.GetObject(ctx, input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Compute the sha256 hash
		// The body is streamed so it is computing while the object is being downloaded
		if resume == "" {
			h = sha256.New()
		}
		_, err = io.Copy(h, obj.Body)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				state, err := hashMarshalBinary(h)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				encodedState := base64.StdEncoding.EncodeToString(state)
				position = hashGetLen(h)
				fmt.Printf("Aborted after %s.\n", formatFilesize(position))
				fmt.Println()
				fmt.Println("To resume hashing from this position, run:")
				fmt.Println(formatResumeCommand(profile, encodedState, bucket, key))
				fmt.Println()
				fmt.Println("Note: This value is the internal state of the hash function. It may not be compatible across versions of s3sha256sum or across Go versions.")
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(1)
		}

		// Print the sum
		sum := hex.EncodeToString(h.Sum(nil))
		fmt.Printf("%s  s3://%s/%s\n", sum, bucket, key)
		fmt.Println()

		// Compare with the object metadata if possible
		objSum := obj.Metadata["sha256sum"]
		objSumSource := "metadata"
		if objSum == "" && obj.TagCount > 0 {
			// No metadata entry, check if there's a tag
			tags, err := regionalClient.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Was not able to get object tags (looking for 'sha256sum' tag to compare against).")
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, t := range tags.TagSet {
				if *t.Key == "sha256sum" {
					objSum = *t.Value
					objSumSource = "tag"
					break
				}
			}
		}
		if objSum == "" {
			fmt.Println("Metadata 'sha256sum' not present. Populate this metadata (or tag) to enable automatic comparison.")
		} else {
			if strings.EqualFold(sum, objSum) {
				fmt.Printf("OK (matches object %s)\n", objSumSource)
			} else {
				fmt.Printf("FAILED (did not match object %s)\n", objSumSource)
				fmt.Printf("Expected: %s\n", objSum)
			}
		}
	}
}