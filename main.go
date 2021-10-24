package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
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
	var profile string
	var versionFlag bool
	flag.StringVar(&profile, "profile", "", "Use a specific profile from your credential file.")
	flag.BoolVar(&versionFlag, "version", false, "Print version number.")
	flag.Parse()

	if versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(0)
	}

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

	// Cache the bucket location to avoid extra calls
	bucketLocations := make(map[string]string)

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
		obj, err := regionalClient.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Compute and print the sha256 hash
		// The body is streamed so it is computing while the object is being downloaded
		hash := sha256.New()
		_, err = io.Copy(hash, obj.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sum := hex.EncodeToString(hash.Sum(nil))
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
