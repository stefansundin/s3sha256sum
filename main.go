package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
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
	var paranoidInterval time.Duration
	var profile, resume, endpointURL, caBundle string
	var noVerifySsl, noSignRequest, debug, verbose, versionFlag bool
	flag.DurationVar(&paranoidInterval, "paranoid", 0, "Print status and hash state on an interval. (e.g. \"10s\")")
	flag.StringVar(&profile, "profile", "", "Use a specific profile from your credential file.")
	flag.StringVar(&resume, "resume", "", "Provide a hash state to resume from a specific position.")
	flag.StringVar(&endpointURL, "endpoint-url", "", "Override the S3 endpoint URL. (for use with S3 compatible APIs)")
	flag.StringVar(&caBundle, "ca-bundle", "", "The CA certificate bundle to use when verifying SSL certificates.")
	flag.BoolVar(&noVerifySsl, "no-verify-ssl", false, "Do not verify SSL certificates.")
	flag.BoolVar(&noSignRequest, "no-sign-request", false, "Do not sign requests.")
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output.")
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
		fmt.Println()
	}

	// If paranoid, start the go routine that runs in the background
	// This feels a bit unsafe but haven't had any problems in my testing
	var bucket, key string
	var obj *s3.GetObjectOutput
	var objLength uint64
	copying := false
	if paranoidInterval != 0 {
		go func() {
			lastPosition := position
			for {
				time.Sleep(paranoidInterval)
				if !copying {
					continue
				}
				position := hashGetLen(h)
				if position == 0 || position == lastPosition {
					continue
				}
				lastPosition = position
				state, err := hashMarshalBinary(h)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if state == nil {
					continue
				}
				encodedState := base64.StdEncoding.EncodeToString(state)
				fmt.Printf("To resume hashing from %s out of %s (%2.1f%%), run: %s\n", formatFilesize(position), formatFilesize(objLength), 100*float64(position)/float64(objLength), formatResumeCommand(verbose, debug, noSignRequest, noVerifySsl, paranoidInterval, profile, endpointURL, caBundle, encodedState, bucket, key))
			}
		}()
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
		ctx,
		func(o *config.LoadOptions) error {
			if profile != "" {
				o.SharedConfigProfile = profile
			}
			if caBundle != "" {
				f, err := os.Open(caBundle)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				o.CustomCABundle = f
			}
			if noVerifySsl {
				o.HTTPClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}
			}
			if debug {
				var lm aws.ClientLogMode = aws.LogRequest | aws.LogResponse
				o.ClientLogMode = &lm
			}
			return nil
		},
		config.WithAssumeRoleCredentialOptions(func(o *stscreds.AssumeRoleOptions) {
			o.TokenProvider = stscreds.StdinTokenProvider
		}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := s3.NewFromConfig(cfg,
		func(o *s3.Options) {
			if noSignRequest {
				o.Credentials = aws.AnonymousCredentials{}
			}
			if endpointURL != "" {
				o.EndpointResolver = s3.EndpointResolverFromURL(endpointURL)
				o.UsePathStyle = true
			}
		})

	// Cache bucket locations to avoid extra calls
	bucketLocations := make(map[string]string)

	// Loop the provided arguments
	for i, arg := range flag.Args() {
		if i != 0 {
			fmt.Println()
		}

		bucket, key = parseS3Uri(arg)
		if bucket == "" || key == "" {
			fmt.Fprintln(os.Stderr, "Error: The S3Uri must have the format s3://<bucketname>/<key>")
			os.Exit(1)
		}

		// Create an S3 client for the region
		regionalClient := client
		if endpointURL == "" {
			// Get the bucket location
			if bucketLocations[bucket] == "" {
				bucketLocationOutput, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
					Bucket: aws.String(bucket),
				})
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				bucketLocations[bucket] = normalizeBucketLocation(bucketLocationOutput.LocationConstraint)
			}
			regionalClient = s3.NewFromConfig(cfg, func(o *s3.Options) {
				o.Region = bucketLocations[bucket]
			})
		}

		// Get the object
		if verbose {
			fmt.Printf("Getting s3://%s/%s\n", bucket, key)
		}
		input := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		if position != 0 {
			input.Range = aws.String(fmt.Sprintf("bytes=%d-", position))
		}
		obj, err = regionalClient.GetObject(ctx, input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		objLength = position + uint64(obj.ContentLength)

		// Compute the sha256 hash
		// The body is streamed so it is computing while the object is being downloaded
		if resume == "" {
			h = sha256.New()
		}
		copying = true
		_, err = io.Copy(h, obj.Body)
		copying = false
		if err != nil {
			if errors.Is(err, context.Canceled) {
				state, err := hashMarshalBinary(h)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				encodedState := base64.StdEncoding.EncodeToString(state)
				position := hashGetLen(h)
				fmt.Printf("Aborted after %s out of %s (%2.1f%%).\n", formatFilesize(position), formatFilesize(objLength), 100*float64(position)/float64(objLength))
				fmt.Println()
				fmt.Println("To resume hashing from this position, run:")
				fmt.Println(formatResumeCommand(verbose, debug, noSignRequest, noVerifySsl, paranoidInterval, profile, endpointURL, caBundle, encodedState, bucket, key))
				fmt.Println()
				fmt.Println("Note: This value is the internal state of the hash function. It may not be compatible across versions of s3sha256sum or across Go versions.")
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(1)
		}
		if paranoidInterval != 0 || verbose {
			fmt.Println()
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
			tags, err := regionalClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
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
