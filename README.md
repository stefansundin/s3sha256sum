s3sha256sum is a small program that calculates SHA256 checksums of objects stored on Amazon S3. Use it to verify the integrity of your objects.

If the expected checksum value has been attached to the object metadata (or tag), then s3sha256sum will automatically compare the values and report `OK` or `FAILED`. [See here for an example.](https://github.com/stefansundin/s3sha256sum/discussions/1)

s3sha256sum has a fancy feature that helps avoid double work and extra data transfer charges if you have to abort the hashing process. If you interrupt the program with Ctrl-C, it will print the internal state of the hash function and print a command that will resume the process from that position in the object.

For the paranoid, s3sha256sum also has an option that prints the status on an interval. This can be useful for humongous objects where you can't afford to restart the process from the beginning.

**Tip:** In many cases it may be worth running s3sha256sum on an EC2 instance located in the same region as the S3 bucket. Data transfer from S3 to EC2 is free.

## Installation

Precompiled binaries will be provided at a later date. For now you can install using `go install`:

```
go install github.com/stefansundin/s3sha256sum@latest
```

## Usage

```
$ s3sha256sum -help
Usage: s3sha256sum [parameters] <S3Uri> [S3Uri]...
S3Uri must have the format s3://<bucketname>/<key>.

Parameters:
  -ca-bundle string
    	The CA certificate bundle to use when verifying SSL certificates.
  -debug
    	Turn on debug logging.
  -endpoint-url string
    	Override the S3 endpoint URL. (for use with S3 compatible APIs)
  -expected-bucket-owner string
    	The account ID of the expected bucket owner.
  -no-sign-request
    	Do not sign requests.
  -no-verify-ssl
    	Do not verify SSL certificates.
  -paranoid duration
    	Print status and hash state on an interval. (e.g. "10s")
  -profile string
    	Use a specific profile from your credential file.
  -region string
    	The region to use. Overrides config/env settings. Avoids one API call.
  -resume string
    	Provide a hash state to resume from a specific position.
  -verbose
    	Verbose output.
  -version
    	Print version number.
  -version-id string
    	Version ID used to reference a specific version of the S3 object.
```

You can also set environment variables that [aws-sdk-go-v2](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/config#EnvConfig) automatically consumes:

```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
AWS_ROLE_ARN
AWS_ROLE_SESSION_NAME
AWS_REGION
AWS_PROFILE
AWS_SHARED_CREDENTIALS_FILE
AWS_CONFIG_FILE
AWS_CA_BUNDLE
```
