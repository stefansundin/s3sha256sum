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
  -paranoid duration
    	Print status and hash state on an interval. (e.g. "10s")
  -profile string
    	Use a specific profile from your credential file.
  -resume string
    	Provide a hash state to resume from a specific position.
  -verbose
    	Verbose output.
  -version
    	Print version number.
```
