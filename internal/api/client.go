package api

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hydn-co/mesh-aws/internal/credentials"
)

// Client wraps AWS IAM and CloudTrail SDK v2 clients.
type Client struct {
	IAM        *iam.Client
	CloudTrail *cloudtrail.Client
}

// New creates a new Client using the provided AWSCredentials.
func New(_ context.Context, creds *credentials.AWSCredentials) (*Client, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials are required")
	}

	provider := awscredentials.NewStaticCredentialsProvider(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		creds.SessionToken,
	)

	cfg := aws.Config{
		Region:      creds.Region,
		Credentials: provider,
	}

	return &Client{
		IAM:        iam.NewFromConfig(cfg),
		CloudTrail: cloudtrail.NewFromConfig(cfg),
	}, nil
}
