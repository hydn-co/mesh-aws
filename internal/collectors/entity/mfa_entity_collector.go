package entity

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

type awsMFAEntityClient interface {
	IAMVirtualMFADeviceEnumerator(ctx context.Context) enumerators.Enumerator[api.IAMVirtualMFADevice]
	IAMUserEnumerator(ctx context.Context) enumerators.Enumerator[api.IAMUser]
}

type awsMFAEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (awsMFAEntityClient, error)

// AWSMFAEntityCollector collects AWS IAM MFA entities and account associations.
type AWSMFAEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSMFAEntityCollectorOptions, *connector.NoPayload]
	client    awsMFAEntityClient
	newClient awsMFAEntityClientFactory
	state     connectorutil.FeatureState
}

// NewAWSMFAEntityCollector constructs the collector with the given feature context.
func NewAWSMFAEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSMFAEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSMFAEntityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultAWSMFAEntityClientFactory,
	}
}

func defaultAWSMFAEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (awsMFAEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSMFAEntityCollector) Init(ctx context.Context) error {
	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	opts := c.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecretFrom(
		c.GetCredentials(),
		connectorutil.DefaultCredentialName,
	)
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	if c.newClient == nil {
		c.newClient = defaultAWSMFAEntityClientFactory
	}
	client, err := c.newClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSMFAEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS MFA entity collector")

	mfasEmitted := 0
	linksEmitted := 0
	userArnByID := map[string]string{}
	userArnByName := map[string]string{}
	userEnum := c.client.IAMUserEnumerator(ctx)
	if err := enumerators.ForEach(userEnum, func(user api.IAMUser) error {
		if user.UserID != "" {
			userArnByID[user.UserID] = user.Arn
		}
		if user.UserName != "" {
			userArnByName[user.UserName] = user.Arn
		}
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM users for MFA links: %w", err)
	}
	mfaEnum := c.client.IAMVirtualMFADeviceEnumerator(ctx)
	if err := enumerators.ForEach(mfaEnum, func(device api.IAMVirtualMFADevice) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		mfa := entities.NewMultiFactor()
		mfa.MultiFactorRef = device.SerialNumber
		if !device.EnableDate.IsZero() {
			mfa.CreatedAt = &device.EnableDate
		}

		if err := c.Emit(ctx, mfa); err != nil {
			return fmt.Errorf("emit MFA device %s: %w", device.SerialNumber, err)
		}
		mfasEmitted++

		if device.UserID == "" {
			return nil
		}

		link := entities.NewAccountMultiFactor()
		if arn := userArnByID[device.UserID]; arn != "" {
			link.AccountRef = arn
		} else if arn := userArnByName[device.UserName]; arn != "" {
			link.AccountRef = arn
		} else {
			link.AccountRef = device.UserID
		}
		link.MultiFactorRef = device.SerialNumber
		if !device.EnableDate.IsZero() {
			link.CreatedAt = &device.EnableDate
		}

		if err := c.Emit(ctx, link); err != nil {
			return fmt.Errorf("emit MFA link %s/%s: %w", device.UserID, device.SerialNumber, err)
		}
		linksEmitted++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM MFA devices: %w", err)
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS MFA entity collector",
		"multi_factors_emitted", mfasEmitted,
		"account_multi_factor_links_emitted", linksEmitted,
	)
	return nil
}

func (c *AWSMFAEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
