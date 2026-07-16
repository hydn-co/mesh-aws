package entity

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
	"github.com/hydn-co/substrate/enumerators"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

const secretProvider = "aws-secrets-manager"

type awsSecretEntityClient interface {
	SecretEnumerator(ctx context.Context) enumerators.Enumerator[api.Secret]
}

type awsSecretEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (awsSecretEntityClient, error)

// AWSSecretEntityCollector collects AWS Secrets Manager secret metadata. Secret
// values are never retrieved. Secrets Manager is regional, so in organization
// mode the collector fans out across every (account, region) target.
type AWSSecretEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSSecretEntityCollectorOptions, *connector.NoPayload]
	client    awsSecretEntityClient
	newClient awsSecretEntityClientFactory
	resolver  *scope.Resolver
	state     connectorutil.FeatureState
}

// NewAWSSecretEntityCollector constructs the collector with the given feature context.
func NewAWSSecretEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSSecretEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSSecretEntityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultAWSSecretEntityClientFactory,
	}
}

func defaultAWSSecretEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (awsSecretEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSSecretEntityCollector) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	opts := c.GetOptions()
	if err := connectorutil.Validate(opts, "feature options"); err != nil {
		return err
	}

	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecretFrom(
		c.GetCredentials(),
		connectorutil.DefaultCredentialName,
	)
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	if c.newClient == nil {
		c.newClient = defaultAWSSecretEntityClientFactory
	}
	c.resolver = scope.NewResolver(
		&opts.AWSScopeOptionsCore,
		opts.GetRegion(),
		opts.GetSessionToken(),
		creds,
		scope.WithLogger(func(level slog.Level, msg string, args ...any) {
			connectorutil.LogFeature(context.Background(), c.TypedFeatureContext, level, msg, args...)
		}),
	)
	c.state.MarkReady()
	return nil
}

func (c *AWSSecretEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS secret entity collector")

	secretsEmitted := 0

	// Secrets Manager is regional, so the resolver expands organization mode to
	// one target per (account, region).
	if err := scope.ForEachTarget(ctx, c.resolver, true, c.newClient,
		func(ctx context.Context, client awsSecretEntityClient, _ scope.Target) error {
			c.client = client
			return c.collectSecrets(ctx, &secretsEmitted)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS secret entity collector",
		"secrets_emitted", secretsEmitted,
	)
	return nil
}

// collectSecrets enumerates Secrets Manager secret metadata for the current
// target and emits a Secret entity per secret.
func (c *AWSSecretEntityCollector) collectSecrets(ctx context.Context, secretsEmitted *int) error {
	secretEnum := c.client.SecretEnumerator(ctx)
	if err := enumerators.ForEach(secretEnum, func(secret api.Secret) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewSecret()
		entity.SecretRef = secret.ARN
		entity.Name = secret.Name
		entity.Provider = secretProvider
		entity.Path = secret.ARN
		entity.Type = "secret"
		entity.CredentialRotationEnabled = secret.RotationEnabled

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit secret %s: %w", secret.ARN, err)
		}
		(*secretsEmitted)++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate secrets: %w", err)
	}
	return nil
}

func (c *AWSSecretEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
