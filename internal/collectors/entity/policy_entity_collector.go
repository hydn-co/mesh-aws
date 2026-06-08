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
	"github.com/hydn-co/mesh-aws/internal/scope"
)

type awsPolicyEntityClient interface {
	IAMPolicyEnumerator(ctx context.Context, scope string) enumerators.Enumerator[api.IAMPolicy]
}

type awsPolicyEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (awsPolicyEntityClient, error)

// AWSPolicyEntityCollector collects AWS IAM managed policy entities.
type AWSPolicyEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload]
	client    awsPolicyEntityClient
	newClient awsPolicyEntityClientFactory
	resolver  *scope.Resolver
	state     connectorutil.FeatureState
}

// NewAWSPolicyEntityCollector constructs the collector with the given feature context.
func NewAWSPolicyEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSPolicyEntityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultAWSPolicyEntityClientFactory,
	}
}

func defaultAWSPolicyEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (awsPolicyEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSPolicyEntityCollector) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

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
		c.newClient = defaultAWSPolicyEntityClientFactory
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

func (c *AWSPolicyEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS policy entity collector")

	policiesEmitted := 0

	// IAM managed policies are collected per account so a single collector fans
	// out across every member account in organization mode.
	if err := scope.ForEachTarget(ctx, c.resolver, false, c.newClient,
		func(ctx context.Context, client awsPolicyEntityClient, _ scope.Target) error {
			c.client = client
			return c.collectPolicies(ctx, &policiesEmitted)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS policy entity collector",
		"policies_emitted",
		policiesEmitted,
	)
	return nil
}

// collectPolicies enumerates IAM managed policies for the current target account.
func (c *AWSPolicyEntityCollector) collectPolicies(ctx context.Context, policiesEmitted *int) error {
	policyEnum := c.client.IAMPolicyEnumerator(ctx, "Local")
	if err := enumerators.ForEach(policyEnum, func(policy api.IAMPolicy) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewPolicy()
		entity.PolicyRef = policy.PolicyID
		entity.Name = policy.PolicyName
		entity.Description = policy.Description

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit IAM policy %s: %w", policy.PolicyID, err)
		}
		(*policiesEmitted)++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM policies: %w", err)
	}
	return nil
}

func (c *AWSPolicyEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
