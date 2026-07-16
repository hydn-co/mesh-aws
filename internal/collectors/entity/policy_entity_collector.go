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

// AWSPolicyEntityClient is the provider API surface this collector consumes. It is
// exported (with the NewClient seam) so the parent-package contract tests
// can inject a fake client.
type AWSPolicyEntityClient interface {
	IAMPolicyEnumerator(ctx context.Context, scope string) enumerators.Enumerator[api.IAMPolicy]
}

// AWSPolicyEntityClientFactory constructs the collector's provider client.
type AWSPolicyEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (AWSPolicyEntityClient, error)

// AWSPolicyEntityCollector collects AWS IAM managed policy entities.
type AWSPolicyEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload]
	client AWSPolicyEntityClient
	// NewClient builds the provider client during Init; contract tests
	// inject fakes through this seam.
	NewClient    AWSPolicyEntityClientFactory
	resolver     *scope.Resolver
	ResolverOpts []scope.Option // extra Resolver options; tests inject a fake OrgClient factory
	state        connectorutil.FeatureState
}

// NewAWSPolicyEntityCollector constructs the collector with the given feature context.
func NewAWSPolicyEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSPolicyEntityCollector{
		TypedFeatureContext: ctx,
		NewClient:           defaultAWSPolicyEntityClientFactory,
	}
}

func defaultAWSPolicyEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (AWSPolicyEntityClient, error) {
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

	if c.NewClient == nil {
		c.NewClient = defaultAWSPolicyEntityClientFactory
	}
	resolverOpts := append([]scope.Option{
		scope.WithLogger(func(level slog.Level, msg string, args ...any) {
			connectorutil.LogFeature(context.Background(), c.TypedFeatureContext, level, msg, args...)
		}),
	}, c.ResolverOpts...)
	c.resolver = scope.NewResolver(
		&opts.AWSScopeOptionsCore,
		opts.GetRegion(),
		opts.GetSessionToken(),
		creds,
		resolverOpts...,
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
	if err := scope.ForEachTarget(ctx, c.resolver, false, c.NewClient,
		func(ctx context.Context, client AWSPolicyEntityClient, _ scope.Target) error {
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
