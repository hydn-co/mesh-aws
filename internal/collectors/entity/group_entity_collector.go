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

// AWSGroupEntityClient is the provider API surface this collector consumes. It is
// exported (with the NewClient seam) so the parent-package contract tests
// can inject a fake client.
type AWSGroupEntityClient interface {
	IAMGroupEnumerator(ctx context.Context) enumerators.Enumerator[api.IAMGroup]
	IdentityStoreGroupEnumerator(
		ctx context.Context,
		identityStoreID string,
	) enumerators.Enumerator[api.IdentityStoreGroup]
}

// AWSGroupEntityClientFactory constructs the collector's provider client.
type AWSGroupEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (AWSGroupEntityClient, error)

// AWSGroupEntityCollector collects AWS group entities from IAM and Identity Store.
type AWSGroupEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSGroupEntityCollectorOptions, *connector.NoPayload]
	client AWSGroupEntityClient
	// NewClient builds the provider client during Init; contract tests
	// inject fakes through this seam.
	NewClient    AWSGroupEntityClientFactory
	resolver     *scope.Resolver
	mgmtCreds    *api.AWSCredentials
	ResolverOpts []scope.Option // extra Resolver options; tests inject a fake OrgClient factory
	state        connectorutil.FeatureState
}

// NewAWSGroupEntityCollector constructs the collector with the given feature context.
func NewAWSGroupEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSGroupEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSGroupEntityCollector{
		TypedFeatureContext: ctx,
		NewClient:           defaultAWSGroupEntityClientFactory,
	}
}

func defaultAWSGroupEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (AWSGroupEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSGroupEntityCollector) Init(ctx context.Context) error {
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

	if c.NewClient == nil {
		c.NewClient = defaultAWSGroupEntityClientFactory
	}
	c.mgmtCreds = creds
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

func (c *AWSGroupEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	opts := c.GetOptions()
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS group entity collector")

	groupsEmitted := 0

	// IAM groups are collected per account so a single collector fans out across
	// every member account in organization mode.
	if err := scope.ForEachTarget(ctx, c.resolver, false, c.NewClient,
		func(ctx context.Context, client AWSGroupEntityClient, _ scope.Target) error {
			c.client = client
			return c.emitIAMGroups(ctx, &groupsEmitted)
		}); err != nil {
		return err
	}

	// Identity Center groups live in the management/delegated account, so they are
	// collected once using management credentials rather than per member account.
	if identityStoreID := opts.GetIdentityStoreID(); identityStoreID != "" {
		mgmtClient, err := c.NewClient(c.mgmtCreds, opts.GetRegion(), opts.GetSessionToken())
		if err != nil {
			return fmt.Errorf("create AWS client: %w", err)
		}
		c.client = mgmtClient
		if err := c.emitIdentityStoreGroups(ctx, identityStoreID, &groupsEmitted); err != nil {
			return err
		}
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS group entity collector",
		"groups_emitted", groupsEmitted,
	)
	return nil
}

func (c *AWSGroupEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func (c *AWSGroupEntityCollector) emitIAMGroups(ctx context.Context, groupsEmitted *int) error {
	groupEnum := c.client.IAMGroupEnumerator(ctx)
	if err := enumerators.ForEach(groupEnum, func(group api.IAMGroup) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewGroup()
		entity.GroupRef = group.GroupID
		entity.Name = group.GroupName
		entity.Description = group.Arn
		if !group.CreateDate.IsZero() {
			entity.CreatedAt = &group.CreateDate
		}

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit IAM group %s: %w", group.GroupID, err)
		}
		(*groupsEmitted)++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM groups: %w", err)
	}

	return nil
}

func (c *AWSGroupEntityCollector) emitIdentityStoreGroups(
	ctx context.Context,
	identityStoreID string,
	groupsEmitted *int,
) error {
	groupEnum := c.client.IdentityStoreGroupEnumerator(ctx, identityStoreID)
	if err := enumerators.ForEach(groupEnum, func(group api.IdentityStoreGroup) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewGroup()
		entity.GroupRef = group.GroupID
		entity.Name = group.DisplayName
		entity.Description = group.Description
		if !group.CreatedAt.IsZero() {
			entity.CreatedAt = &group.CreatedAt
		}

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit Identity Store group %s: %w", group.GroupID, err)
		}
		(*groupsEmitted)++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate Identity Store groups: %w", err)
	}

	return nil
}
