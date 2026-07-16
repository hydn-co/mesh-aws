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
	"github.com/hydn-co/mesh-aws/internal/mappings"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

// AWSRoleEntityClient is the provider API surface this collector consumes. It is
// exported (with the NewClient seam) so the parent-package contract tests
// can inject a fake client.
type AWSRoleEntityClient interface {
	IAMRoleEnumerator(ctx context.Context) enumerators.Enumerator[api.IAMRole]
	IAMAttachedRolePolicyEnumerator(ctx context.Context, roleName string) enumerators.Enumerator[api.IAMAttachedPolicy]
	IAMInlineRolePolicyEnumerator(ctx context.Context, roleName string) enumerators.Enumerator[string]
	IAMManagedPolicyActions(ctx context.Context, policyArn string) ([]string, error)
	IAMInlineRolePolicyActions(ctx context.Context, roleName, policyName string) ([]string, error)
}

// AWSRoleEntityClientFactory constructs the collector's provider client.
type AWSRoleEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (AWSRoleEntityClient, error)

// AWSRoleEntityCollector collects AWS IAM role entities.
type AWSRoleEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload]
	client AWSRoleEntityClient
	// NewClient builds the provider client during Init; contract tests
	// inject fakes through this seam.
	NewClient    AWSRoleEntityClientFactory
	resolver     *scope.Resolver
	ResolverOpts []scope.Option // extra Resolver options; tests inject a fake OrgClient factory
	state        connectorutil.FeatureState
}

// NewAWSRoleEntityCollector constructs the collector with the given feature context.
func NewAWSRoleEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSRoleEntityCollector{
		TypedFeatureContext: ctx,
		NewClient:           defaultAWSRoleEntityClientFactory,
	}
}

func defaultAWSRoleEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (AWSRoleEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSRoleEntityCollector) Init(ctx context.Context) error {
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
		c.NewClient = defaultAWSRoleEntityClientFactory
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

func (c *AWSRoleEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS role entity collector")

	collectInline := c.GetOptions().GetCollectInlinePolicies()
	// The dedupe sets and the managed-policy action cache span the whole run: a
	// permission (IAM action) is granted by many roles but the catalog only needs
	// it emitted once, and AWS-managed policy ARNs repeat across roles and
	// accounts so their documents are only resolved once. IAM is global per
	// account, so a single target per account (the resolver passes nil/global
	// region) is collected.
	state := &roleCollectionState{
		seenPermissions:      map[string]struct{}{},
		seenRolePermissions:  map[string]struct{}{},
		managedPolicyActions: map[string][]string{},
	}

	if err := scope.ForEachTarget(ctx, c.resolver, false, c.NewClient,
		func(ctx context.Context, client AWSRoleEntityClient, _ scope.Target) error {
			c.client = client
			return c.collectRoles(ctx, collectInline, state)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS role entity collector",
		"roles_emitted",
		state.counts.roles,
		"permissions_emitted",
		state.counts.permissions,
		"role_permissions_emitted",
		state.counts.rolePermissions,
	)
	return nil
}

// collectRoles enumerates IAM roles for the current target account and emits role
// and permission entities. It is invoked once per resolved target.
func (c *AWSRoleEntityCollector) collectRoles(
	ctx context.Context,
	collectInline bool,
	state *roleCollectionState,
) error {
	roleEnum := c.client.IAMRoleEnumerator(ctx)
	if err := enumerators.ForEach(roleEnum, func(role api.IAMRole) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewRole()
		entity.RoleRef = role.RoleID
		entity.Name = role.RoleName
		entity.Description = role.Description

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit IAM role %s: %w", role.RoleID, err)
		}
		state.counts.roles++

		return c.emitRolePermissions(ctx, role, collectInline, state)
	}); err != nil {
		return fmt.Errorf("enumerate IAM roles: %w", err)
	}
	return nil
}

type rolePermissionCounts struct {
	roles           int
	permissions     int
	rolePermissions int
}

// roleCollectionState carries the run-wide dedupe sets, the managed-policy
// document cache, and the emission counters across targets.
type roleCollectionState struct {
	seenPermissions      map[string]struct{}
	seenRolePermissions  map[string]struct{}
	managedPolicyActions map[string][]string
	counts               rolePermissionCounts
}

// emitRolePermissions emits Permission and RolePermission entities for each IAM
// action granted by the policies attached to the role: attached managed policies
// always, plus inline policies when enabled. A role deleted mid-enumeration
// (NoSuchEntity) is skipped rather than failing the whole run, and a single
// policy whose document cannot be fetched is logged and skipped so the role and
// its other policies still land.
func (c *AWSRoleEntityCollector) emitRolePermissions(
	ctx context.Context,
	role api.IAMRole,
	collectInline bool,
	state *roleCollectionState,
) error {
	attachedEnum := c.client.IAMAttachedRolePolicyEnumerator(ctx, role.RoleName)
	if err := enumerators.ForEach(attachedEnum, func(policy api.IAMAttachedPolicy) error {
		actions, err := c.managedPolicyActions(ctx, policy.PolicyArn, state)
		if err != nil {
			connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelWarn,
				"skipping managed policy: could not resolve actions",
				"role", role.RoleName, "policy_arn", policy.PolicyArn, "error", err.Error())
			return nil
		}
		return c.emitRoleActions(ctx, role.RoleID, actions, state)
	}); err != nil {
		if api.IsNoSuchEntity(err) {
			return nil
		}
		return fmt.Errorf("enumerate attached policies for role %s: %w", role.RoleID, err)
	}

	if !collectInline {
		return nil
	}

	inlineEnum := c.client.IAMInlineRolePolicyEnumerator(ctx, role.RoleName)
	if err := enumerators.ForEach(inlineEnum, func(name string) error {
		actions, err := c.client.IAMInlineRolePolicyActions(ctx, role.RoleName, name)
		if err != nil {
			connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelWarn,
				"skipping inline policy: could not resolve actions",
				"role", role.RoleName, "policy_name", name, "error", err.Error())
			return nil
		}
		return c.emitRoleActions(ctx, role.RoleID, actions, state)
	}); err != nil {
		if api.IsNoSuchEntity(err) {
			return nil
		}
		return fmt.Errorf("enumerate inline policies for role %s: %w", role.RoleID, err)
	}

	return nil
}

// managedPolicyActions resolves a managed policy ARN to its allowed actions via
// the run-wide cache, fetching the policy's default version document on a miss.
func (c *AWSRoleEntityCollector) managedPolicyActions(
	ctx context.Context,
	policyArn string,
	state *roleCollectionState,
) ([]string, error) {
	if actions, ok := state.managedPolicyActions[policyArn]; ok {
		return actions, nil
	}

	actions, err := c.client.IAMManagedPolicyActions(ctx, policyArn)
	if err != nil {
		return nil, err
	}
	state.managedPolicyActions[policyArn] = actions
	return actions, nil
}

// emitRoleActions emits one Permission per IAM action (deduped run-wide,
// classified to a CRUDE verb) and one RolePermission edge per role/action pair
// (deduped by role|action).
func (c *AWSRoleEntityCollector) emitRoleActions(
	ctx context.Context,
	roleRef string,
	actions []string,
	state *roleCollectionState,
) error {
	for _, action := range actions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if action == "" {
			continue
		}

		if _, exists := state.seenPermissions[action]; !exists {
			state.seenPermissions[action] = struct{}{}
			permission := entities.NewPermission()
			permission.PermissionRef = action
			permission.Name = action
			permission.PermissionType = mappings.MapAWSActionPermissionType(action)
			if err := c.Emit(ctx, permission); err != nil {
				return fmt.Errorf("emit permission %s: %w", action, err)
			}
			state.counts.permissions++
		}

		edgeKey := roleRef + "|" + action
		if _, exists := state.seenRolePermissions[edgeKey]; exists {
			continue
		}
		state.seenRolePermissions[edgeKey] = struct{}{}

		rolePermission := entities.NewRolePermission()
		rolePermission.RoleRef = roleRef
		rolePermission.PermissionRef = action
		if err := c.Emit(ctx, rolePermission); err != nil {
			return fmt.Errorf("emit role permission %s/%s: %w", roleRef, action, err)
		}
		state.counts.rolePermissions++
	}
	return nil
}

func (c *AWSRoleEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
