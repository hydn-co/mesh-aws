package entity

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/entitlements"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

type awsRoleEntityClient interface {
	IAMRoleEnumerator(ctx context.Context) enumerators.Enumerator[api.IAMRole]
	IAMAttachedRolePolicyEnumerator(ctx context.Context, roleName string) enumerators.Enumerator[api.IAMAttachedPolicy]
	IAMInlineRolePolicyEnumerator(ctx context.Context, roleName string) enumerators.Enumerator[string]
}

type awsRoleEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (awsRoleEntityClient, error)

// AWSRoleEntityCollector collects AWS IAM role entities.
type AWSRoleEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload]
	client       awsRoleEntityClient
	newClient    awsRoleEntityClientFactory
	resolver     *scope.Resolver
	resolverOpts []scope.Option // extra Resolver options; tests inject a fake OrgClient factory
	state        connectorutil.FeatureState
}

// NewAWSRoleEntityCollector constructs the collector with the given feature context.
func NewAWSRoleEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSRoleEntityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultAWSRoleEntityClientFactory,
	}
}

func defaultAWSRoleEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (awsRoleEntityClient, error) {
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

	if c.newClient == nil {
		c.newClient = defaultAWSRoleEntityClientFactory
	}
	resolverOpts := append([]scope.Option{
		scope.WithLogger(func(level slog.Level, msg string, args ...any) {
			connectorutil.LogFeature(context.Background(), c.TypedFeatureContext, level, msg, args...)
		}),
	}, c.resolverOpts...)
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
	counts := rolePermissionCounts{}
	// seenResources dedups derived Resource entities across the whole run: a
	// resource (e.g. "s3") is typically inferred from many permissions, but the
	// catalog only needs it emitted once. IAM is global per account, so a single
	// target per account (the resolver passes nil/global region) is collected.
	seenResources := map[string]struct{}{}

	if err := scope.ForEachTarget(ctx, c.resolver, false, c.newClient,
		func(ctx context.Context, client awsRoleEntityClient, _ scope.Target) error {
			c.client = client
			return c.collectRoles(ctx, collectInline, seenResources, &counts)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS role entity collector",
		"roles_emitted",
		counts.roles,
		"permissions_emitted",
		counts.permissions,
		"role_permissions_emitted",
		counts.rolePermissions,
	)
	return nil
}

// collectRoles enumerates IAM roles for the current target account and emits role
// and permission entities. It is invoked once per resolved target.
func (c *AWSRoleEntityCollector) collectRoles(
	ctx context.Context,
	collectInline bool,
	seenResources map[string]struct{},
	counts *rolePermissionCounts,
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
		counts.roles++

		return c.emitRolePermissions(ctx, role, collectInline, seenResources, counts)
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

// emitRolePermissions emits Permission and RolePermission entities for the policies that grant
// the role its access: attached managed policies always, plus inline policies when enabled. A
// role deleted mid-enumeration (NoSuchEntity) is skipped rather than failing the whole run.
func (c *AWSRoleEntityCollector) emitRolePermissions(
	ctx context.Context,
	role api.IAMRole,
	collectInline bool,
	seenResources map[string]struct{},
	counts *rolePermissionCounts,
) error {
	seen := map[string]struct{}{}

	attachedEnum := c.client.IAMAttachedRolePolicyEnumerator(ctx, role.RoleName)
	if err := enumerators.ForEach(attachedEnum, func(policy api.IAMAttachedPolicy) error {
		return c.emitPermissionLink(ctx, role.RoleID, policy.PolicyArn, policy.PolicyName, seen, seenResources, counts)
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
		ref := role.Arn + ":inline/" + name
		return c.emitPermissionLink(ctx, role.RoleID, ref, name, seen, seenResources, counts)
	}); err != nil {
		if api.IsNoSuchEntity(err) {
			return nil
		}
		return fmt.Errorf("enumerate inline policies for role %s: %w", role.RoleID, err)
	}

	return nil
}

// emitPermissionLink emits a Permission and a RolePermission for one role/policy pair, skipping
// permission references already emitted for this role.
func (c *AWSRoleEntityCollector) emitPermissionLink(
	ctx context.Context,
	roleRef, permissionRef, name string,
	seen map[string]struct{},
	seenResources map[string]struct{},
	counts *rolePermissionCounts,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if permissionRef == "" {
		return nil
	}
	if _, exists := seen[permissionRef]; exists {
		return nil
	}
	seen[permissionRef] = struct{}{}

	permission := entities.NewPermission()
	permission.PermissionRef = permissionRef
	permission.Name = name
	if err := c.Emit(ctx, permission); err != nil {
		return fmt.Errorf("emit permission %s: %w", permissionRef, err)
	}
	counts.permissions++

	if err := c.emitDerivedResources(ctx, permission, seenResources); err != nil {
		return err
	}

	rolePermission := entities.NewRolePermission()
	rolePermission.RoleRef = roleRef
	rolePermission.PermissionRef = permissionRef
	if err := c.Emit(ctx, rolePermission); err != nil {
		return fmt.Errorf("emit role permission %s/%s: %w", roleRef, permissionRef, err)
	}
	counts.rolePermissions++

	return nil
}

// emitDerivedResources derives the Resource a permission acts on plus one
// ResourcePermission edge per CRUDE verb it grants, emitting each. The Resource
// is de-duplicated by resource_ref across the whole run via seenResources; the
// edges are not, since their compound reference is already unique per permission.
func (c *AWSRoleEntityCollector) emitDerivedResources(
	ctx context.Context,
	permission *entities.Permission,
	seenResources map[string]struct{},
) error {
	resource, resourcePerms := entitlements.Derive(permission)
	if resource != nil {
		if _, ok := seenResources[resource.ResourceRef]; !ok {
			seenResources[resource.ResourceRef] = struct{}{}
			if err := c.Emit(ctx, resource); err != nil {
				return fmt.Errorf("emit resource %s: %w", resource.ResourceRef, err)
			}
		}
	}
	for _, rp := range resourcePerms {
		if err := c.Emit(ctx, rp); err != nil {
			return fmt.Errorf(
				"emit resource permission %s/%s/%s: %w",
				rp.PermissionRef, rp.ResourceRef, rp.PermissionType, err,
			)
		}
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
