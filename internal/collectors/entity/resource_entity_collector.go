package entity

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

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

// AWSResourceEntityClient is the provider API surface this collector consumes. It is
// exported (with the NewClient seam) so the parent-package contract tests
// can inject a fake client.
type AWSResourceEntityClient interface {
	GetCallerIdentity(ctx context.Context) (string, error)
	TaggedResourceEnumerator(ctx context.Context) enumerators.Enumerator[api.TaggedResource]
}

// AWSResourceEntityClientFactory constructs the collector's provider client.
type AWSResourceEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (AWSResourceEntityClient, error)

// AWSResourceOrgClient is the management-account view the collector uses to walk
// the AWS Organizations tree into ResourceContainer entities in organization mode.
type AWSResourceOrgClient interface {
	OrganizationRootEnumerator(ctx context.Context) enumerators.Enumerator[api.OrganizationalUnit]
	OrganizationalUnitsForParentEnumerator(
		ctx context.Context,
		parentID string,
	) enumerators.Enumerator[api.OrganizationalUnit]
	OrganizationAccountsForParentEnumerator(ctx context.Context, parentID string) enumerators.Enumerator[api.Account]
}

// AWSResourceOrgClientFactory constructs the management-account Organizations client.
type AWSResourceOrgClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (AWSResourceOrgClient, error)

// AWSResourceEntityCollector emits the AWS scope hierarchy as ResourceContainers
// (the caller's account in single mode; the Organizations roots, OUs, and member
// accounts in organization mode, nested by ResourceContainerResourceContainer
// edges) and the tagged-resource inventory as Resource entities (classified into
// a normalized ResourceType, linked into their account by ResourceContainerResource
// edges). Inventory comes from the Resource Groups Tagging API, which is regional,
// so in organization mode the collector fans out across every (account, region)
// target; only resources that are or once were tagged are returned.
type AWSResourceEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSResourceEntityCollectorOptions, *connector.NoPayload]
	client AWSResourceEntityClient
	// NewClient builds the provider client during Init; contract tests
	// inject fakes through this seam.
	NewClient AWSResourceEntityClientFactory
	// NewOrgClient builds the management-account Organizations client during
	// Init; contract tests inject fakes through this seam.
	NewOrgClient AWSResourceOrgClientFactory
	resolver     *scope.Resolver
	creds        *api.AWSCredentials
	ResolverOpts []scope.Option // extra Resolver options; tests inject a fake OrgClient factory
	state        connectorutil.FeatureState
}

// NewAWSResourceEntityCollector constructs the collector with the given feature context.
func NewAWSResourceEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSResourceEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSResourceEntityCollector{
		TypedFeatureContext: ctx,
		NewClient:           defaultAWSResourceEntityClientFactory,
		NewOrgClient:        defaultAWSResourceOrgClientFactory,
	}
}

func defaultAWSResourceEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (AWSResourceEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func defaultAWSResourceOrgClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (AWSResourceOrgClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSResourceEntityCollector) Init(ctx context.Context) error {
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
	c.creds = &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	if c.NewClient == nil {
		c.NewClient = defaultAWSResourceEntityClientFactory
	}
	if c.NewOrgClient == nil {
		c.NewOrgClient = defaultAWSResourceOrgClientFactory
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
		c.creds,
		resolverOpts...,
	)
	c.state.MarkReady()
	return nil
}

func (c *AWSResourceEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS resource entity collector")

	counts := resourceEntityCounts{}
	// fallbackAccountID anchors membership edges in single mode, where resolver
	// targets carry no account ID; in organization mode each target names its account.
	fallbackAccountID, err := c.collectContainers(ctx, &counts)
	if err != nil {
		return err
	}

	// seenResources dedups Resource entities (and their membership edge — an ARN
	// belongs to exactly one account) across the whole run: the Tagging API is
	// regional, but some ARNs (e.g. IAM, S3) are global and surface in every region.
	seenResources := map[string]struct{}{}

	// The Tagging API is regional, so the resolver expands organization mode to
	// one target per (account, region).
	if err := scope.ForEachTarget(ctx, c.resolver, true, c.NewClient,
		func(ctx context.Context, client AWSResourceEntityClient, target scope.Target) error {
			c.client = client
			accountID := target.AccountID
			if accountID == "" {
				accountID = fallbackAccountID
			}
			return c.collectResources(ctx, accountID, seenResources, &counts)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS resource entity collector",
		"resource_containers_emitted", counts.containers,
		"container_nestings_emitted", counts.nestings,
		"resources_emitted", counts.resources,
	)
	return nil
}

type resourceEntityCounts struct {
	containers int
	nestings   int
	resources  int
}

// collectContainers emits the scope hierarchy and returns the account ID that
// anchors membership edges in single mode. In single mode that is the caller's
// own account, emitted as the one container; in organization mode the whole
// Organizations tree is walked and every target carries its own account ID, so
// no fallback is returned.
func (c *AWSResourceEntityCollector) collectContainers(
	ctx context.Context,
	counts *resourceEntityCounts,
) (string, error) {
	opts := c.GetOptions()

	if !c.resolver.IsOrganizationMode() {
		client, err := c.NewClient(c.creds, opts.GetRegion(), opts.GetSessionToken())
		if err != nil {
			return "", fmt.Errorf("create AWS client: %w", err)
		}
		accountID, err := client.GetCallerIdentity(ctx)
		if err != nil {
			return "", fmt.Errorf("resolve caller account: %w", err)
		}
		container := entities.NewResourceContainer()
		container.ContainerRef = accountID
		container.Name = accountID
		container.ContainerType = entities.ContainerTypeAccount
		if err := c.Emit(ctx, container); err != nil {
			return "", fmt.Errorf("emit resource container %s: %w", accountID, err)
		}
		counts.containers++
		return accountID, nil
	}

	mgmt, err := c.NewOrgClient(c.creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return "", fmt.Errorf("create management client: %w", err)
	}

	// emitted dedups container refs so a shared ancestor is never emitted twice.
	emitted := map[string]struct{}{}
	rootEnum := mgmt.OrganizationRootEnumerator(ctx)
	if err := enumerators.ForEach(rootEnum, func(root api.OrganizationalUnit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.emitContainer(
			ctx, root.ID, root.Name, "", entities.ContainerTypeManagementGroup, emitted, counts,
		); err != nil {
			return err
		}
		return c.walkContainerTree(ctx, mgmt, root.ID, emitted, counts)
	}); err != nil {
		return "", fmt.Errorf("enumerate organization roots: %w", err)
	}
	return "", nil
}

// walkContainerTree recursively emits the OUs and member accounts under parentID
// as ResourceContainers, nesting each under its parent so the hierarchy is never
// dangling.
func (c *AWSResourceEntityCollector) walkContainerTree(
	ctx context.Context,
	mgmt AWSResourceOrgClient,
	parentID string,
	emitted map[string]struct{},
	counts *resourceEntityCounts,
) error {
	accountEnum := mgmt.OrganizationAccountsForParentEnumerator(ctx, parentID)
	if err := enumerators.ForEach(accountEnum, func(account api.Account) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return c.emitContainer(ctx, account.ID, account.Name, parentID, entities.ContainerTypeAccount, emitted, counts)
	}); err != nil {
		return fmt.Errorf("enumerate accounts for parent %s: %w", parentID, err)
	}

	ouEnum := mgmt.OrganizationalUnitsForParentEnumerator(ctx, parentID)
	if err := enumerators.ForEach(ouEnum, func(ou api.OrganizationalUnit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.emitContainer(
			ctx, ou.ID, ou.Name, parentID, entities.ContainerTypeManagementGroup, emitted, counts,
		); err != nil {
			return err
		}
		return c.walkContainerTree(ctx, mgmt, ou.ID, emitted, counts)
	}); err != nil {
		return fmt.Errorf("enumerate organizational units for parent %s: %w", parentID, err)
	}

	return nil
}

func (c *AWSResourceEntityCollector) emitContainer(
	ctx context.Context,
	ref, name, parentRef, containerType string,
	emitted map[string]struct{},
	counts *resourceEntityCounts,
) error {
	if ref == "" {
		return nil
	}
	if _, exists := emitted[ref]; exists {
		return nil
	}
	emitted[ref] = struct{}{}

	container := entities.NewResourceContainer()
	container.ContainerRef = ref
	container.Name = name
	container.ContainerType = containerType
	if err := c.Emit(ctx, container); err != nil {
		return fmt.Errorf("emit resource container %s: %w", ref, err)
	}
	counts.containers++

	if parentRef == "" {
		return nil
	}
	nesting := entities.NewResourceContainerResourceContainer()
	nesting.ParentContainerRef = parentRef
	nesting.ChildContainerRef = ref
	if err := c.Emit(ctx, nesting); err != nil {
		return fmt.Errorf("emit resource container nesting %s/%s: %w", parentRef, ref, err)
	}
	counts.nestings++
	return nil
}

// collectResources enumerates the tagged-resource inventory for the current
// target and emits a classified Resource plus its account-membership edge per
// ARN. The membership edge is keyed on the target's account ID rather than the
// ARN's account segment, which some services (e.g. S3) leave empty.
func (c *AWSResourceEntityCollector) collectResources(
	ctx context.Context,
	accountID string,
	seenResources map[string]struct{},
	counts *resourceEntityCounts,
) error {
	resourceEnum := c.client.TaggedResourceEnumerator(ctx)
	if err := enumerators.ForEach(resourceEnum, func(tagged api.TaggedResource) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tagged.ARN == "" {
			return nil
		}
		if _, exists := seenResources[tagged.ARN]; exists {
			return nil
		}
		seenResources[tagged.ARN] = struct{}{}

		resource := entities.NewResource()
		resource.ResourceRef = tagged.ARN
		resource.Name = resourceDisplayName(tagged)
		resource.ResourceType = mappings.MapAWSResourceType(tagged.ARN)
		if err := c.Emit(ctx, resource); err != nil {
			return fmt.Errorf("emit resource %s: %w", tagged.ARN, err)
		}
		counts.resources++

		if accountID == "" {
			return nil
		}
		membership := entities.NewResourceContainerResource()
		membership.ContainerRef = accountID
		membership.ResourceRef = tagged.ARN
		if err := c.Emit(ctx, membership); err != nil {
			return fmt.Errorf("emit resource membership %s/%s: %w", accountID, tagged.ARN, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate tagged resources: %w", err)
	}
	return nil
}

// resourceDisplayName prefers the resource's "Name" tag — AWS has no display-name
// field, and the Name tag is the convention for resources whose ARN tail is an
// opaque ID (EC2 instances, volumes, VPCs) — falling back to the ARN's trailing
// name segment.
func resourceDisplayName(tagged api.TaggedResource) string {
	if name := strings.TrimSpace(tagged.Tags["Name"]); name != "" {
		return name
	}
	return arnResourceName(tagged.ARN)
}

// arnResourceName returns the trailing name segment of an ARN's resource part
// ("arn:aws:ec2:us-east-1:111111111111:instance/i-0abc" → "i-0abc"), falling
// back to the full ARN when it does not have the six expected segments.
func arnResourceName(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[5] == "" {
		return arn
	}
	name := parts[5]
	if idx := strings.LastIndexAny(name, "/:"); idx >= 0 && idx+1 < len(name) {
		name = name[idx+1:]
	}
	return name
}

func (c *AWSResourceEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
