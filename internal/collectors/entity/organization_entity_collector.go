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

// Organizational-unit types emitted for the AWS Organizations hierarchy.
const (
	ouTypeRoot    = "root"
	ouTypeOU      = "organizational_unit"
	ouTypeAccount = "account"
)

type awsOrganizationEntityClient interface {
	OrganizationRootEnumerator(ctx context.Context) enumerators.Enumerator[api.OrganizationalUnit]
	OrganizationalUnitsForParentEnumerator(
		ctx context.Context,
		parentID string,
	) enumerators.Enumerator[api.OrganizationalUnit]
	OrganizationAccountsForParentEnumerator(ctx context.Context, parentID string) enumerators.Enumerator[api.Account]
}

type awsOrganizationEntityClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (awsOrganizationEntityClient, error)

// AWSOrganizationEntityCollector emits the AWS Organizations hierarchy (roots,
// organizational units, and member accounts) as an organizational-unit tree. It
// reads the organization from the management/delegated account; it does not
// assume member-account roles.
type AWSOrganizationEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSOrganizationEntityCollectorOptions, *connector.NoPayload]
	client    awsOrganizationEntityClient
	newClient awsOrganizationEntityClientFactory
	state     connectorutil.FeatureState
}

// NewAWSOrganizationEntityCollector constructs the collector with the given feature context.
func NewAWSOrganizationEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSOrganizationEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSOrganizationEntityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultAWSOrganizationEntityClientFactory,
	}
}

func defaultAWSOrganizationEntityClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (awsOrganizationEntityClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

func (c *AWSOrganizationEntityCollector) Init(ctx context.Context) error {
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
		c.newClient = defaultAWSOrganizationEntityClientFactory
	}
	client, err := c.newClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSOrganizationEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS organization entity collector")

	// emitted dedups OU refs so a shared ancestor is never emitted twice.
	emitted := map[string]bool{}
	counts := struct{ ous, accounts int }{}

	rootEnum := c.client.OrganizationRootEnumerator(ctx)
	if err := enumerators.ForEach(rootEnum, func(root api.OrganizationalUnit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.emitOU(ctx, root.ID, root.Name, "", ouTypeRoot, emitted, &counts.ous); err != nil {
			return err
		}
		return c.walkTree(ctx, root.ID, emitted, &counts.ous, &counts.accounts)
	}); err != nil {
		return fmt.Errorf("enumerate organization roots: %w", err)
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS organization entity collector",
		"organizational_units_emitted", counts.ous,
		"accounts_emitted", counts.accounts,
	)
	return nil
}

// walkTree recursively emits the OUs and member accounts under parentID, linking
// each to its parent so the hierarchy is never dangling.
func (c *AWSOrganizationEntityCollector) walkTree(
	ctx context.Context,
	parentID string,
	emitted map[string]bool,
	ousEmitted, accountsEmitted *int,
) error {
	accountEnum := c.client.OrganizationAccountsForParentEnumerator(ctx, parentID)
	if err := enumerators.ForEach(accountEnum, func(account api.Account) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return c.emitOU(ctx, account.ID, account.Name, parentID, ouTypeAccount, emitted, accountsEmitted)
	}); err != nil {
		return fmt.Errorf("enumerate accounts for parent %s: %w", parentID, err)
	}

	ouEnum := c.client.OrganizationalUnitsForParentEnumerator(ctx, parentID)
	if err := enumerators.ForEach(ouEnum, func(ou api.OrganizationalUnit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.emitOU(ctx, ou.ID, ou.Name, parentID, ouTypeOU, emitted, ousEmitted); err != nil {
			return err
		}
		return c.walkTree(ctx, ou.ID, emitted, ousEmitted, accountsEmitted)
	}); err != nil {
		return fmt.Errorf("enumerate organizational units for parent %s: %w", parentID, err)
	}

	return nil
}

func (c *AWSOrganizationEntityCollector) emitOU(
	ctx context.Context,
	ref, name, parentRef, ouType string,
	emitted map[string]bool,
	counter *int,
) error {
	if ref == "" || emitted[ref] {
		return nil
	}

	ou := entities.NewOrganizationalUnit()
	ou.OURef = ref
	ou.Name = name
	ou.ParentOURef = parentRef
	ou.Type = ouType

	if err := c.Emit(ctx, ou); err != nil {
		return fmt.Errorf("emit organizational unit %s: %w", ref, err)
	}
	emitted[ref] = true
	(*counter)++
	return nil
}

func (c *AWSOrganizationEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
