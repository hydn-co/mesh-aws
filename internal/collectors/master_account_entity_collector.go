package collectors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/helpers"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// MasterAccountEntityCollector loads the AWS Organizations management account.
type MasterAccountEntityCollector struct {
	*connector.TypedFeatureContext[*options.MasterAccountOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewMasterAccountEntityCollector constructs the collector with the given feature context.
func NewMasterAccountEntityCollector(
	ctx *connector.TypedFeatureContext[*options.MasterAccountOptions, *connector.NoPayload],
) runner.Feature {
	return &MasterAccountEntityCollector{TypedFeatureContext: ctx}
}

func (c *MasterAccountEntityCollector) Init(ctx context.Context) error {
	creds, err := credentials.Parse(c.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds)
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.initialized = true
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized master account collector")
	return nil
}

func (c *MasterAccountEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting master account collection")

	organization, err := c.client.DescribeOrganization(ctx)
	if err != nil {
		logCollector(ctx, c.TypedFeatureContext, slog.LevelError, "failed to describe AWS organization", "error", err)
		return fmt.Errorf("describe organization: %w", err)
	}

	account := entities.NewAccount()
	account.AccountRef = organization.MasterAccountID
	account.AccountType = types.AccountTypeUser
	account.Name = firstNonEmpty(organization.MasterAccountEmail, organization.MasterAccountID)
	account.DisplayName = organization.MasterAccountEmail
	account.Description = organization.MasterAccountArn
	account.Enabled = true
	if organization.MasterAccountEmail != "" {
		account.PrimaryEmail = &types.Email{Address: organization.MasterAccountEmail}
	}

	if err := c.Emit(ctx, account); err != nil {
		logCollector(
			ctx,
			c.TypedFeatureContext,
			slog.LevelError,
			"failed to emit master account",
			"account_ref",
			account.AccountRef,
			"error",
			err,
		)
		return fmt.Errorf("emit master account: %w", err)
	}

	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "finished master account collection", "count", 1)
	return nil
}

func (c *MasterAccountEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped master account collector")
	return nil
}
