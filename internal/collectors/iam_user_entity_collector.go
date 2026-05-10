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
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IAMUserEntityCollector lists IAM users and emits Account entities.
type IAMUserEntityCollector struct {
	*connector.TypedFeatureContext[*options.UsersOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIAMUserEntityCollector constructs the collector with the given feature context.
func NewIAMUserEntityCollector(
	ctx *connector.TypedFeatureContext[*options.UsersOptions, *connector.NoPayload],
) runner.Feature {
	return &IAMUserEntityCollector{TypedFeatureContext: ctx}
}

func (c *IAMUserEntityCollector) Init(ctx context.Context) error {
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
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized IAM user collector")
	return nil
}

func (c *IAMUserEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped IAM user collector")
	return nil
}

func (c *IAMUserEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting IAM user collection")

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		users, truncated, nextMarker, err := c.client.ListUsers(ctx, "", marker)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list IAM users",
				"error",
				err,
			)
			return fmt.Errorf("list IAM users: %w", err)
		}

		for _, u := range users {
			account := entities.NewAccount()
			account.AccountRef = u.UserID
			account.Name = u.UserName
			account.DisplayName = u.UserName
			account.AccountType = types.AccountTypeUser
			account.Enabled = true
			if !u.CreateDate.IsZero() {
				account.CreatedAt = &u.CreateDate
			}

			if err := c.Emit(ctx, account); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit IAM user",
					"account_ref",
					account.AccountRef,
					"error",
					err,
				)
				return fmt.Errorf("emit account: %w", err)
			}
			count++
		}

		if !truncated {
			break
		}
		marker = nextMarker
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "finished IAM user collection", "count", count)
	return nil
}
