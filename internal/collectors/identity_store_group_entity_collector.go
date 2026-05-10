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
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IdentityStoreGroupEntityCollector lists groups from AWS Identity Store.
type IdentityStoreGroupEntityCollector struct {
	*connector.TypedFeatureContext[*options.IdentityStoreGroupsOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIdentityStoreGroupEntityCollector constructs the collector with the given feature context.
func NewIdentityStoreGroupEntityCollector(
	ctx *connector.TypedFeatureContext[*options.IdentityStoreGroupsOptions, *connector.NoPayload],
) runner.Feature {
	return &IdentityStoreGroupEntityCollector{TypedFeatureContext: ctx}
}

func (c *IdentityStoreGroupEntityCollector) Init(ctx context.Context) error {
	options := c.GetOptions()
	if options == nil || options.IdentityStoreID == "" {
		return fmt.Errorf("identity_store_id is required")
	}

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
	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"initialized Identity Store group collector",
		"identity_store_id",
		options.IdentityStoreID,
	)
	return nil
}

func (c *IdentityStoreGroupEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	options := c.GetOptions()
	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"starting Identity Store group collection",
		"identity_store_id",
		options.IdentityStoreID,
	)

	count := 0
	var nextToken string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		groups, token, err := c.client.ListIdentityStoreGroups(ctx, options.IdentityStoreID, nextToken)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list Identity Store groups",
				"error",
				err,
			)
			return fmt.Errorf("list Identity Store groups: %w", err)
		}

		for _, group := range groups {
			entity := entities.NewGroup()
			entity.GroupRef = group.GroupID
			entity.Name = firstNonEmpty(group.DisplayName, group.GroupID)
			entity.Description = group.Description

			if err := c.Emit(ctx, entity); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit Identity Store group",
					"group_ref",
					entity.GroupRef,
					"error",
					err,
				)
				return fmt.Errorf("emit Identity Store group: %w", err)
			}
			count++
		}

		if token == "" {
			break
		}
		nextToken = token
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"finished Identity Store group collection",
		"count",
		count,
	)
	return nil
}

func (c *IdentityStoreGroupEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped Identity Store group collector")
	return nil
}
