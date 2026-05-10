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

// IAMGroupEntityCollector lists IAM groups and emits Group entities.
type IAMGroupEntityCollector struct {
	*connector.TypedFeatureContext[*options.GroupsOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIAMGroupEntityCollector constructs the collector with the given feature context.
func NewIAMGroupEntityCollector(
	ctx *connector.TypedFeatureContext[*options.GroupsOptions, *connector.NoPayload],
) runner.Feature {
	return &IAMGroupEntityCollector{TypedFeatureContext: ctx}
}

func (c *IAMGroupEntityCollector) Init(ctx context.Context) error {
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
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized IAM group collector")
	return nil
}

func (c *IAMGroupEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped IAM group collector")
	return nil
}

func (c *IAMGroupEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting IAM group collection")

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		groups, truncated, nextMarker, err := c.client.ListGroups(ctx, "", marker)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list IAM groups",
				"error",
				err,
			)
			return fmt.Errorf("list IAM groups: %w", err)
		}

		for _, g := range groups {
			group := entities.NewGroup()
			group.GroupRef = g.GroupID
			group.Name = g.GroupName
			group.CreatedAt = &g.CreateDate

			if err := c.Emit(ctx, group); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit IAM group",
					"group_ref",
					group.GroupRef,
					"error",
					err,
				)
				return fmt.Errorf("emit group: %w", err)
			}
			count++
		}

		if !truncated {
			break
		}
		marker = nextMarker
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"finished IAM group collection",
		"count",
		count,
	)
	return nil
}
