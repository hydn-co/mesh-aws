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

// IAMRoleEntityCollector lists IAM roles and emits Role entities.
type IAMRoleEntityCollector struct {
	*connector.TypedFeatureContext[*options.RolesOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIAMRoleEntityCollector constructs the collector with the given feature context.
func NewIAMRoleEntityCollector(
	ctx *connector.TypedFeatureContext[*options.RolesOptions, *connector.NoPayload],
) runner.Feature {
	return &IAMRoleEntityCollector{TypedFeatureContext: ctx}
}

func (c *IAMRoleEntityCollector) Init(ctx context.Context) error {
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
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized IAM role collector")
	return nil
}

func (c *IAMRoleEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped IAM role collector")
	return nil
}

func (c *IAMRoleEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting IAM role collection")

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		roles, truncated, nextMarker, err := c.client.ListRoles(ctx, "", marker)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list IAM roles",
				"error",
				err,
			)
			return fmt.Errorf("list IAM roles: %w", err)
		}

		for _, r := range roles {
			role := entities.NewRole()
			role.RoleRef = r.RoleID
			role.Name = r.RoleName
			role.Description = r.Description

			if err := c.Emit(ctx, role); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit IAM role",
					"role_ref",
					role.RoleRef,
					"error",
					err,
				)
				return fmt.Errorf("emit role: %w", err)
			}
			count++
		}

		if !truncated {
			break
		}
		marker = nextMarker
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "finished IAM role collection", "count", count)
	return nil
}
