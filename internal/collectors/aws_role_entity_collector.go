package collectors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AWSRoleEntityCollector collects AWS IAM role entities.
type AWSRoleEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSRoleEntityCollector constructs the collector with the given feature context.
func NewAWSRoleEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSRoleEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSRoleEntityCollector{TypedFeatureContext: ctx}
}

func (c *AWSRoleEntityCollector) Init(ctx context.Context) error {
	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	creds, err := credentials.Parse(c.GetCredentials())
	opts := c.GetOptions()
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
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

	rolesEmitted := 0
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
		rolesEmitted++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM roles: %w", err)
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS role entity collector",
		"roles_emitted",
		rolesEmitted,
	)
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
