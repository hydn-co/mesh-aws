package collectors

import (
	"context"
	"fmt"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IAMRoleEntityCollector lists IAM roles and emits Role entities.
type IAMRoleEntityCollector struct {
	ctx *connector.TypedFeatureContext[*options.RolesOptions, *payloads.ActivityResumePayload]
}

// NewIAMRoleEntityCollector constructs the collector with the given feature context.
func NewIAMRoleEntityCollector(ctx *connector.TypedFeatureContext[*options.RolesOptions, *payloads.ActivityResumePayload]) runner.Feature {
	return &IAMRoleEntityCollector{ctx: ctx}
}

func (c *IAMRoleEntityCollector) Init(_ context.Context) error { return nil }
func (c *IAMRoleEntityCollector) Stop(_ context.Context) error { return nil }

func (c *IAMRoleEntityCollector) Start(ctx context.Context) error {
	const name = "iam-role-entity-collector"
	logCollectStart(name)

	creds, err := credentials.Parse(c.ctx.GetCredentials())
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.New(creds)
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("create AWS client: %w", err)
	}

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		roles, truncated, nextMarker, err := client.ListRoles(ctx, "", marker)
		if err != nil {
			logCollectError(name, err)
			return fmt.Errorf("list IAM roles: %w", err)
		}

		for _, r := range roles {
			role := entities.NewRole()
			role.RoleRef = r.RoleName
			role.Name = r.RoleName
			role.Description = r.Description

			if err := c.ctx.Emit(ctx, role); err != nil {
				logCollectError(name, err)
				return fmt.Errorf("emit role: %w", err)
			}
			count++
		}

		if !truncated {
			break
		}
		marker = nextMarker
	}

	logCollectDone(name, count)
	return nil
}
