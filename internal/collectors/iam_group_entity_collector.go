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

// IAMGroupEntityCollector lists IAM groups and emits Group entities.
type IAMGroupEntityCollector struct {
	ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.ActivityResumePayload]
}

// NewIAMGroupEntityCollector constructs the collector with the given feature context.
func NewIAMGroupEntityCollector(ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.ActivityResumePayload]) runner.Feature {
	return &IAMGroupEntityCollector{ctx: ctx}
}

func (c *IAMGroupEntityCollector) Init(_ context.Context) error { return nil }
func (c *IAMGroupEntityCollector) Stop(_ context.Context) error { return nil }

func (c *IAMGroupEntityCollector) Start(ctx context.Context) error {
	const name = "iam-group-entity-collector"
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

		groups, truncated, nextMarker, err := client.ListGroups(ctx, "", marker)
		if err != nil {
			logCollectError(name, err)
			return fmt.Errorf("list IAM groups: %w", err)
		}

		for _, g := range groups {
			group := entities.NewGroup()
			group.GroupRef = g.GroupName
			group.Name = g.GroupName
			group.CreatedAt = g.CreateDate

			if err := c.ctx.Emit(ctx, group); err != nil {
				logCollectError(name, err)
				return fmt.Errorf("emit group: %w", err)
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
