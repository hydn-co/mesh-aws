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

// IAMPolicyEntityCollector lists customer-managed IAM policies and emits Policy entities.
type IAMPolicyEntityCollector struct {
	*connector.TypedFeatureContext[*options.PoliciesOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIAMPolicyEntityCollector constructs the collector with the given feature context.
func NewIAMPolicyEntityCollector(
	ctx *connector.TypedFeatureContext[*options.PoliciesOptions, *connector.NoPayload],
) runner.Feature {
	return &IAMPolicyEntityCollector{TypedFeatureContext: ctx}
}

func (c *IAMPolicyEntityCollector) Init(ctx context.Context) error {
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
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized IAM policy collector")
	return nil
}

func (c *IAMPolicyEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped IAM policy collector")
	return nil
}

func (c *IAMPolicyEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting IAM policy collection")

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		policies, truncated, nextMarker, err := c.client.ListPolicies(ctx, "Local", marker)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list IAM policies",
				"error",
				err,
			)
			return fmt.Errorf("list IAM policies: %w", err)
		}

		for _, p := range policies {
			policy := entities.NewPolicy()
			policy.PolicyRef = p.PolicyID
			policy.Name = p.PolicyName
			policy.Description = p.Description
			policy.PolicyType = types.PolicyTypeAuthorization
			policy.State = "enabled"

			if err := c.Emit(ctx, policy); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit IAM policy",
					"policy_ref",
					policy.PolicyRef,
					"error",
					err,
				)
				return fmt.Errorf("emit policy: %w", err)
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
		"finished IAM policy collection",
		"count",
		count,
	)
	return nil
}
