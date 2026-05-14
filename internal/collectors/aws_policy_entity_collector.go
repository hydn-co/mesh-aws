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

// AWSPolicyEntityCollector collects AWS IAM managed policy entities.
type AWSPolicyEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSPolicyEntityCollector constructs the collector with the given feature context.
func NewAWSPolicyEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSPolicyEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSPolicyEntityCollector{TypedFeatureContext: ctx}
}

func (c *AWSPolicyEntityCollector) Init(ctx context.Context) error {
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

func (c *AWSPolicyEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS policy entity collector")

	policiesEmitted := 0
	policyEnum := c.client.IAMPolicyEnumerator(ctx, "Local")
	if err := enumerators.ForEach(policyEnum, func(policy api.IAMPolicy) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		entity := entities.NewPolicy()
		entity.PolicyRef = policy.PolicyID
		entity.Name = policy.PolicyName
		entity.Description = policy.Description

		if err := c.Emit(ctx, entity); err != nil {
			return fmt.Errorf("emit IAM policy %s: %w", policy.PolicyID, err)
		}
		policiesEmitted++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM policies: %w", err)
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS policy entity collector",
		"policies_emitted",
		policiesEmitted,
	)
	return nil
}

func (c *AWSPolicyEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}
