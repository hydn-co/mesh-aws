package actions

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
)

// AWSCreateGroupAction creates an IAM group.
type AWSCreateGroupAction struct {
	*connector.TypedFeatureContext[*options.AWSCreateGroupActionOptions, *payloads.AWSCreateGroupPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSCreateGroupAction constructs the action with the given feature context.
func NewAWSCreateGroupAction(
	ctx *connector.TypedFeatureContext[*options.AWSCreateGroupActionOptions, *payloads.AWSCreateGroupPayload],
) runner.Feature {
	return &AWSCreateGroupAction{TypedFeatureContext: ctx}
}

func (a *AWSCreateGroupAction) Init(ctx context.Context) error {
	if err := connectorutil.Validate(a.GetOptions(), "feature options"); err != nil {
		return err
	}
	if err := connectorutil.Validate(a.GetPayload(), "create group payload"); err != nil {
		return err
	}

	opts := a.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecretFrom(
		a.GetCredentials(),
		connectorutil.DefaultCredentialName,
	)
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	client, err := api.NewClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	a.client = client
	a.state.MarkReady()
	return nil
}

func (a *AWSCreateGroupAction) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.state.RequireReady(); err != nil {
		return err
	}

	payload := a.GetPayload()
	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Starting AWS create group action",
		"group_name", payload.GroupName,
		"path", payload.Path,
	)

	if err := a.client.CreateGroup(ctx, payload.GroupName, payload.Path); err != nil {
		connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelError, "failed to create group",
			"group_name", payload.GroupName,
			"error", err,
		)
		return fmt.Errorf("create group %q: %w", payload.GroupName, err)
	}

	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Completed AWS create group action",
		"group_name", payload.GroupName,
	)
	return nil
}

func (a *AWSCreateGroupAction) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	a.state.Reset()
	a.client = nil
	return nil
}
