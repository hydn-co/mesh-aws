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

// AWSCreateUserAction creates an IAM user.
type AWSCreateUserAction struct {
	*connector.TypedFeatureContext[*options.AWSCreateUserActionOptions, *payloads.AWSCreateUserPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSCreateUserAction constructs the action with the given feature context.
func NewAWSCreateUserAction(
	ctx *connector.TypedFeatureContext[*options.AWSCreateUserActionOptions, *payloads.AWSCreateUserPayload],
) runner.Feature {
	return &AWSCreateUserAction{TypedFeatureContext: ctx}
}

func (a *AWSCreateUserAction) Init(ctx context.Context) error {
	if err := connectorutil.Validate(a.GetOptions(), "feature options"); err != nil {
		return err
	}
	if err := connectorutil.Validate(a.GetPayload(), "create user payload"); err != nil {
		return err
	}

	opts := a.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecret(a.GetCredentials())
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

func (a *AWSCreateUserAction) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.state.RequireReady(); err != nil {
		return err
	}

	payload := a.GetPayload()
	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Starting AWS create user action",
		"user_name", payload.UserName,
		"path", payload.Path,
	)

	if err := a.client.CreateUser(ctx, payload.UserName, payload.Path); err != nil {
		connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelError, "failed to create user",
			"user_name", payload.UserName,
			"error", err,
		)
		return fmt.Errorf("create user %q: %w", payload.UserName, err)
	}

	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Completed AWS create user action",
		"user_name", payload.UserName,
	)
	return nil
}

func (a *AWSCreateUserAction) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	a.state.Reset()
	a.client = nil
	return nil
}
