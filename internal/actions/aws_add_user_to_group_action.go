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

// AWSAddUserToGroupAction adds an IAM user to an IAM group.
type AWSAddUserToGroupAction struct {
	*connector.TypedFeatureContext[*options.AWSAddUserToGroupActionOptions, *payloads.AWSAddUserToGroupPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSAddUserToGroupAction constructs the action with the given feature context.
func NewAWSAddUserToGroupAction(
	ctx *connector.TypedFeatureContext[*options.AWSAddUserToGroupActionOptions, *payloads.AWSAddUserToGroupPayload],
) runner.Feature {
	return &AWSAddUserToGroupAction{TypedFeatureContext: ctx}
}

func (a *AWSAddUserToGroupAction) Init(ctx context.Context) error {
	if err := connectorutil.Validate(a.GetOptions(), "feature options"); err != nil {
		return err
	}
	if err := connectorutil.Validate(a.GetPayload(), "add user to group payload"); err != nil {
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

func (a *AWSAddUserToGroupAction) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.state.RequireReady(); err != nil {
		return err
	}

	payload := a.GetPayload()
	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Starting AWS add user to group action",
		"user_name", payload.UserName,
		"group_name", payload.GroupName,
	)

	if err := a.client.AddUserToGroup(ctx, payload.UserName, payload.GroupName); err != nil {
		connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelError, "failed to add user to group",
			"user_name", payload.UserName,
			"group_name", payload.GroupName,
			"error", err,
		)
		return fmt.Errorf("add user %q to group %q: %w", payload.UserName, payload.GroupName, err)
	}

	connectorutil.LogFeature(ctx, a.TypedFeatureContext, slog.LevelInfo, "Completed AWS add user to group action",
		"user_name", payload.UserName,
		"group_name", payload.GroupName,
	)
	return nil
}

func (a *AWSAddUserToGroupAction) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	a.state.Reset()
	a.client = nil
	return nil
}
