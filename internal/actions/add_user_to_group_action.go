package actions

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/helpers"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AddUserToGroupAction adds an IAM user to an IAM group.
type AddUserToGroupAction struct {
	*connector.TypedFeatureContext[*options.GroupsOptions, *payloads.AddUserToGroupPayload]
	client      *api.Client
	initialized bool
}

// NewAddUserToGroupAction constructs the action with the given feature context.
func NewAddUserToGroupAction(
	ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.AddUserToGroupPayload],
) runner.Feature {
	return &AddUserToGroupAction{TypedFeatureContext: ctx}
}

func (a *AddUserToGroupAction) Init(ctx context.Context) error {
	payload := a.GetPayload()
	if payload == nil || payload.UserName == "" || payload.GroupName == "" {
		return fmt.Errorf("user_name and group_name are required in payload")
	}

	creds, err := credentials.Parse(a.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds)
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	a.client = client
	a.initialized = true
	logAction(ctx, a.TypedFeatureContext, slog.LevelInfo, "initialized add-user-to-group action")
	return nil
}

func (a *AddUserToGroupAction) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(a.initialized); err != nil {
		return err
	}

	a.client = nil
	a.initialized = false
	logAction(ctx, a.TypedFeatureContext, slog.LevelInfo, "stopped add-user-to-group action")
	return nil
}

func (a *AddUserToGroupAction) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(a.initialized); err != nil {
		return err
	}

	payload := a.GetPayload()
	logAction(ctx, a.TypedFeatureContext, slog.LevelInfo, "starting add-user-to-group action",
		"user_name", payload.UserName,
		"group_name", payload.GroupName,
	)

	if err := a.client.AddUserToGroup(ctx, payload.UserName, payload.GroupName); err != nil {
		logAction(ctx, a.TypedFeatureContext, slog.LevelError, "failed to add user to group", "error", err)
		return fmt.Errorf("add user %q to group %q: %w", payload.UserName, payload.GroupName, err)
	}

	logAction(ctx, a.TypedFeatureContext, slog.LevelInfo, "completed add-user-to-group action",
		"user_name", payload.UserName,
		"group_name", payload.GroupName,
	)
	return nil
}
