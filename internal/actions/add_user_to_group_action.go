package actions

import (
	"context"
	"fmt"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AddUserToGroupAction adds an IAM user to an IAM group.
type AddUserToGroupAction struct {
	ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.AddUserToGroupPayload]
}

// NewAddUserToGroupAction constructs the action with the given feature context.
func NewAddUserToGroupAction(ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.AddUserToGroupPayload]) runner.Feature {
	return &AddUserToGroupAction{ctx: ctx}
}

func (a *AddUserToGroupAction) Init(_ context.Context) error { return nil }
func (a *AddUserToGroupAction) Stop(_ context.Context) error { return nil }

func (a *AddUserToGroupAction) Start(ctx context.Context) error {
	const name = "add-user-to-group"
	logActionStart(name)

	payload := a.ctx.GetPayload()
	if payload == nil || payload.UserName == "" || payload.GroupName == "" {
		return fmt.Errorf("add-user-to-group: user_name and group_name are required in payload")
	}

	creds, err := credentials.Parse(a.ctx.GetCredentials())
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.New(creds)
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("create AWS client: %w", err)
	}

	if err := client.AddUserToGroup(ctx, payload.UserName, payload.GroupName); err != nil {
		logActionError(name, err)
		return fmt.Errorf("add user %q to group %q: %w", payload.UserName, payload.GroupName, err)
	}

	logActionDone(name)
	return nil
}
