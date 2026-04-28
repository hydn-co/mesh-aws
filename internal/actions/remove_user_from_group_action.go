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

// RemoveUserFromGroupAction removes an IAM user from an IAM group.
type RemoveUserFromGroupAction struct {
	ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.RemoveUserFromGroupPayload]
}

// NewRemoveUserFromGroupAction constructs the action with the given feature context.
func NewRemoveUserFromGroupAction(ctx *connector.TypedFeatureContext[*options.GroupsOptions, *payloads.RemoveUserFromGroupPayload]) runner.Feature {
	return &RemoveUserFromGroupAction{ctx: ctx}
}

func (a *RemoveUserFromGroupAction) Init(_ context.Context) error { return nil }
func (a *RemoveUserFromGroupAction) Stop(_ context.Context) error { return nil }

func (a *RemoveUserFromGroupAction) Start(ctx context.Context) error {
	const name = "remove-user-from-group"
	logActionStart(name)

	payload := a.ctx.GetPayload()
	if payload == nil || payload.UserName == "" || payload.GroupName == "" {
		return fmt.Errorf("remove-user-from-group: user_name and group_name are required in payload")
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

	if err := client.RemoveUserFromGroup(ctx, payload.UserName, payload.GroupName); err != nil {
		logActionError(name, err)
		return fmt.Errorf("remove user %q from group %q: %w", payload.UserName, payload.GroupName, err)
	}

	logActionDone(name)
	return nil
}
