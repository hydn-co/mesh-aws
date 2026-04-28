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

// DisableIAMUserAction deletes the login profile, deactivates access keys,
// and deactivates MFA devices for the target IAM user.
type DisableIAMUserAction struct {
	ctx *connector.TypedFeatureContext[*options.UsersOptions, *payloads.DisableUserPayload]
}

// NewDisableIAMUserAction constructs the action with the given feature context.
func NewDisableIAMUserAction(ctx *connector.TypedFeatureContext[*options.UsersOptions, *payloads.DisableUserPayload]) runner.Feature {
	return &DisableIAMUserAction{ctx: ctx}
}

func (a *DisableIAMUserAction) Init(_ context.Context) error { return nil }
func (a *DisableIAMUserAction) Stop(_ context.Context) error { return nil }

func (a *DisableIAMUserAction) Start(ctx context.Context) error {
	const name = "disable-iam-user"
	logActionStart(name)

	payload := a.ctx.GetPayload()
	if payload == nil || payload.UserName == "" {
		return fmt.Errorf("disable-iam-user: user_name is required in payload")
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

	userName := payload.UserName

	// 1. Delete login profile (silently ignores NoSuchEntity when the user has no password).
	if err := client.DeleteLoginProfile(ctx, userName); err != nil {
		logActionError(name, fmt.Errorf("delete login profile for %q: %w", userName, err))
		return fmt.Errorf("delete login profile: %w", err)
	}

	// 2. Deactivate all access keys.
	keys, err := client.ListAccessKeys(ctx, userName)
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("list access keys for %q: %w", userName, err)
	}

	for _, key := range keys {
		if err := client.UpdateAccessKey(ctx, userName, key.AccessKeyID, "Inactive"); err != nil {
			logActionError(name, fmt.Errorf("deactivate access key %q: %w", key.AccessKeyID, err))
			return fmt.Errorf("deactivate access key: %w", err)
		}
	}

	// 3. Deactivate all MFA devices.
	devices, err := client.ListMFADevices(ctx, userName)
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("list MFA devices for %q: %w", userName, err)
	}

	for _, device := range devices {
		if err := client.DeactivateMFADevice(ctx, userName, device.SerialNumber); err != nil {
			logActionError(name, fmt.Errorf("deactivate MFA device %q: %w", device.SerialNumber, err))
			return fmt.Errorf("deactivate MFA device: %w", err)
		}
	}

	logActionDone(name)
	return nil
}
