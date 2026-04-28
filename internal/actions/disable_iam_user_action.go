package actions

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
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

	client, err := api.New(ctx, creds)
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("create AWS client: %w", err)
	}

	userName := payload.UserName

	// 1. Delete login profile (ignores NoSuchEntity if user has no password).
	_, err = client.IAM.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		logActionError(name, fmt.Errorf("delete login profile for %q: %w", userName, err))
		// Non-fatal: user may not have a console login profile.
	}

	// 2. Deactivate all access keys.
	keysOut, err := client.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("list access keys for %q: %w", userName, err)
	}

	for _, key := range keysOut.AccessKeyMetadata {
		_, err := client.IAM.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    aws.String(userName),
			AccessKeyId: key.AccessKeyId,
			Status:      "Inactive",
		})
		if err != nil {
			logActionError(name, fmt.Errorf("deactivate access key %q: %w", aws.ToString(key.AccessKeyId), err))
			return fmt.Errorf("deactivate access key: %w", err)
		}
	}

	// 3. Deactivate all MFA devices.
	mfaOut, err := client.IAM.ListMFADevices(ctx, &iam.ListMFADevicesInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		logActionError(name, err)
		return fmt.Errorf("list MFA devices for %q: %w", userName, err)
	}

	for _, device := range mfaOut.MFADevices {
		_, err := client.IAM.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{
			UserName:     aws.String(userName),
			SerialNumber: device.SerialNumber,
		})
		if err != nil {
			logActionError(name, fmt.Errorf("deactivate MFA device %q: %w", aws.ToString(device.SerialNumber), err))
			return fmt.Errorf("deactivate MFA device: %w", err)
		}
	}

	logActionDone(name)
	return nil
}
