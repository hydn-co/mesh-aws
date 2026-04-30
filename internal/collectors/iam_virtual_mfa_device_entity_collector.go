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
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IAMVirtualMFADeviceEntityCollector lists assigned virtual MFA devices and emits MFA entities.
type IAMVirtualMFADeviceEntityCollector struct {
	*connector.TypedFeatureContext[*options.VirtualMFADevicesOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIAMVirtualMFADeviceEntityCollector constructs the collector with the given feature context.
func NewIAMVirtualMFADeviceEntityCollector(
	ctx *connector.TypedFeatureContext[*options.VirtualMFADevicesOptions, *connector.NoPayload],
) runner.Feature {
	return &IAMVirtualMFADeviceEntityCollector{TypedFeatureContext: ctx}
}

func (c *IAMVirtualMFADeviceEntityCollector) Init(ctx context.Context) error {
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
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized IAM virtual MFA device collector")
	return nil
}

func (c *IAMVirtualMFADeviceEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting IAM virtual MFA device collection")

	count := 0
	var marker string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		devices, truncated, nextMarker, err := c.client.ListVirtualMFADevices(ctx, marker)
		if err != nil {
			logCollector(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list IAM virtual MFA devices",
				"error",
				err,
			)
			return fmt.Errorf("list virtual MFA devices: %w", err)
		}

		for _, device := range devices {
			multiFactor := entities.NewMultiFactor()
			multiFactor.MultiFactorRef = device.SerialNumber
			multiFactor.Status = types.MultiFactorStatusEnabled
			multiFactor.Kind = types.MultiFactorKindAuthenticator
			multiFactor.CreatedAt = &device.EnableDate

			if err := c.Emit(ctx, multiFactor); err != nil {
				logCollector(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit MFA entity",
					"serial_number",
					device.SerialNumber,
					"error",
					err,
				)
				return fmt.Errorf("emit multi-factor: %w", err)
			}

			if device.UserID != "" {
				accountMFA := entities.NewAccountMultiFactor()
				accountMFA.AccountRef = device.UserID
				accountMFA.MultiFactorRef = device.SerialNumber
				accountMFA.CreatedAt = &device.EnableDate

				if err := c.Emit(ctx, accountMFA); err != nil {
					logCollector(
						ctx,
						c.TypedFeatureContext,
						slog.LevelError,
						"failed to emit account MFA entity",
						"serial_number",
						device.SerialNumber,
						"user_name",
						device.UserName,
						"error",
						err,
					)
					return fmt.Errorf("emit account multi-factor: %w", err)
				}
			}
			count++
		}

		if !truncated {
			break
		}
		marker = nextMarker
	}

	logCollector(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"finished IAM virtual MFA device collection",
		"count",
		count,
	)
	return nil
}

func (c *IAMVirtualMFADeviceEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped IAM virtual MFA device collector")
	return nil
}
