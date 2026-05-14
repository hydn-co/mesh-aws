package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AWSSSOLoginActivityCollector collects AWS IAM Identity Center login activity.
type AWSSSOLoginActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSSSOLoginActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSSSOLoginActivityCollector constructs the collector with the given feature context.
func NewAWSSSOLoginActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSSSOLoginActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSSSOLoginActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSSSOLoginActivityCollector) Init(ctx context.Context) error {
	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	opts := c.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecret(c.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	client, err := api.NewClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSSSOLoginActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS SSO login activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := awsLoginResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS SSO login activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	emitted := 0
	for _, eventName := range []string{"Federate", "ConsoleLogin"} {
		eventEnum := c.client.CloudTrailEventEnumerator(ctx, eventName, startTime)
		if err := enumerators.ForEach(eventEnum, func(rawEvent api.CloudTrailEvent) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			if lastEventRef != "" && rawEvent.EventID == lastEventRef {
				return nil
			}
			if rawEvent.CloudTrailEvent == "" {
				return nil
			}

			var detail awsCloudTrailEventDetail
			if err := json.Unmarshal([]byte(rawEvent.CloudTrailEvent), &detail); err != nil {
				connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelError,
					"failed to parse SSO CloudTrail event JSON",
					"event_id", rawEvent.EventID,
					"error", err,
				)
				return fmt.Errorf("parse SSO CloudTrail event %s: %w", rawEvent.EventID, err)
			}

			principal := rawEvent.Username
			if principal == "" {
				return nil
			}

			actor := types.Actor{Ref: principal, Type: detail.UserIdentity.Type, DisplayName: principal}
			eventContext := types.EventContext{IPAddress: detail.SourceIPAddress, UserAgent: detail.UserAgent}
			eventRef := rawEvent.EventID
			timestamp := rawEvent.EventTime

			switch eventName {
			case "Federate":
				login := &events.LoginSucceeded{
					EventRef:  eventRef,
					Timestamp: timestamp,
					Actor:     actor,
					Context:   eventContext,
					Outcome:   types.EventOutcome{Action: "login", Result: "success"},
					LoginType: "sso",
				}
				if err := c.Emit(ctx, login); err != nil {
					return fmt.Errorf("emit SSO login succeeded event: %w", err)
				}
				emitted++
			case "ConsoleLogin":
				if detail.ResponseElements["ConsoleLogin"] != "Failure" {
					return nil
				}

				failureReason := detail.ErrorMessage
				login := &events.LoginFailed{
					EventRef:      eventRef,
					Timestamp:     timestamp,
					Actor:         actor,
					Context:       eventContext,
					FailureReason: failureReason,
					Outcome:       types.EventOutcome{Action: "login", Result: "failure", Reason: failureReason},
					LoginType:     "sso",
				}
				if err := c.Emit(ctx, login); err != nil {
					return fmt.Errorf("emit SSO login failed event: %w", err)
				}
				emitted++
			}

			return nil
		}); err != nil {
			return fmt.Errorf("enumerate SSO CloudTrail events for %s: %w", eventName, err)
		}
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS SSO login activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSSSOLoginActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func awsLoginResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.LoginSucceeded:
		return &event.Timestamp, event.EventRef
	case *events.LoginFailed:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
