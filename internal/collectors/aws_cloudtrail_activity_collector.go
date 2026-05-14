package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// awsCloudTrailEventDetail is the parsed structure of the CloudTrailEvent JSON string.
type awsCloudTrailEventDetail struct {
	SourceIPAddress  string                    `json:"sourceIPAddress"`
	UserAgent        string                    `json:"userAgent"`
	UserIdentity     awsCloudTrailUserIdentity `json:"userIdentity"`
	ResponseElements map[string]string         `json:"responseElements"`
	ErrorCode        string                    `json:"errorCode,omitempty"`
	ErrorMessage     string                    `json:"errorMessage,omitempty"`
}

type awsCloudTrailUserIdentity struct {
	Type     string `json:"type"`
	UserName string `json:"userName"`
	ARN      string `json:"arn"`
}

// AWSCloudTrailActivityCollector collects ConsoleLogin events from CloudTrail.
type AWSCloudTrailActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSCloudTrailActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSCloudTrailActivityCollector constructs the collector with the given feature context.
func NewAWSCloudTrailActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSCloudTrailActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSCloudTrailActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSCloudTrailActivityCollector) Init(ctx context.Context) error {
	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	creds, err := credentials.Parse(c.GetCredentials())
	opts := c.GetOptions()
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSCloudTrailActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS CloudTrail activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := awsActivityResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS CloudTrail activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	emitted := 0
	eventEnum := c.client.CloudTrailEventEnumerator(ctx, "ConsoleLogin", startTime)
	if err := enumerators.ForEach(eventEnum, func(event api.CloudTrailEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if lastEventRef != "" && event.EventID == lastEventRef {
			return nil
		}
		if event.CloudTrailEvent == "" {
			return nil
		}

		var detail awsCloudTrailEventDetail
		if err := json.Unmarshal([]byte(event.CloudTrailEvent), &detail); err != nil {
			connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelError,
				"failed to parse CloudTrail event JSON",
				"event_id", event.EventID,
				"error", err,
			)
			return fmt.Errorf("parse CloudTrail event %s: %w", event.EventID, err)
		}

		actor := types.Actor{
			Ref:         detail.UserIdentity.UserName,
			Type:        detail.UserIdentity.Type,
			DisplayName: detail.UserIdentity.UserName,
		}
		eventCtx := types.EventContext{IPAddress: detail.SourceIPAddress, UserAgent: detail.UserAgent}

		if detail.ResponseElements["ConsoleLogin"] == "Success" {
			login := &events.LoginSucceeded{
				EventRef:  event.EventID,
				Timestamp: event.EventTime,
				Actor:     actor,
				Context:   eventCtx,
				Outcome: types.EventOutcome{
					Action: "login",
					Result: "success",
				},
				LoginType: "console",
			}
			if err := c.Emit(ctx, login); err != nil {
				return fmt.Errorf("emit LoginSucceeded: %w", err)
			}
			emitted++
			return nil
		}

		failureReason := detail.ErrorMessage
		login := &events.LoginFailed{
			EventRef:      event.EventID,
			Timestamp:     event.EventTime,
			Actor:         actor,
			Context:       eventCtx,
			FailureReason: failureReason,
			Outcome: types.EventOutcome{
				Action: "login",
				Result: "failure",
				Reason: failureReason,
			},
			LoginType: "console",
		}
		if err := c.Emit(ctx, login); err != nil {
			return fmt.Errorf("emit LoginFailed: %w", err)
		}
		emitted++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate CloudTrail events: %w", err)
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS CloudTrail activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSCloudTrailActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func awsActivityResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.LoginSucceeded:
		return &event.Timestamp, event.EventRef
	case *events.LoginFailed:
		return &event.Timestamp, event.EventRef
	case *events.SessionCreated:
		return &event.Timestamp, event.EventRef
	case *events.SessionTerminated:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
