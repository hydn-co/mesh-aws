package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/helpers"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// cloudTrailEventDetail is the parsed structure of the CloudTrailEvent JSON string.
type cloudTrailEventDetail struct {
	EventID          string                 `json:"eventID"`
	EventTime        time.Time              `json:"eventTime"`
	SourceIPAddress  string                 `json:"sourceIPAddress"`
	UserAgent        string                 `json:"userAgent"`
	UserIdentity     cloudTrailUserIdentity `json:"userIdentity"`
	ResponseElements map[string]string      `json:"responseElements"`
	ErrorCode        string                 `json:"errorCode,omitempty"`
	ErrorMessage     string                 `json:"errorMessage,omitempty"`
}

type cloudTrailUserIdentity struct {
	Type     string `json:"type"`
	UserName string `json:"userName"`
	ARN      string `json:"arn"`
}

// CloudTrailActivityCollector collects ConsoleLogin events from CloudTrail.
type CloudTrailActivityCollector struct {
	*connector.TypedFeatureContext[*options.ActivityOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewCloudTrailActivityCollector constructs the collector with the given feature context.
func NewCloudTrailActivityCollector(
	ctx *connector.TypedFeatureContext[*options.ActivityOptions, *connector.NoPayload],
) runner.Feature {
	return &CloudTrailActivityCollector{TypedFeatureContext: ctx}
}

func (c *CloudTrailActivityCollector) Init(ctx context.Context) error {
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
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized CloudTrail activity collector")
	return nil
}

func (c *CloudTrailActivityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped CloudTrail activity collector")
	return nil
}

func (c *CloudTrailActivityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting CloudTrail activity collection")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		switch event := c.Payload.Content.(type) {
		case *events.LoginSucceeded:
			timestamp := event.Timestamp.UTC()
			startTime = &timestamp
			lastEventRef = event.EventRef
		case *events.LoginFailed:
			timestamp := event.Timestamp.UTC()
			startTime = &timestamp
			lastEventRef = event.EventRef
		case *events.SessionCreated:
			timestamp := event.Timestamp.UTC()
			startTime = &timestamp
			lastEventRef = event.EventRef
		case *events.SessionTerminated:
			timestamp := event.Timestamp.UTC()
			startTime = &timestamp
			lastEventRef = event.EventRef
		}
	}
	if startTime != nil {
		logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "resuming CloudTrail activity collection",
			"timestamp", startTime.Format(time.RFC3339),
			"event_ref", lastEventRef,
		)
	}

	count := 0
	var nextToken string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		evts, token, err := c.client.LookupEvents(ctx, "ConsoleLogin", startTime, nextToken)
		if err != nil {
			logCollector(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to look up CloudTrail events",
				"error",
				err,
			)
			return fmt.Errorf("lookup CloudTrail events: %w", err)
		}

		for _, e := range evts {
			if lastEventRef != "" && e.EventID == lastEventRef {
				continue
			}

			if e.CloudTrailEvent == "" {
				continue
			}

			var detail cloudTrailEventDetail
			if err := json.Unmarshal([]byte(e.CloudTrailEvent), &detail); err != nil {
				logCollector(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to parse CloudTrail event JSON",
					"event_id",
					e.EventID,
					"error",
					err,
				)
				continue
			}

			actor := types.Actor{
				Ref:         detail.UserIdentity.UserName,
				Type:        "account",
				DisplayName: detail.UserIdentity.UserName,
			}

			eventCtx := types.EventContext{
				IPAddress: detail.SourceIPAddress,
				UserAgent: detail.UserAgent,
			}

			eventRef := detail.EventID
			if eventRef == "" {
				eventRef = e.EventID
			}

			ts := detail.EventTime
			if ts.IsZero() {
				ts = e.EventTime
			}

			consoleLogin := detail.ResponseElements["ConsoleLogin"]
			isSuccess := consoleLogin == "Success"

			if isSuccess {
				ev := &events.LoginSucceeded{
					EventRef:  eventRef,
					Timestamp: ts,
					Actor:     actor,
					Context:   eventCtx,
					Outcome: types.EventOutcome{
						Action: "login",
						Result: "success",
					},
					LoginType: "console",
				}
				if err := c.Emit(ctx, ev); err != nil {
					logCollector(
						ctx,
						c.TypedFeatureContext,
						slog.LevelError,
						"failed to emit LoginSucceeded event",
						"event_ref",
						eventRef,
						"error",
						err,
					)
					return fmt.Errorf("emit LoginSucceeded: %w", err)
				}
			} else {
				reason := detail.ErrorMessage
				if reason == "" {
					reason = detail.ErrorCode
				}
				ev := &events.LoginFailed{
					EventRef:      eventRef,
					Timestamp:     ts,
					Actor:         actor,
					Context:       eventCtx,
					FailureReason: reason,
					Outcome: types.EventOutcome{
						Action: "login",
						Result: "failure",
						Reason: reason,
					},
					LoginType: "console",
				}
				if err := c.Emit(ctx, ev); err != nil {
					logCollector(
						ctx,
						c.TypedFeatureContext,
						slog.LevelError,
						"failed to emit LoginFailed event",
						"event_ref",
						eventRef,
						"error",
						err,
					)
					return fmt.Errorf("emit LoginFailed: %w", err)
				}
			}
			count++
		}

		if token == "" {
			break
		}
		nextToken = token
	}

	logCollector(ctx, c.TypedFeatureContext, slog.LevelInfo, "finished CloudTrail activity collection", "count", count)
	return nil
}
