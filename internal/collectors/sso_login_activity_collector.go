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
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// SSOLoginActivityCollector collects AWS IAM Identity Center login activity.
type SSOLoginActivityCollector struct {
	*connector.TypedFeatureContext[*options.SSOActivityOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewSSOLoginActivityCollector constructs the collector with the given feature context.
func NewSSOLoginActivityCollector(
	ctx *connector.TypedFeatureContext[*options.SSOActivityOptions, *connector.NoPayload],
) runner.Feature {
	return &SSOLoginActivityCollector{TypedFeatureContext: ctx}
}

func (c *SSOLoginActivityCollector) Init(ctx context.Context) error {
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
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "initialized SSO activity collector")
	return nil
}

func (c *SSOLoginActivityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "starting SSO activity collection")

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
		}
	}

	count := 0
	count, err := c.collectLookupEvents(ctx, "Federate", startTime, lastEventRef, count)
	if err != nil {
		return err
	}

	count, err = c.collectLookupEvents(ctx, "ConsoleLogin", startTime, lastEventRef, count)
	if err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"finished SSO activity collection",
		"count",
		count,
	)
	return nil
}

func (c *SSOLoginActivityCollector) collectLookupEvents(
	ctx context.Context,
	eventName string,
	startTime *time.Time,
	lastEventRef string,
	count int,
) (int, error) {
	var nextToken string
	for {
		evts, token, err := c.client.LookupEvents(ctx, eventName, startTime, nextToken)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to look up SSO CloudTrail events",
				"event_name",
				eventName,
				"error",
				err,
			)
			return count, fmt.Errorf("lookup SSO CloudTrail events: %w", err)
		}

		for _, rawEvent := range evts {
			if lastEventRef != "" && rawEvent.EventID == lastEventRef {
				continue
			}
			if rawEvent.CloudTrailEvent == "" {
				continue
			}

			var detail cloudTrailEventDetail
			if err := json.Unmarshal([]byte(rawEvent.CloudTrailEvent), &detail); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to parse SSO CloudTrail event JSON",
					"event_id",
					rawEvent.EventID,
					"error",
					err,
				)
				continue
			}

			principal := firstNonEmpty(rawEvent.Username, detail.UserIdentity.UserName, detail.UserIdentity.ARN)
			if principal == "" {
				continue
			}

			actor := types.Actor{Ref: principal, Type: "account", DisplayName: principal}
			eventContext := types.EventContext{IPAddress: detail.SourceIPAddress, UserAgent: detail.UserAgent}
			eventRef := firstNonEmpty(detail.EventID, rawEvent.EventID)
			timestamp := rawEvent.EventTime
			if !detail.EventTime.IsZero() {
				timestamp = detail.EventTime
			}

			switch eventName {
			case "Federate":
				event := &events.LoginSucceeded{
					EventRef:  eventRef,
					Timestamp: timestamp,
					Actor:     actor,
					Context:   eventContext,
					Outcome:   types.EventOutcome{Action: "login", Result: "success"},
					LoginType: "sso",
				}
				if err := c.Emit(ctx, event); err != nil {
					connectorutil.LogFeature(
						ctx,
						c.TypedFeatureContext,
						slog.LevelError,
						"failed to emit SSO login succeeded event",
						"event_ref",
						eventRef,
						"error",
						err,
					)
					return count, fmt.Errorf("emit SSO login succeeded event: %w", err)
				}
				count++
			case "ConsoleLogin":
				if detail.ResponseElements["ConsoleLogin"] != "Failure" {
					continue
				}

				reason := firstNonEmpty(detail.ErrorMessage, detail.ErrorCode)
				event := &events.LoginFailed{
					EventRef:      eventRef,
					Timestamp:     timestamp,
					Actor:         actor,
					Context:       eventContext,
					FailureReason: reason,
					Outcome:       types.EventOutcome{Action: "login", Result: "failure", Reason: reason},
					LoginType:     "sso",
				}
				if err := c.Emit(ctx, event); err != nil {
					connectorutil.LogFeature(
						ctx,
						c.TypedFeatureContext,
						slog.LevelError,
						"failed to emit SSO login failed event",
						"event_ref",
						eventRef,
						"error",
						err,
					)
					return count, fmt.Errorf("emit SSO login failed event: %w", err)
				}
				count++
			}
		}

		if token == "" {
			break
		}
		nextToken = token
	}

	return count, nil
}

func (c *SSOLoginActivityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped SSO activity collector")
	return nil
}
