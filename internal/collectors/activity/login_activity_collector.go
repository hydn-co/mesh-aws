package activity

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AWSLoginActivityCollector collects AWS Management Console and IAM Identity Center login activity.
type AWSLoginActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSLoginActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSLoginActivityCollector constructs the collector with the given feature context.
func NewAWSLoginActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSLoginActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSLoginActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSLoginActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSLoginActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS login activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := loginResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS login activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{"ConsoleLogin", "UserAuthentication", "CredentialVerification", "LogoutUser"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect login activity events: %w", err)
	}
	cloudTrailEvents = resumeFilteredCloudTrailEvents(cloudTrailEvents, startTime, lastEventRef)

	emitted := 0
	for _, event := range cloudTrailEvents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if event.CloudTrailEvent == "" {
			continue
		}

		detail, err := parseCloudTrailEventDetail(event)
		if err != nil {
			connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelError,
				"failed to parse AWS login activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapLoginActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit login activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS login activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSLoginActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapLoginActivityEvent(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)
	switch event.EventName {
	case "ConsoleLogin":
		if responseStatus(detail, "ConsoleLogin") == "Success" {
			return &events.LoginSucceeded{
				EventRef:  event.EventID,
				Timestamp: event.EventTime,
				Actor:     actor,
				Context:   context,
				Outcome:   types.EventOutcome{Action: "login", Result: "success"},
				LoginType: "console",
			}, true
		}

		failureReason := strings.TrimSpace(detail.ErrorMessage)
		if failureReason == "" {
			failureReason = strings.TrimSpace(detail.ErrorCode)
		}
		return &events.LoginFailed{
			EventRef:      event.EventID,
			Timestamp:     event.EventTime,
			Actor:         actor,
			Context:       context,
			FailureReason: failureReason,
			Outcome:       types.EventOutcome{Action: "login", Result: "failure", Reason: failureReason},
			LoginType:     "console",
		}, true
	case "UserAuthentication":
		return &events.LoginSucceeded{
			EventRef:  event.EventID,
			Timestamp: event.EventTime,
			Actor:     actor,
			Context:   context,
			Outcome:   types.EventOutcome{Action: "login", Result: "success"},
			LoginType: "sso",
		}, true
	case "CredentialVerification":
		status := responseStatus(detail, "CredentialVerification")
		if status != "Failure" && detail.ErrorCode == "" && detail.ErrorMessage == "" {
			return nil, false
		}
		failureReason := strings.TrimSpace(detail.ErrorMessage)
		if failureReason == "" {
			failureReason = strings.TrimSpace(detail.ErrorCode)
		}
		if failureReason == "" {
			failureReason = status
		}
		return &events.LoginFailed{
			EventRef:      event.EventID,
			Timestamp:     event.EventTime,
			Actor:         actor,
			Context:       context,
			FailureReason: failureReason,
			Outcome:       types.EventOutcome{Action: "login", Result: "failure", Reason: failureReason},
			LoginType:     "sso",
		}, true
	case "LogoutUser":
		return &events.SessionTerminated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "logout", Result: "success"},
			Reason:      "logout",
			SessionType: "console",
		}, true
	default:
		return nil, false
	}
}
