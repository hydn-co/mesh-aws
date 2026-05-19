package activity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AWSSessionActivityCollector collects AWS IAM Identity Center session lifecycle activity.
type AWSSessionActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSSessionActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSSessionActivityCollector constructs the collector with the given feature context.
func NewAWSSessionActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSSessionActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSSessionActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSSessionActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSSessionActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS session activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := sessionResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS session activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{"Authenticate", "Federate", "Logout"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect session activity events: %w", err)
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
				"failed to parse AWS session activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapSessionActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit session activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS session activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSSessionActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapSessionActivityEvent(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)
	switch event.EventName {
	case "Authenticate", "Federate":
		return &events.SessionCreated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "login", Result: "success"},
			SessionType: "sso",
		}, true
	case "Logout":
		return &events.SessionTerminated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "logout", Result: "success"},
			Reason:      "logout",
			SessionType: "sso",
		}, true
	default:
		return nil, false
	}
}
