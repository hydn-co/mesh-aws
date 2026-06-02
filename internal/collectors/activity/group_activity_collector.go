package activity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

// AWSGroupActivityCollector collects AWS group creation and deletion activity.
type AWSGroupActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSGroupActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	state     connectorutil.FeatureState
}

// NewAWSGroupActivityCollector constructs the collector with the given feature context.
func NewAWSGroupActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSGroupActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSGroupActivityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultCloudTrailClientFactory,
	}
}

func (c *AWSGroupActivityCollector) Init(ctx context.Context) error {
	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	opts := c.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecret(c.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	if c.newClient == nil {
		c.newClient = defaultCloudTrailClientFactory
	}
	client, err := c.newClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSGroupActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS group activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := groupResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS group activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{"CreateGroup", "DeleteGroup"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect group activity events: %w", err)
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
				"failed to parse AWS group activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapGroupActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit group activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS group activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSGroupActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapGroupActivityEvent(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (events.ActivityEvent, bool) {
	if detail.EventSource == cognitoUserPoolEventSource {
		return nil, false
	}

	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	groupName := requestString(detail, "groupName")
	if groupName == "" {
		return nil, false
	}

	target := types.Target{Ref: groupName, Type: "group", DisplayName: groupName}
	context := activityContext(detail)

	switch event.EventName {
	case "CreateGroup":
		return &events.GroupCreated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Target:      target,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "create", Result: "success"},
			GroupType:   "IAM",
			MailEnabled: false,
		}, true
	case "DeleteGroup":
		return &events.GroupRemoved{
			EventRef:      event.EventID,
			Timestamp:     event.EventTime,
			Actor:         actor,
			Target:        target,
			Context:       context,
			Outcome:       types.EventOutcome{Action: "delete", Result: "success"},
			GroupType:     "IAM",
			RemovalReason: "deleted",
		}, true
	default:
		return nil, false
	}
}

func groupResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.GroupCreated:
		return &event.Timestamp, event.EventRef
	case *events.GroupRemoved:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
