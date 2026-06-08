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
	"github.com/hydn-co/mesh-aws/internal/scope"
)

// AWSGroupActivityCollector collects AWS group creation and deletion activity.
type AWSGroupActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSGroupActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	resolver  *scope.Resolver
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
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := connectorutil.Validate(c.GetOptions(), "feature options"); err != nil {
		return err
	}

	opts := c.GetOptions()
	accessKeyID, secretAccessKey, err := connectorutil.ExtractAPIKeyAndSecretFrom(
		c.GetCredentials(),
		connectorutil.DefaultCredentialName,
	)
	if err != nil {
		return fmt.Errorf("parse AWS credentials: %w", err)
	}
	creds := &api.AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}

	if c.newClient == nil {
		c.newClient = defaultCloudTrailClientFactory
	}
	c.resolver = scope.NewResolver(
		&opts.AWSScopeOptionsCore,
		opts.GetRegion(),
		opts.GetSessionToken(),
		creds,
		scope.WithLogger(func(level slog.Level, msg string, args ...any) {
			connectorutil.LogFeature(context.Background(), c.TypedFeatureContext, level, msg, args...)
		}),
	)
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

	emitted := 0
	// CloudTrail is per-account, so a single collector fans out across every
	// member account in organization mode. Each account is queried from the same
	// resume cursor; duplicate event refs across accounts are de-duplicated by the
	// catalog's distinct identity.
	if err := scope.ForEachTarget(ctx, c.resolver, false, c.newClient,
		func(ctx context.Context, client cloudTrailClient, _ scope.Target) error {
			c.client = client
			return c.collectGroupEvents(ctx, startTime, lastEventRef, &emitted)
		}); err != nil {
		return err
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

// collectGroupEvents collects and emits group activity for the current target account.
func (c *AWSGroupActivityCollector) collectGroupEvents(
	ctx context.Context,
	startTime *time.Time,
	lastEventRef string,
	emitted *int,
) error {
	eventNames := []string{"CreateGroup", "DeleteGroup"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect group activity events: %w", err)
	}
	cloudTrailEvents = resumeFilteredCloudTrailEvents(cloudTrailEvents, startTime, lastEventRef)

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
		(*emitted)++
	}
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
