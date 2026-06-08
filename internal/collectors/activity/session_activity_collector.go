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

// AWSSessionActivityCollector collects AWS IAM Identity Center session lifecycle activity.
type AWSSessionActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSSessionActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	resolver  *scope.Resolver
	state     connectorutil.FeatureState
}

// NewAWSSessionActivityCollector constructs the collector with the given feature context.
func NewAWSSessionActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSSessionActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSSessionActivityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultCloudTrailClientFactory,
	}
}

func (c *AWSSessionActivityCollector) Init(ctx context.Context) error {
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

	emitted := 0
	// CloudTrail is per-account, so a single collector fans out across every
	// member account in organization mode. Each account is queried from the same
	// resume cursor; duplicate event refs across accounts are de-duplicated by the
	// catalog's distinct identity.
	if err := scope.ForEachTarget(ctx, c.resolver, false, c.newClient,
		func(ctx context.Context, client cloudTrailClient, _ scope.Target) error {
			c.client = client
			return c.collectSessionEvents(ctx, startTime, lastEventRef, &emitted)
		}); err != nil {
		return err
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

// collectSessionEvents collects and emits session activity for the current target account.
func (c *AWSSessionActivityCollector) collectSessionEvents(
	ctx context.Context,
	startTime *time.Time,
	lastEventRef string,
	emitted *int,
) error {
	eventNames := []string{"Authenticate", "Federate", "Logout"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect session activity events: %w", err)
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
		(*emitted)++
	}
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
