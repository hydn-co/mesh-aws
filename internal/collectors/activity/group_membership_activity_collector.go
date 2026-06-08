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

// AWSGroupMembershipActivityCollector collects AWS group membership changes.
type AWSGroupMembershipActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSGroupMembershipActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	resolver  *scope.Resolver
	state     connectorutil.FeatureState
}

// NewAWSGroupMembershipActivityCollector constructs the collector with the given feature context.
func NewAWSGroupMembershipActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSGroupMembershipActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSGroupMembershipActivityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultCloudTrailClientFactory,
	}
}

func (c *AWSGroupMembershipActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSGroupMembershipActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Starting AWS group membership activity collector",
	)

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := groupMembershipResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS group membership activity collector",
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
			return c.collectGroupMembershipEvents(ctx, startTime, lastEventRef, &emitted)
		}); err != nil {
		return err
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS group membership activity collector",
		"emitted",
		emitted,
	)
	return nil
}

// collectGroupMembershipEvents collects and emits group membership activity for the current target account.
func (c *AWSGroupMembershipActivityCollector) collectGroupMembershipEvents(
	ctx context.Context,
	startTime *time.Time,
	lastEventRef string,
	emitted *int,
) error {
	eventNames := []string{"AddUserToGroup", "RemoveUserFromGroup"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect group membership activity events: %w", err)
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
				"failed to parse AWS group membership activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapGroupMembershipActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit group membership activity %T: %w", activityEvent, err)
		}
		(*emitted)++
	}
	return nil
}

func (c *AWSGroupMembershipActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapGroupMembershipActivityEvent(
	event api.CloudTrailEvent,
	detail *awsCloudTrailEventDetail,
) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	groupRef := requestString(detail, "groupId")
	groupName := requestString(detail, "groupName")
	memberRef := requestString(detail, "userName")
	if memberRef == "" {
		return nil, false
	}

	groupType := "IAM"
	target := types.Target{Ref: memberRef, Type: "account", DisplayName: displayNameFromReference(memberRef)}
	context := activityContext(detail)

	switch event.EventName {
	case "AddUserToGroup":
		return &events.GroupMemberAdded{
			EventRef:  event.EventID,
			Timestamp: event.EventTime,
			Actor:     actor,
			Target:    target,
			Context:   context,
			Outcome:   types.EventOutcome{Action: "add", Result: "success"},
			GroupRef:  groupRef,
			GroupName: groupName,
			GroupType: groupType,
		}, true
	case "RemoveUserFromGroup":
		return &events.GroupMemberRemoved{
			EventRef:  event.EventID,
			Timestamp: event.EventTime,
			Actor:     actor,
			Target:    target,
			Context:   context,
			Outcome:   types.EventOutcome{Action: "remove", Result: "success"},
			GroupRef:  groupRef,
			GroupName: groupName,
			GroupType: groupType,
		}, true
	default:
		return nil, false
	}
}

func groupMembershipResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.GroupMemberAdded:
		return &event.Timestamp, event.EventRef
	case *events.GroupMemberRemoved:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
