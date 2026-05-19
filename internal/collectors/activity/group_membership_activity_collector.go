package activity

import (
	"context"
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

// AWSGroupMembershipActivityCollector collects AWS group membership changes.
type AWSGroupMembershipActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSGroupMembershipActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSGroupMembershipActivityCollector constructs the collector with the given feature context.
func NewAWSGroupMembershipActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSGroupMembershipActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSGroupMembershipActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSGroupMembershipActivityCollector) Init(ctx context.Context) error {
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
	for _, eventName := range []string{"AddUserToGroup", "RemoveUserFromGroup"} {
		eventEnum := c.client.CloudTrailEventEnumerator(ctx, eventName, startTime)
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
				return nil
			}
			if err := c.Emit(ctx, activityEvent); err != nil {
				return fmt.Errorf("emit group membership activity %T: %w", activityEvent, err)
			}
			emitted++
			return nil
		}); err != nil {
			return fmt.Errorf("enumerate group membership activity events for %s: %w", eventName, err)
		}
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
