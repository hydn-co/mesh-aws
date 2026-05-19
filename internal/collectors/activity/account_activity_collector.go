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

// AWSAccountActivityCollector collects AWS user and organization account lifecycle activity.
type AWSAccountActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSAccountActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSAccountActivityCollector constructs the collector with the given feature context.
func NewAWSAccountActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSAccountActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSAccountActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSAccountActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSAccountActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS account activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := accountResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS account activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{"CreateUser", "DeleteUser", "CreateAccount", "CloseAccount"}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect account activity events: %w", err)
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
				"failed to parse AWS account activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapAccountActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit account activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS account activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSAccountActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapAccountActivityEvent(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)

	switch event.EventName {
	case "CreateUser":
		accountRef := requestString(detail, "userName")
		if accountRef == "" {
			return nil, false
		}
		target := types.Target{Ref: accountRef, Type: "account", DisplayName: displayNameFromReference(accountRef)}
		return &events.AccountCreated{
			EventRef:        event.EventID,
			Timestamp:       event.EventTime,
			Actor:           actor,
			Target:          target,
			Context:         context,
			Outcome:         types.EventOutcome{Action: "create", Result: "success"},
			AccountType:     "User",
			SourceDirectory: "IAM",
		}, true
	case "DeleteUser":
		accountRef := requestString(detail, "userName")
		if accountRef == "" {
			return nil, false
		}
		target := types.Target{Ref: accountRef, Type: "account", DisplayName: displayNameFromReference(accountRef)}
		return &events.AccountDeleted{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			DeletionMethod: "deleted",
		}, true
	case "CreateAccount":
		accountRef := requestString(detail, "accountName")
		if accountRef == "" {
			return nil, false
		}
		target := types.Target{Ref: accountRef, Type: "account", DisplayName: displayNameFromReference(accountRef)}
		return &events.AccountCreated{
			EventRef:        event.EventID,
			Timestamp:       event.EventTime,
			Actor:           actor,
			Target:          target,
			Context:         context,
			Outcome:         types.EventOutcome{Action: "create", Result: "success"},
			AccountType:     "Organization",
			SourceDirectory: "Organizations",
		}, true
	case "CloseAccount":
		accountRef := requestString(detail, "accountId")
		if accountRef == "" {
			return nil, false
		}
		target := types.Target{Ref: accountRef, Type: "account", DisplayName: displayNameFromReference(accountRef)}
		return &events.AccountDeleted{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			DeletionMethod: "closed",
		}, true
	default:
		return nil, false
	}
}

func accountResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.AccountCreated:
		return &event.Timestamp, event.EventRef
	case *events.AccountDeleted:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
