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

// AWSRoleActivityCollector collects AWS role, policy, and permission set lifecycle activity.
type AWSRoleActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSRoleActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	state     connectorutil.FeatureState
}

// NewAWSRoleActivityCollector constructs the collector with the given feature context.
func NewAWSRoleActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSRoleActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSRoleActivityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultCloudTrailClientFactory,
	}
}

func (c *AWSRoleActivityCollector) Init(ctx context.Context) error {
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
	client, err := c.newClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSRoleActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS role activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := roleResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS role activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{
		"CreateRole",
		"DeleteRole",
		"CreatePolicy",
		"DeletePolicy",
		"CreatePermissionSet",
		"DeletePermissionSet",
	}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect role activity events: %w", err)
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
				"failed to parse AWS role activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapRoleActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit role activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS role activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSRoleActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapRoleActivityEvent(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)

	switch event.EventName {
	case "CreateRole":
		roleName := requestString(detail, "roleName")
		if roleName == "" {
			return nil, false
		}
		target := types.Target{Ref: roleName, Type: "role", DisplayName: displayNameFromReference(roleName)}
		summary := fmt.Sprintf("IAM role %q created", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "create", Result: "success"},
			Category:       "role",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	case "DeleteRole":
		roleName := requestString(detail, "roleName")
		if roleName == "" {
			return nil, false
		}
		target := types.Target{Ref: roleName, Type: "role", DisplayName: displayNameFromReference(roleName)}
		summary := fmt.Sprintf("IAM role %q deleted", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			Category:       "role",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	case "CreatePolicy":
		policyRef := requestString(detail, "policyName")
		if policyRef == "" {
			return nil, false
		}
		target := types.Target{Ref: policyRef, Type: "policy", DisplayName: displayNameFromReference(policyRef)}
		summary := fmt.Sprintf("IAM policy %q created", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "create", Result: "success"},
			Category:       "policy",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	case "DeletePolicy":
		policyRef := requestString(detail, "policyArn")
		if policyRef == "" {
			return nil, false
		}
		target := types.Target{Ref: policyRef, Type: "policy", DisplayName: displayNameFromReference(policyRef)}
		summary := fmt.Sprintf("IAM policy %q deleted", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			Category:       "policy",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	case "CreatePermissionSet":
		permissionSetRef := requestString(detail, "permissionSetName")
		if permissionSetRef == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetRef,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetRef),
		}
		summary := fmt.Sprintf("AWS permission set %q created", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "create", Result: "success"},
			Category:       "permission_set",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	case "DeletePermissionSet":
		permissionSetRef := requestString(detail, "permissionSetArn")
		if permissionSetRef == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetRef,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetRef),
		}
		summary := fmt.Sprintf("AWS permission set %q deleted", target.DisplayName)
		return &events.AdministrativeActionPerformed{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			Category:       "permission_set",
			Summary:        summary,
			Description:    summary,
			Source:         event.EventName,
			RelatedTargets: []types.Target{target},
		}, true
	default:
		return nil, false
	}
}

func roleResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.AdministrativeActionPerformed:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
