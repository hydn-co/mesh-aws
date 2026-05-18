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

// AWSRoleActivityCollector collects AWS role, policy, and permission set lifecycle activity.
type AWSRoleActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSRoleActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSRoleActivityCollector constructs the collector with the given feature context.
func NewAWSRoleActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSRoleActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSRoleActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSRoleActivityCollector) Init(ctx context.Context) error {
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

	emitted := 0
	for _, eventName := range []string{"CreateRole", "DeleteRole", "CreatePolicy", "DeletePolicy", "CreatePermissionSet", "DeletePermissionSet"} {
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
					"failed to parse AWS role activity event JSON",
					"event_name", event.EventName,
					"event_id", event.EventID,
					"error", err,
				)
				return err
			}

			activityEvent, ok := mapRoleActivityEvent(event, detail)
			if !ok {
				return nil
			}
			if err := c.Emit(ctx, activityEvent); err != nil {
				return fmt.Errorf("emit role activity %T: %w", activityEvent, err)
			}
			emitted++
			return nil
		}); err != nil {
			return fmt.Errorf("enumerate role activity events for %s: %w", eventName, err)
		}
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
		roleName := firstNonEmpty(
			firstRequestString(detail, "roleName", "RoleName"),
			firstResponseString(detail, "roleName", "RoleName"),
		)
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
		roleName := firstNonEmpty(
			firstRequestString(detail, "roleName", "RoleName"),
			firstResponseString(detail, "roleName", "RoleName"),
		)
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
		policyName := firstNonEmpty(
			firstRequestString(detail, "policyName", "PolicyName"),
			displayNameFromReference(firstRequestString(detail, "policyArn", "PolicyArn")),
		)
		if policyName == "" {
			return nil, false
		}
		target := types.Target{Ref: policyName, Type: "policy", DisplayName: displayNameFromReference(policyName)}
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
		policyName := firstNonEmpty(
			firstRequestString(detail, "policyName", "PolicyName"),
			displayNameFromReference(firstRequestString(detail, "policyArn", "PolicyArn")),
		)
		if policyName == "" {
			return nil, false
		}
		target := types.Target{Ref: policyName, Type: "policy", DisplayName: displayNameFromReference(policyName)}
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
		permissionSetName := firstNonEmpty(
			firstRequestString(detail, "permissionSetName", "PermissionSetName"),
			displayNameFromReference(firstRequestString(detail, "permissionSetArn", "PermissionSetArn")),
		)
		if permissionSetName == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetName,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetName),
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
		permissionSetName := firstNonEmpty(
			firstRequestString(detail, "permissionSetName", "PermissionSetName"),
			displayNameFromReference(firstRequestString(detail, "permissionSetArn", "PermissionSetArn")),
		)
		if permissionSetName == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetName,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetName),
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
