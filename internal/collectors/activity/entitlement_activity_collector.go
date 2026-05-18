package activity

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// AWSEntitlementActivityCollector collects AWS permission and policy change activity.
type AWSEntitlementActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSEntitlementActivityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSEntitlementActivityCollector constructs the collector with the given feature context.
func NewAWSEntitlementActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSEntitlementActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSEntitlementActivityCollector{TypedFeatureContext: ctx}
}

func (c *AWSEntitlementActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSEntitlementActivityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS entitlement activity collector")

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := entitlementResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS entitlement activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	emitted := 0
	for _, eventName := range []string{
		"AttachRolePolicy",
		"DetachRolePolicy",
		"AttachUserPolicy",
		"DetachUserPolicy",
		"AttachGroupPolicy",
		"DetachGroupPolicy",
		"PutRolePolicy",
		"PutUserPolicy",
		"PutGroupPolicy",
		"DeleteRolePolicy",
		"DeleteUserPolicy",
		"DeleteGroupPolicy",
		"UpdateAssumeRolePolicy",
		"CreatePolicyVersion",
		"UpdatePermissionSet",
		"AttachManagedPolicyToPermissionSet",
		"DetachManagedPolicyFromPermissionSet",
		"PutInlinePolicyToPermissionSet",
		"DeleteInlinePolicyFromPermissionSet",
	} {
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
					"failed to parse AWS entitlement activity event JSON",
					"event_name", event.EventName,
					"event_id", event.EventID,
					"error", err,
				)
				return err
			}

			activityEvent, ok := mapEntitlementActivityEvent(event, detail)
			if !ok {
				return nil
			}
			if err := c.Emit(ctx, activityEvent); err != nil {
				return fmt.Errorf("emit entitlement activity %T: %w", activityEvent, err)
			}
			emitted++
			return nil
		}); err != nil {
			return fmt.Errorf("enumerate entitlement activity events for %s: %w", eventName, err)
		}
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS entitlement activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSEntitlementActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapEntitlementActivityEvent(
	event api.CloudTrailEvent,
	detail *awsCloudTrailEventDetail,
) (events.ActivityEvent, bool) {
	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)

	switch event.EventName {
	case "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy", "DeleteRolePolicy":
		return mapIAMPrincipalPermissionEvent(event, detail, actor, context, "role")
	case "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "DeleteUserPolicy":
		return mapIAMPrincipalPermissionEvent(event, detail, actor, context, "account")
	case "AttachGroupPolicy", "DetachGroupPolicy", "PutGroupPolicy", "DeleteGroupPolicy":
		return mapIAMPrincipalPermissionEvent(event, detail, actor, context, "group")
	case "UpdateAssumeRolePolicy":
		roleName := firstNonEmpty(
			firstRequestString(detail, "roleName", "RoleName"),
			displayNameFromReference(firstRequestString(detail, "roleArn", "RoleArn")),
		)
		if roleName == "" {
			return nil, false
		}
		target := types.Target{Ref: roleName, Type: "role", DisplayName: displayNameFromReference(roleName)}
		summary := fmt.Sprintf("IAM role trust policy updated for %q", target.DisplayName)
		return newPolicyModifiedEvent(
			event,
			actor,
			context,
			target,
			"role_trust_policy",
			"Updated",
			[]string{"assume_role_policy"},
			summary,
		), true
	case "CreatePolicyVersion":
		policyRef := firstNonEmpty(
			firstRequestString(detail, "policyArn", "PolicyArn"),
			firstRequestString(detail, "policyName", "PolicyName"),
		)
		if policyRef == "" {
			return nil, false
		}
		target := types.Target{Ref: policyRef, Type: "policy", DisplayName: displayNameFromReference(policyRef)}
		versionID := firstResponseString(detail, "versionId", "VersionId")
		summary := fmt.Sprintf("Managed policy %q version created", target.DisplayName)
		modified := newPolicyModifiedEvent(
			event,
			actor,
			context,
			target,
			"managed_policy",
			"Updated",
			[]string{"policy_version"},
			summary,
		)
		modified.NewVersion = versionID
		return modified, true
	case "UpdatePermissionSet":
		permissionSetRef := firstNonEmpty(
			firstRequestString(detail, "permissionSetName", "PermissionSetName"),
			displayNameFromReference(firstRequestString(detail, "permissionSetArn", "PermissionSetArn")),
		)
		if permissionSetRef == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetRef,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetRef),
		}
		summary := fmt.Sprintf("Permission set %q updated", target.DisplayName)
		return newPolicyModifiedEvent(
			event,
			actor,
			context,
			target,
			"permission_set",
			"Updated",
			[]string{"permission_set"},
			summary,
		), true
	case "AttachManagedPolicyToPermissionSet", "DetachManagedPolicyFromPermissionSet":
		permissionSetRef := firstNonEmpty(
			firstRequestString(detail, "permissionSetArn", "PermissionSetArn"),
			firstRequestString(detail, "permissionSetName", "PermissionSetName"),
		)
		policyRef := firstNonEmpty(
			firstRequestString(detail, "policyArn", "PolicyArn"),
			firstRequestString(detail, "managedPolicyArn", "ManagedPolicyArn"),
			firstRequestString(detail, "policyName", "PolicyName"),
		)
		if permissionSetRef == "" || policyRef == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetRef,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetRef),
		}
		permissionName := displayNameFromReference(policyRef)
		grantType := "managed_policy"
		if event.EventName == "AttachManagedPolicyToPermissionSet" {
			return newPermissionGrantedEvent(
				event,
				actor,
				context,
				target,
				policyRef,
				permissionName,
				"permission_set",
				grantType,
				permissionIsPrivileged(permissionName),
			), true
		}
		return newPermissionRevokedEvent(
			event,
			actor,
			context,
			target,
			policyRef,
			permissionName,
			"permission_set",
			"managed_policy_detached",
			permissionIsPrivileged(permissionName),
		), true
	case "PutInlinePolicyToPermissionSet", "DeleteInlinePolicyFromPermissionSet":
		permissionSetRef := firstNonEmpty(
			firstRequestString(detail, "permissionSetArn", "PermissionSetArn"),
			firstRequestString(detail, "permissionSetName", "PermissionSetName"),
		)
		if permissionSetRef == "" {
			return nil, false
		}
		target := types.Target{
			Ref:         permissionSetRef,
			Type:        "permission_set",
			DisplayName: displayNameFromReference(permissionSetRef),
		}
		summary := fmt.Sprintf(
			"Permission set inline policy %s",
			map[string]string{"PutInlinePolicyToPermissionSet": "updated", "DeleteInlinePolicyFromPermissionSet": "deleted"}[event.EventName],
		)
		changeType := map[string]string{"PutInlinePolicyToPermissionSet": "Updated", "DeleteInlinePolicyFromPermissionSet": "Deleted"}[event.EventName]
		return newPolicyModifiedEvent(
			event,
			actor,
			context,
			target,
			"permission_set_inline_policy",
			changeType,
			[]string{"inline_policy"},
			summary,
		), true
	default:
		return nil, false
	}
}

func mapIAMPrincipalPermissionEvent(
	event api.CloudTrailEvent,
	detail *awsCloudTrailEventDetail,
	actor types.Actor,
	context types.EventContext,
	targetType string,
) (events.ActivityEvent, bool) {
	principalNameKey := map[string]string{
		"role":    "roleName",
		"account": "userName",
		"group":   "groupName",
	}[targetType]
	principalIDKey := map[string]string{
		"role":    "roleId",
		"account": "userId",
		"group":   "groupId",
	}[targetType]
	principalRef := firstNonEmpty(
		firstRequestString(detail, principalNameKey, strings.ToUpper(principalNameKey[:1])+principalNameKey[1:]),
		firstRequestString(detail, principalIDKey, strings.ToUpper(principalIDKey[:1])+principalIDKey[1:]),
	)
	if principalRef == "" {
		return nil, false
	}

	target := types.Target{Ref: principalRef, Type: targetType, DisplayName: displayNameFromReference(principalRef)}
	policyRef := firstNonEmpty(
		firstRequestString(detail, "policyArn", "PolicyArn"),
		firstRequestString(detail, "policyName", "PolicyName"),
	)
	if policyRef == "" {
		return nil, false
	}
	permissionName := displayNameFromReference(policyRef)
	permissionScope := targetType
	grantType := "attached"
	if strings.HasPrefix(event.EventName, "Put") {
		grantType = "inline"
	}

	switch event.EventName {
	case "AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy":
		return newPermissionGrantedEvent(
			event,
			actor,
			context,
			target,
			policyRef,
			permissionName,
			permissionScope,
			grantType,
			permissionIsPrivileged(permissionName),
		), true
	case "DetachRolePolicy", "DetachUserPolicy", "DetachGroupPolicy":
		return newPermissionRevokedEvent(
			event,
			actor,
			context,
			target,
			policyRef,
			permissionName,
			permissionScope,
			"detached",
			permissionIsPrivileged(permissionName),
		), true
	case "PutRolePolicy", "PutUserPolicy", "PutGroupPolicy":
		return newPermissionGrantedEvent(
			event,
			actor,
			context,
			target,
			policyRef,
			permissionName,
			permissionScope,
			"inline",
			permissionIsPrivileged(permissionName),
		), true
	case "DeleteRolePolicy", "DeleteUserPolicy", "DeleteGroupPolicy":
		return newPermissionRevokedEvent(
			event,
			actor,
			context,
			target,
			policyRef,
			permissionName,
			permissionScope,
			"inline policy deleted",
			permissionIsPrivileged(permissionName),
		), true
	default:
		return nil, false
	}
}

func newPermissionGrantedEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	permissionRef string,
	permissionName string,
	permissionScope string,
	grantType string,
	privileged bool,
) *events.PermissionGranted {
	return &events.PermissionGranted{
		EventRef:        event.EventID,
		Timestamp:       event.EventTime,
		Actor:           actor,
		Target:          target,
		Context:         context,
		Outcome:         types.EventOutcome{Action: "grant", Result: "success"},
		PermissionRef:   permissionRef,
		PermissionName:  permissionName,
		PermissionScope: permissionScope,
		GrantType:       grantType,
		Privileged:      privileged,
	}
}

func newPermissionRevokedEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	permissionRef string,
	permissionName string,
	permissionScope string,
	revocationReason string,
	privileged bool,
) *events.PermissionRevoked {
	return &events.PermissionRevoked{
		EventRef:         event.EventID,
		Timestamp:        event.EventTime,
		Actor:            actor,
		Target:           target,
		Context:          context,
		Outcome:          types.EventOutcome{Action: "revoke", Result: "success"},
		PermissionRef:    permissionRef,
		PermissionName:   permissionName,
		PermissionScope:  permissionScope,
		RevocationReason: revocationReason,
		WasPrivileged:    privileged,
	}
}

func newPolicyModifiedEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	policyType string,
	changeType string,
	changedProperties []string,
	changeSummary string,
) *events.PolicyModified {
	return &events.PolicyModified{
		EventRef:          event.EventID,
		Timestamp:         event.EventTime,
		Actor:             actor,
		Target:            target,
		Context:           context,
		Outcome:           types.EventOutcome{Action: "modify", Result: "success"},
		PolicyRef:         target.Ref,
		PolicyName:        target.DisplayName,
		PolicyType:        policyType,
		ChangeType:        changeType,
		ChangedProperties: changedProperties,
		ChangeSummary:     changeSummary,
	}
}

func permissionIsPrivileged(permissionName string) bool {
	lower := strings.ToLower(permissionName)
	return strings.Contains(lower, "admin") || strings.Contains(lower, "fullaccess") ||
		strings.Contains(lower, "poweruser")
}

func entitlementResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.PermissionGranted:
		return &event.Timestamp, event.EventRef
	case *events.PermissionRevoked:
		return &event.Timestamp, event.EventRef
	case *events.PolicyModified:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}
