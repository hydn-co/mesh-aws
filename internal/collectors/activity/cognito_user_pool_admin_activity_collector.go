package activity

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

// AWSCognitoUserPoolAdminActivityCollector collects Amazon Cognito user pool administrative activity.
type AWSCognitoUserPoolAdminActivityCollector struct {
	*connector.TypedFeatureContext[*options.AWSCognitoUserPoolAdminActivityCollectorOptions, *connector.NoPayload]
	client    cloudTrailClient
	newClient cloudTrailClientFactory
	state     connectorutil.FeatureState
}

// NewAWSCognitoUserPoolAdminActivityCollector constructs the collector with the given feature context.
func NewAWSCognitoUserPoolAdminActivityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSCognitoUserPoolAdminActivityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSCognitoUserPoolAdminActivityCollector{
		TypedFeatureContext: ctx,
		newClient:           defaultCloudTrailClientFactory,
	}
}

func (c *AWSCognitoUserPoolAdminActivityCollector) Init(ctx context.Context) error {
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

func (c *AWSCognitoUserPoolAdminActivityCollector) Start(ctx context.Context) error {
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
		"Starting AWS Cognito user pool admin activity collector",
	)

	var (
		startTime    *time.Time
		lastEventRef string
	)
	if c.Payload != nil && c.Payload.Content != nil {
		if ts, eventRef := cognitoUserPoolResumeCursor(c.Payload.Content); ts != nil {
			startTime = ts
			lastEventRef = eventRef
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelInfo,
				"Resuming AWS Cognito user pool admin activity collector",
				"timestamp",
				startTime.UTC().Format(time.RFC3339Nano),
				"event_ref",
				lastEventRef,
			)
		}
	}

	eventNames := []string{
		"AdminCreateUser",
		"AdminDeleteUser",
		"AdminConfirmSignUp",
		"AdminEnableUser",
		"AdminDisableUser",
		"AdminResetUserPassword",
		"AdminSetUserPassword",
		"AdminAddUserToGroup",
		"AdminRemoveUserFromGroup",
		"CreateGroup",
		"DeleteGroup",
		"AdminUpdateUserAttributes",
		"AdminDeleteUserAttributes",
		"AdminSetUserMFAPreference",
		"AdminSetUserSettings",
		"AdminUpdateAuthEventFeedback",
		"AdminUpdateDeviceStatus",
		"AdminForgetDevice",
		"AdminDisableProviderForUser",
		"AdminLinkProviderForUser",
		"AdminUserGlobalSignOut",
	}
	cloudTrailEvents, err := collectMergedCloudTrailEvents(ctx, c.client, eventNames, startTime)
	if err != nil {
		return fmt.Errorf("collect Cognito user pool admin activity events: %w", err)
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
				"failed to parse AWS Cognito user pool admin activity event JSON",
				"event_name", event.EventName,
				"event_id", event.EventID,
				"error", err,
			)
			return err
		}

		activityEvent, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)
		if !ok {
			continue
		}
		if err := c.Emit(ctx, activityEvent); err != nil {
			return fmt.Errorf("emit Cognito user pool admin activity %T: %w", activityEvent, err)
		}
		emitted++
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"Finished AWS Cognito user pool admin activity collector",
		"emitted",
		emitted,
	)
	return nil
}

func (c *AWSCognitoUserPoolAdminActivityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func mapCognitoUserPoolAdminActivityEvent(
	event api.CloudTrailEvent,
	detail *awsCloudTrailEventDetail,
) (events.ActivityEvent, bool) {
	if detail.EventSource != cognitoUserPoolEventSource {
		return nil, false
	}

	actor, ok := activityActor(event, detail)
	if !ok {
		return nil, false
	}

	context := activityContext(detail)

	switch event.EventName {
	case "AdminCreateUser":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.AccountCreated{
			EventRef:        event.EventID,
			Timestamp:       event.EventTime,
			Actor:           actor,
			Target:          target,
			Context:         context,
			Outcome:         types.EventOutcome{Action: "create", Result: "success"},
			AccountType:     "User",
			SourceDirectory: "Cognito User Pool",
		}, true
	case "AdminDeleteUser":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.AccountDeleted{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "delete", Result: "success"},
			DeletionMethod: "admin_deleted",
		}, true
	case "AdminConfirmSignUp":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.AccountEnabled{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "enable", Result: "success"},
			PreviousStatus: "PendingConfirmation",
			EnabledBy:      event.EventName,
		}, true
	case "AdminEnableUser":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.AccountEnabled{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "enable", Result: "success"},
			PreviousStatus: "Disabled",
			EnabledBy:      event.EventName,
		}, true
	case "AdminDisableUser":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.AccountDisabled{
			EventRef:       event.EventID,
			Timestamp:      event.EventTime,
			Actor:          actor,
			Target:         target,
			Context:        context,
			Outcome:        types.EventOutcome{Action: "disable", Result: "success"},
			Reason:         "administrator disabled user",
			PreviousStatus: "Active",
			DisabledBy:     event.EventName,
		}, true
	case "AdminResetUserPassword":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoPasswordResetEvent(
			event,
			actor,
			context,
			target,
			event.EventName,
			"administrator reset user password",
			true,
			true,
			true,
		), true
	case "AdminSetUserPassword":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		permanent := requestBool(detail, "permanent")
		target := cognitoAccountTarget(username)
		return newCognitoPasswordResetEvent(
			event,
			actor,
			context,
			target,
			event.EventName,
			"administrator set user password",
			false,
			!permanent,
			!permanent,
		), true
	case "AdminAddUserToGroup":
		username := cognitoUsername(detail)
		groupName := cognitoGroupName(detail)
		if username == "" || groupName == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.GroupMemberAdded{
			EventRef:  event.EventID,
			Timestamp: event.EventTime,
			Actor:     actor,
			Target:    target,
			Context:   context,
			Outcome:   types.EventOutcome{Action: "add", Result: "success"},
			GroupRef:  groupName,
			GroupName: groupName,
			GroupType: "Cognito User Pool",
		}, true
	case "AdminRemoveUserFromGroup":
		username := cognitoUsername(detail)
		groupName := cognitoGroupName(detail)
		if username == "" || groupName == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.GroupMemberRemoved{
			EventRef:  event.EventID,
			Timestamp: event.EventTime,
			Actor:     actor,
			Target:    target,
			Context:   context,
			Outcome:   types.EventOutcome{Action: "remove", Result: "success"},
			GroupRef:  groupName,
			GroupName: groupName,
			GroupType: "Cognito User Pool",
		}, true
	case "CreateGroup":
		groupName := cognitoGroupName(detail)
		if groupName == "" {
			return nil, false
		}
		target := cognitoGroupTarget(groupName)
		return &events.GroupCreated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Target:      target,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "create", Result: "success"},
			GroupType:   "Cognito User Pool",
			MailEnabled: false,
		}, true
	case "DeleteGroup":
		groupName := cognitoGroupName(detail)
		if groupName == "" {
			return nil, false
		}
		target := cognitoGroupTarget(groupName)
		return &events.GroupRemoved{
			EventRef:      event.EventID,
			Timestamp:     event.EventTime,
			Actor:         actor,
			Target:        target,
			Context:       context,
			Outcome:       types.EventOutcome{Action: "delete", Result: "success"},
			GroupType:     "Cognito User Pool",
			RemovalReason: "admin_deleted",
		}, true
	case "AdminUpdateUserAttributes":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"account",
			"update",
			fmt.Sprintf("Cognito user attributes updated for %q", target.DisplayName),
			fmt.Sprintf("Amazon Cognito admin updated user attributes for %q.", target.DisplayName),
			[]string{"user_attributes"},
			nil,
		), true
	case "AdminDeleteUserAttributes":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"account",
			"delete",
			fmt.Sprintf("Cognito user attributes deleted for %q", target.DisplayName),
			fmt.Sprintf("Amazon Cognito admin deleted user attributes for %q.", target.DisplayName),
			[]string{"user_attributes"},
			nil,
		), true
	case "AdminSetUserMFAPreference":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		methodKind, methodName, ok := cognitoMFAPreference(detail)
		if !ok {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoMultiFactorUpdatedEvent(event, actor, context, target, methodKind, methodName, "admin"), true
	case "AdminSetUserSettings":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoMultiFactorUpdatedEvent(
			event,
			actor,
			context,
			target,
			types.MultiFactorKindSMS,
			"SMS",
			"admin",
		), true
	case "AdminUpdateAuthEventFeedback":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		eventID := requestString(detail, "eventId")
		feedbackValue := requestString(detail, "feedbackValue")
		target := cognitoAccountTarget(username)
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"security",
			"update",
			fmt.Sprintf("Cognito auth event feedback %s for %q", strings.ToLower(feedbackValue), target.DisplayName),
			fmt.Sprintf(
				"Amazon Cognito admin marked auth event %q as %s for %q.",
				eventID,
				strings.ToLower(feedbackValue),
				target.DisplayName,
			),
			[]string{"auth_event_feedback"},
			nil,
		), true
	case "AdminUpdateDeviceStatus":
		username := cognitoUsername(detail)
		deviceKey := requestString(detail, "deviceKey")
		if username == "" || deviceKey == "" {
			return nil, false
		}
		status := requestString(detail, "deviceRememberedStatus")
		target := cognitoAccountTarget(username)
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"device",
			"update",
			fmt.Sprintf(
				"Cognito device %q marked %s for %q",
				displayNameFromReference(deviceKey),
				status,
				target.DisplayName,
			),
			fmt.Sprintf(
				"Amazon Cognito admin set device %q remembered status to %s for %q.",
				deviceKey,
				status,
				target.DisplayName,
			),
			[]string{"device_remembered_status"},
			[]types.Target{cognitoDeviceTarget(deviceKey)},
		), true
	case "AdminForgetDevice":
		username := cognitoUsername(detail)
		deviceKey := requestString(detail, "deviceKey")
		if username == "" || deviceKey == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"device",
			"delete",
			fmt.Sprintf("Cognito device %q forgotten for %q", displayNameFromReference(deviceKey), target.DisplayName),
			fmt.Sprintf("Amazon Cognito admin forgot device %q for %q.", deviceKey, target.DisplayName),
			[]string{"device"},
			[]types.Target{cognitoDeviceTarget(deviceKey)},
		), true
	case "AdminDisableProviderForUser":
		username := requestObjectString(detail, "User", "ProviderAttributeValue")
		providerName := requestObjectString(detail, "User", "ProviderName")
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		relatedTargets := make([]types.Target, 0, 1)
		if providerName != "" {
			relatedTargets = append(relatedTargets, cognitoIdentityProviderTarget(providerName))
		}
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"identity_provider",
			"delete",
			fmt.Sprintf("Cognito linked provider disabled for %q", target.DisplayName),
			fmt.Sprintf("Amazon Cognito admin disabled linked provider %q for %q.", providerName, target.DisplayName),
			[]string{"linked_provider"},
			relatedTargets,
		), true
	case "AdminLinkProviderForUser":
		destinationUsername := requestObjectString(detail, "DestinationUser", "ProviderAttributeValue")
		sourceProviderName := requestObjectString(detail, "SourceUser", "ProviderName")
		sourceAttributeName := requestObjectString(detail, "SourceUser", "ProviderAttributeName")
		sourceAttributeValue := requestObjectString(detail, "SourceUser", "ProviderAttributeValue")
		if destinationUsername == "" {
			return nil, false
		}
		target := cognitoAccountTarget(destinationUsername)
		relatedTargets := make([]types.Target, 0, 2)
		if sourceProviderName != "" {
			relatedTargets = append(relatedTargets, cognitoIdentityProviderTarget(sourceProviderName))
		}
		if sourceAttributeValue != "" {
			relatedTargets = append(
				relatedTargets,
				types.Target{
					Ref:         sourceAttributeValue,
					Type:        "external_identity",
					DisplayName: displayNameFromReference(sourceAttributeValue),
				},
			)
		}
		sourceDescription := sourceProviderName
		if sourceAttributeName != "" && sourceAttributeValue != "" {
			sourceDescription = fmt.Sprintf("%s:%s", sourceAttributeName, sourceAttributeValue)
		}
		return newCognitoAdministrativeActionEvent(
			event,
			actor,
			context,
			target,
			"identity_provider",
			"create",
			fmt.Sprintf("Cognito identity provider %q linked to %q", sourceProviderName, target.DisplayName),
			fmt.Sprintf(
				"Amazon Cognito admin linked external identity %q to user %q.",
				sourceDescription,
				target.DisplayName,
			),
			[]string{"linked_provider"},
			relatedTargets,
		), true
	case "AdminUserGlobalSignOut":
		username := cognitoUsername(detail)
		if username == "" {
			return nil, false
		}
		target := cognitoAccountTarget(username)
		return &events.SessionTerminated{
			EventRef:    event.EventID,
			Timestamp:   event.EventTime,
			Actor:       actor,
			Target:      target,
			Context:     context,
			Outcome:     types.EventOutcome{Action: "logout", Result: "success"},
			Reason:      "admin_global_signout",
			SessionType: "cognito",
		}, true
	default:
		return nil, false
	}
}

func cognitoUserPoolResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.AccountCreated:
		return &event.Timestamp, event.EventRef
	case *events.AccountDeleted:
		return &event.Timestamp, event.EventRef
	case *events.AccountEnabled:
		return &event.Timestamp, event.EventRef
	case *events.AccountDisabled:
		return &event.Timestamp, event.EventRef
	case *events.PasswordReset:
		return &event.Timestamp, event.EventRef
	case *events.GroupMemberAdded:
		return &event.Timestamp, event.EventRef
	case *events.GroupMemberRemoved:
		return &event.Timestamp, event.EventRef
	case *events.GroupCreated:
		return &event.Timestamp, event.EventRef
	case *events.GroupRemoved:
		return &event.Timestamp, event.EventRef
	case *events.MultiFactorUpdated:
		return &event.Timestamp, event.EventRef
	case *events.SessionTerminated:
		return &event.Timestamp, event.EventRef
	case *events.AdministrativeActionPerformed:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}

func cognitoUsername(detail *awsCloudTrailEventDetail) string {
	return requestString(detail, "username")
}

func cognitoGroupName(detail *awsCloudTrailEventDetail) string {
	return requestString(detail, "groupName")
}

func cognitoAccountTarget(username string) types.Target {
	return types.Target{Ref: username, Type: "account", DisplayName: displayNameFromReference(username)}
}

func cognitoGroupTarget(groupName string) types.Target {
	return types.Target{Ref: groupName, Type: "group", DisplayName: displayNameFromReference(groupName)}
}

func cognitoDeviceTarget(deviceKey string) types.Target {
	return types.Target{Ref: deviceKey, Type: "device", DisplayName: displayNameFromReference(deviceKey)}
}

func cognitoIdentityProviderTarget(providerName string) types.Target {
	return types.Target{
		Ref:         providerName,
		Type:        "identity_provider",
		DisplayName: displayNameFromReference(providerName),
	}
}

func cognitoMFAPreference(detail *awsCloudTrailEventDetail) (types.MultiFactorKind, string, bool) {
	type mfaSetting struct {
		key   string
		kind  types.MultiFactorKind
		label string
	}

	settings := []mfaSetting{
		{key: "EmailMfaSettings", kind: types.MultiFactorKindEmail, label: "Email"},
		{key: "SMSMfaSettings", kind: types.MultiFactorKindSMS, label: "SMS"},
		{key: "SoftwareTokenMfaSettings", kind: types.MultiFactorKindTOTP, label: "TOTP"},
		{key: "WebAuthnMfaSettings", kind: types.MultiFactorKindPasskey, label: "Passkey"},
	}

	labels := make([]string, 0, len(settings))
	preferredKind := types.MultiFactorKindUnknown
	firstEnabledKind := types.MultiFactorKindUnknown

	for _, setting := range settings {
		settingObject := requestObject(detail, setting.key)
		if settingObject == nil {
			continue
		}

		labels = append(labels, setting.label)
		enabled := requestObjectBool(settingObject, "Enabled")
		preferred := requestObjectBool(settingObject, "PreferredMfa")
		if preferred && preferredKind == types.MultiFactorKindUnknown {
			preferredKind = setting.kind
		}
		if enabled && firstEnabledKind == types.MultiFactorKindUnknown {
			firstEnabledKind = setting.kind
		}
	}

	if len(labels) == 0 {
		return types.MultiFactorKindUnknown, "", false
	}

	methodKind := preferredKind
	if methodKind == types.MultiFactorKindUnknown {
		methodKind = firstEnabledKind
	}
	if methodKind == types.MultiFactorKindUnknown {
		methodKind = types.MultiFactorKindOther
	}

	return methodKind, strings.Join(labels, ", "), true
}

func requestObject(detail *awsCloudTrailEventDetail, key string) map[string]any {
	raw, ok := lookupValue(detail.RequestParameters, key)
	if !ok {
		return nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return object
}

func requestObjectString(detail *awsCloudTrailEventDetail, objectKey string, field string) string {
	return requestObjectStringFromMap(requestObject(detail, objectKey), field)
}

func requestObjectStringFromMap(values map[string]any, field string) string {
	return lookupString(values, field)
}

func requestObjectBool(values map[string]any, field string) bool {
	raw, ok := lookupValue(values, field)
	if !ok {
		return false
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	case float64:
		return value != 0
	}
	return false
}

func newCognitoMultiFactorUpdatedEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	methodKind types.MultiFactorKind,
	methodName string,
	updatedBy string,
) *events.MultiFactorUpdated {
	return &events.MultiFactorUpdated{
		EventRef:   event.EventID,
		Timestamp:  event.EventTime,
		Actor:      actor,
		Target:     target,
		Context:    context,
		Outcome:    types.EventOutcome{Action: "update", Result: "success"},
		MethodRef:  target.Ref,
		MethodKind: methodKind,
		MethodName: methodName,
		UpdatedBy:  updatedBy,
	}
}

func requestBool(detail *awsCloudTrailEventDetail, key string) bool {
	raw, ok := lookupValue(detail.RequestParameters, key)
	if !ok {
		return false
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	case float64:
		return value != 0
	}
	return false
}

func newCognitoPasswordResetEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	resetMethod string,
	resetReason string,
	notificationSent bool,
	temporaryPassword bool,
	mustChangeOnLogin bool,
) *events.PasswordReset {
	return &events.PasswordReset{
		EventRef:          event.EventID,
		Timestamp:         event.EventTime,
		Actor:             actor,
		Target:            target,
		Context:           context,
		Outcome:           types.EventOutcome{Action: "reset", Result: "success"},
		ResetMethod:       resetMethod,
		ResetReason:       resetReason,
		NotificationSent:  notificationSent,
		TemporaryPassword: temporaryPassword,
		MustChangeOnLogin: mustChangeOnLogin,
	}
}

func newCognitoAdministrativeActionEvent(
	event api.CloudTrailEvent,
	actor types.Actor,
	context types.EventContext,
	target types.Target,
	category string,
	action string,
	summary string,
	description string,
	changedProperties []string,
	relatedTargets []types.Target,
) *events.AdministrativeActionPerformed {
	return &events.AdministrativeActionPerformed{
		EventRef:          event.EventID,
		Timestamp:         event.EventTime,
		Actor:             actor,
		Target:            target,
		Context:           context,
		Outcome:           types.EventOutcome{Action: action, Result: "success"},
		Category:          category,
		Summary:           summary,
		Description:       description,
		Source:            cognitoUserPoolEventSource,
		ChangedProperties: changedProperties,
		RelatedTargets:    relatedTargets,
	}
}
