package activity

import (
	"testing"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldMapCognitoLifecycleEventsWhenAdminAndGroupChangesOccur(t *testing.T) {
	testCases := []struct {
		name      string
		eventName string
		request   map[string]any
		assertFn  func(*testing.T, events.ActivityEvent)
	}{
		{
			name:      "admin create user",
			eventName: "AdminCreateUser",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				created, ok := mapped.(*events.AccountCreated)
				require.True(t, ok)
				assert.Equal(t, "jane.doe", created.Target.Ref)
				assert.Equal(t, "User", created.AccountType)
				assert.Equal(t, "Cognito User Pool", created.SourceDirectory)
			},
		},
		{
			name:      "admin delete user",
			eventName: "AdminDeleteUser",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				deleted, ok := mapped.(*events.AccountDeleted)
				require.True(t, ok)
				assert.Equal(t, "jane.doe", deleted.Target.Ref)
				assert.Equal(t, "admin_deleted", deleted.DeletionMethod)
				assert.Equal(t, "", deleted.PreviousStatus)
			},
		},
		{
			name:      "create group",
			eventName: "CreateGroup",
			request:   map[string]any{"groupName": "admins"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				created, ok := mapped.(*events.GroupCreated)
				require.True(t, ok)
				assert.Equal(t, "admins", created.Target.Ref)
				assert.Equal(t, "Cognito User Pool", created.GroupType)
			},
		},
		{
			name:      "delete group",
			eventName: "DeleteGroup",
			request:   map[string]any{"groupName": "admins"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				removed, ok := mapped.(*events.GroupRemoved)
				require.True(t, ok)
				assert.Equal(t, "admins", removed.Target.Ref)
				assert.Equal(t, "Cognito User Pool", removed.GroupType)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := api.CloudTrailEvent{
				EventID:   "evt-" + testCase.eventName,
				EventName: testCase.eventName,
				EventTime: time.Date(2026, 5, 14, 20, 0, 0, 0, time.UTC),
				Username:  "admin@example.com",
			}
			detail := &awsCloudTrailEventDetail{
				EventSource:       cognitoUserPoolEventSource,
				RequestParameters: testCase.request,
				UserIdentity: awsCloudTrailUserIdentity{
					Type:     "IAMUser",
					UserName: "admin@example.com",
				},
			}

			mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

			require.True(t, ok)
			require.NotNil(t, mapped)
			testCase.assertFn(t, mapped)
		})
	}
}

func TestShouldMapCognitoGroupMembershipAndStatusEventsWhenAdminChangesOccur(t *testing.T) {
	testCases := []struct {
		name      string
		eventName string
		request   map[string]any
		assertFn  func(*testing.T, events.ActivityEvent)
	}{
		{
			name:      "admin add user to group",
			eventName: "AdminAddUserToGroup",
			request:   map[string]any{"groupName": "admins", "username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				added, ok := mapped.(*events.GroupMemberAdded)
				require.True(t, ok)
				assert.Equal(t, "admins", added.GroupRef)
				assert.Equal(t, "jane.doe", added.Target.Ref)
				assert.Equal(t, "Cognito User Pool", added.GroupType)
			},
		},
		{
			name:      "admin remove user from group",
			eventName: "AdminRemoveUserFromGroup",
			request:   map[string]any{"groupName": "admins", "username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				removed, ok := mapped.(*events.GroupMemberRemoved)
				require.True(t, ok)
				assert.Equal(t, "admins", removed.GroupRef)
				assert.Equal(t, "jane.doe", removed.Target.Ref)
				assert.Equal(t, "Cognito User Pool", removed.GroupType)
			},
		},
		{
			name:      "admin confirm sign up",
			eventName: "AdminConfirmSignUp",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				enabled, ok := mapped.(*events.AccountEnabled)
				require.True(t, ok)
				assert.Equal(t, "PendingConfirmation", enabled.PreviousStatus)
				assert.Equal(t, "AdminConfirmSignUp", enabled.EnabledBy)
			},
		},
		{
			name:      "admin enable user",
			eventName: "AdminEnableUser",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				enabled, ok := mapped.(*events.AccountEnabled)
				require.True(t, ok)
				assert.Equal(t, "Disabled", enabled.PreviousStatus)
				assert.Equal(t, "AdminEnableUser", enabled.EnabledBy)
			},
		},
		{
			name:      "admin disable user",
			eventName: "AdminDisableUser",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				disabled, ok := mapped.(*events.AccountDisabled)
				require.True(t, ok)
				assert.Equal(t, "Active", disabled.PreviousStatus)
				assert.Equal(t, "AdminDisableUser", disabled.DisabledBy)
			},
		},
		{
			name:      "admin reset user password",
			eventName: "AdminResetUserPassword",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				reset, ok := mapped.(*events.PasswordReset)
				require.True(t, ok)
				assert.Equal(t, "AdminResetUserPassword", reset.ResetMethod)
				assert.True(t, reset.NotificationSent)
				assert.True(t, reset.TemporaryPassword)
				assert.True(t, reset.MustChangeOnLogin)
			},
		},
		{
			name:      "admin set user password",
			eventName: "AdminSetUserPassword",
			request:   map[string]any{"username": "jane.doe", "permanent": false},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				reset, ok := mapped.(*events.PasswordReset)
				require.True(t, ok)
				assert.Equal(t, "AdminSetUserPassword", reset.ResetMethod)
				assert.False(t, reset.NotificationSent)
				assert.True(t, reset.TemporaryPassword)
				assert.True(t, reset.MustChangeOnLogin)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := api.CloudTrailEvent{
				EventID:   "evt-" + testCase.eventName,
				EventName: testCase.eventName,
				EventTime: time.Date(2026, 5, 14, 20, 1, 0, 0, time.UTC),
				Username:  "admin@example.com",
			}
			detail := &awsCloudTrailEventDetail{
				EventSource:       cognitoUserPoolEventSource,
				RequestParameters: testCase.request,
				UserIdentity: awsCloudTrailUserIdentity{
					Type:     "IAMUser",
					UserName: "admin@example.com",
				},
			}

			mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

			require.True(t, ok)
			require.NotNil(t, mapped)
			testCase.assertFn(t, mapped)
		})
	}
}

func TestShouldMapCognitoAdministrativeActionWhenAttributesChangeOccur(t *testing.T) {
	testCases := []struct {
		name      string
		eventName string
		assertFn  func(*testing.T, events.ActivityEvent)
	}{
		{
			name:      "admin update user attributes",
			eventName: "AdminUpdateUserAttributes",
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "account", activity.Category)
				assert.Equal(t, cognitoUserPoolEventSource, activity.Source)
				assert.NotEmpty(t, activity.ChangedProperties)
			},
		},
		{
			name:      "admin delete user attributes",
			eventName: "AdminDeleteUserAttributes",
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "account", activity.Category)
				assert.Equal(t, cognitoUserPoolEventSource, activity.Source)
				assert.NotEmpty(t, activity.ChangedProperties)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := api.CloudTrailEvent{
				EventID:   "evt-" + testCase.eventName,
				EventName: testCase.eventName,
				EventTime: time.Date(2026, 5, 14, 20, 2, 0, 0, time.UTC),
				Username:  "admin@example.com",
			}
			detail := &awsCloudTrailEventDetail{
				EventSource:       cognitoUserPoolEventSource,
				RequestParameters: map[string]any{"username": "jane.doe"},
				UserIdentity: awsCloudTrailUserIdentity{
					Type:     "IAMUser",
					UserName: "admin@example.com",
				},
			}

			mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

			require.True(t, ok)
			require.NotNil(t, mapped)
			testCase.assertFn(t, mapped)
		})
	}
}

func TestShouldSkipWhenEventSourceIsNotCognitoUserPools(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-non-cognito",
		EventName: "AdminDeleteUser",
		EventTime: time.Date(2026, 5, 14, 20, 3, 0, 0, time.UTC),
		Username:  "admin@example.com",
	}
	detail := &awsCloudTrailEventDetail{
		EventSource:       "cognito-identity.amazonaws.com",
		RequestParameters: map[string]any{"username": "jane.doe"},
		UserIdentity: awsCloudTrailUserIdentity{
			Type:     "IAMUser",
			UserName: "admin@example.com",
		},
	}

	mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

	require.False(t, ok)
	assert.Nil(t, mapped)
}

func TestShouldMapCognitoMfaPreferenceAndSignOutEventsWhenAdminChangesOccur(t *testing.T) {
	testCases := []struct {
		name      string
		eventName string
		request   map[string]any
		assertFn  func(*testing.T, events.ActivityEvent)
	}{
		{
			name:      "admin set user mfa preference",
			eventName: "AdminSetUserMFAPreference",
			request: map[string]any{
				"username": "jane.doe",
				"SMSMfaSettings": map[string]any{
					"Enabled":      true,
					"PreferredMfa": true,
				},
				"SoftwareTokenMfaSettings": map[string]any{
					"Enabled":      true,
					"PreferredMfa": false,
				},
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				updated, ok := mapped.(*events.MultiFactorUpdated)
				require.True(t, ok)
				assert.Equal(t, "jane.doe", updated.Target.Ref)
				assert.Equal(t, "admin", updated.UpdatedBy)
				assert.Equal(t, types.MultiFactorKindSMS, updated.MethodKind)
				assert.Contains(t, updated.MethodName, "SMS")
				assert.Contains(t, updated.MethodName, "TOTP")
			},
		},
		{
			name:      "admin set user settings",
			eventName: "AdminSetUserSettings",
			request: map[string]any{
				"username": "jane.doe",
				"MFAOptions": []any{
					map[string]any{"AttributeName": "phone_number", "DeliveryMedium": "SMS"},
				},
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				updated, ok := mapped.(*events.MultiFactorUpdated)
				require.True(t, ok)
				assert.Equal(t, "jane.doe", updated.Target.Ref)
				assert.Equal(t, "admin", updated.UpdatedBy)
				assert.Equal(t, types.MultiFactorKindSMS, updated.MethodKind)
				assert.Equal(t, "SMS", updated.MethodName)
			},
		},
		{
			name:      "admin global sign out",
			eventName: "AdminUserGlobalSignOut",
			request:   map[string]any{"username": "jane.doe"},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				terminated, ok := mapped.(*events.SessionTerminated)
				require.True(t, ok)
				assert.Equal(t, "jane.doe", terminated.Target.Ref)
				assert.Equal(t, "admin_global_signout", terminated.Reason)
				assert.Equal(t, "cognito", terminated.SessionType)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := api.CloudTrailEvent{
				EventID:   "evt-" + testCase.eventName,
				EventName: testCase.eventName,
				EventTime: time.Date(2026, 5, 14, 20, 4, 0, 0, time.UTC),
				Username:  "admin@example.com",
			}
			detail := &awsCloudTrailEventDetail{
				EventSource:       cognitoUserPoolEventSource,
				RequestParameters: testCase.request,
				UserIdentity: awsCloudTrailUserIdentity{
					Type:     "IAMUser",
					UserName: "admin@example.com",
				},
			}

			mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

			require.True(t, ok)
			require.NotNil(t, mapped)
			testCase.assertFn(t, mapped)
		})
	}
}

func TestShouldMapCognitoDeviceProviderAndFeedbackEventsWhenAdminChangesOccur(t *testing.T) {
	testCases := []struct {
		name      string
		eventName string
		request   map[string]any
		assertFn  func(*testing.T, events.ActivityEvent)
	}{
		{
			name:      "admin update device status",
			eventName: "AdminUpdateDeviceStatus",
			request: map[string]any{
				"Username":               "jane.doe",
				"DeviceKey":              "us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
				"DeviceRememberedStatus": "remembered",
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "device", activity.Category)
				assert.Equal(t, "update", activity.Outcome.Action)
				assert.Len(t, activity.RelatedTargets, 1)
				assert.Equal(t, "device", activity.RelatedTargets[0].Type)
				assert.Contains(t, activity.ChangedProperties, "device_remembered_status")
			},
		},
		{
			name:      "admin forget device",
			eventName: "AdminForgetDevice",
			request: map[string]any{
				"Username":  "jane.doe",
				"DeviceKey": "us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE22222",
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "device", activity.Category)
				assert.Equal(t, "delete", activity.Outcome.Action)
				assert.Len(t, activity.RelatedTargets, 1)
				assert.Equal(t, "device", activity.RelatedTargets[0].Type)
				assert.Contains(t, activity.ChangedProperties, "device")
			},
		},
		{
			name:      "admin disable provider for user",
			eventName: "AdminDisableProviderForUser",
			request: map[string]any{
				"User": map[string]any{
					"ProviderAttributeValue": "jane.doe",
					"ProviderName":           "Cognito",
				},
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "identity_provider", activity.Category)
				assert.Equal(t, "delete", activity.Outcome.Action)
				assert.NotEmpty(t, activity.RelatedTargets)
			},
		},
		{
			name:      "admin link provider for user",
			eventName: "AdminLinkProviderForUser",
			request: map[string]any{
				"DestinationUser": map[string]any{
					"ProviderAttributeValue": "jane.doe",
					"ProviderName":           "Cognito",
				},
				"SourceUser": map[string]any{
					"ProviderAttributeName":  "Cognito_Subject",
					"ProviderAttributeValue": "123456789012345",
					"ProviderName":           "Google",
				},
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "identity_provider", activity.Category)
				assert.Equal(t, "create", activity.Outcome.Action)
				assert.NotEmpty(t, activity.RelatedTargets)
				assert.Equal(t, "jane.doe", activity.Target.Ref)
			},
		},
		{
			name:      "admin update auth event feedback",
			eventName: "AdminUpdateAuthEventFeedback",
			request: map[string]any{
				"Username":      "jane.doe",
				"EventId":       "evt-risk-123",
				"FeedbackValue": "Valid",
			},
			assertFn: func(t *testing.T, mapped events.ActivityEvent) {
				activity, ok := mapped.(*events.AdministrativeActionPerformed)
				require.True(t, ok)
				assert.Equal(t, "security", activity.Category)
				assert.Equal(t, "update", activity.Outcome.Action)
				assert.Contains(t, activity.Summary, "valid")
				assert.Contains(t, activity.ChangedProperties, "auth_event_feedback")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := api.CloudTrailEvent{
				EventID:   "evt-" + testCase.eventName,
				EventName: testCase.eventName,
				EventTime: time.Date(2026, 5, 14, 20, 5, 0, 0, time.UTC),
				Username:  "admin@example.com",
			}
			detail := &awsCloudTrailEventDetail{
				EventSource:       cognitoUserPoolEventSource,
				RequestParameters: testCase.request,
				UserIdentity: awsCloudTrailUserIdentity{
					Type:     "IAMUser",
					UserName: "admin@example.com",
				},
			}

			mapped, ok := mapCognitoUserPoolAdminActivityEvent(event, detail)

			require.True(t, ok)
			require.NotNil(t, mapped)
			testCase.assertFn(t, mapped)
		})
	}
}
