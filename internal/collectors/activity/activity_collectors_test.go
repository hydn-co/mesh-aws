package activity

import (
	"testing"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldMapConsoleLoginSucceededWhenConsoleLoginSucceeds(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-console-success",
		EventName: "ConsoleLogin",
		EventTime: time.Date(2026, 5, 14, 18, 1, 0, 0, time.UTC),
	}
	detail := &awsCloudTrailEventDetail{
		SourceIPAddress: "192.0.2.10",
		UserAgent:       "Mozilla/5.0",
		UserIdentity: awsCloudTrailUserIdentity{
			Type:     "IAMUser",
			UserName: "alice",
		},
		ResponseElements: map[string]any{"ConsoleLogin": "Success"},
	}

	mapped, ok := mapLoginActivityEvent(event, detail)

	require.True(t, ok)
	login, ok := mapped.(*events.LoginSucceeded)
	require.True(t, ok)
	assert.Equal(t, "evt-console-success", login.EventRef)
	assert.Equal(t, "alice", login.Actor.Ref)
	assert.Equal(t, "console", login.LoginType)
	assert.Equal(t, "success", login.Outcome.Result)
}

func TestShouldMapConsoleLogoutWhenLogoutUserOccurs(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-console-logout",
		EventName: "LogoutUser",
		EventTime: time.Date(2026, 5, 14, 18, 1, 30, 0, time.UTC),
		Username:  "alice@example.com",
	}
	detail := &awsCloudTrailEventDetail{
		SourceIPAddress: "192.0.2.11",
		UserAgent:       "Mozilla/5.0",
		UserIdentity: awsCloudTrailUserIdentity{
			Type:         "IAMUser",
			UserName:     "alice@example.com",
			CredentialID: "session-logout",
		},
	}

	mapped, ok := mapLoginActivityEvent(event, detail)

	require.True(t, ok)
	terminated, ok := mapped.(*events.SessionTerminated)
	require.True(t, ok)
	assert.Equal(t, "evt-console-logout", terminated.EventRef)
	assert.Equal(t, "logout", terminated.Reason)
	assert.Equal(t, "console", terminated.SessionType)
	assert.Equal(t, "success", terminated.Outcome.Result)
}

func TestShouldMapCredentialVerificationFailureWhenVerificationFails(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-sso-failure",
		EventName: "CredentialVerification",
		EventTime: time.Date(2026, 5, 14, 18, 2, 0, 0, time.UTC),
	}
	detail := &awsCloudTrailEventDetail{
		SourceIPAddress: "198.51.100.10",
		UserIdentity: awsCloudTrailUserIdentity{
			Type: "IdentityCenterUser",
			OnBehalfOf: &awsCloudTrailOnBehalfOf{
				UserID: "94d00cd8-e9e6-4810-b177-b08e84775435",
			},
		},
		AdditionalEventData: map[string]any{"UserName": "alice@example.com"},
		ResponseElements:    map[string]any{"CredentialVerification": "Failure"},
		ErrorMessage:        "incorrect password",
	}

	mapped, ok := mapLoginActivityEvent(event, detail)

	require.True(t, ok)
	login, ok := mapped.(*events.LoginFailed)
	require.True(t, ok)
	assert.Equal(t, "94d00cd8-e9e6-4810-b177-b08e84775435", login.Actor.Ref)
	assert.Equal(t, "alice@example.com", login.Actor.DisplayName)
	assert.Equal(t, "sso", login.LoginType)
	assert.Equal(t, "incorrect password", login.FailureReason)
}

func TestShouldMapLogoutWhenSessionTerminates(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-logout",
		EventName: "Logout",
		EventTime: time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC),
		Username:  "alice@example.com",
	}
	detail := &awsCloudTrailEventDetail{
		SourceIPAddress: "203.0.113.10",
		UserAgent:       "Mozilla/5.0",
		UserIdentity: awsCloudTrailUserIdentity{
			Type:         "IdentityCenterUser",
			CredentialID: "session-123",
			OnBehalfOf: &awsCloudTrailOnBehalfOf{
				UserID: "94d00cd8-e9e6-4810-b177-b08e84775435",
			},
		},
		AdditionalEventData: map[string]any{"UserName": "alice@example.com"},
	}

	mapped, ok := mapSessionActivityEvent(event, detail)

	require.True(t, ok)
	terminated, ok := mapped.(*events.SessionTerminated)
	require.True(t, ok)
	assert.Equal(t, "evt-logout", terminated.EventRef)
	assert.Equal(t, "94d00cd8-e9e6-4810-b177-b08e84775435", terminated.Actor.Ref)
	assert.Equal(t, "session-123", terminated.Context.SessionID)
	assert.Equal(t, "logout", terminated.Reason)
	assert.Equal(t, "success", terminated.Outcome.Result)
}

func TestShouldResumeMergedCloudTrailEventsGivenSavedEventRefAtSharedTimestamp(t *testing.T) {
	resumeAt := time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC)
	events := []api.CloudTrailEvent{
		{EventID: "b", EventName: "DeleteUser", EventTime: resumeAt},
		{EventID: "a", EventName: "CreateUser", EventTime: resumeAt},
		{EventID: "c", EventName: "CloseAccount", EventTime: resumeAt.Add(time.Second)},
	}

	sortCloudTrailEvents(events)
	filtered := resumeFilteredCloudTrailEvents(events, &resumeAt, "a")

	require.Len(t, filtered, 2)
	assert.Equal(t, "b", filtered[0].EventID)
	assert.Equal(t, "c", filtered[1].EventID)
}

func TestShouldResumeAfterTimestampGivenSavedEventRefIsMissing(t *testing.T) {
	resumeAt := time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC)
	events := []api.CloudTrailEvent{
		{EventID: "a", EventName: "CreateUser", EventTime: resumeAt},
		{EventID: "b", EventName: "DeleteUser", EventTime: resumeAt},
		{EventID: "c", EventName: "CloseAccount", EventTime: resumeAt.Add(time.Second)},
	}

	sortCloudTrailEvents(events)
	filtered := resumeFilteredCloudTrailEvents(events, &resumeAt, "missing")

	require.Len(t, filtered, 1)
	assert.Equal(t, "c", filtered[0].EventID)
}
