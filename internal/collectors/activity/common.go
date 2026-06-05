package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"

	"github.com/hydn-co/mesh-aws/internal/api"
)

const cognitoUserPoolEventSource = "cognito-idp.amazonaws.com"

// cloudTrailClient is the seam every activity collector depends on. It contains only the
// CloudTrail enumeration method the collectors use, so tests can inject a fake client.
type cloudTrailClient interface {
	CloudTrailEventEnumerator(
		ctx context.Context,
		eventName string,
		startTime *time.Time,
	) enumerators.Enumerator[api.CloudTrailEvent]
}

// cloudTrailClientFactory builds a cloudTrailClient from connector credentials and connection
// settings. Collectors set this in their constructor and call it in Init so tests can override it.
type cloudTrailClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (cloudTrailClient, error)

func defaultCloudTrailClientFactory(
	creds *api.AWSCredentials,
	region, sessionToken string,
) (cloudTrailClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

type awsCloudTrailEventDetail struct {
	EventSource         string                    `json:"eventSource"`
	SourceIPAddress     string                    `json:"sourceIPAddress"`
	UserAgent           string                    `json:"userAgent"`
	UserIdentity        awsCloudTrailUserIdentity `json:"userIdentity"`
	AdditionalEventData map[string]any            `json:"additionalEventData"`
	ResponseElements    map[string]any            `json:"responseElements"`
	RequestParameters   map[string]any            `json:"requestParameters"`
	ErrorCode           string                    `json:"errorCode,omitempty"`
	ErrorMessage        string                    `json:"errorMessage,omitempty"`
}

type awsCloudTrailUserIdentity struct {
	OnBehalfOf   *awsCloudTrailOnBehalfOf `json:"onBehalfOf,omitempty"`
	Type         string                   `json:"type"`
	UserName     string                   `json:"userName"`
	ARN          string                   `json:"arn"`
	AccountID    string                   `json:"accountId"`
	CredentialID string                   `json:"credentialId"`
}

type awsCloudTrailOnBehalfOf struct {
	UserID           string `json:"userId"`
	IdentityStoreARN string `json:"identityStoreArn"`
}

func parseCloudTrailEventDetail(event api.CloudTrailEvent) (*awsCloudTrailEventDetail, error) {
	var detail awsCloudTrailEventDetail
	if err := json.Unmarshal([]byte(event.CloudTrailEvent), &detail); err != nil {
		return nil, fmt.Errorf("parse CloudTrail event %s: %w", event.EventID, err)
	}
	return &detail, nil
}

func activityActor(event api.CloudTrailEvent, detail *awsCloudTrailEventDetail) (types.Actor, bool) {
	ref := userIDFromOnBehalfOf(detail.UserIdentity.OnBehalfOf)
	if ref == "" {
		ref = strings.TrimSpace(detail.UserIdentity.UserName)
	}
	if ref == "" {
		ref = strings.TrimSpace(detail.UserIdentity.ARN)
	}
	if ref == "" {
		ref = strings.TrimSpace(detail.UserIdentity.AccountID)
	}
	if ref == "" {
		ref = strings.TrimSpace(event.Username)
	}
	if ref == "" {
		return types.Actor{}, false
	}

	displayName := strings.TrimSpace(detail.UserIdentity.UserName)
	if displayName == "" {
		displayName = lookupString(detail.AdditionalEventData, "UserName")
	}
	if displayName == "" {
		displayName = strings.TrimSpace(event.Username)
	}
	if displayName == "" {
		displayName = ref
	}

	actorType := strings.TrimSpace(detail.UserIdentity.Type)
	if actorType == "" {
		actorType = "unknown"
	}

	return types.Actor{
		Ref:         ref,
		Type:        actorType,
		DisplayName: displayName,
	}, true
}

func activityContext(detail *awsCloudTrailEventDetail) types.EventContext {
	context := types.EventContext{
		IPAddress: detail.SourceIPAddress,
		UserAgent: detail.UserAgent,
	}
	if sessionID := strings.TrimSpace(detail.UserIdentity.CredentialID); sessionID != "" {
		context.SessionID = sessionID
	}
	return context
}

func loginResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.LoginSucceeded:
		return &event.Timestamp, event.EventRef
	case *events.LoginFailed:
		return &event.Timestamp, event.EventRef
	case *events.SessionTerminated:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}

func sessionResumeCursor(payload any) (*time.Time, string) {
	if payload == nil {
		return nil, ""
	}

	switch event := payload.(type) {
	case *events.SessionCreated:
		return &event.Timestamp, event.EventRef
	case *events.SessionTerminated:
		return &event.Timestamp, event.EventRef
	default:
		return nil, ""
	}
}

func collectMergedCloudTrailEvents(
	ctx context.Context,
	client cloudTrailClient,
	eventNames []string,
	startTime *time.Time,
) ([]api.CloudTrailEvent, error) {
	merged := make([]api.CloudTrailEvent, 0)
	for _, eventName := range eventNames {
		eventEnum := client.CloudTrailEventEnumerator(ctx, eventName, startTime)
		if err := enumerators.ForEach(eventEnum, func(event api.CloudTrailEvent) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			merged = append(merged, event)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("enumerate CloudTrail events for %s: %w", eventName, err)
		}
	}

	sortCloudTrailEvents(merged)

	return merged, nil
}

func sortCloudTrailEvents(events []api.CloudTrailEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		left := events[i]
		right := events[j]
		if left.EventTime.Equal(right.EventTime) {
			if left.EventID == right.EventID {
				return left.EventName < right.EventName
			}
			return left.EventID < right.EventID
		}
		return left.EventTime.Before(right.EventTime)
	})
}

func resumeFilteredCloudTrailEvents(
	events []api.CloudTrailEvent,
	resumeTime *time.Time,
	lastEventRef string,
) []api.CloudTrailEvent {
	if resumeTime == nil {
		return events
	}

	filtered := make([]api.CloudTrailEvent, 0, len(events))
	resumeReached := lastEventRef == ""
	for _, event := range events {
		if event.EventTime.Before(*resumeTime) {
			continue
		}
		if event.EventTime.After(*resumeTime) {
			resumeReached = true
			filtered = append(filtered, event)
			continue
		}
		if resumeReached {
			filtered = append(filtered, event)
			continue
		}
		if event.EventID == lastEventRef {
			resumeReached = true
		}
	}

	if lastEventRef != "" && !resumeReached {
		filtered = filtered[:0]
		for _, event := range events {
			if event.EventTime.After(*resumeTime) {
				filtered = append(filtered, event)
			}
		}
	}

	return filtered
}

func responseStatus(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.ResponseElements, key))
}

func requestString(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.RequestParameters, key))
}

func responseString(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.ResponseElements, key))
}

func displayNameFromReference(value string) string {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return ""
	}

	for _, separator := range []string{"/", ":", "#"} {
		if index := strings.LastIndex(trimmedValue, separator); index >= 0 && index < len(trimmedValue)-1 {
			return trimmedValue[index+1:]
		}
	}

	return trimmedValue
}

func lookupString(values map[string]any, key string) string {
	raw, ok := lookupValue(values, key)
	if !ok {
		return ""
	}
	stringValue, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue)
}

func lookupValue(values map[string]any, key string) (any, bool) {
	if len(values) == 0 {
		return nil, false
	}
	raw, ok := values[key]
	if ok && raw != nil {
		return raw, true
	}
	normalizedKey := strings.ToLower(strings.TrimSpace(key))
	for currentKey, value := range values {
		if value == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(currentKey)) == normalizedKey {
			return value, true
		}
	}
	return nil, false
}

func userIDFromOnBehalfOf(subject *awsCloudTrailOnBehalfOf) string {
	if subject == nil {
		return ""
	}
	return strings.TrimSpace(subject.UserID)
}
