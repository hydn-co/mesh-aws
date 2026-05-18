package activity

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
)

const cognitoUserPoolEventSource = "cognito-idp.amazonaws.com"

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
	Type         string                   `json:"type"`
	UserName     string                   `json:"userName"`
	ARN          string                   `json:"arn"`
	AccountID    string                   `json:"accountId"`
	CredentialID string                   `json:"credentialId"`
	OnBehalfOf   *awsCloudTrailOnBehalfOf `json:"onBehalfOf,omitempty"`
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
	displayName := firstNonEmpty(
		lookupString(detail.AdditionalEventData, "UserName"),
		strings.TrimSpace(detail.UserIdentity.UserName),
		strings.TrimSpace(event.Username),
	)
	ref := firstNonEmpty(
		userIDFromOnBehalfOf(detail.UserIdentity.OnBehalfOf),
		strings.TrimSpace(detail.UserIdentity.UserName),
		lookupString(detail.AdditionalEventData, "UserName"),
		strings.TrimSpace(event.Username),
		strings.TrimSpace(detail.UserIdentity.ARN),
		strings.TrimSpace(detail.UserIdentity.AccountID),
	)
	if ref == "" {
		return types.Actor{}, false
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

func responseStatus(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.ResponseElements, key))
}

func requestString(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.RequestParameters, key))
}

func responseString(detail *awsCloudTrailEventDetail, key string) string {
	return strings.TrimSpace(lookupString(detail.ResponseElements, key))
}

func firstRequestString(detail *awsCloudTrailEventDetail, keys ...string) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, requestString(detail, key))
	}
	return firstNonEmpty(values...)
}

func firstResponseString(detail *awsCloudTrailEventDetail, keys ...string) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, responseString(detail, key))
	}
	return firstNonEmpty(values...)
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
	if len(values) == 0 {
		return ""
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return ""
	}
	stringValue, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue)
}

func userIDFromOnBehalfOf(subject *awsCloudTrailOnBehalfOf) string {
	if subject == nil {
		return ""
	}
	return strings.TrimSpace(subject.UserID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue != "" {
			return trimmedValue
		}
	}
	return ""
}
