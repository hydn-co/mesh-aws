package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const cloudtrailLookupEventsTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"

// CloudTrailEvent represents a single event returned by the LookupEvents API.
type CloudTrailEvent struct {
	EventID         string
	EventName       string
	EventTime       time.Time
	Username        string
	CloudTrailEvent string // raw JSON string of the full event detail
}

// cloudtrailLookupEventsRequest is the JSON request body for LookupEvents.
type cloudtrailLookupEventsRequest struct {
	StartTime        *int64                      `json:"StartTime,omitempty"`
	NextToken        string                      `json:"NextToken,omitempty"`
	LookupAttributes []cloudtrailLookupAttribute `json:"LookupAttributes,omitempty"`
	MaxResults       int                         `json:"MaxResults,omitempty"`
}

type cloudtrailLookupAttribute struct {
	AttributeKey   string `json:"AttributeKey"`
	AttributeValue string `json:"AttributeValue"`
}

// cloudtrailLookupEventsResponse is the JSON response body from LookupEvents.
type cloudtrailLookupEventsResponse struct {
	NextToken string                `json:"NextToken"`
	Events    []cloudtrailEventJSON `json:"Events"`
}

type cloudtrailEventJSON struct {
	EventID         string  `json:"EventId"`
	EventName       string  `json:"EventName"`
	Username        string  `json:"Username"`
	CloudTrailEvent string  `json:"CloudTrailEvent"`
	EventTime       float64 `json:"EventTime"`
}

// LookupEvents returns one page of CloudTrail events filtered by event name.
// startTime is optional (nil means no lower bound). nextToken is optional (empty = first page).
func (c *Client) LookupEvents(
	ctx context.Context,
	eventName string,
	startTime *time.Time,
	nextToken string,
) ([]CloudTrailEvent, string, error) {
	req := cloudtrailLookupEventsRequest{
		LookupAttributes: []cloudtrailLookupAttribute{
			{AttributeKey: "EventName", AttributeValue: eventName},
		},
		MaxResults: 50,
	}
	if startTime != nil {
		unix := startTime.Unix()
		req.StartTime = &unix
	}
	if nextToken != "" {
		req.NextToken = nextToken
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("marshal cloudtrail request: %w", err)
	}

	data, err := c.cloudtrailPost(ctx, cloudtrailLookupEventsTarget, body)
	if err != nil {
		return nil, "", fmt.Errorf("cloudtrail lookup events: %w", err)
	}

	var resp cloudtrailLookupEventsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse cloudtrail response: %w", err)
	}

	events := make([]CloudTrailEvent, 0, len(resp.Events))
	for _, e := range resp.Events {
		events = append(events, CloudTrailEvent{
			EventID:         e.EventID,
			EventName:       e.EventName,
			EventTime:       time.Unix(int64(e.EventTime), 0).UTC(),
			Username:        e.Username,
			CloudTrailEvent: e.CloudTrailEvent,
		})
	}
	return events, resp.NextToken, nil
}
