package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// cloudTrailEventDetail is the parsed structure of the CloudTrailEvent JSON string.
type cloudTrailEventDetail struct {
	EventID         string                 `json:"eventID"`
	EventTime       time.Time              `json:"eventTime"`
	SourceIPAddress string                 `json:"sourceIPAddress"`
	UserAgent       string                 `json:"userAgent"`
	UserIdentity    cloudTrailUserIdentity `json:"userIdentity"`
	ResponseElements map[string]string     `json:"responseElements"`
	ErrorCode       string                 `json:"errorCode,omitempty"`
	ErrorMessage    string                 `json:"errorMessage,omitempty"`
}

type cloudTrailUserIdentity struct {
	Type     string `json:"type"`
	UserName string `json:"userName"`
	ARN      string `json:"arn"`
}

// CloudTrailActivityCollector collects ConsoleLogin events from CloudTrail.
type CloudTrailActivityCollector struct {
	ctx *connector.TypedFeatureContext[*options.ActivityOptions, *payloads.ActivityResumePayload]
}

// NewCloudTrailActivityCollector constructs the collector with the given feature context.
func NewCloudTrailActivityCollector(ctx *connector.TypedFeatureContext[*options.ActivityOptions, *payloads.ActivityResumePayload]) runner.Feature {
	return &CloudTrailActivityCollector{ctx: ctx}
}

func (c *CloudTrailActivityCollector) Init(_ context.Context) error { return nil }
func (c *CloudTrailActivityCollector) Stop(_ context.Context) error { return nil }

func (c *CloudTrailActivityCollector) Start(ctx context.Context) error {
	const name = "cloudtrail-activity-collector"
	logCollectStart(name)

	creds, err := credentials.Parse(c.ctx.GetCredentials())
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.New(ctx, creds)
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("create AWS client: %w", err)
	}

	input := &cloudtrail.LookupEventsInput{
		LookupAttributes: []cttypes.LookupAttribute{
			{
				AttributeKey:   cttypes.LookupAttributeKeyEventName,
				AttributeValue: aws.String("ConsoleLogin"),
			},
		},
	}

	// Support resume from last event time.
	if payload := c.ctx.GetPayload(); payload != nil && payload.LastEventTime != nil {
		input.StartTime = payload.LastEventTime
	}

	count := 0
	paginator := cloudtrail.NewLookupEventsPaginator(client.CloudTrail, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			logCollectError(name, err)
			return fmt.Errorf("lookup CloudTrail events: %w", err)
		}

		for _, e := range page.Events {
			if e.CloudTrailEvent == nil {
				continue
			}

			var detail cloudTrailEventDetail
			if err := json.Unmarshal([]byte(aws.ToString(e.CloudTrailEvent)), &detail); err != nil {
				logCollectError(name, fmt.Errorf("parse CloudTrail event JSON: %w", err))
				continue
			}

			actor := types.Actor{
				Ref:         detail.UserIdentity.UserName,
				Type:        "account",
				DisplayName: detail.UserIdentity.UserName,
			}

			eventCtx := types.EventContext{
				IPAddress: detail.SourceIPAddress,
				UserAgent: detail.UserAgent,
			}

			eventRef := detail.EventID
			if eventRef == "" {
				eventRef = aws.ToString(e.EventId)
			}

			ts := detail.EventTime
			if ts.IsZero() && e.EventTime != nil {
				ts = *e.EventTime
			}

			consoleLogin := detail.ResponseElements["ConsoleLogin"]
			isSuccess := consoleLogin == "Success"

			if isSuccess {
				ev := &events.LoginSucceeded{
					EventRef:  eventRef,
					Timestamp: ts,
					Actor:     actor,
					Context:   eventCtx,
					Outcome: types.EventOutcome{
						Action: "login",
						Result: "success",
					},
					LoginType: "console",
				}
				if err := c.ctx.Emit(ctx, ev); err != nil {
					logCollectError(name, err)
					return fmt.Errorf("emit LoginSucceeded: %w", err)
				}
			} else {
				reason := detail.ErrorMessage
				if reason == "" {
					reason = detail.ErrorCode
				}
				ev := &events.LoginFailed{
					EventRef:      eventRef,
					Timestamp:     ts,
					Actor:         actor,
					Context:       eventCtx,
					FailureReason: reason,
					Outcome: types.EventOutcome{
						Action: "login",
						Result: "failure",
						Reason: reason,
					},
					LoginType: "console",
				}
				if err := c.ctx.Emit(ctx, ev); err != nil {
					logCollectError(name, err)
					return fmt.Errorf("emit LoginFailed: %w", err)
				}
			}
			count++
		}
	}

	logCollectDone(name, count)
	return nil
}
