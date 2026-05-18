package api

import (
	"context"
	"strings"
	"time"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
)

const (
	awsThrottleBaseDelay  = 2 * time.Second
	awsThrottleMaxDelay   = 60 * time.Second
	awsThrottleMaxRetries = 5
)

func awsPageEnumerator[T any](
	ctx context.Context,
	fetchPage func() ([]T, bool, error),
) enumerators.Enumerator[T] {
	return connectorutil.ThrottledPageEnumerator(ctx, connectorutil.ThrottlePolicy{
		IsThrottled: isAWSThrottleError,
		BaseDelay:   awsThrottleBaseDelay,
		MaxDelay:    awsThrottleMaxDelay,
		MaxRetries:  awsThrottleMaxRetries,
	}, fetchPage)
}

func isAWSThrottleError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "throttlingexception") ||
		strings.Contains(message, "throttling") ||
		strings.Contains(message, "throttledexception") ||
		strings.Contains(message, "requestlimitexceeded") ||
		strings.Contains(message, "toomanyrequests") ||
		strings.Contains(message, "too many requests") ||
		strings.Contains(message, "rate exceeded") ||
		strings.Contains(message, "rate limit") ||
		strings.Contains(message, "slow down") ||
		strings.Contains(message, "http 429") ||
		strings.Contains(message, "status 429")
}
