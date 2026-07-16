package api

import (
	"context"
	"strings"
	"time"

	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/substrate/enumerators"
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

// awsRetryOperation runs a single (non-paginated) AWS call with the same
// throttle-retry policy awsPageEnumerator applies to paged enumerations.
func awsRetryOperation(ctx context.Context, operation func(ctx context.Context) error) error {
	return connectorutil.RetryOperation(ctx, connectorutil.RetryPolicy{
		ShouldRetry: isAWSThrottleError,
		BaseDelay:   awsThrottleBaseDelay,
		MaxDelay:    awsThrottleMaxDelay,
		MaxRetries:  awsThrottleMaxRetries,
	}, func(ctx context.Context) (connectorutil.RetryOperationResult, error) {
		return connectorutil.RetryOperationResult{}, operation(ctx)
	})
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
