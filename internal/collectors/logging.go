package collectors

import (
	"context"
	"log/slog"

	"github.com/hydn-co/mesh-sdk/pkg/connector"
)

func logCollector[T connector.FeatureOptions, P connector.FeaturePayload](
	ctx context.Context,
	collector *connector.TypedFeatureContext[T, P],
	level slog.Level,
	msg string,
	args ...any,
) {
	logArgs := make([]any, 0, len(args)+6)
	if collector != nil {
		logArgs = append(logArgs,
			"tenant_id", collector.GetTenantID(),
			"connector_id", collector.GetSegmentID(),
			"feature_name", collector.GetName(),
		)
	}
	logArgs = append(logArgs, args...)

	switch {
	case level <= slog.LevelDebug:
		slog.DebugContext(ctx, msg, logArgs...)
	case level < slog.LevelWarn:
		slog.InfoContext(ctx, msg, logArgs...)
	case level < slog.LevelError:
		slog.WarnContext(ctx, msg, logArgs...)
	default:
		slog.ErrorContext(ctx, msg, logArgs...)
	}
}
