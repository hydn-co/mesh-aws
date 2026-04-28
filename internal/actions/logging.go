package actions

import (
	"context"
	"log/slog"

	"github.com/hydn-co/mesh-sdk/pkg/connector"
)

func logAction[T connector.FeatureOptions, P connector.FeaturePayload](
	ctx context.Context,
	action *connector.TypedFeatureContext[T, P],
	level slog.Level,
	msg string,
	args ...any,
) {
	logArgs := make([]any, 0, len(args)+6)
	if action != nil {
		logArgs = append(logArgs,
			"tenant_id", action.GetTenantID(),
			"connector_id", action.GetSegmentID(),
			"feature_name", action.GetName(),
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
