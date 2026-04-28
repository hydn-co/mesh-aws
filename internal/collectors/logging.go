package collectors

import (
	"log/slog"
)

func logCollectStart(name string) {
	slog.Info("collector started", slog.String("collector", name))
}

func logCollectDone(name string, count int) {
	slog.Info("collector finished", slog.String("collector", name), slog.Int("count", count))
}

func logCollectError(name string, err error) {
	slog.Error("collector error", slog.String("collector", name), slog.String("err", err.Error()))
}
