package actions

import (
	"log/slog"
)

func logActionStart(name string) {
	slog.Info("action started", slog.String("action", name))
}

func logActionDone(name string) {
	slog.Info("action completed", slog.String("action", name))
}

func logActionError(name string, err error) {
	slog.Error("action error", slog.String("action", name), slog.String("err", err.Error()))
}
