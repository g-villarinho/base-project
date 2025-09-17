package logger

import (
	"log/slog"
	"os"

	"github.com/g-villarinho/user-demo/config"
)

func NewLogger(config *config.Config) *slog.Logger {
	return setupLogger(config.Env)
}

func setupLogger(enviroment string) *slog.Logger {
	switch enviroment {
	case "production":
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	case "development":
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: false,
		}))
	default:
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
}
