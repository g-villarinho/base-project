package logger

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/g-villarinho/base-project/config"
)

func NewLogger(config *config.Config) *slog.Logger {
	return setupLogger(config.Env)
}

func setupLogger(enviroment string) *slog.Logger {
	switch enviroment {
	case "production", "staging":
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:       slog.LevelInfo,
			AddSource:   true,
			ReplaceAttr: cleanSourcePath,
		}))

	case "development":
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))

	default:
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))
	}
}

func cleanSourcePath(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.SourceKey {
		source, _ := a.Value.Any().(*slog.Source)
		if source != nil {
			source.File = filepath.Base(source.File)
		}
	}
	return a
}
