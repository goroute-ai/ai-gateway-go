package demoutil

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	isJSONOnce sync.Once
	isJSON     bool
	logger     *slog.Logger
)

func initLogger() {
	isJSONOnce.Do(func() {
		mode := strings.ToLower(strings.TrimSpace(os.Getenv("DEMO_LOGS")))
		if mode == "" {
			mode = strings.ToLower(strings.TrimSpace(os.Getenv("DEMO_LOG_FORMAT")))
		}
		if mode == "json" {
			isJSON = true
			logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		} else {
			isJSON = false
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		}
	})
}

// IsJSONMode reports whether JSON logging mode is enabled.
func IsJSONMode() bool {
	initLogger()
	return isJSON
}

// Banner renders an 80-character framed header banner.
func Banner(title string) {
	initLogger()
	if isJSON {
		logger.Info("demo_banner", slog.String("title", title))
		return
	}
	divider := strings.Repeat("=", 80)
	padding := (80 - len(title)) / 2
	if padding < 0 {
		padding = 0
	}
	centered := strings.Repeat(" ", padding) + title
	fmt.Println(divider)
	fmt.Println(centered)
	fmt.Println(divider)
}

// Section renders a numbered major demo section.
func Section(step int, title string) {
	initLogger()
	if isJSON {
		logger.Info("demo_section", slog.Int("step", step), slog.String("title", title))
		return
	}
	fmt.Printf("\n[Step %d] %s:\n", step, title)
}

// Part renders a numbered sub-part header (e.g. "[Part 1] Synchronous Chat:").
func Part(part int, title string) {
	initLogger()
	if isJSON {
		logger.Info("demo_part", slog.Int("part", part), slog.String("title", title))
		return
	}
	fmt.Printf("\n[Part %d] %s:\n", part, title)
}

// Mode renders an execution mode header (e.g. "[Mode 1: Explicit Target]").
func Mode(mode int, title string) {
	initLogger()
	if isJSON {
		logger.Info("demo_mode", slog.Int("mode", mode), slog.String("title", title))
		return
	}
	fmt.Printf("\n[Mode %d: %s]\n", mode, title)
}

// Header renders an arbitrary bracketed section header.
func Header(title string) {
	initLogger()
	if isJSON {
		logger.Info("demo_header", slog.String("title", title))
		return
	}
	fmt.Printf("\n[%s]\n", title)
}

// Field prints an aligned key-value line.
func Field(label string, value any) {
	initLogger()
	if isJSON {
		logger.Info("demo_field", slog.String("label", label), slog.Any("value", value))
		return
	}
	fmt.Printf("  [%-13s] %v\n", label, value)
}

// Fieldf prints a formatted key-value line.
func Fieldf(label string, format string, args ...any) {
	initLogger()
	val := fmt.Sprintf(format, args...)
	if isJSON {
		logger.Info("demo_field", slog.String("label", label), slog.String("value", val))
		return
	}
	fmt.Printf("  [%-13s] %s\n", label, val)
}

// Item prints a bulleted item in an inventory or list.
func Item(item string) {
	initLogger()
	if isJSON {
		logger.Info("demo_item", slog.String("item", item))
		return
	}
	fmt.Printf("   * %s\n", item)
}

// StreamHeader begins a stream output line without a trailing newline.
func StreamHeader(label string) {
	initLogger()
	if isJSON {
		logger.Info("demo_stream_started", slog.String("label", label))
		return
	}
	fmt.Printf("  [%-13s] ", label)
}

// StreamDelta writes a chunk of streaming text to stdout.
func StreamDelta(chunk string) {
	initLogger()
	if isJSON {
		return // Streaming chunks are aggregated on completion in JSON mode
	}
	fmt.Print(chunk)
}

// StreamDone concludes a streaming sequence.
func StreamDone(requestID string, totalTokens int) {
	initLogger()
	if isJSON {
		logger.Info("demo_stream_done", slog.String("request_id", requestID), slog.Int("total_tokens", totalTokens))
		return
	}
	fmt.Printf("\n  [Stream Done  ] RequestID=%s | Tokens=%d\n", requestID, totalTokens)
}

// LogEvent records a structured diagnostic log event.
func LogEvent(msg string, args ...any) {
	initLogger()
	logger.Info(msg, args...)
}

// LogWarn records a structured diagnostic warning event.
func LogWarn(msg string, args ...any) {
	initLogger()
	logger.Warn(msg, args...)
}

// Fail logs a fatal structured error and terminates the demo process cleanly.
func Fail(msg string, err error, args ...any) {
	initLogger()
	allArgs := append([]any{slog.String("error", err.Error())}, args...)
	logger.Error(msg, allArgs...)
	os.Exit(1)
}
