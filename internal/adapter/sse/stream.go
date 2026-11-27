package sse

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const maxSSEEventBytes = 4 * 1024 * 1024 // 4 MiB cumulative cap per multi-line SSE event

// ErrEventTooLarge is returned by ReadEvents when a single SSE event's accumulated
// data payload exceeds the maximum permitted size before a blank-line delimiter.
var ErrEventTooLarge = errors.New("sse: event exceeds maximum size limit")

// Event represents a single Server-Sent Event frame (`event:` and `data:`).
type Event struct {
	Event string
	Data  string
}

// ReadEvents reads Server-Sent Events from an upstream HTTP response body and invokes fn for each complete event.
func ReadEvents(r io.Reader, fn func(ev Event) error) error {
	scanner := bufio.NewScanner(r)
	// Allow up to 2MB per SSE line for large tool call JSON or base64 chunks
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var curEvent string
	var dataLines []string
	var dataBytes int

	flush := func() error {
		if len(dataLines) == 0 && curEvent == "" {
			return nil
		}
		ev := Event{
			Event: curEvent,
			Data:  strings.Join(dataLines, "\n"),
		}
		curEvent = ""
		dataLines = dataLines[:0]
		dataBytes = 0
		return fn(ev)
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			// SSE comment / keep-alive
			continue
		}
		if strings.HasPrefix(line, "event:") {
			curEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			dataBytes += len(payload)
			if len(dataLines) > 0 {
				dataBytes++ // newline join delimiter
			}
			if dataBytes > maxSSEEventBytes {
				return ErrEventTooLarge
			}
			dataLines = append(dataLines, payload)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}

// Writer wraps an http.ResponseWriter + http.Flusher to emit OpenAI-compatible SSE chunks.
type Writer struct {
	w       http.ResponseWriter
	flusher http.Flusher
	started bool
}

// NewWriter wraps w as an SSE Writer, returning an error if w does not implement http.Flusher.
func NewWriter(w http.ResponseWriter) (*Writer, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("response writer does not support http.Flusher")
	}
	return &Writer{w: w, flusher: flusher}, nil
}

// WriteHeaders commits the `text/event-stream` HTTP headers once before the first chunk is flushed.
func (sw *Writer) WriteHeaders() {
	if sw.started {
		return
	}
	sw.w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	sw.w.Header().Set("Cache-Control", "no-cache, no-transform")
	sw.w.Header().Set("Connection", "keep-alive")
	sw.w.Header().Set("X-Accel-Buffering", "no")
	sw.w.WriteHeader(http.StatusOK)
	sw.started = true
}

// Started reports whether headers and at least one chunk have been committed to the client.
func (sw *Writer) Started() bool {
	return sw.started
}

// WriteChunk serializes and flushes a CanonicalStreamChunk as `data: <json>\n\n`.
func (sw *Writer) WriteChunk(chunk *domain.CanonicalStreamChunk) error {
	sw.WriteHeaders()
	b, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(sw.w, "data: %s\n\n", b); err != nil {
		return err
	}
	sw.flusher.Flush()
	return nil
}

// WriteError emits an explicit mid-stream SSE error event (`event: error\ndata: {"error":{...}}\n\n`)
// followed by `data: [DONE]\n\n` when an upstream connection drops after HTTP 200 headers and initial chunks were already sent.
func (sw *Writer) WriteError(err error) error {
	sw.WriteHeaders()
	gwErr := &domain.GatewayError{
		StatusCode: http.StatusBadGateway,
		Type:       domain.ErrorTypeUpstream,
		Code:       "mid_stream_interrupted",
		Message:    err.Error(),
	}
	if e, ok := err.(*domain.GatewayError); ok {
		gwErr = e
	}
	b, _ := json.Marshal(domain.OpenAIErrorEnvelope{Error: gwErr})
	if _, writeErr := fmt.Fprintf(sw.w, "event: error\ndata: %s\n\ndata: [DONE]\n\n", b); writeErr != nil {
		return writeErr
	}
	sw.flusher.Flush()
	return nil
}

// WriteDone writes the final `data: [DONE]\n\n` sentinel expected by OpenAI SDKs.
func (sw *Writer) WriteDone() error {
	sw.WriteHeaders()
	if _, err := fmt.Fprint(sw.w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	sw.flusher.Flush()
	return nil
}
