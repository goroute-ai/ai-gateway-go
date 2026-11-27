package sse

import (
	"errors"
	"strings"
	"testing"
)

func TestReadEvents_NormalMultiLineAndSeparateEvents(t *testing.T) {
	stream := strings.Join([]string{
		": keep-alive",
		"event: message",
		"data: line-one",
		"data: line-two",
		"",
		"data: second-event",
		"",
	}, "\n")

	var events []Event
	err := ReadEvents(strings.NewReader(stream), func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(events), events)
	}
	if events[0].Event != "message" || events[0].Data != "line-one\nline-two" {
		t.Fatalf("unexpected first event: %+v", events[0])
	}
	if events[1].Event != "" || events[1].Data != "second-event" {
		t.Fatalf("unexpected second event: %+v", events[1])
	}
}

func TestReadEvents_RejectsOversizedAccumulatedEvent(t *testing.T) {
	// Stream 5 consecutive 1 MiB data: lines without a blank-line delimiter (> 4 MiB cap).
	chunk := strings.Repeat("a", 1024*1024)
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString("data: ")
		b.WriteString(chunk)
		b.WriteByte('\n')
	}

	called := false
	err := ReadEvents(strings.NewReader(b.String()), func(ev Event) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("expected ErrEventTooLarge, got %v", err)
	}
	if called {
		t.Fatal("callback must not be invoked for oversized event")
	}
}
