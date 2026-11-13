package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTraceMiddlewareRecordsStatusCodeAndErrorOn5xx(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	cases := []struct {
		name       string
		statusCode int
		implicit   bool
		wantErr    bool
	}{
		{name: "implicit_200", statusCode: http.StatusOK, implicit: true, wantErr: false},
		{name: "client_404", statusCode: http.StatusNotFound, wantErr: false},
		{name: "server_502", statusCode: http.StatusBadGateway, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sr.Ended())
			handler := TraceMiddlewareWithTracer(tracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.implicit {
					_, _ = w.Write([]byte("ok"))
					return
				}
				w.WriteHeader(tc.statusCode)
			}))

			req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			ended := sr.Ended()
			if len(ended) != before+1 {
				t.Fatalf("expected %d ended spans, got %d", before+1, len(ended))
			}
			span := ended[len(ended)-1]

			var gotCode int64
			var found bool
			for _, attr := range span.Attributes() {
				if attr.Key == attribute.Key("http.response.status_code") {
					gotCode = attr.Value.AsInt64()
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected http.response.status_code attribute on span")
			}
			if gotCode != int64(tc.statusCode) {
				t.Fatalf("http.response.status_code = %d, want %d", gotCode, tc.statusCode)
			}
			if tc.wantErr && span.Status().Code != codes.Error {
				t.Fatalf("expected span status codes.Error for %d, got %v", tc.statusCode, span.Status().Code)
			}
			if !tc.wantErr && span.Status().Code == codes.Error {
				t.Fatalf("did not expect span status codes.Error for %d", tc.statusCode)
			}
		})
	}
}

func TestReservoirUniformSamplingAlgorithmR(t *testing.T) {
	var r reservoir
	const total = 10000
	for i := 1; i <= total; i++ {
		r.add(int64(i))
	}

	if r.count != total {
		t.Fatalf("count = %d, want %d", r.count, total)
	}
	if len(r.samples) != maxReservoirSamples {
		t.Fatalf("len(samples) = %d, want %d", len(r.samples), maxReservoirSamples)
	}

	// Under rolling-overwrite, all samples would be >= total - maxReservoirSamples + 1 (8977).
	// Under Vitter's Algorithm R, early items must still be represented uniformly.
	var earlyCount int
	var sum int64
	for _, s := range r.samples {
		sum += s
		if s <= 2000 {
			earlyCount++
		}
	}
	if earlyCount == 0 {
		t.Fatalf("expected early samples (<= 2000) to be retained under uniform reservoir sampling")
	}
	sampleMean := float64(sum) / float64(len(r.samples))
	if sampleMean < 4200 || sampleMean > 5800 {
		t.Fatalf("reservoir sample mean = %.2f, expected near 5000.5", sampleMean)
	}
}

func TestCollectorDeploymentMapBoundedEviction(t *testing.T) {
	col := NewCollector()
	col.maxDeployments = 5

	for i := 1; i <= 5; i++ {
		depID := string(rune('a' + i - 1))
		col.Record(RequestObservation{
			Provider:     "openai",
			Model:        "gpt-4.1-mini",
			DeploymentID: "dep-" + depID,
			StatusCode:   200,
			LatencyMs:    10,
		})
	}
	// Refresh dep-a so it is no longer the least recently used entry.
	col.RecordDeploymentAttempt("dep-a", "dep-a", "openai", "gpt-4.1-mini", 15, false)

	// Insert 3 more deployments; cap must remain 5 and dep-a must remain present.
	for _, suffix := range []string{"f", "g", "h"} {
		col.Record(RequestObservation{
			Provider:     "openai",
			Model:        "gpt-4.1-mini",
			DeploymentID: "dep-" + suffix,
			StatusCode:   200,
			LatencyMs:    10,
		})
	}

	snap := col.Snapshot()
	if len(snap.Deployments) != 5 {
		t.Fatalf("expected bounded 5 deployments, got %d", len(snap.Deployments))
	}
	if _, ok := snap.Deployments["dep-a"]; !ok {
		t.Fatalf("expected recently accessed dep-a to be retained after eviction")
	}
	if _, ok := snap.Deployments["dep-b"]; ok {
		t.Fatalf("expected oldest unused deployment dep-b to be evicted")
	}
}
