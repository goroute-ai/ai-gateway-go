package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	baseURL := flag.String("url", "https://localhost:28443", "Gateway HTTPS base URL")
	apiKey := flag.String("key", "", "Virtual key bearer token")
	model := flag.String("model", "prod-chat", "Realtime model alias")
	caFile := flag.String("cafile", os.Getenv("SSL_CERT_FILE"), "Optional PEM CA bundle to trust")
	expectReject := flag.Bool("expect-reject", false, "Expect upgrade rejection (e.g. 503 for budgeted key)")
	flag.Parse()

	if *apiKey == "" {
		fmt.Fprintln(os.Stderr, "ws-probe: -key is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := []gateway.Option{gateway.WithRemote(*baseURL, *apiKey)}
	if *caFile != "" {
		pemBytes, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ws-probe: read cafile: %v\n", err)
			os.Exit(1)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			fmt.Fprintf(os.Stderr, "ws-probe: failed to parse CA certs from %s\n", *caFile)
			os.Exit(1)
		}
		opts = append(opts, gateway.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		}))
	}

	client, err := gateway.New(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ws-probe: gateway.New: %v\n", err)
		os.Exit(1)
	}

	sess, err := client.ConnectRealtime(ctx, *model)
	if *expectReject {
		if err == nil {
			_ = sess.Close()
			fmt.Fprintln(os.Stderr, "ws-probe: expected ConnectRealtime to fail, but it succeeded")
			os.Exit(1)
		}
		if strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "tls:") {
			fmt.Fprintf(os.Stderr, "ws-probe: expected HTTP rejection, got TLS error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ws-probe: ConnectRealtime: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = sess.Close() }()

	created, err := sess.ReadEvent(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ws-probe: ReadEvent(session.created): %v\n", err)
		os.Exit(1)
	}
	if created.Type != "session.created" {
		fmt.Fprintf(os.Stderr, "ws-probe: expected session.created, got %q\n", created.Type)
		os.Exit(1)
	}

	if err := sess.SendEvent(ctx, gateway.RealtimeEvent{
		Type: "session.update",
		Session: &gateway.RealtimeSessionConfig{
			Modalities:   []string{"text"},
			Instructions: "Speak tersely.",
		},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ws-probe: SendEvent(session.update): %v\n", err)
		os.Exit(1)
	}

	updated, err := sess.ReadEvent(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ws-probe: ReadEvent(session.updated): %v\n", err)
		os.Exit(1)
	}
	if updated.Type != "session.updated" || updated.Session == nil || updated.Session.Instructions != "Speak tersely." {
		fmt.Fprintf(os.Stderr, "ws-probe: unexpected session.updated event: %+v\n", updated)
		os.Exit(1)
	}
}
