package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

type specValidator struct {
	router routers.Router
}

func loadSpecValidator(t *testing.T, relPath string) *specValidator {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", relPath),
		relPath,
	}
	var specFile string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			specFile = c
			break
		}
	}
	require.NotEmpty(t, specFile, "could not locate OpenAPI spec %s", relPath)

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specFile)
	require.NoError(t, err)
	require.NoError(t, doc.Validate(
		context.Background(),
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation(),
	))
	// Clear server URLs so requests match by path regardless of test host/port.
	doc.Servers = nil
	rtr, err := legacy.NewRouter(
		doc,
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation(),
	)
	require.NoError(t, err)
	return &specValidator{router: rtr}
}

func (v *specValidator) assertRequestResponse(t *testing.T, req *http.Request, reqBody []byte, status int, hdr http.Header, respBody []byte) {
	t.Helper()
	route, pathParams, err := v.router.FindRoute(req)
	if err != nil {
		t.Errorf("OpenAPI route missing for %s %s: %v", req.Method, req.URL.Path, err)
		return
	}

	valReq := req.Clone(req.Context())
	if len(reqBody) > 0 {
		valReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		valReq.ContentLength = int64(len(reqBody))
	} else {
		valReq.Body = http.NoBody
	}

	reqInput := &openapi3filter.RequestValidationInput{
		Request:    valReq,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	}
	if err := openapi3filter.ValidateRequest(req.Context(), reqInput); err != nil {
		t.Errorf("OpenAPI request validation failed for %s %s: %v", req.Method, req.URL.Path, err)
	}

	respHdr := hdr.Clone()
	if respHdr == nil {
		respHdr = make(http.Header)
	}
	if respHdr.Get("Content-Type") == "" {
		respHdr.Set("Content-Type", "application/json")
	}
	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 status,
		Header:                 respHdr,
	}
	respInput.SetBodyBytes(respBody)
	if err := openapi3filter.ValidateResponse(req.Context(), respInput); err != nil {
		t.Errorf("OpenAPI response validation failed for %s %s (status=%d, body=%s): %v", req.Method, req.URL.Path, status, string(respBody), err)
	}
}

func TestDataPlane_OpenAPIContract(t *testing.T) {
	gwValidator := loadSpecValidator(t, filepath.Join("docs", "openapi", "gateway.openapi.yaml"))
	oaiValidator := loadSpecValidator(t, filepath.Join("docs", "openapi", "openai.openapi.yaml"))
	antValidator := loadSpecValidator(t, filepath.Join("docs", "openapi", "anthropic.openapi.yaml"))
	groqValidator := loadSpecValidator(t, filepath.Join("docs", "openapi", "groq.openapi.yaml"))
	orValidator := loadSpecValidator(t, filepath.Join("docs", "openapi", "openrouter.openapi.yaml"))

	const tinyPNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"

	openAISrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var respStatus = http.StatusOK
		var contentType = "application/json"
		var respBytes []byte

		switch r.URL.Path {
		case "/v1/chat/completions":
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			toolCallMode := false
			if tc, ok := body["tool_choice"].(string); ok && tc == "required" {
				toolCallMode = true
			}
			if toolCallMode {
				respBytes = []byte(`{"id":"chatcmpl-oai-tc","object":"chat.completion","created":1730000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"ping","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
			} else {
				respBytes = []byte(`{"id":"chatcmpl-oai-1","object":"chat.completion","created":1730000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
			}
			oaiValidator.assertRequestResponse(t, cloneReqForPath(r, "/chat/completions"), raw, respStatus, http.Header{"Content-Type": {contentType}}, respBytes)
		case "/v1/completions":
			respBytes = []byte(`{"id":"cmpl-1","object":"text_completion","created":1730000000,"model":"gpt-3.5-turbo-instruct","choices":[{"text":"ok","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
		case "/v1/embeddings":
			respBytes = []byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":1,"total_tokens":1}}`)
		case "/v1/moderations":
			respBytes = []byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.001}}]}`)
		case "/v1/images/generations", "/v1/images/edits", "/v1/images/variations":
			respBytes = []byte(`{"created":1730000000,"data":[{"url":"https://cdn.openai.com/test.png","revised_prompt":"a dot"}]}`)
		case "/v1/audio/speech":
			contentType = "audio/mpeg"
			respBytes = []byte("ID3mockmp3bytes")
		case "/v1/audio/transcriptions", "/v1/audio/translations":
			respBytes = []byte(`{"text":"hello world"}`)
		default:
			respStatus = http.StatusNotFound
			respBytes = []byte(`{"error":{"message":"unexpected mock path"}}`)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(respStatus)
		_, _ = w.Write(respBytes)
	}))
	defer openAISrv.Close()

	anthropicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		respBytes := []byte(`{"id":"msg_123","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","container":null,"content":[{"type":"text","text":"ok","citations":null}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":2,"cache_creation":null,"cache_creation_input_tokens":null,"cache_read_input_tokens":null,"server_tool_use":null,"service_tier":"standard"}}`)
		antValidator.assertRequestResponse(t, cloneReqForPath(r, "/v1/messages"), raw, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, respBytes)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer anthropicSrv.Close()

	groqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		respBytes := []byte(`{"id":"chatcmpl-groq-1","object":"chat.completion","created":1730000000,"model":"openai/gpt-oss-20b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
		groqValidator.assertRequestResponse(t, cloneReqForPath(r, "/chat/completions"), raw, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, respBytes)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer groqSrv.Close()

	openRouterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		respBytes := []byte(`{"id":"gen-or-1","object":"chat.completion","created":1730000000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
		orValidator.assertRequestResponse(t, cloneReqForPath(r, "/chat/completions"), raw, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, respBytes)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer openRouterSrv.Close()

	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-contract-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	h := gw.Handler()

	org := &domain.Organization{ID: "org-contract", Name: "ContractOrg", Slug: "contract-org", IsActive: true, DeveloperSelfServeKeys: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	adminHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}
	doAdmin := func(method, path string, body any, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "http://localhost:8080"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range adminHeaders {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, rec.Code, "admin %s %s failed: %s", method, path, rec.Body.String())
		if out != nil {
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), out))
		}
	}

	var vk domain.VirtualKey
	doAdmin(http.MethodPost, "/admin/v1/keys", map[string]any{"org_id": org.ID, "name": "contract-vk"}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	setupModel := func(provider domain.ProviderType, baseURL, alias, modelName string) {
		gmID := string(provider) + "/" + modelName
		require.NoError(t, repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
			ID: gmID, Provider: provider, ModelName: modelName,
			SupportsInference: true, SupportsStreaming: true, SupportsTools: true, SupportsEmbeddings: strings.Contains(modelName, "embed"),
			LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			Capabilities: domain.ModelCapabilities{
				Tools: domain.CapabilitySupported, Streaming: domain.CapabilitySupported,
				Moderation: domain.CapabilitySupported, ImageGen: domain.CapabilitySupported,
				AudioTTS: domain.CapabilitySupported, AudioSTT: domain.CapabilitySupported,
			},
			SupportedOperations: []domain.OperationType{
				domain.OperationChat, domain.OperationCompletion, domain.OperationEmbedding,
				domain.OperationModeration, domain.OperationImageGeneration, domain.OperationImageEdit, domain.OperationImageVariation,
				domain.OperationAudioTTS, domain.OperationAudioSTT,
			},
		}))
		var cred, grp map[string]any
		doAdmin(http.MethodPost, "/admin/v1/credentials", map[string]any{
			"org_id": org.ID, "provider": string(provider), "name": alias + "-cred", "api_key": "sk-test-" + alias, "base_url": baseURL,
		}, &cred)
		doAdmin(http.MethodPost, "/admin/v1/model-groups", map[string]any{
			"org_id": org.ID, "alias": alias, "routing_strategy": "weighted_shuffle",
		}, &grp)
		doAdmin(http.MethodPost, "/admin/v1/deployments", map[string]any{
			"model_group_id": grp["id"], "global_model_id": gmID, "credential_id": cred["id"], "deployment_name": alias + "-dep", "weight": 1,
		}, nil)
	}

	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-chat", "gpt-4o-mini")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-cmpl", "gpt-3.5-turbo-instruct")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-embed", "text-embedding-3-small")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-mod", "omni-moderation-latest")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-img", "gpt-image-1.5")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-tts", "tts-1")
	setupModel(domain.ProviderOpenAI, openAISrv.URL+"/v1", "oai-stt", "whisper-1")
	setupModel(domain.ProviderAnthropic, anthropicSrv.URL, "ant-chat", "claude-haiku-4-5-20251001")
	setupModel(domain.ProviderGroq, groqSrv.URL+"/openai/v1", "groq-chat", "openai/gpt-oss-20b")
	setupModel(domain.ProviderOpenRouter, openRouterSrv.URL+"/api/v1", "or-chat", "openai/gpt-4o-mini")

	callJSON := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, "http://localhost:8080"+path, bytes.NewReader(raw))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range vkHeaders {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		gwValidator.assertRequestResponse(t, req, raw, rec.Code, rec.Header(), rec.Body.Bytes())
		return rec.Code, rec.Body.Bytes()
	}

	// Core text, tools, embeddings, moderations, responses, anthropic messages, tokenize
	callJSON(http.MethodGet, "/v1/models", nil)
	callJSON(http.MethodPost, "/v1/tokenize", map[string]any{"model": "oai-chat", "prompt": "hello"})
	for _, alias := range []string{"oai-chat", "ant-chat", "groq-chat", "or-chat"} {
		st, _ := callJSON(http.MethodPost, "/v1/chat/completions", map[string]any{
			"model":      alias,
			"max_tokens": 8,
			"messages":   []map[string]any{{"role": "user", "content": "Say ok"}},
		})
		require.Equal(t, http.StatusOK, st)
	}
	st, _ := callJSON(http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":       "oai-chat",
		"max_tokens":  16,
		"tool_choice": "required",
		"tools": []map[string]any{{
			"type":     "function",
			"function": map[string]any{"name": "ping", "description": "pong", "parameters": map[string]any{"type": "object"}},
		}},
		"messages": []map[string]any{{"role": "user", "content": "call ping"}},
	})
	require.Equal(t, http.StatusOK, st)

	st, _ = callJSON(http.MethodPost, "/v1/completions", map[string]any{"model": "oai-cmpl", "prompt": "Say ok", "max_tokens": 4})
	require.Equal(t, http.StatusOK, st)
	st, _ = callJSON(http.MethodPost, "/v1/embeddings", map[string]any{"model": "oai-embed", "input": "hello"})
	require.Equal(t, http.StatusOK, st)
	st, _ = callJSON(http.MethodPost, "/v1/moderations", map[string]any{"model": "oai-mod", "input": "hello"})
	require.Equal(t, http.StatusOK, st)

	for _, respPath := range []string{"/v1/responses", "/openai/v1/responses"} {
		st, _ = callJSON(http.MethodPost, respPath, map[string]any{"model": "oai-chat", "input": "Say ok", "max_output_tokens": 16})
		require.Equal(t, http.StatusOK, st)
	}
	for _, msgPath := range []string{"/v1/messages", "/anthropic/v1/messages"} {
		st, _ = callJSON(http.MethodPost, msgPath, map[string]any{
			"model":      "ant-chat",
			"max_tokens": 8,
			"messages":   []map[string]any{{"role": "user", "content": "Say ok"}},
		})
		require.Equal(t, http.StatusOK, st)
	}
	for _, ctPath := range []string{"/v1/messages/count_tokens", "/anthropic/v1/messages/count_tokens"} {
		st, _ = callJSON(http.MethodPost, ctPath, map[string]any{
			"model":    "ant-chat",
			"messages": []map[string]any{{"role": "user", "content": "Say ok"}},
		})
		require.Equal(t, http.StatusOK, st)
	}

	// Audio TTS + STT + Images + Files + Batches
	st, _ = callJSON(http.MethodPost, "/v1/audio/speech", map[string]any{"model": "oai-tts", "input": "hello", "voice": "alloy"})
	require.Equal(t, http.StatusOK, st)
	st, _ = callJSON(http.MethodPost, "/v1/images/generations", map[string]any{"model": "oai-img", "prompt": "a dot"})
	require.Equal(t, http.StatusOK, st)

	callMultipart := func(path string, fields map[string]string, fileField, fileName, fileBytes string) (int, []byte) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = w.WriteField(k, v)
		}
		fw, err := w.CreateFormFile(fileField, fileName)
		require.NoError(t, err)
		_, _ = fw.Write([]byte(fileBytes))
		require.NoError(t, w.Close())
		raw := buf.Bytes()
		req := httptest.NewRequest(http.MethodPost, "http://localhost:8080"+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", w.FormDataContentType())
		for k, v := range vkHeaders {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		gwValidator.assertRequestResponse(t, req, raw, rec.Code, rec.Header(), rec.Body.Bytes())
		return rec.Code, rec.Body.Bytes()
	}

	st, _ = callMultipart("/v1/audio/transcriptions", map[string]string{"model": "oai-stt"}, "file", "test.wav", "RIFF0000WAVEfmt ")
	require.Equal(t, http.StatusOK, st)
	st, _ = callMultipart("/v1/audio/translations", map[string]string{"model": "oai-stt"}, "file", "test.wav", "RIFF0000WAVEfmt ")
	require.Equal(t, http.StatusOK, st)
	st, _ = callMultipart("/v1/images/edits", map[string]string{"model": "oai-img", "prompt": "dot"}, "image", "img.png", tinyPNG)
	require.Equal(t, http.StatusOK, st)
	st, _ = callMultipart("/v1/images/variations", map[string]string{"model": "oai-img"}, "image", "img.png", tinyPNG)
	require.Equal(t, http.StatusOK, st)

	st, fileBody := callMultipart("/v1/files", map[string]string{"purpose": "batch"}, "file", "batch.jsonl", `{"custom_id":"1","method":"POST","url":"/v1/chat/completions","body":{"model":"oai-chat","messages":[{"role":"user","content":"hi"}]}}`+"\n")
	require.Equal(t, http.StatusCreated, st)
	var fileObj map[string]any
	require.NoError(t, json.Unmarshal(fileBody, &fileObj))
	fileID := fileObj["id"].(string)

	callJSON(http.MethodGet, "/v1/files", nil)
	callJSON(http.MethodGet, "/v1/files/"+fileID, nil)
	callJSON(http.MethodGet, "/v1/files/"+fileID+"/content", nil)

	st, batchBody := callJSON(http.MethodPost, "/v1/batches", map[string]any{"input_file_id": fileID, "endpoint": "/v1/chat/completions", "completion_window": "24h"})
	require.Equal(t, http.StatusCreated, st)
	var batchObj map[string]any
	require.NoError(t, json.Unmarshal(batchBody, &batchObj))
	batchID := batchObj["id"].(string)

	callJSON(http.MethodGet, "/v1/batches", nil)
	callJSON(http.MethodGet, "/v1/batches/"+batchID, nil)
	callJSON(http.MethodPost, "/v1/batches/"+batchID+"/cancel", nil)
	callJSON(http.MethodDelete, "/v1/files/"+fileID, nil)

	// Virtual key self-info & self-service keys
	st, _ = callJSON(http.MethodGet, "/v1/key/info", nil)
	require.Equal(t, http.StatusOK, st)

	team := &domain.Team{ID: "team-contract-dev", OrgID: org.ID, Name: "DevTeam", IsActive: true}
	require.NoError(t, repo.CreateTeam(ctx, team))
	devUser := &domain.User{ID: "usr-contract-dev", OrgID: org.ID, TeamID: team.ID, Email: "dev@contract.local", Role: domain.RoleDeveloper, IsActive: true}
	require.NoError(t, repo.CreateUser(ctx, devUser))
	mgmtVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: org.ID, TeamID: team.ID, UserID: devUser.ID, Name: "self-mgmt", Role: domain.RoleDeveloper, KeyType: domain.KeyTypeManagement,
	})
	require.NoError(t, err)
	callSelf := func(method, path string, body any) (int, []byte) {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, "http://localhost:8080"+path, bytes.NewReader(raw))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+mgmtVK.RawKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		gwValidator.assertRequestResponse(t, req, raw, rec.Code, rec.Header(), rec.Body.Bytes())
		return rec.Code, rec.Body.Bytes()
	}

	st, selfCreateBody := callSelf(http.MethodPost, "/v1/self/keys", map[string]any{"name": "contract-self-vk"})
	require.Equal(t, http.StatusCreated, st, string(selfCreateBody))
	var createdSelf map[string]any
	require.NoError(t, json.Unmarshal(selfCreateBody, &createdSelf))
	selfKeyID := createdSelf["id"].(string)

	st, _ = callSelf(http.MethodGet, "/v1/self/keys", nil)
	require.Equal(t, http.StatusOK, st)
	st, _ = callSelf(http.MethodPost, "/v1/self/keys/"+selfKeyID+"/rotate", map[string]any{"grace_period_sec": 60})
	require.Equal(t, http.StatusOK, st)
	st, _ = callSelf(http.MethodDelete, "/v1/self/keys/"+selfKeyID, nil)
	require.Equal(t, http.StatusOK, st)

	// Realtime WebSocket sessions (/v1/realtime & /openai/v1/realtime)
	wsSrv := httptest.NewServer(h)
	defer wsSrv.Close()
	for _, rtPath := range []string{"/v1/realtime", "/openai/v1/realtime"} {
		rtCtx, rtCancel := context.WithTimeout(ctx, 5*time.Second)
		wsURL := "ws" + strings.TrimPrefix(wsSrv.URL, "http") + rtPath + "?model=oai-chat"
		conn, _, dialErr := websocket.Dial(rtCtx, wsURL, &websocket.DialOptions{
			Subprotocols: []string{"realtime"},
			HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vk.RawKey}},
		})
		require.NoError(t, dialErr)
		_, _, readErr := conn.Read(rtCtx) // session.created
		require.NoError(t, readErr)
		_ = conn.Close(websocket.StatusNormalClosure, "ok")
		rtCancel()
	}
}

func cloneReqForPath(r *http.Request, p string) *http.Request {
	c := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	u.Host = "localhost"
	u.Path = p
	u.RawPath = ""
	c.URL = &u
	c.RequestURI = (&url.URL{Path: p, RawQuery: r.URL.RawQuery}).RequestURI()
	return c
}
