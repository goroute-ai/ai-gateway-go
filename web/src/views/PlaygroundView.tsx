import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../context/AuthContext';
import { adminApi } from '../api/admin';
import { isPlatformAdminForbidden } from '../components/common/ErrorAlert';
import { streamChatCompletion, ChatStreamChunk, ChatStreamHeaders } from '../api/sse';
import type { GoRouteExtensions } from '../types';
import { Badge } from '../components/common/Badge';
import { CodeBlock } from '../components/common/CodeBlock';
import { Modal } from '../components/common/Modal';
import {
  X,
  Trash2,
  Settings,
  Key,
  Bot,
  User,
  AlertTriangle,
  Copy,
  Check,
  ChevronDown,
  Clock,
  Zap,
} from 'lucide-react';

interface ChatMessage {
  id: string;
  role: 'system' | 'user' | 'assistant';
  content: string;
  reasoning_content?: string;
  tool_calls?: any[];
  timestamp: string;
  latencyMs?: number;
}

const generateId = (): string => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
};

const escapeShellSingle = (val: string): string => `'${val.replace(/'/g, `'\\''`)}'`;

export const PlaygroundView: React.FC = () => {
  const { adminKey, activeOrgId, lastIssuedKey } = useAuth();

  // Authentication State
  const [virtualKey, setVirtualKey] = useState<string>('');
  const [showKeyInput, setShowKeyInput] = useState<boolean>(false);

  // Model & System Configuration
  const [selectedModel, setSelectedModel] = useState<string>('fast');
  const [customModelInput, setCustomModelInput] = useState<string>('');
  const [systemPrompt, setSystemPrompt] = useState<string>(
    'You are a helpful, precise AI assistant routed through GoRoute AI Gateway.'
  );
  const [isSystemOpen, setIsSystemOpen] = useState<boolean>(false);

  // Hyperparameters
  const [temperature, setTemperature] = useState<number>(0.7);
  const [maxTokens, setMaxTokens] = useState<number>(2048);
  const [topP, setTopP] = useState<number>(1.0);

  // Routing Hint Controls (goroute_extensions)
  const [isHintsOpen, setIsHintsOpen] = useState<boolean>(false);
  const [hintRegion, setHintRegion] = useState<string>('');
  const [hintTags, setHintTags] = useState<string>('');
  const [hintSessionId, setHintSessionId] = useState<string>('');
  const [hintPriority, setHintPriority] = useState<string>('');
  const [hintHedgeMs, setHintHedgeMs] = useState<string>('');

  // Chat State
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [userInput, setUserInput] = useState<string>('');
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [streamError, setStreamError] = useState<string | null>(null);

  // Inspector & Performance Telemetry
  const [lastRequestMetrics, setLastRequestMetrics] = useState<{
    latencyMs: number;
    ttftMs?: number;
    chunkCount: number;
    model: string;
    headers?: ChatStreamHeaders;
  } | null>(null);

  // Code Export Modal
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [exportLanguage, setExportLanguage] = useState<'curl' | 'python' | 'ts' | 'go'>('curl');
  const [includeKeyInExport, setIncludeKeyInExport] = useState<boolean>(false);
  const [copiedSnippet, setCopiedSnippet] = useState<boolean>(false);

  // Streaming Controller Ref
  const abortControllerRef = useRef<AbortController | null>(null);
  const chatBottomRef = useRef<HTMLDivElement | null>(null);

  // Fetch dynamic aliases & catalogue models when admin key is unlocked
  const { data: modelGroupsData } = useQuery({
    queryKey: ['admin', 'model-groups', adminKey, activeOrgId],
    queryFn: () => adminApi.listModelGroups(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  const { data: catalogueData } = useQuery({
    queryKey: ['admin', 'catalogue', adminKey],
    queryFn: async () => {
      try {
        return await adminApi.listCatalogue(adminKey);
      } catch (err) {
        if (isPlatformAdminForbidden(err)) return { data: [] };
        throw err;
      }
    },
    enabled: !!adminKey,
    retry: (count, err) => !isPlatformAdminForbidden(err) && count < 2,
  });

  const aliasOptions = useMemo(() => {
    const base = ['fast', 'reasoning', 'coding', 'auto', 'router/semantic', 'router/quality', 'router/adaptive'];
    const dynamic = (modelGroupsData?.data || []).map((g) => g.alias).filter(Boolean);
    return Array.from(new Set([...base, ...dynamic]));
  }, [modelGroupsData]);

  const modelSuggestions = useMemo(() => {
    const catIds = (catalogueData?.data || []).map((m) => m.id).filter(Boolean);
    return Array.from(new Set([...aliasOptions, ...catIds])).slice(0, 120);
  }, [aliasOptions, catalogueData]);

  // Automatically offer the newly issued key if captured in this session
  useEffect(() => {
    if (lastIssuedKey && !virtualKey) {
      setVirtualKey(lastIssuedKey);
    }
  }, [lastIssuedKey]);

  // Scroll to bottom when messages update
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isStreaming]);

  const activeModel = customModelInput.trim() || selectedModel;

  const buildExtensions = (): GoRouteExtensions | undefined => {
    const ext: GoRouteExtensions = {};
    const tags = hintTags.split(',').map((t) => t.trim()).filter(Boolean);
    if (tags.length > 0) ext.tags = tags;
    if (hintRegion.trim()) ext.allowed_region = hintRegion.trim();
    if (hintSessionId.trim()) ext.session_id = hintSessionId.trim();
    const prio = parseInt(hintPriority, 10);
    if (hintPriority.trim() && !isNaN(prio)) ext.priority = prio;
    const hedge = parseInt(hintHedgeMs, 10);
    if (hintHedgeMs.trim() && !isNaN(hedge) && hedge > 0) ext.hedge_after_ms = hedge;
    return Object.keys(ext).length > 0 ? ext : undefined;
  };

  const handleSendMessage = async () => {
    if (!userInput.trim() || isStreaming) return;
    if (!virtualKey.trim()) {
      setStreamError('A valid Virtual Key (sk-gw-...) is required to send inference requests.');
      return;
    }

    setStreamError(null);
    const userMsg: ChatMessage = {
      id: generateId(),
      role: 'user',
      content: userInput.trim(),
      timestamp: new Date().toISOString(),
    };

    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setUserInput('');

    // Prepare assistant placeholder
    const assistantMsgId = generateId();
    const assistantMsg: ChatMessage = {
      id: assistantMsgId,
      role: 'assistant',
      content: '',
      timestamp: new Date().toISOString(),
    };
    setMessages([...newMessages, assistantMsg]);
    setIsStreaming(true);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const startTime = performance.now();
    let firstTokenTime: number | undefined;
    let chunksReceived = 0;
    let capturedHeaders: ChatStreamHeaders | undefined;

    // Build payload messages including system prompt
    const apiMessages: Array<{ role: string; content: string }> = [];
    if (systemPrompt.trim()) {
      apiMessages.push({ role: 'system', content: systemPrompt.trim() });
    }
    for (const m of newMessages) {
      apiMessages.push({ role: m.role, content: m.content });
    }

    const ext = buildExtensions();
    const payload: Record<string, any> = {
      model: activeModel,
      messages: apiMessages,
      temperature,
      max_tokens: maxTokens,
      top_p: topP,
      stream: true,
      ...(ext ? { goroute_extensions: ext } : {}),
    };

    try {
      await streamChatCompletion(
        '/v1/chat/completions',
        virtualKey.trim(),
        payload,
        (chunk: ChatStreamChunk) => {
          chunksReceived++;
          if (firstTokenTime === undefined && (chunk.content || chunk.reasoning_content)) {
            firstTokenTime = performance.now() - startTime;
          }

          setMessages((prev) =>
            prev.map((msg) => {
              if (msg.id !== assistantMsgId) return msg;

              let updatedContent = msg.content;
              if (chunk.content) {
                updatedContent += chunk.content;
              }

              let updatedReasoning = msg.reasoning_content;
              if (chunk.reasoning_content) {
                updatedReasoning = (updatedReasoning || '') + chunk.reasoning_content;
              }

              let updatedToolCalls = msg.tool_calls;
              if (chunk.tool_calls) {
                updatedToolCalls = chunk.tool_calls;
              }

              return {
                ...msg,
                content: updatedContent,
                reasoning_content: updatedReasoning,
                tool_calls: updatedToolCalls,
              };
            })
          );
        },
        controller.signal,
        (headers) => {
          capturedHeaders = headers;
        }
      );

      const totalLatency = performance.now() - startTime;
      setLastRequestMetrics({
        latencyMs: Math.round(totalLatency),
        ttftMs: firstTokenTime ? Math.round(firstTokenTime) : undefined,
        chunkCount: chunksReceived,
        model: activeModel,
        headers: capturedHeaders,
      });

      setMessages((prev) =>
        prev.map((msg) => (msg.id === assistantMsgId ? { ...msg, latencyMs: Math.round(totalLatency) } : msg))
      );
    } catch (err: any) {
      setMessages((prev) =>
        prev.filter(
          (m) =>
            m.id !== assistantMsgId ||
            Boolean(m.content || m.reasoning_content || m.tool_calls?.length)
        )
      );
      if (err.name === 'AbortError') {
        setStreamError('Request cancelled by user.');
      } else {
        setStreamError(err.message || 'Stream connection error');
      }
    } finally {
      setIsStreaming(false);
      abortControllerRef.current = null;
    }
  };

  const handleStopStreaming = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  const handleClearChat = () => {
    if (isStreaming) handleStopStreaming();
    setMessages([]);
    setStreamError(null);
    setLastRequestMetrics(null);
  };

  // Generate code export snippets
  const getCodeSnippet = (lang: 'curl' | 'python' | 'ts' | 'go') => {
    const key = includeKeyInExport && virtualKey.trim() ? virtualKey.trim() : '$GOROUTE_API_KEY';
    const endpoint = `${window.location.origin}/v1/chat/completions`;
    const baseUrl = `${window.location.origin}/v1`;
    const msgs = [
      ...(systemPrompt ? [{ role: 'system', content: systemPrompt }] : []),
      ...messages.map((m) => ({ role: m.role, content: m.content })),
    ];
    if (msgs.length === 0) {
      msgs.push({ role: 'user', content: 'Hello GoRoute Gateway!' });
    }

    const ext = buildExtensions();
    const reqBody = {
      model: activeModel,
      messages: msgs,
      temperature,
      max_tokens: maxTokens,
      stream: true,
      ...(ext ? { goroute_extensions: ext } : {}),
    };

    switch (lang) {
      case 'curl':
        return `curl -X POST ${escapeShellSingle(endpoint)} \\
  -H ${escapeShellSingle(`Authorization: Bearer ${key}`)} \\
  -H 'Content-Type: application/json' \\
  -d ${escapeShellSingle(JSON.stringify(reqBody, null, 2))}`;

      case 'python':
        return `from openai import OpenAI
client = OpenAI(api_key=${JSON.stringify(key)}, base_url=${JSON.stringify(baseUrl)})
for c in client.chat.completions.create(model=${JSON.stringify(activeModel)}, messages=${JSON.stringify(msgs)}, temperature=${temperature}, max_tokens=${maxTokens}, stream=True):
    print(c.choices[0].delta.content or "", end="", flush=True)`;

      case 'ts':
        return `import OpenAI from 'openai';
const client = new OpenAI({ apiKey: ${JSON.stringify(key)}, baseURL: ${JSON.stringify(baseUrl)} });
const stream = await client.chat.completions.create({ model: ${JSON.stringify(activeModel)}, messages: ${JSON.stringify(msgs)}, temperature: ${temperature}, max_tokens: ${maxTokens}, stream: true });
for await (const c of stream) process.stdout.write(c.choices[0]?.delta?.content || '');`;

      case 'go':
        return `package main
import ("bytes"; "encoding/json"; "io"; "net/http"; "os")
func main() {
  body, _ := json.Marshal(map[string]any{"model": ${JSON.stringify(activeModel)}, "messages": ${JSON.stringify(msgs)}, "temperature": ${temperature}})
  req, _ := http.NewRequest("POST", ${JSON.stringify(endpoint)}, bytes.NewBuffer(body))
  req.Header.Set("Authorization", "Bearer "+${JSON.stringify(key)})
  req.Header.Set("Content-Type", "application/json")
  resp, err := http.DefaultClient.Do(req); if err != nil { panic(err) }
  defer resp.Body.Close(); io.Copy(os.Stdout, resp.Body)
}`;
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="flex flex-col lg:flex-row gap-4 h-[calc(100vh-140px)] min-h-[600px]">
      {/* Center / Left: Interactive Chat Canvas */}
      <div className="flex-1 flex flex-col bg-surface-base border border-border-subtle rounded-lg overflow-hidden">
        {/* Chat Header Bar */}
        <div className="px-4 py-2.5 bg-surface-elevated/40 border-b border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-accent-primary" />
            <span className="text-xs font-semibold text-brand-title font-mono">Chat Playground</span>
            <Badge variant="primary">{activeModel}</Badge>
            {isStreaming && (
              <span className="flex items-center gap-1.5 text-[11px] text-accent-glow font-mono animate-pulse">
                <span className="w-1.5 h-1.5 rounded-full bg-accent-glow" />
                Streaming...
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowExportModal(true)}
              className="flex items-center gap-1 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
              title="Export as Code"
            >
              <Copy className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export Code</span>
            </button>
            <button
              onClick={handleClearChat}
              disabled={messages.length === 0}
              className="flex items-center gap-1 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-muted hover:text-status-danger rounded text-xs font-mono transition disabled:opacity-40"
              title="Clear Conversation"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Clear</span>
            </button>
          </div>
        </div>

        {/* Collapsible System Prompt */}
        <div className="border-b border-border-subtle bg-canvas/40">
          <button
            onClick={() => setIsSystemOpen(!isSystemOpen)}
            className="w-full px-4 py-2 flex items-center justify-between text-xs font-mono text-brand-muted hover:text-brand-title transition"
          >
            <span className="flex items-center gap-1.5">
              <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isSystemOpen ? '' : '-rotate-90'}`} />
              System Instructions
            </span>
            <span className="text-[10px] text-brand-muted truncate max-w-[300px]">
              {isSystemOpen ? 'Click to collapse' : systemPrompt.slice(0, 45) + '...'}
            </span>
          </button>
          {isSystemOpen && (
            <div className="px-4 pb-3">
              <textarea
                rows={2}
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                placeholder="Define role or behavior constraints..."
                className="w-full p-2 text-xs bg-surface-input border border-border-subtle rounded text-brand-body font-mono focus:outline-none focus:border-accent-primary resize-y"
              />
            </div>
          )}
        </div>

        {/* Error Notification Banner */}
        {streamError && (
          <div className="mx-4 mt-3 p-3 status-danger border rounded flex items-start justify-between text-xs font-mono">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-status-danger shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Execution Error: </span>
                {streamError}
              </div>
            </div>
            <button onClick={() => setStreamError(null)} className="text-status-danger hover:opacity-80 ml-2">
              ×
            </button>
          </div>
        )}

        {/* Messages Stream Container */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center text-brand-muted space-y-3">
              <div className="w-12 h-12 rounded-full bg-surface-elevated flex items-center justify-center border border-border-subtle text-accent-primary">
                <Bot className="w-6 h-6" />
              </div>
              <div className="max-w-sm">
                <h3 className="text-sm font-semibold text-brand-title font-mono">Interactive Streaming Playground</h3>
                <p className="text-xs text-brand-muted mt-1">
                  Authenticate using a virtual key, select a model or smart alias, and stream responses in real time.
                </p>
              </div>
              {lastIssuedKey && !virtualKey && (
                <button
                  onClick={() => setVirtualKey(lastIssuedKey)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-primary/20 hover:bg-accent-primary/30 border border-accent-primary/50 text-accent-primary rounded text-xs font-mono transition"
                >
                  <Key className="w-3.5 h-3.5" />
                  Use newly issued session key ({lastIssuedKey.slice(0, 14)}...)
                </button>
              )}
            </div>
          ) : (
            messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 text-xs font-mono ${
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-7 h-7 rounded-full bg-surface-elevated border border-border-subtle flex items-center justify-center text-accent-primary shrink-0 mt-1">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-lg p-3 space-y-2 ${
                    msg.role === 'user'
                      ? 'bg-accent-soft border border-accent-primary/30 text-brand-title'
                      : 'bg-surface-elevated border border-border-subtle text-brand-body'
                  }`}
                >
                  {/* Reasoning Block if available */}
                  {msg.reasoning_content && (
                    <details className="bg-surface-code border border-border-subtle rounded p-2 text-brand-muted text-[11px] mb-2">
                      <summary className="cursor-pointer text-brand-muted font-semibold hover:text-brand-title">
                        Thinking Process
                      </summary>
                      <div className="mt-1.5 pt-1.5 border-t border-border-subtle whitespace-pre-wrap font-sans text-brand-muted">
                        {msg.reasoning_content}
                      </div>
                    </details>
                  )}

                  {/* Main Content */}
                  <div className="whitespace-pre-wrap font-sans leading-relaxed text-brand-title">
                    {msg.content || (isStreaming && msg.id === messages[messages.length - 1]?.id ? (
                      <span className="text-brand-muted italic">Generating response...</span>
                    ) : (
                      ''
                    ))}
                  </div>

                  {/* Tool calls deltas if any */}
                  {msg.tool_calls && msg.tool_calls.length > 0 && (
                    <div className="pt-2 border-t border-border-subtle space-y-1">
                      <span className="text-[10px] text-accent-primary uppercase font-bold">
                        Tool Invocation Delta:
                      </span>
                      <pre className="text-[10px] bg-surface-code p-1.5 rounded overflow-x-auto text-brand-body">
                        {JSON.stringify(msg.tool_calls, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Timestamp & Latency */}
                  <div className="flex items-center justify-between text-[10px] text-brand-muted pt-1">
                    <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                    {msg.latencyMs && (
                      <span className="flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" /> {msg.latencyMs}ms
                      </span>
                    )}
                  </div>
                </div>

                {msg.role === 'user' && (
                  <div className="w-7 h-7 rounded-full bg-surface-elevated border border-border-subtle flex items-center justify-center text-brand-body shrink-0 mt-1">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={chatBottomRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3 bg-surface-elevated/40 border-t border-border-subtle space-y-2">
          {/* Virtual Key Quick Status / Field */}
          <div className="flex items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center gap-2 flex-1">
              <Key className="w-3.5 h-3.5 text-brand-muted shrink-0" />
              <input
                type={showKeyInput ? 'text' : 'password'}
                value={virtualKey}
                onChange={(e) => setVirtualKey(e.target.value)}
                placeholder="Virtual Key: paste sk-gw-..."
                className="w-full max-w-sm px-2 py-0.5 text-xs bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted font-mono focus:outline-none focus:border-accent-primary"
              />
              <button
                type="button"
                onClick={() => setShowKeyInput(!showKeyInput)}
                className="text-[10px] text-brand-muted hover:text-brand-title transition"
              >
                {showKeyInput ? 'Hide' : 'Show'}
              </button>
            </div>

            {lastIssuedKey && virtualKey !== lastIssuedKey && (
              <button
                type="button"
                onClick={() => setVirtualKey(lastIssuedKey)}
                className="text-[10px] text-accent-primary hover:underline font-mono"
              >
                Use session key
              </button>
            )}
          </div>

          <div className="flex gap-2">
            <textarea
              rows={2}
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSendMessage();
                }
              }}
              placeholder="Ask anything or test prompt routing... (Enter to send, Shift+Enter for newline)"
              className="flex-1 p-2.5 text-xs bg-surface-input border border-border-subtle rounded text-brand-title placeholder-brand-muted font-mono focus:outline-none focus:border-accent-primary resize-none"
            />

            <div className="flex flex-col gap-1.5 justify-end">
              {isStreaming ? (
                <button
                  type="button"
                  onClick={handleStopStreaming}
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-medium rounded text-xs font-mono transition flex items-center justify-center gap-1.5 h-full"
                >
                  <X className="w-3.5 h-3.5" />
                  Stop
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleSendMessage}
                  disabled={!userInput.trim() || !virtualKey.trim()}
                  className="px-4 py-2 bg-accent-primary hover:bg-accent-dark text-accent-contrast font-medium rounded text-xs font-mono transition flex items-center justify-center gap-1.5 h-full disabled:opacity-40"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Send
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Right Sidebar: Model Parameters & Telemetry Inspector (300px) */}
      <div className="w-full lg:w-80 flex flex-col gap-4">
        {/* Model & Routing Configuration */}
        <div className="bg-surface-base border border-border-subtle rounded-lg p-4 space-y-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-brand-title flex items-center gap-1.5">
            <Settings className="w-3.5 h-3.5 text-accent-primary" />
            Model & Parameters
          </h3>

          {/* Model Smart Aliases */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-brand-muted font-mono">Routing Target / Alias:</label>
            <div className="grid grid-cols-2 gap-1.5 max-h-36 overflow-y-auto">
              {aliasOptions.map((alias) => (
                <button
                  key={alias}
                  type="button"
                  onClick={() => {
                    setSelectedModel(alias);
                    setCustomModelInput('');
                  }}
                  className={`px-2.5 py-1.5 rounded text-xs font-mono transition text-left flex items-center justify-between ${
                    selectedModel === alias && !customModelInput
                      ? 'bg-accent-soft text-accent-primary border border-accent-primary/40 font-bold'
                      : 'bg-surface-elevated text-brand-muted border border-border-subtle hover:text-brand-title'
                  }`}
                >
                  <span className="truncate">{alias}</span>
                  {selectedModel === alias && !customModelInput && <Zap className="w-3 h-3 text-accent-primary shrink-0" />}
                </button>
              ))}
            </div>

            <div className="pt-1.5">
              <input
                type="text"
                list="playground-models-list"
                value={customModelInput}
                onChange={(e) => setCustomModelInput(e.target.value)}
                placeholder="Or specify exact model ID..."
                className="w-full px-2.5 py-1 text-xs bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted font-mono focus:outline-none focus:border-accent-primary"
              />
              <datalist id="playground-models-list">
                {modelSuggestions.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </div>
          </div>

          {/* Sliders */}
          <div className="space-y-3 pt-2 border-t border-border-subtle text-xs font-mono">
            {[
              { label: 'Temperature', display: temperature.toFixed(2), min: 0, max: 2, step: 0.05, value: temperature, set: (v: string) => setTemperature(parseFloat(v)) },
              { label: 'Max Tokens', display: String(maxTokens), min: 128, max: 8192, step: 128, value: maxTokens, set: (v: string) => setMaxTokens(parseInt(v, 10)) },
              { label: 'Top P', display: topP.toFixed(2), min: 0, max: 1, step: 0.05, value: topP, set: (v: string) => setTopP(parseFloat(v)) },
            ].map((s) => (
              <div key={s.label} className="space-y-1">
                <div className="flex justify-between text-brand-muted">
                  <span>{s.label}</span>
                  <span className="text-brand-title font-bold">{s.display}</span>
                </div>
                <input
                  type="range"
                  min={s.min}
                  max={s.max}
                  step={s.step}
                  value={s.value}
                  onChange={(e) => s.set(e.target.value)}
                  className="w-full accent-accent-primary cursor-pointer"
                />
              </div>
            ))}
          </div>

          {/* Routing Hints */}
          <div className="pt-2 border-t border-border-subtle text-xs font-mono">
            <button
              type="button"
              onClick={() => setIsHintsOpen(!isHintsOpen)}
              className="w-full flex items-center justify-between text-brand-muted hover:text-brand-title transition py-1"
            >
              <span>Routing Hints</span>
              <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isHintsOpen ? '' : '-rotate-90'}`} />
            </button>
            {isHintsOpen && (
              <div className="space-y-2 pt-2">
                <input
                  type="text"
                  value={hintRegion}
                  onChange={(e) => setHintRegion(e.target.value)}
                  placeholder="Allowed region (e.g. us-east-1)"
                  className="w-full px-2 py-1 text-[11px] bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
                />
                <input
                  type="text"
                  value={hintTags}
                  onChange={(e) => setHintTags(e.target.value)}
                  placeholder="Tags (comma-sep: tier:fast, eu)"
                  className="w-full px-2 py-1 text-[11px] bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
                />
                <input
                  type="text"
                  value={hintSessionId}
                  onChange={(e) => setHintSessionId(e.target.value)}
                  placeholder="Session ID (sticky affinity)"
                  className="w-full px-2 py-1 text-[11px] bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
                />
                <div className="grid grid-cols-2 gap-1.5">
                  <input
                    type="number"
                    value={hintPriority}
                    onChange={(e) => setHintPriority(e.target.value)}
                    placeholder="Priority"
                    className="w-full px-2 py-1 text-[11px] bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
                  />
                  <input
                    type="number"
                    min={0}
                    value={hintHedgeMs}
                    onChange={(e) => setHintHedgeMs(e.target.value)}
                    placeholder="Hedge (ms)"
                    className="w-full px-2 py-1 text-[11px] bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Live Performance & Telemetry Card */}
        <div className="bg-surface-base border border-border-subtle rounded-lg p-4 space-y-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-brand-title flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-status-success" />
            Invocation Telemetry
          </h3>

          {lastRequestMetrics ? (
            <div className="space-y-2 text-xs font-mono">
              {lastRequestMetrics.headers?.requestId && (
                <div className="flex justify-between items-center text-brand-muted">
                  <span>Request ID:</span>
                  <span
                    className="text-brand-body text-[11px] truncate max-w-[150px] cursor-pointer hover:text-accent-primary"
                    title={lastRequestMetrics.headers.requestId}
                    onClick={() => copyToClipboard(lastRequestMetrics.headers!.requestId!)}
                  >
                    {lastRequestMetrics.headers.requestId.slice(0, 14)}...
                  </span>
                </div>
              )}
              {[
                lastRequestMetrics.headers?.provider && ['Upstream Provider:', lastRequestMetrics.headers.provider, 'text-brand-body capitalize font-medium'],
                ['Target Model:', lastRequestMetrics.model, 'text-accent-primary font-medium'],
                lastRequestMetrics.headers?.cache && ['Exact Cache:', lastRequestMetrics.headers.cache, lastRequestMetrics.headers.cache === 'HIT' ? 'text-status-success font-bold' : 'text-brand-muted'],
                lastRequestMetrics.headers?.tokenEstimate !== undefined && ['Estimated Tokens:', String(lastRequestMetrics.headers.tokenEstimate), 'text-brand-body'],
                lastRequestMetrics.headers?.costMicros !== undefined && ['Estimated Cost:', `$${(lastRequestMetrics.headers.costMicros / 1_000_000).toFixed(6)} (${lastRequestMetrics.headers.costMicros} µ$)`, 'text-status-success font-bold'],
                lastRequestMetrics.headers?.guardrailAction && ['Guardrail Action:', lastRequestMetrics.headers.guardrailAction, 'text-status-warning font-semibold uppercase'],
                lastRequestMetrics.headers?.routeReason && ['Route Reason:', lastRequestMetrics.headers.routeReason, 'text-accent-primary font-medium truncate max-w-[150px]'],
                lastRequestMetrics.headers?.fallbackAttempted && ['Fallback Attempted:', lastRequestMetrics.headers.fallbackAttempted, lastRequestMetrics.headers.fallbackAttempted === 'true' ? 'text-status-warning font-bold' : 'text-brand-muted'],
                lastRequestMetrics.headers?.streamContinued && ['Stream Continued:', lastRequestMetrics.headers.streamContinued, lastRequestMetrics.headers.streamContinued === 'true' ? 'text-status-warning font-bold' : 'text-brand-muted'],
                lastRequestMetrics.headers?.routingMicros !== undefined && !isNaN(lastRequestMetrics.headers.routingMicros) && ['Routing Overhead:', `${lastRequestMetrics.headers.routingMicros} µs`, 'text-brand-body'],
                lastRequestMetrics.headers?.tierStepdowns !== undefined && !isNaN(lastRequestMetrics.headers.tierStepdowns) && ['Tier Stepdowns:', String(lastRequestMetrics.headers.tierStepdowns), 'text-brand-body'],
                ['Total Latency:', `${lastRequestMetrics.latencyMs} ms`, 'text-brand-body font-bold'],
                lastRequestMetrics.ttftMs && ['Time-To-First-Token:', `${lastRequestMetrics.ttftMs} ms`, 'text-status-success font-bold'],
                ['Stream Chunks:', `${lastRequestMetrics.chunkCount} SSE events`, 'text-brand-body'],
              ].filter((x): x is [string, string, string] => Boolean(x)).map(([label, val, cls]) => (
                <div key={label} className="flex justify-between text-brand-muted">
                  <span>{label}</span>
                  <span className={cls}>{val}</span>
                </div>
              ))}
              <div className="pt-1.5 border-t border-border-subtle text-[11px] text-brand-muted">
                Ledger: Recorded under active virtual key.
              </div>
            </div>
          ) : (
            <div className="text-xs text-brand-muted font-mono py-2 text-center">
              Awaiting first streaming request...
            </div>
          )}
        </div>
      </div>

      {/* Code Export Modal */}
      {showExportModal && (
        <Modal
          title="Export Inference Request Code"
          isOpen={showExportModal}
          onClose={() => {
            setShowExportModal(false);
            setIncludeKeyInExport(false);
          }}
          size="lg"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <div className="flex gap-2">
                {(['curl', 'python', 'ts', 'go'] as const).map((lang) => (
                  <button
                    key={lang}
                    onClick={() => setExportLanguage(lang)}
                    className={`px-3 py-1 rounded text-xs font-mono uppercase transition ${
                      exportLanguage === lang
                        ? 'bg-accent-primary text-accent-contrast font-bold'
                        : 'bg-surface-elevated text-brand-muted hover:text-brand-title'
                    }`}
                  >
                    {lang}
                  </button>
                ))}
              </div>

              <button
                onClick={() => copyToClipboard(getCodeSnippet(exportLanguage))}
                className="flex items-center gap-1.5 px-3 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
              >
                {copiedSnippet ? <Check className="w-3.5 h-3.5 text-status-success" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedSnippet ? 'Copied' : 'Copy'}
              </button>
            </div>

            <label className="flex items-center gap-2 text-xs font-mono text-brand-muted select-none cursor-pointer">
              <input
                type="checkbox"
                checked={includeKeyInExport}
                disabled={!virtualKey.trim()}
                onChange={(e) => setIncludeKeyInExport(e.target.checked)}
                className="rounded border-border-subtle bg-surface-input text-accent-primary focus:ring-accent-primary disabled:opacity-40"
              />
              <span className={!virtualKey.trim() ? 'opacity-50' : ''}>
                Embed current session virtual key instead of <code className="text-brand-body">$GOROUTE_API_KEY</code>
              </span>
            </label>

            <CodeBlock code={getCodeSnippet(exportLanguage)} language={exportLanguage} />
          </div>
        </Modal>
      )}
    </div>
  );
};
