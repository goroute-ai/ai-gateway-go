import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { streamChatCompletion, ChatStreamChunk, ChatStreamHeaders } from '../api/sse';
import { Badge } from '../components/common/Badge';
import { CodeBlock } from '../components/common/CodeBlock';
import { Modal } from '../components/common/Modal';
import {
  Send,
  Square,
  Trash2,
  Settings,
  Code,
  Key,
  KeyRound,
  Bot,
  User,
  Sparkles,
  AlertCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
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

export const PlaygroundView: React.FC = () => {
  const { lastIssuedKey } = useAuth();

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

  const handleSendMessage = async () => {
    if (!userInput.trim() || isStreaming) return;
    if (!virtualKey.trim()) {
      setStreamError('A valid Virtual Key (sk-gw-...) is required to send inference requests.');
      return;
    }

    setStreamError(null);
    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content: userInput.trim(),
      timestamp: new Date().toISOString(),
    };

    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setUserInput('');

    // Prepare assistant placeholder
    const assistantMsgId = crypto.randomUUID();
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

    const payload = {
      model: activeModel,
      messages: apiMessages,
      temperature,
      max_tokens: maxTokens,
      top_p: topP,
      stream: true,
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
    const msgs = [
      ...(systemPrompt ? [{ role: 'system', content: systemPrompt }] : []),
      ...messages.map((m) => ({ role: m.role, content: m.content })),
    ];
    if (msgs.length === 0) {
      msgs.push({ role: 'user', content: 'Hello GoRoute Gateway!' });
    }

    switch (lang) {
      case 'curl':
        return `curl -X POST "${endpoint}" \\
  -H "Authorization: Bearer ${key}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "${activeModel}",
    "messages": ${JSON.stringify(msgs, null, 4).replace(/\n/g, '\n    ')},
    "temperature": ${temperature},
    "max_tokens": ${maxTokens},
    "stream": true
  }'`;

      case 'python':
        return `from openai import OpenAI

client = OpenAI(
    api_key="${key}",
    base_url="${window.location.origin}/v1"
)

response = client.chat.completions.create(
    model="${activeModel}",
    messages=${JSON.stringify(msgs, null, 4)},
    temperature=${temperature},
    max_tokens=${maxTokens},
    stream=True,
)

for chunk in response:
    content = chunk.choices[0].delta.content or ""
    print(content, end="", flush=True)
`;

      case 'ts':
        return `import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: '${key}',
  baseURL: '${window.location.origin}/v1',
  dangerouslyAllowBrowser: true, // Only if executing client-side
});

async function main() {
  const stream = await client.chat.completions.create({
    model: '${activeModel}',
    messages: ${JSON.stringify(msgs, null, 2)},
    temperature: ${temperature},
    max_tokens: ${maxTokens},
    stream: true,
  });

  for await (const chunk of stream) {
    process.stdout.write(chunk.choices[0]?.delta?.content || '');
  }
}

main();`;

      case 'go':
        return `package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	payload := map[string]interface{}{
		"model":       "${activeModel}",
		"messages":    ${JSON.stringify(msgs)},
		"temperature": ${temperature},
		"stream":      false,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "${endpoint}", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer ${key}")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
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
      <div className="flex-1 flex flex-col bg-surface-base border border-subtle rounded-lg overflow-hidden">
        {/* Chat Header Bar */}
        <div className="px-4 py-2.5 bg-surface-elevated/40 border-b border-subtle flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-accent-primary" />
            <span className="text-xs font-semibold text-zinc-100 font-mono">Chat Playground</span>
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
              className="flex items-center gap-1 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono transition"
              title="Export as Code"
            >
              <Code className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export Code</span>
            </button>
            <button
              onClick={handleClearChat}
              disabled={messages.length === 0}
              className="flex items-center gap-1 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-400 hover:text-red-300 rounded text-xs font-mono transition disabled:opacity-40"
              title="Clear Conversation"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Clear</span>
            </button>
          </div>
        </div>

        {/* Collapsible System Prompt */}
        <div className="border-b border-subtle bg-canvas/40">
          <button
            onClick={() => setIsSystemOpen(!isSystemOpen)}
            className="w-full px-4 py-2 flex items-center justify-between text-xs font-mono text-zinc-400 hover:text-zinc-200 transition"
          >
            <span className="flex items-center gap-1.5">
              {isSystemOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              System Instructions
            </span>
            <span className="text-[10px] text-zinc-500 truncate max-w-[300px]">
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
                className="w-full p-2 text-xs bg-surface-elevated border border-subtle rounded text-zinc-200 font-mono focus:outline-none focus:border-accent-primary resize-y"
              />
            </div>
          )}
        </div>

        {/* Error Notification Banner */}
        {streamError && (
          <div className="mx-4 mt-3 p-3 bg-red-950/40 border border-red-900/60 rounded flex items-start justify-between text-xs text-red-300 font-mono">
            <div className="flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Execution Error: </span>
                {streamError}
              </div>
            </div>
            <button onClick={() => setStreamError(null)} className="text-red-400 hover:text-red-200 ml-2">
              ×
            </button>
          </div>
        )}

        {/* Messages Stream Container */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center text-zinc-500 space-y-3">
              <div className="w-12 h-12 rounded-full bg-surface-elevated flex items-center justify-center border border-subtle text-accent-primary">
                <Bot className="w-6 h-6" />
              </div>
              <div className="max-w-sm">
                <h3 className="text-sm font-semibold text-zinc-300 font-mono">Interactive Streaming Playground</h3>
                <p className="text-xs text-zinc-400 mt-1">
                  Authenticate using a virtual key, select a model or smart alias, and stream responses in real time.
                </p>
              </div>
              {lastIssuedKey && !virtualKey && (
                <button
                  onClick={() => setVirtualKey(lastIssuedKey)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-primary/20 hover:bg-accent-primary/30 border border-accent-primary/50 text-accent-primary rounded text-xs font-mono transition"
                >
                  <KeyRound className="w-3.5 h-3.5" />
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
                  <div className="w-7 h-7 rounded-full bg-surface-elevated border border-subtle flex items-center justify-center text-accent-primary shrink-0 mt-1">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-lg p-3 space-y-2 ${
                    msg.role === 'user'
                      ? 'bg-accent-primary/10 border border-accent-primary/30 text-zinc-100'
                      : 'bg-surface-elevated border border-subtle text-zinc-200'
                  }`}
                >
                  {/* Reasoning Block if available */}
                  {msg.reasoning_content && (
                    <details className="bg-canvas/60 border border-subtle rounded p-2 text-zinc-400 text-[11px] mb-2">
                      <summary className="cursor-pointer text-zinc-400 font-semibold hover:text-zinc-200">
                        Thinking Process
                      </summary>
                      <div className="mt-1.5 pt-1.5 border-t border-subtle whitespace-pre-wrap font-sans text-zinc-400">
                        {msg.reasoning_content}
                      </div>
                    </details>
                  )}

                  {/* Main Content */}
                  <div className="whitespace-pre-wrap font-sans leading-relaxed text-zinc-100">
                    {msg.content || (isStreaming && msg.id === messages[messages.length - 1]?.id ? (
                      <span className="text-zinc-500 italic">Generating response...</span>
                    ) : (
                      ''
                    ))}
                  </div>

                  {/* Tool calls deltas if any */}
                  {msg.tool_calls && msg.tool_calls.length > 0 && (
                    <div className="pt-2 border-t border-subtle space-y-1">
                      <span className="text-[10px] text-accent-primary uppercase font-bold">
                        Tool Invocation Delta:
                      </span>
                      <pre className="text-[10px] bg-canvas p-1.5 rounded overflow-x-auto text-zinc-300">
                        {JSON.stringify(msg.tool_calls, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Timestamp & Latency */}
                  <div className="flex items-center justify-between text-[10px] text-zinc-500 pt-1">
                    <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                    {msg.latencyMs && (
                      <span className="flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" /> {msg.latencyMs}ms
                      </span>
                    )}
                  </div>
                </div>

                {msg.role === 'user' && (
                  <div className="w-7 h-7 rounded-full bg-zinc-800 border border-subtle flex items-center justify-center text-zinc-300 shrink-0 mt-1">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={chatBottomRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3 bg-surface-elevated/40 border-t border-subtle space-y-2">
          {/* Virtual Key Quick Status / Field */}
          <div className="flex items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center gap-2 flex-1">
              <Key className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
              <input
                type={showKeyInput ? 'text' : 'password'}
                value={virtualKey}
                onChange={(e) => setVirtualKey(e.target.value)}
                placeholder="Virtual Key: paste sk-gw-..."
                className="w-full max-w-sm px-2 py-0.5 text-xs bg-canvas border border-subtle rounded text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-accent-primary"
              />
              <button
                type="button"
                onClick={() => setShowKeyInput(!showKeyInput)}
                className="text-[10px] text-zinc-400 hover:text-zinc-200 transition"
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
              className="flex-1 p-2.5 text-xs bg-canvas border border-subtle rounded text-zinc-100 placeholder-zinc-500 font-mono focus:outline-none focus:border-accent-primary resize-none"
            />

            <div className="flex flex-col gap-1.5 justify-end">
              {isStreaming ? (
                <button
                  type="button"
                  onClick={handleStopStreaming}
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-medium rounded text-xs font-mono transition flex items-center justify-center gap-1.5 h-full"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  Stop
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleSendMessage}
                  disabled={!userInput.trim() || !virtualKey.trim()}
                  className="px-4 py-2 bg-accent-primary hover:bg-accent-glow text-zinc-950 font-medium rounded text-xs font-mono transition flex items-center justify-center gap-1.5 h-full disabled:opacity-40"
                >
                  <Send className="w-3.5 h-3.5" />
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
        <div className="bg-surface-base border border-subtle rounded-lg p-4 space-y-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
            <Settings className="w-3.5 h-3.5 text-accent-primary" />
            Model & Parameters
          </h3>

          {/* Model Smart Aliases */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-zinc-400 font-mono">Routing Target / Alias:</label>
            <div className="grid grid-cols-2 gap-1.5">
              {(['fast', 'reasoning', 'coding', 'auto'] as const).map((alias) => (
                <button
                  key={alias}
                  type="button"
                  onClick={() => {
                    setSelectedModel(alias);
                    setCustomModelInput('');
                  }}
                  className={`px-2.5 py-1.5 rounded text-xs font-mono capitalize transition text-left flex items-center justify-between ${
                    selectedModel === alias && !customModelInput
                      ? 'bg-[rgba(124,58,237,0.15)] text-accent-primary border border-accent-primary/40 font-bold'
                      : 'bg-surface-elevated text-zinc-400 border border-subtle hover:text-zinc-200'
                  }`}
                >
                  <span>{alias}</span>
                  {selectedModel === alias && !customModelInput && <Zap className="w-3 h-3 text-accent-primary" />}
                </button>
              ))}
            </div>

            <div className="pt-1.5">
              <input
                type="text"
                value={customModelInput}
                onChange={(e) => setCustomModelInput(e.target.value)}
                placeholder="Or specify exact model ID..."
                className="w-full px-2.5 py-1 text-xs bg-canvas border border-subtle rounded text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-accent-primary"
              />
            </div>
          </div>

          {/* Sliders */}
          <div className="space-y-3 pt-2 border-t border-subtle text-xs font-mono">
            {/* Temperature */}
            <div className="space-y-1">
              <div className="flex justify-between text-zinc-400">
                <span>Temperature</span>
                <span className="text-zinc-200 font-bold">{temperature.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.00"
                max="2.00"
                step="0.05"
                value={temperature}
                onChange={(e) => setTemperature(parseFloat(e.target.value))}
                className="w-full accent-accent-primary cursor-pointer"
              />
            </div>

            {/* Max Tokens */}
            <div className="space-y-1">
              <div className="flex justify-between text-zinc-400">
                <span>Max Tokens</span>
                <span className="text-zinc-200 font-bold">{maxTokens}</span>
              </div>
              <input
                type="range"
                min="128"
                max="8192"
                step="128"
                value={maxTokens}
                onChange={(e) => setMaxTokens(parseInt(e.target.value, 10))}
                className="w-full accent-accent-primary cursor-pointer"
              />
            </div>

            {/* Top P */}
            <div className="space-y-1">
              <div className="flex justify-between text-zinc-400">
                <span>Top P</span>
                <span className="text-zinc-200 font-bold">{topP.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.00"
                max="1.00"
                step="0.05"
                value={topP}
                onChange={(e) => setTopP(parseFloat(e.target.value))}
                className="w-full accent-accent-primary cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Live Performance & Telemetry Card */}
        <div className="bg-surface-base border border-subtle rounded-lg p-4 space-y-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-emerald-400" />
            Invocation Telemetry
          </h3>

          {lastRequestMetrics ? (
            <div className="space-y-2 text-xs font-mono">
              {lastRequestMetrics.headers?.requestId && (
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Request ID:</span>
                  <span
                    className="text-zinc-300 font-mono text-[11px] truncate max-w-[150px] cursor-pointer hover:text-accent-primary"
                    title={lastRequestMetrics.headers.requestId}
                    onClick={() => copyToClipboard(lastRequestMetrics.headers!.requestId!)}
                  >
                    {lastRequestMetrics.headers.requestId.slice(0, 14)}...
                  </span>
                </div>
              )}
              {lastRequestMetrics.headers?.provider && (
                <div className="flex justify-between text-zinc-400">
                  <span>Upstream Provider:</span>
                  <span className="text-zinc-200 capitalize font-medium">{lastRequestMetrics.headers.provider}</span>
                </div>
              )}
              <div className="flex justify-between text-zinc-400">
                <span>Target Model:</span>
                <span className="text-accent-primary font-medium">{lastRequestMetrics.model}</span>
              </div>
              {lastRequestMetrics.headers?.cache && (
                <div className="flex justify-between text-zinc-400">
                  <span>Exact Cache:</span>
                  <span className={lastRequestMetrics.headers.cache === 'HIT' ? 'text-emerald-400 font-bold' : 'text-zinc-400'}>
                    {lastRequestMetrics.headers.cache}
                  </span>
                </div>
              )}
              {lastRequestMetrics.headers?.tokenEstimate !== undefined && (
                <div className="flex justify-between text-zinc-400">
                  <span>Estimated Tokens:</span>
                  <span className="text-zinc-300">{lastRequestMetrics.headers.tokenEstimate}</span>
                </div>
              )}
              <div className="flex justify-between text-zinc-400">
                <span>Total Latency:</span>
                <span className="text-zinc-200 font-bold">{lastRequestMetrics.latencyMs} ms</span>
              </div>
              {lastRequestMetrics.ttftMs && (
                <div className="flex justify-between text-zinc-400">
                  <span>Time-To-First-Token:</span>
                  <span className="text-emerald-400 font-bold">{lastRequestMetrics.ttftMs} ms</span>
                </div>
              )}
              <div className="flex justify-between text-zinc-400">
                <span>Stream Chunks:</span>
                <span className="text-zinc-200">{lastRequestMetrics.chunkCount} SSE events</span>
              </div>
              <div className="pt-1.5 border-t border-subtle text-[11px] text-zinc-500">
                Ledger: Recorded as standard spend event under active virtual key.
              </div>
            </div>
          ) : (
            <div className="text-xs text-zinc-500 font-mono py-2 text-center">
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
            <div className="flex items-center justify-between border-b border-subtle pb-2">
              <div className="flex gap-2">
                {(['curl', 'python', 'ts', 'go'] as const).map((lang) => (
                  <button
                    key={lang}
                    onClick={() => setExportLanguage(lang)}
                    className={`px-3 py-1 rounded text-xs font-mono uppercase transition ${
                      exportLanguage === lang
                        ? 'bg-accent-primary text-zinc-950 font-bold'
                        : 'bg-surface-elevated text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    {lang}
                  </button>
                ))}
              </div>

              <button
                onClick={() => copyToClipboard(getCodeSnippet(exportLanguage))}
                className="flex items-center gap-1.5 px-3 py-1 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono transition"
              >
                {copiedSnippet ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedSnippet ? 'Copied' : 'Copy'}
              </button>
            </div>

            <label className="flex items-center gap-2 text-xs font-mono text-zinc-400 select-none cursor-pointer">
              <input
                type="checkbox"
                checked={includeKeyInExport}
                disabled={!virtualKey.trim()}
                onChange={(e) => setIncludeKeyInExport(e.target.checked)}
                className="rounded border-subtle bg-canvas text-accent-primary focus:ring-accent-primary disabled:opacity-40"
              />
              <span className={!virtualKey.trim() ? 'opacity-50' : ''}>
                Embed current session virtual key instead of <code className="text-zinc-300">$GOROUTE_API_KEY</code>
              </span>
            </label>

            <CodeBlock code={getCodeSnippet(exportLanguage)} language={exportLanguage} />
          </div>
        </Modal>
      )}
    </div>
  );
};
