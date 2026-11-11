import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  language?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, language = 'bash', className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`relative group rounded-lg bg-black/60 border border-border-subtle overflow-hidden font-mono text-xs ${className}`}>
      <div className="flex items-center justify-between px-3 py-1.5 bg-surface-base/80 border-b border-border-subtle/40 text-slate-400">
        <span className="uppercase text-[10px] tracking-wider font-semibold">{language}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 hover:text-slate-200 transition-colors py-0.5 px-1.5 rounded hover:bg-surface-elevated"
          title="Copy code"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-[10px] text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span className="text-[10px]">Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3 overflow-x-auto text-slate-300 leading-relaxed whitespace-pre-wrap break-all">
        <code>{code}</code>
      </pre>
    </div>
  );
};
