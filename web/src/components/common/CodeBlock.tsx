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
    <div className={`relative group rounded-[0.65rem] bg-[#0d0d12] border border-border overflow-hidden font-mono text-xs ${className}`}>
      <div className="flex items-center justify-between px-3.5 py-2 bg-surface-elevated/70 border-b border-border text-[#9696a4]">
        <span className="uppercase text-[10px] tracking-wider font-semibold text-accent-primary">{language}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 hover:text-white transition-colors py-1 px-2 rounded-md hover:bg-surface-hover hover:text-accent-primary"
          title="Copy code"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-accent-primary" />
              <span className="text-[10px] text-accent-primary font-semibold">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span className="text-[10px]">Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3.5 overflow-x-auto text-[#d2d0dc] leading-relaxed whitespace-pre-wrap break-all font-mono">
        <code>{code}</code>
      </pre>
    </div>
  );
};
