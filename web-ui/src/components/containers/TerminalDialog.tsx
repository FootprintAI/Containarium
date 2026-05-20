'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { X, Loader2 } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';

interface TerminalDialogProps {
  open: boolean;
  onClose: () => void;
  containerName: string;
  username: string;
  serverEndpoint: string;
  token: string;
}

interface TerminalMessage {
  type: 'input' | 'output' | 'resize' | 'error';
  data?: string;
  cols?: number;
  rows?: number;
}

export default function TerminalDialog({ open, onClose, containerName, username, serverEndpoint, token }: TerminalDialogProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminalInstance = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  const cleanup = useCallback(() => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    if (terminalInstance.current) { terminalInstance.current.dispose(); terminalInstance.current = null; }
    fitAddon.current = null;
    setConnected(false); setConnecting(false); setError(null);
  }, []);

  const connect = useCallback(() => {
    if (!terminalRef.current || connecting || connected) return;
    setConnecting(true); setError(null);

    const term = new Terminal({
      cursorBlink: true, fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: { background: '#09090b', foreground: '#d4d4d4', cursor: '#d4d4d4', selectionBackground: '#264f78' },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(terminalRef.current);
    fit.fit();
    terminalInstance.current = term;
    fitAddon.current = fit;

    let wsUrl = serverEndpoint.replace(/^http/, 'ws').replace(/\/v1\/?$/, '');
    const cleanToken = token.replace(/\s+/g, '');
    wsUrl = `${wsUrl}/v1/containers/${username}/terminal`;

    term.writeln(`Connecting to ${containerName}...`);

    // Phase 1.5 — auth via WebSocket subprotocol header
    // (Sec-WebSocket-Protocol) so the JWT never lands in URL
    // bars, access logs, or proxy logs. Server matches the
    // 'containarium.bearer' marker and reads the next entry
    // as the token; see internal/auth/ws_token.go.
    const ws = new WebSocket(wsUrl, ['containarium.bearer', cleanToken]);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true); setConnecting(false);
      term.writeln('Connected!\r\n');
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    };

    ws.onmessage = (event) => {
      try {
        const msg: TerminalMessage = JSON.parse(event.data);
        if (msg.type === 'output' && msg.data) term.write(msg.data);
        else if (msg.type === 'error' && msg.data) { term.writeln(`\r\n\x1b[31mError: ${msg.data}\x1b[0m`); setError(msg.data); }
      } catch { term.write(event.data); }
    };

    ws.onerror = () => { setError('WebSocket connection error'); setConnecting(false); term.writeln('\r\n\x1b[31mConnection error\x1b[0m'); };
    ws.onclose = () => { setConnected(false); setConnecting(false); term.writeln('\r\n\x1b[33mConnection closed\x1b[0m'); };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'input', data }));
    });

    const handleResize = () => {
      if (fitAddon.current && terminalInstance.current) {
        fitAddon.current.fit();
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols: terminalInstance.current.cols, rows: terminalInstance.current.rows }));
        }
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [serverEndpoint, username, token, containerName, connecting, connected]);

  useEffect(() => {
    if (open) {
      const t = setTimeout(() => {
        if (terminalRef.current) connect();
        else setTimeout(() => { if (terminalRef.current) connect(); }, 200);
      }, 100);
      return () => clearTimeout(t);
    }
  }, [open, connect]);

  useEffect(() => { if (!open) cleanup(); }, [open, cleanup]);

  useEffect(() => {
    if (open && fitAddon.current) {
      const t = setTimeout(() => fitAddon.current?.fit(), 100);
      return () => clearTimeout(t);
    }
  }, [open]);

  const handleClose = () => { cleanup(); onClose(); };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={handleClose} />
      <div className="relative z-10 flex h-[80vh] w-[90vw] max-w-5xl flex-col rounded-xl border border-[var(--border)] bg-[#09090b] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2.5">
          <span className="text-xs font-medium text-zinc-300">Terminal: {containerName}</span>
          {connecting && <Loader2 size={13} className="animate-spin text-zinc-500" />}
          {connected && <span className="text-[10px] text-[var(--c-emerald)]">Connected</span>}
          {error && <span className="text-[10px] text-[var(--c-red)]">{error}</span>}
          <button onClick={handleClose} className="ml-auto rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300 transition-colors">
            <X size={14} />
          </button>
        </div>
        {/* Terminal */}
        <div ref={terminalRef} className="flex-1 overflow-hidden [&_.xterm]:h-full [&_.xterm]:p-2" />
      </div>
    </div>
  );
}
