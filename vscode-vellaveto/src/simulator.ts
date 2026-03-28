import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import { URL } from 'url';
import { getConfig } from './config';

/**
 * Creates and manages the Simulator webview panel.
 * Allows testing actions against the current policy file.
 */
export class SimulatorPanel {
    private static currentPanel: SimulatorPanel | undefined;
    private readonly panel: vscode.WebviewPanel;
    private disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel) {
        this.panel = panel;
        this.panel.webview.html = this.getHtml();

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                if (message.command === 'simulate') {
                    await this.handleSimulate(message.tool, message.fn, message.params);
                }
            },
            null,
            this.disposables,
        );

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    }

    static show(extensionUri: vscode.Uri): void {
        if (SimulatorPanel.currentPanel) {
            SimulatorPanel.currentPanel.panel.reveal(vscode.ViewColumn.Beside);
            return;
        }
        const panel = vscode.window.createWebviewPanel(
            'vellavetoSimulator',
            'Vellaveto Simulator',
            vscode.ViewColumn.Beside,
            { enableScripts: true },
        );
        SimulatorPanel.currentPanel = new SimulatorPanel(panel);
    }

    private dispose(): void {
        SimulatorPanel.currentPanel = undefined;
        this.panel.dispose();
        for (const d of this.disposables) {
            d.dispose();
        }
    }

    private async handleSimulate(tool: string, fn: string, params: string): Promise<void> {
        const config = getConfig();
        let parsedParams: Record<string, unknown> = {};
        try {
            if (params.trim()) {
                parsedParams = JSON.parse(params);
            }
        } catch {
            this.panel.webview.postMessage({
                command: 'result',
                error: 'Invalid JSON in parameters field',
            });
            return;
        }

        const body = JSON.stringify({
            action: {
                tool,
                function: fn || undefined,
                parameters: Object.keys(parsedParams).length > 0 ? parsedParams : undefined,
            },
        });

        try {
            const result = await this.postJson(
                `${config.serverUrl}/api/simulator/evaluate`,
                body,
                config.apiKey,
            );
            this.panel.webview.postMessage({ command: 'result', data: result });
        } catch (err) {
            this.panel.webview.postMessage({
                command: 'result',
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }

    private postJson(urlStr: string, body: string, apiKey: string): Promise<unknown> {
        const url = new URL(urlStr);
        return new Promise((resolve, reject) => {
            const mod = url.protocol === 'https:' ? https : http;
            const req = mod.request(
                url,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(body),
                        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
                    },
                    timeout: 10000,
                },
                (res) => {
                    const MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB
                    let data = '';
                    res.on('data', (chunk: string) => {
                        data += chunk;
                        if (data.length > MAX_RESPONSE_SIZE) {
                            req.destroy();
                            reject(new Error('Response too large'));
                            return;
                        }
                    });
                    res.on('end', () => {
                        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                            try {
                                resolve(JSON.parse(data));
                            } catch {
                                reject(new Error('Invalid JSON response'));
                            }
                        } else {
                            reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
                        }
                    });
                },
            );
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
            req.write(body);
            req.end();
        });
    }

    private getHtml(): string {
        const nonce = crypto.randomUUID();
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vellaveto Simulator</title>
  <style>
    body { font-family: var(--vscode-font-family); padding: 16px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
    label { display: block; margin-top: 12px; font-weight: bold; }
    input, textarea { width: 100%; padding: 6px 8px; margin-top: 4px; border: 1px solid var(--vscode-input-border); background: var(--vscode-input-background); color: var(--vscode-input-foreground); border-radius: 2px; font-family: var(--vscode-editor-font-family); }
    textarea { min-height: 80px; resize: vertical; }
    button { margin-top: 16px; padding: 8px 16px; background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; border-radius: 2px; cursor: pointer; font-size: 14px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    #result { margin-top: 16px; padding: 12px; border-radius: 4px; white-space: pre-wrap; font-family: var(--vscode-editor-font-family); font-size: 13px; }
    .allow { background: rgba(0, 180, 0, 0.15); border: 1px solid rgba(0, 180, 0, 0.4); }
    .deny { background: rgba(220, 40, 40, 0.15); border: 1px solid rgba(220, 40, 40, 0.4); }
    .require_approval { background: rgba(220, 180, 0, 0.15); border: 1px solid rgba(220, 180, 0, 0.4); }
    .error { background: rgba(220, 40, 40, 0.1); border: 1px solid rgba(220, 40, 40, 0.3); }
    h2 { margin-top: 0; }
  </style>
</head>
<body>
  <h2>Policy Simulator</h2>
  <p>Test an action against your loaded policies.</p>
  <label for="tool">Tool Name</label>
  <input type="text" id="tool" placeholder="e.g., read_file" />
  <label for="fn">Function (optional)</label>
  <input type="text" id="fn" placeholder="e.g., read" />
  <label for="params">Parameters (JSON, optional)</label>
  <textarea id="params" placeholder='{"path": "/tmp/test.txt"}'></textarea>
  <button onclick="simulate()">Evaluate</button>
  <div id="result"></div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    function simulate() {
      vscode.postMessage({
        command: 'simulate',
        tool: document.getElementById('tool').value,
        fn: document.getElementById('fn').value,
        params: document.getElementById('params').value,
      });
      document.getElementById('result').textContent = 'Evaluating...';
      document.getElementById('result').className = '';
    }
    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg.command === 'result') {
        const el = document.getElementById('result');
        if (msg.error) {
          el.textContent = 'Error: ' + msg.error;
          el.className = 'error';
        } else {
          const verdict = msg.data.verdict || 'unknown';
          const verdictStr = typeof verdict === 'string' ? verdict.toLowerCase() : 'deny';
          el.textContent = JSON.stringify(msg.data, null, 2);
          el.className = verdictStr;
        }
      }
    });
  </script>
</body>
</html>`;
    }
}
