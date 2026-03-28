import * as vscode from 'vscode';

export interface VellavetoConfig {
    serverUrl: string;
    apiKey: string;
    validateOnSave: boolean;
}

export function getConfig(): VellavetoConfig {
    const config = vscode.workspace.getConfiguration('vellaveto');
    const serverUrl = config.get<string>('serverUrl', 'http://localhost:3000').replace(/\/+$/, '');
    const apiKey = config.get<string>('apiKey', '');

    // Warn when API key will be sent over unencrypted HTTP to a non-local server
    if (
        apiKey &&
        !serverUrl.startsWith('https://') &&
        !serverUrl.includes('localhost') &&
        !serverUrl.includes('127.0.0.1') &&
        !serverUrl.includes('::1')
    ) {
        vscode.window.showWarningMessage(
            'Vellaveto: API key will be sent over unencrypted HTTP connection',
        );
    }

    return {
        serverUrl,
        apiKey,
        validateOnSave: config.get<boolean>('validateOnSave', true),
    };
}
