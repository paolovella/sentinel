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

    // R262-VSC-1: Block API key over unencrypted HTTP to non-local servers.
    // Previously only showed a warning; now refuses to return the key to prevent
    // accidental credential leakage to attacker-controlled plaintext endpoints.
    const isLocal =
        serverUrl.includes('localhost') ||
        serverUrl.includes('127.0.0.1') ||
        serverUrl.includes('::1');

    if (apiKey && !serverUrl.startsWith('https://') && !isLocal) {
        vscode.window.showErrorMessage(
            'Vellaveto: API key requires HTTPS for remote servers. ' +
            'Either change serverUrl to https:// or remove the API key.',
        );
        return {
            serverUrl,
            apiKey: '', // Strip the key to prevent plaintext transmission
            validateOnSave: config.get<boolean>('validateOnSave', true),
        };
    }

    return {
        serverUrl,
        apiKey,
        validateOnSave: config.get<boolean>('validateOnSave', true),
    };
}
