# Vellaveto Policy — VS Code Extension

VS Code extension for authoring and testing [Vellaveto](https://github.com/paolovella/vellaveto) policy files.

## Features

- **TOML validation** — real-time diagnostics for `.vellaveto.toml` and `vellaveto.toml` files
- **Policy completions** — autocomplete for policy fields, rule types, and known tool names
- **Snippets** — scaffolding for common policy patterns (path rules, network rules, ABAC constraints)
- **Simulator** — evaluate a tool call against your local policy file without a running server

## Installation

Search for **"Vellaveto Policy"** in the VS Code Extensions Marketplace, or install from the command line:

```bash
code --install-extension vellaveto.vellaveto-policy
```

## Commands

| Command | Description |
|---------|-------------|
| `Vellaveto: Validate Policy` | Validate the current policy file |
| `Vellaveto: Open Simulator` | Simulate a tool call against the active policy |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `vellaveto.serverUrl` | `http://localhost:3000` | Vellaveto server URL for live evaluation |
| `vellaveto.apiKey` | — | API key for server authentication |
| `vellaveto.validateOnSave` | `true` | Run validation automatically on file save |

## Development

```bash
npm install
npm run compile
npm test          # 26 tests
npm run package   # Build .vsix
```

## License

See [LICENSING.md](../LICENSING.md) for repository licensing details.
