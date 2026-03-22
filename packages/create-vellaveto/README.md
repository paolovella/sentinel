# create-vellaveto

Interactive setup wizard for [Vellaveto](https://github.com/paolovella/vellaveto) — the agent interaction firewall for AI tool calls.

## Quick Alternative

If you just want protection without a config file, skip the wizard:

```bash
cargo install vellaveto-proxy
vellaveto-proxy --protect shield -- ./your-mcp-server
```

Three levels: `shield` (8 policies — credentials, SANDWORM defense, exfil blocking, system files), `fortress` (11 policies — adds package config protection, sudo approval, memory tracking), `vault` (11 policies — deny-by-default, source reads allowed, writes need approval). No config file needed.

## Setup Wizard

For a custom configuration, use the interactive wizard:

```bash
npx create-vellaveto
```

Or with your preferred package manager:

```bash
npm init vellaveto
yarn create vellaveto
pnpm create vellaveto
```

The wizard walks you through:

1. Choose a policy preset (deny-by-default, permissive, enterprise, etc.)
2. Configure detection settings (injection scanning, DLP)
3. Set up audit logging
4. Generate a ready-to-use `vellaveto.toml` config file

## Requirements

- Node.js 18+

## License

See [LICENSING.md](../../LICENSING.md) for repository licensing details.
