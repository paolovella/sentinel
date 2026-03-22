# Vellaveto Admin Console

React SPA for managing and monitoring the [Vellaveto](https://github.com/paolovella/vellaveto) agent interaction firewall.

## Features

- **Policy editor** — create, edit, and simulate policies with live validation
- **Audit dashboard** — searchable decision trail with hash-chain verification
- **Topology viewer** — visual graph of discovered MCP servers, tools, and data flows
- **Approval queue** — review and resolve pending human-in-the-loop requests
- **Compliance reports** — EU AI Act, SOC 2, DORA, NIS2, and other framework dashboards
- **RBAC navigation** — UI elements adapt to the authenticated user's role (Admin, Operator, Auditor, Viewer)
- **OIDC + API-key auth** — supports Okta, Azure AD, Keycloak, or static API keys
- **Dark theme** — system-aware light/dark mode

## Quick Start

```bash
npm install
npm run dev
```

The dev server starts at `http://localhost:5173` and proxies API requests to the Vellaveto server at `http://localhost:3000`.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server with HMR |
| `npm run build` | Production build to `dist/` |
| `npm run preview` | Preview production build locally |
| `npm test` | Run 59 vitest tests |
| `npm run lint` | ESLint check |

## Tech Stack

- React 18 + TypeScript
- Vite
- Vitest for testing
- TailwindCSS

## License

See [LICENSING.md](../LICENSING.md) for repository licensing details.
