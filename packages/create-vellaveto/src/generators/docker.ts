/**
 * Docker Compose and .env file generator.
 *
 * Mirrors the production docker-compose.yml with security hardening:
 * read_only, no-new-privileges, healthcheck, resource limits, tmpfs, logging.
 */

import type { WizardState, GeneratedFile } from "../types.js";
import { IMAGE_REPO, IMAGE_TAG, DEFAULT_PORT, DEFAULT_PROXY_PORT } from "../constants.js";

export function generateDockerFiles(state: WizardState): GeneratedFile[] {
  return [
    {
      path: "docker-compose.yml",
      content: generateDockerCompose(),
      description: "Docker Compose with hardened Vellaveto services",
    },
    {
      path: ".env",
      content: generateDotEnv(state),
      description: "Environment variables (contains API key — do not commit)",
    },
  ];
}

function generateDockerCompose(): string {
  return `# Vellaveto — Docker Compose
#
# Usage:
#   docker compose up -d          # Start Vellaveto
#   docker compose logs -f        # Follow logs
#   docker compose down           # Stop
#
# Environment variables loaded from .env file automatically.

services:
  vellaveto:
    image: ${IMAGE_REPO}:${IMAGE_TAG}
    ports:
      - "${DEFAULT_PORT}:${DEFAULT_PORT}"
    env_file:
      - .env
    environment:
      - RUST_LOG=\${RUST_LOG:-info}
    volumes:
      - ./vellaveto.toml:/etc/vellaveto/config.toml:ro
      - vellaveto-audit:/var/log/vellaveto
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:${DEFAULT_PORT}/health"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 256M
        reservations:
          cpus: "0.25"
          memory: 64M
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  vellaveto-proxy:
    image: ${IMAGE_REPO}:${IMAGE_TAG}
    entrypoint: ["vellaveto-http-proxy"]
    command: ["--config", "/etc/vellaveto/config.toml", "--listen", "0.0.0.0:${DEFAULT_PROXY_PORT}"]
    ports:
      - "${DEFAULT_PROXY_PORT}:${DEFAULT_PROXY_PORT}"
    env_file:
      - .env
    environment:
      - RUST_LOG=\${RUST_LOG:-info}
    volumes:
      - ./vellaveto.toml:/etc/vellaveto/config.toml:ro
      - vellaveto-audit:/var/log/vellaveto
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:${DEFAULT_PROXY_PORT}/health"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 256M
        reservations:
          cpus: "0.25"
          memory: 64M
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  vellaveto-audit:
`;
}

function generateDotEnv(state: WizardState): string {
  // SECURITY: Quote values to prevent shell expansion if the .env is sourced.
  const quote = (v: string) => `'${v.replace(/'/g, "'\\''")}'`;
  let env = "";
  env += "# Vellaveto environment variables\n";
  env += "# IMPORTANT: Do not commit this file to version control\n\n";
  env += `VELLAVETO_API_KEY=${quote(state.apiKey)}\n`;
  if (state.corsOrigins.length > 0) {
    env += `VELLAVETO_CORS_ORIGINS=${quote(state.corsOrigins.join(","))}\n`;
  }
  if (state.checkpointInterval > 0) {
    env += `VELLAVETO_CHECKPOINT_INTERVAL=${state.checkpointInterval}\n`;
  }
  return env;
}
