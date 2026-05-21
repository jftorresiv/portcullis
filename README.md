# Portcullis

A local security proxy for AI agents. Sits between your AI client (Claude Desktop, Cursor, Windsurf, etc.) and the MCP servers it talks to. Logs every tool call, enforces policy, and breaks the *lethal trifecta* before it can hurt you.

> The portcullis between your agent and your data.

> **Status:** Pre-alpha. Built in public. Not production-ready. Useful today.

---

## The problem

AI agents now read your email, search your files, and call APIs on your behalf. They are powerful and almost completely unmonitored. The dominant integration standard, Model Context Protocol (MCP), encourages mixing tools from many sources — and in 2025 alone, researchers documented:

- Malicious npm-distributed MCP servers exfiltrating email and shipping reverse shells
- Remote code execution via MCP STDIO configuration injection across every major coding assistant
- Indirect prompt injection through GitHub issues that leaked private repositories
- The first widely reported MCP supply-chain attacks (Postmark impersonator, dual reverse-shell package)

The structural cause was named by Simon Willison: the **lethal trifecta**. Any agent that has (1) access to private data, (2) exposure to untrusted content, and (3) the ability to communicate externally is structurally vulnerable to data theft. Detection-based filters reach ~97% accuracy on known patterns. In application security, 97% is a failing grade.

The only reliable defense is structural: cut one leg of the trifecta. Portcullis is the place to cut it.

---

## What Portcullis does

1. **Observes every tool call.** Append-only JSONL audit log of every MCP message in and out. You finally know what your agents are doing.
2. **Tags tools by capability.** Each tool gets flagged as reading private data, seeing untrusted content, and/or capable of exfiltration. Tags are user-overridable.
3. **Detects the lethal trifecta in real time.** When the active session covers all three legs, Portcullis blocks risky calls or requires confirmation.
4. **Scans tool descriptions for prompt injection.** Hidden instructions, ignore-previous patterns, suspiciously authoritative language — flagged before the tool ever runs.
5. **Enforces YAML-defined policy.** Allow/deny by tool name, argument regex, time of day, source server, capability combination, or session taint.
6. **Provides a kill switch.** One hotkey terminates every active agent session.

---

## Quickstart

```bash
# install
npm install -g portcullis

# point your MCP client at the proxy instead of your real MCP servers
# e.g. in ~/.config/claude/claude_desktop_config.json:
{
  "mcpServers": {
    "portcullis": {
      "command": "portcullis",
      "args": ["proxy", "--config", "~/.portcullis/policy.yaml"]
    }
  }
}

# start the dashboard
portcullis dashboard
# open http://localhost:7778
```

Your existing MCP servers are configured inside `~/.portcullis/policy.yaml`. Portcullis becomes the single MCP endpoint your client knows about.

---

## Architecture

```
┌───────────────────┐         ┌──────────────────────────────┐         ┌──────────────────┐
│   MCP Client      │  JSON-  │          Portcullis           │  JSON-  │   MCP Servers    │
│ (Claude Desktop,  │  RPC    │                               │  RPC    │ (gmail, github,  │
│  Cursor, etc.)    │ ──────► │  ┌─────────────────────────┐  │ ──────► │  filesystem,     │
│                   │ ◄────── │  │ policy engine + trifecta│  │ ◄────── │  fetch, etc.)    │
└───────────────────┘         │  │ capability tagger        │  │         └──────────────────┘
                              │  │ injection scanner        │  │
                              │  │ audit logger             │  │
                              │  └─────────────────────────┘  │
                              │            ▼                  │
                              │      ┌──────────┐             │
                              │      │ SQLite + │             │
                              │      │  JSONL   │             │
                              │      └──────────┘             │
                              │            ▲                  │
                              │     ┌──────┴──────┐           │
                              │     │  Dashboard  │           │
                              │     │  :7778      │           │
                              │     └─────────────┘           │
                              └───────────────────────────────┘
```

---

## Repository layout

```
portcullis/
├── README.md
├── LICENSE
├── package.json
├── tsconfig.json
├── .env.example
├── .gitignore
│
├── policies/
│   ├── default.yaml              # ships with sensible defaults
│   └── example-strict.yaml       # for high-sensitivity environments
│
├── src/
│   ├── index.ts                  # CLI entrypoint
│   ├── proxy/
│   │   ├── server.ts             # MCP proxy (JSON-RPC over STDIO + HTTP/SSE)
│   │   ├── transport.ts          # transport abstraction
│   │   └── router.ts             # routes calls to upstream MCP servers
│   ├── policy/
│   │   ├── engine.ts             # evaluates rules against calls
│   │   ├── parser.ts             # loads + validates YAML
│   │   └── trifecta.ts           # lethal trifecta state machine
│   ├── capabilities/
│   │   ├── tagger.ts             # auto-tags tools with capability flags
│   │   ├── registry.ts           # known-tool capability database
│   │   └── scanner.ts            # scans tool descriptions for injection
│   ├── audit/
│   │   ├── logger.ts             # JSONL append-only logger
│   │   ├── store.ts              # SQLite query layer
│   │   └── replay.ts             # rebuild a session from logs
│   ├── dashboard/
│   │   ├── server.ts             # localhost:7778 web server
│   │   ├── api.ts                # REST API for the UI
│   │   └── ui/                   # React app (Lovable/v0 output drops here)
│   ├── analysis/
│   │   ├── claude.ts             # Anthropic API client for LLM analysis
│   │   └── patterns.ts           # regex/heuristic detectors
│   └── types/
│       └── mcp.ts                # MCP protocol type definitions
│
├── tests/
│   ├── fixtures/
│   │   ├── malicious-tool-descriptions.json   # known attack samples
│   │   └── attack-scenarios.json              # reproducible exploits
│   └── integration/
│
└── docs/
    ├── architecture.md
    ├── threat-model.md           # OWASP Top 10 Agentic mapping
    └── policy-reference.md       # full YAML schema docs
```

---

## How policy works

Portcullis loads a YAML policy at startup. Rules are evaluated in order; the first matching rule wins. A minimal example:

```yaml
version: 1
name: "Personal default"

rules:
  - name: "Block lethal trifecta"
    when:
      session_has_capabilities:
        all: [reads_private_data, sees_untrusted_content, can_exfiltrate]
    action: block

  - name: "Block credential-looking arguments"
    when:
      tool_call:
        arguments_match:
          - 'sk-[a-zA-Z0-9]{32,}'      # OpenAI-style keys
          - 'AKIA[0-9A-Z]{16}'         # AWS access keys
          - '(?i)(api[_-]?key|password|token|secret)\s*[:=]\s*\S+'
    action: block
```

See `policies/default.yaml` for the fully-commented schema.

---

## Threats addressed

Portcullis maps directly to the OWASP Top 10 for Agentic Applications (2026):

| OWASP ID  | Threat                              | How Portcullis helps                                              |
|-----------|-------------------------------------|-------------------------------------------------------------------|
| ASI01     | Agent Goal Hijack                   | Tool description scanner; lethal trifecta enforcement             |
| ASI02     | Tool Misuse and Exploitation        | Argument regex policies; capability-based blocking                |
| ASI03     | Identity and Privilege Abuse        | Per-tool allow/deny; first-use confirmation                       |
| ASI04     | Unexpected Code Execution (RCE)     | Block dangerous tool patterns; STDIO config inspection            |
| ASI05     | Insecure Inter-Agent Communication  | Audit all proxied traffic                                         |
| ASI06     | Agentic Supply Chain                | Capability tagging on first install; injection scan on registration |
| ASI07     | Memory and Context Poisoning        | Taint tracking across session                                     |
| ASI08     | Cascading Failures                  | Kill switch + per-session audit replay                            |
| ASI09     | Human-Agent Trust Exploitation      | Explicit confirmation gates on irreversible actions               |
| ASI10     | Rogue Agents                        | Per-agent identity logging; anomaly view in dashboard             |

---

## Tech stack

- **Proxy core:** TypeScript + `@modelcontextprotocol/sdk`
- **Storage:** SQLite for queryable history, JSONL for append-only log
- **Dashboard:** React (initial scaffold via Lovable / v0, polished in Cursor)
- **LLM analysis:** Anthropic API (Claude Sonnet for routine checks, Opus for deep analysis of flagged events)
- **Embeddings (v2):** OpenAI `text-embedding-3-small` for semantic similarity search across past tool calls
- **Distribution:** npm global install; Homebrew tap to follow

---

## Roadmap

**v0.1 — Observability (target: 4 weeks)**
- STDIO + HTTP/SSE proxy passthrough
- JSONL audit log
- Read-only dashboard with timeline view
- Manual capability tagging via YAML

**v0.2 — Enforcement (target: +4 weeks)**
- Policy engine
- Lethal trifecta detection
- Tool description injection scanner
- Kill switch hotkey

**v0.3 — Intelligence**
- LLM-powered "explain this tool call" in dashboard
- Anomaly detection on tool-call sequences
- Auto-suggested capability tags for unknown tools
- Sandbox mode (run any session through ephemeral Docker)

**v1.0 — Trust scoring**
- Per-server reputation based on community-shared incident data
- Optional cloud sync of anonymized incident reports
- Browser extension companion (catch trifecta in web-based agents like ChatGPT Atlas, Claude in Chrome)

**v2.0 — The Trust Layer**
- Multi-agent visualizations
- Team / family deployment mode
- Granular per-agent OAuth-style permission scopes
- API for third-party tools to query Portcullis's audit log

---

## Build in public

This is built in the open as a long-term project. Weekly progress notes live in `docs/journal/`. Real attacks reproduced against the proxy live in `tests/fixtures/attack-scenarios.json` with a writeup for each in `docs/incidents/`.

If you find a vulnerability in Portcullis itself, please open a private security advisory before filing a public issue.

---

## License

MIT
