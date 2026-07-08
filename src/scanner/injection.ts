import type { Tool } from "../types/mcp.js";

// -----------------------------------------------------------------------------
// Tool description injection scanner (issue #22)
// -----------------------------------------------------------------------------
// Pure, synchronous, dependency-free. Mirrors TaintTracker's style: no Logger,
// no I/O, no audit imports. Scans the `tools/list` advertisement a server sends
// for prompt-injection patterns hidden in tool names, descriptions, and input
// schemas. Purely lexical/structural — regex, length, and unicode checks only.
// No LLM or semantic analysis.
//
// Patterns live in INJECTION_PATTERNS, deliberately separate from scan() so the
// pattern set can be extended without touching the scan loop.

export type ScanField = "name" | "description" | "inputSchema";
export type ScanSeverity = "info" | "warn" | "critical";

export interface InjectionPattern {
  key: string;
  fields: ScanField[];
  check: (text: string) => boolean;
  severity: ScanSeverity;
}

export interface ScanResult {
  toolName: string;
  field: ScanField;
  pattern: string;
  severity: ScanSeverity;
}

// Case-insensitive substring match against a known jailbreak phrase set.
const JAILBREAK_PHRASES = [
  "ignore previous instructions",
  "you are now",
  "disregard",
  "forget your instructions",
];

// Zero-width and bidi-override characters used to hide instructions from a human
// reviewer while keeping them visible to the model. U+200B/C/D zero-width,
// U+FEFF zero-width no-break space, U+202E right-to-left override.
const HIDDEN_UNICODE_RE = /[​‌‍﻿‮]/;

// Nested-instruction syntax that tries to open a new "turn" inside a tool
// description, e.g. "Note to AI:", "Assistant:", "System:".
const NESTED_INSTRUCTION_RE = /(?:note to ai|assistant|system)\s*:/i;

const MAX_DESCRIPTION_LENGTH = 2000;

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    key: "jailbreak_phrase",
    fields: ["description", "inputSchema"],
    severity: "critical",
    check: (text) => {
      const lower = text.toLowerCase();
      return JAILBREAK_PHRASES.some((phrase) => lower.includes(phrase));
    },
  },
  {
    key: "nested_instruction",
    fields: ["description"],
    severity: "warn",
    check: (text) => NESTED_INSTRUCTION_RE.test(text),
  },
  {
    key: "hidden_unicode",
    fields: ["name", "description"],
    severity: "critical",
    check: (text) => HIDDEN_UNICODE_RE.test(text),
  },
  {
    key: "long_description",
    fields: ["description"],
    severity: "info",
    check: (text) => text.length > MAX_DESCRIPTION_LENGTH,
  },
];

export class InjectionScanner {
  // Scans every tool against every pattern for the fields that pattern targets.
  // Returns one ScanResult per (tool, field, pattern) hit. Order is stable:
  // tools outer, patterns inner, fields innermost.
  scan(toolsList: Tool[]): ScanResult[] {
    const results: ScanResult[] = [];

    for (const tool of toolsList) {
      for (const pattern of INJECTION_PATTERNS) {
        for (const field of pattern.fields) {
          const text = extractField(tool, field);
          if (text === null) continue;
          if (pattern.check(text)) {
            results.push({
              toolName: tool.name,
              field,
              pattern: pattern.key,
              severity: pattern.severity,
            });
          }
        }
      }
    }

    return results;
  }
}

// Resolves a tool field to the text a pattern checks against. The inputSchema is
// JSON-stringified so structural patterns can scan nested schema text. Returns
// null when the field is absent so the pattern is simply skipped for that tool.
function extractField(tool: Tool, field: ScanField): string | null {
  switch (field) {
    case "name":
      return tool.name;
    case "description":
      return tool.description ?? null;
    case "inputSchema":
      return tool.inputSchema === undefined
        ? null
        : JSON.stringify(tool.inputSchema);
  }
}
