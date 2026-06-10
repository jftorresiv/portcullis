import type { ToolPattern } from "../policy/parser.js";

interface CompiledPattern {
  readonly regex: RegExp;
  readonly tags: readonly string[];
}

export class CapabilityRegistry {
  private readonly compiled: readonly CompiledPattern[];

  constructor(patterns: ToolPattern[]) {
    this.compiled = patterns.map((p) => ({
      regex: globToRegex(p.match),
      tags: p.tags,
    }));
  }

  tag(serverName: string, toolName: string): string[] {
    const key = `${serverName}.${toolName}`;
    for (const { regex, tags } of this.compiled) {
      if (regex.test(key)) return [...tags];
    }
    return [];
  }
}

// Converts a glob pattern (only * wildcards) to an anchored RegExp.
// Escapes all regex metacharacters first, then turns * into .*.
function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`);
}
