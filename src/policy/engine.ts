import type { Policy, PolicyRule, WhenCondition } from "./parser.js";

export interface ToolCallContext {
  toolName: string;
  serverName: string;
  toolCapabilities: string[];
  sessionCapabilities: string[];
  sessionTainted: boolean;
  trifecta: boolean;
  arguments: unknown;
}

export interface PolicyDecision {
  action: "allow" | "block" | "warn" | "confirm";
  matchedRule?: string;
  message?: string;
}

export class PolicyEngine {
  private readonly rules: PolicyRule[];

  constructor(policy: Policy) {
    this.rules = policy.rules ?? [];
  }

  evaluate(ctx: ToolCallContext): PolicyDecision {
    for (const rule of this.rules) {
      if (this.matches(rule, ctx)) {
        return {
          action: rule.action,
          matchedRule: rule.name,
          ...(rule.message !== undefined ? { message: rule.message } : {}),
        };
      }
    }
    return { action: "allow" };
  }

  private matches(rule: PolicyRule, ctx: ToolCallContext): boolean {
    const when = rule.when;
    if (!when) return false;

    // Unimplemented conditions: rules using these are silently skipped until
    // the corresponding issues (#21 taint, #22 scanner, future server registry,
    // future rate-limiter) land and populate the fields.
    if (when.tool_registration !== undefined) return false;
    if (when.server !== undefined) return false;
    if (when.session_metrics !== undefined) return false;

    let hasAnyCondition = false;

    if (when.session_has_capabilities?.all !== undefined) {
      hasAnyCondition = true;
      const required = when.session_has_capabilities.all;
      if (!required.every((c) => ctx.sessionCapabilities.includes(c))) {
        return false;
      }
    }

    if (when.session_tainted !== undefined) {
      hasAnyCondition = true;
      if (when.session_tainted !== ctx.sessionTainted) return false;
    }

    if (when.trifecta !== undefined) {
      hasAnyCondition = true;
      if (when.trifecta !== ctx.trifecta) return false;
    }

    if (when.tool_call !== undefined) {
      hasAnyCondition = true;
      const tc = when.tool_call;

      if (tc.has_capability !== undefined) {
        if (!ctx.toolCapabilities.includes(tc.has_capability)) return false;
      }

      if (tc.tool_matches !== undefined) {
        const key = `${ctx.serverName}.${ctx.toolName}`;
        if (!tc.tool_matches.some((p) => globToRegex(p).test(key))) return false;
      }

      if (tc.arguments_match !== undefined) {
        const argsStr = JSON.stringify(ctx.arguments ?? {});
        if (!tc.arguments_match.some((p) => new RegExp(p, "u").test(argsStr))) {
          return false;
        }
      }
    }

    return hasAnyCondition;
  }
}

function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`, "u");
}
