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
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { KNOWN_CAPABILITIES } from "./parser.js";
import type { ToolCallEvent } from "../types/mcp.js";

// -----------------------------------------------------------------------------
// Rule schema
// -----------------------------------------------------------------------------
// The full rule list is validated at LOAD time. A `when` condition key the
// engine cannot evaluate is rejected here, not silently ignored at evaluate():
// a rule that looks like it blocks something but does nothing is worse than no
// rule at all. Adding a new condition type requires changing both the matcher
// in evaluate() and this schema in the same commit.

const ACTIONS = ["allow", "block", "warn", "confirm"] as const;
export type PolicyAction = (typeof ACTIONS)[number];

const CapabilitySchema = z.enum(KNOWN_CAPABILITIES);

// `all`: every listed capability must be present on the call.
// `any`: at least one listed capability must be present.
// Empty arrays are rejected — `any: []` would never match, the same silent
// no-op failure the strict load is meant to prevent.
const CapabilityConditionSchema = z
  .object({
    all: z.array(CapabilitySchema).min(1).optional(),
    any: z.array(CapabilitySchema).min(1).optional(),
  })
  .strict();

// All present conditions are AND-combined. An unspecified condition is a
// wildcard; an absent or empty `when` matches every call.
const WhenSchema = z
  .object({
    tool: z.string().min(1).optional(),
    server: z.string().min(1).optional(),
    capabilities: CapabilityConditionSchema.optional(),
    session_trifecta: z.boolean().optional(),
  })
  .strict();

const RuleSchema = z
  .object({
    name: z.string().min(1),
    description: z.string().optional(),
    when: WhenSchema.optional(),
    action: z.enum(ACTIONS),
    message: z.string().optional(),
  })
  .strict();

export type Rule = z.infer<typeof RuleSchema>;

// The engine only consumes the `rules` key. Other top-level keys (servers,
// capabilities, tools, tainting, …) are owned by other subsystems and are
// stripped here rather than rejected.
const PolicyFileSchema = z.object({
  rules: z.array(RuleSchema),
});

// -----------------------------------------------------------------------------
// Decision
// -----------------------------------------------------------------------------
// Rich enough for the caller (the proxy intercept loop, #19) to log the
// outcome without re-deriving anything. The matched rule is carried by
// reference. On no match, `matchedRule` is absent and the action is `allow`.
export interface PolicyDecision {
  action: PolicyAction;
  matchedRule?: Rule;
}

// -----------------------------------------------------------------------------
// Engine
// -----------------------------------------------------------------------------
// Pure functional core: load() does file I/O once at startup; evaluate() is
// synchronous, side-effect-free, and never logs. See "Policy engine invariants"
// in CLAUDE.md for the binding rationale.
export class PolicyEngine {
  private rules: readonly Rule[] = [];
  private loaded = false;

  // Reads, parses, and fully validates the policy file. Throws a clear,
  // message-rich error on malformed YAML, an unknown action, an unknown
  // `when` condition key, or a malformed condition shape. Never defers a
  // schema error to evaluate().
  load(filePath: string): void {
    const resolved = filePath.startsWith("~")
      ? path.join(os.homedir(), filePath.slice(1))
      : filePath;

    const raw = fs.readFileSync(resolved, "utf8");

    let parsed: unknown;
    try {
      parsed = parseYaml(raw);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(`Malformed YAML in policy at ${filePath}: ${detail}`);
    }

    const result = PolicyFileSchema.safeParse(parsed);
    if (!result.success) {
      throw new Error(`Invalid policy rules in ${filePath}: ${result.error.message}`);
    }

    this.rules = result.data.rules;
    this.loaded = true;
  }

  // First-match-wins walk over the loaded rules. Returns the matched rule and
  // its action; on no match returns a default-allow decision with no rule.
  evaluate(event: ToolCallEvent): PolicyDecision {
    if (!this.loaded) {
      // Fail loud, not open: a security tool that evaluates against an unloaded
      // policy and silently allows everything is the worst possible failure.
      throw new Error("PolicyEngine.evaluate() called before load()");
    }

    for (const rule of this.rules) {
      if (matches(rule.when, event)) {
        return { action: rule.action, matchedRule: rule };
      }
    }

    return { action: "allow" };
  }
}

// -----------------------------------------------------------------------------
// Matching (pure)
// -----------------------------------------------------------------------------

// An absent or empty `when` matches every call. Each present condition must
// hold (logical AND); the first failing condition short-circuits.
function matches(when: Rule["when"], event: ToolCallEvent): boolean {
  if (!when) return true;

  if (when.tool !== undefined && !globToRegex(when.tool).test(event.tool)) {
    return false;
  }

  if (when.server !== undefined && !globToRegex(when.server).test(event.server)) {
    return false;
  }

  if (when.capabilities !== undefined) {
    const present = event.capabilities;
    const { all, any } = when.capabilities;
    if (all && !all.every((cap) => present.includes(cap))) return false;
    if (any && !any.some((cap) => present.includes(cap))) return false;
  }

  if (
    when.session_trifecta !== undefined &&
    when.session_trifecta !== (event.sessionTrifecta ?? false)
  ) {
    return false;
  }

  return true;
}

// Converts a glob pattern (only * wildcards) to an anchored RegExp. Mirrors the
// helper in capabilities/registry.ts: escape regex metacharacters, then turn
// * into .*.
function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`);
}
