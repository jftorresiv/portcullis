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
    session_tainted: z.boolean().optional(),
    // Matched against the event's serverIsNew flag — true the first time a
    // server is ever seen (issue #28). Absent flag is treated as false.
    server_is_new: z.boolean().optional(),
    // Fires if the call's descriptionFindings (injection-scanner pattern keys)
    // include any listed string. Exact match against pattern keys, not a glob.
    description_matches: z.array(z.string().min(1)).min(1).optional(),
    // A list of regexes tested against the JSON-serialized call arguments. The
    // condition fires if ANY pattern matches. An empty list is rejected for the
    // same reason as an empty capability list: a condition that can never match
    // is the silent no-op the strict load exists to prevent. Patterns are
    // compiled at load() (see PolicyEngine.load) so an invalid regex fails loud
    // at startup, never deferred to evaluate().
    arguments_match: z.array(z.string().min(1)).min(1).optional(),
    // Windowed session-rate metric (issue #28). Fires when the session has made
    // at least `count_in_window` calls carrying `capability` within the last
    // `window_seconds`. Evaluated against the `sessionCallHistory` the proxy
    // supplies on the event; absent/empty history means it cannot fire.
    session_metrics: z
      .object({
        tool_calls_with_capability: z.object({
          capability: CapabilitySchema,
          count_in_window: z.number().int().min(1),
          window_seconds: z.number().int().min(1),
        }),
      })
      .optional(),
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
  // Compiled `arguments_match` regexes, keyed by the rule they belong to. Built
  // once in load() so evaluate() reuses them and stays fast and pure. Rules
  // without an arguments_match condition are absent from the map.
  private argRegexes = new Map<Rule, readonly RegExp[]>();
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

    // Compile every `arguments_match` pattern now, not at evaluate() time. An
    // invalid regex is a policy authoring error and must fail loud at load,
    // matching how an unknown condition key or action is rejected above — never
    // deferred to a request that would then throw mid-intercept. Compiling with
    // the `i` flag makes the credential/target patterns case-insensitive as
    // their authors intend; `u` keeps unicode escapes well-formed.
    const compiled = new Map<Rule, readonly RegExp[]>();
    for (const rule of this.rules) {
      const patterns = rule.when?.arguments_match;
      if (patterns === undefined) continue;
      const regexes: RegExp[] = [];
      for (const pattern of patterns) {
        try {
          regexes.push(new RegExp(pattern, "iu"));
        } catch (err) {
          const detail = err instanceof Error ? err.message : String(err);
          throw new Error(
            `Invalid arguments_match pattern in rule "${rule.name}" in ${filePath}: ${pattern} — ${detail}`
          );
        }
      }
      compiled.set(rule, regexes);
    }

    this.argRegexes = compiled;
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
      if (matches(rule.when, event, this.argRegexes.get(rule))) {
        return { action: rule.action, matchedRule: rule };
      }
    }

    return { action: "allow" };
  }
}

// -----------------------------------------------------------------------------
// Matching (pure)
// -----------------------------------------------------------------------------

// ReDoS guardrail: the serialized arguments are truncated to this many chars
// BEFORE any regex runs against them. A malicious server could return a huge
// arguments blob crafted to trigger catastrophic backtracking; capping the
// input length bounds the work any single pattern can do. This is the agreed
// mitigation — deliberately no timeout and no external dependency.
const MAX_ARG_MATCH_LENGTH = 5000;

// An absent or empty `when` matches every call. Each present condition must
// hold (logical AND); the first failing condition short-circuits. `argRegexes`
// are the pre-compiled patterns for this rule's `arguments_match` condition (if
// any), supplied by evaluate() from the load-time cache.
function matches(
  when: Rule["when"],
  event: ToolCallEvent,
  argRegexes?: readonly RegExp[]
): boolean {
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

  if (
    when.session_tainted !== undefined &&
    when.session_tainted !== (event.sessionTainted ?? false)
  ) {
    return false;
  }

  if (
    when.server_is_new !== undefined &&
    when.server_is_new !== (event.serverIsNew ?? false)
  ) {
    return false;
  }

  if (when.description_matches !== undefined) {
    const findings = event.descriptionFindings ?? [];
    if (!when.description_matches.some((key) => findings.includes(key))) {
      return false;
    }
  }

  if (when.arguments_match !== undefined) {
    const serialized = JSON.stringify(event.arguments ?? {});
    // Truncate BEFORE testing (see MAX_ARG_MATCH_LENGTH). `.test()` is stateless
    // here because the cached regexes carry no `g` flag, so reuse is safe.
    const subject =
      serialized.length > MAX_ARG_MATCH_LENGTH
        ? serialized.slice(0, MAX_ARG_MATCH_LENGTH)
        : serialized;
    const regexes = argRegexes ?? [];
    if (!regexes.some((re) => re.test(subject))) return false;
  }

  if (when.session_metrics !== undefined) {
    const { capability, count_in_window, window_seconds } =
      when.session_metrics.tool_calls_with_capability;
    const history = event.sessionCallHistory ?? [];
    // Anchor the window to the current wall-clock time. This is the one clock
    // read in evaluate(); it stays free of any other side effect. A record on
    // the exact cutoff boundary is counted (>=).
    const cutoff = Date.now() - window_seconds * 1000;
    const count = history.filter(
      (rec) => rec.timestamp >= cutoff && rec.capabilities.includes(capability)
    ).length;
    if (count < count_in_window) return false;
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
