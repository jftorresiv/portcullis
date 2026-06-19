import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "../../src/policy/engine.js";
import type { ToolCallContext } from "../../src/policy/engine.js";
import type { Policy } from "../../src/policy/parser.js";

function makePolicy(rules: Policy["rules"]): Policy {
  return {
    version: 1,
    name: "test",
    capabilities: ["reads_private_data", "can_exfiltrate", "sees_untrusted_content", "can_execute_code", "can_modify_files", "can_send_messages", "touches_credentials"],
    tools: [],
    rules,
  };
}

const baseCtx: ToolCallContext = {
  toolName: "read_file",
  serverName: "filesystem",
  toolCapabilities: ["reads_private_data"],
  sessionCapabilities: ["reads_private_data"],
  sessionTainted: false,
  trifecta: false,
  arguments: { path: "/home/user/doc.txt" },
};

describe("PolicyEngine.evaluate", () => {
  it("returns allow when no rules are defined", () => {
    const engine = new PolicyEngine(makePolicy([]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
    assert.equal(result.matchedRule, undefined);
  });

  it("returns allow when no rules match", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "block exec",
        action: "block",
        when: { tool_call: { has_capability: "can_execute_code" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
  });

  it("returns block with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "no reads",
        action: "block",
        when: { tool_call: { has_capability: "reads_private_data" } },
        message: "Reading private data is not allowed.",
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "block");
    assert.equal(result.matchedRule, "no reads");
    assert.equal(result.message, "Reading private data is not allowed.");
  });

  it("returns warn with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "warn reads",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "warn");
    assert.equal(result.matchedRule, "warn reads");
  });

  it("returns confirm with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "confirm reads",
        action: "confirm",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "confirm");
    assert.equal(result.matchedRule, "confirm reads");
  });

  it("first-match-wins: earlier block shadows later warn", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "first",
        action: "block",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
      {
        name: "second",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "block");
    assert.equal(result.matchedRule, "first");
  });

  it("matches tool_call.tool_matches glob", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "block filesystem writes",
        action: "block",
        when: { tool_call: { tool_matches: ["filesystem.write*"] } },
      },
    ]));

    const writeCtx: ToolCallContext = { ...baseCtx, toolName: "write_file", toolCapabilities: ["can_modify_files"] };
    const readCtx: ToolCallContext = { ...baseCtx, toolName: "read_file" };

    assert.equal(engine.evaluate(writeCtx).action, "block");
    assert.equal(engine.evaluate(readCtx).action, "allow");
  });

  it("matches tool_call.arguments_match regex — credential pattern", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "credential exfil",
        action: "block",
        when: {
          tool_call: {
            arguments_match: ["sk-[a-zA-Z0-9]{32,}"],
          },
        },
      },
    ]));

    const cleanCtx: ToolCallContext = { ...baseCtx, arguments: { body: "hello world" } };
    const credCtx: ToolCallContext = {
      ...baseCtx,
      arguments: { body: "here is sk-abcdefghijklmnopqrstuvwxyz12345678" },
    };

    assert.equal(engine.evaluate(cleanCtx).action, "allow");
    assert.equal(engine.evaluate(credCtx).action, "block");
  });

  it("matches session_has_capabilities.all — lethal trifecta", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "Lethal trifecta",
        action: "block",
        when: {
          session_has_capabilities: {
            all: ["reads_private_data", "sees_untrusted_content", "can_exfiltrate"],
          },
        },
      },
    ]));

    const safeCtx: ToolCallContext = {
      ...baseCtx,
      sessionCapabilities: ["reads_private_data", "sees_untrusted_content"],
    };
    const dangerCtx: ToolCallContext = {
      ...baseCtx,
      sessionCapabilities: ["reads_private_data", "sees_untrusted_content", "can_exfiltrate"],
    };

    assert.equal(engine.evaluate(safeCtx).action, "allow");
    assert.equal(engine.evaluate(dangerCtx).action, "block");
  });

  it("skips rules with unimplemented conditions (tool_registration)", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "injection scanner",
        action: "block",
        when: { tool_registration: { description_matches: ["ignore previous"] } },
      },
      {
        name: "fallback allow",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    // tool_registration rule is skipped; falls through to the warn rule
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "warn");
    assert.equal(result.matchedRule, "fallback allow");
  });

  it("skips rules with unimplemented conditions (server, session_metrics)", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "new server",
        action: "confirm",
        when: { server: "new" },
      },
      {
        name: "bulk read",
        action: "confirm",
        when: {
          session_metrics: {
            tool_calls_with_capability: {
              capability: "reads_private_data",
              count_in_window: 20,
              window_seconds: 60,
            },
          },
        },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
  });

  it("AND semantics: session_tainted AND tool_call.has_capability both must match", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "tainted exfil",
        action: "confirm",
        when: {
          session_tainted: true,
          tool_call: { has_capability: "can_exfiltrate" },
        },
      },
    ]));

    const notTaintedExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["can_exfiltrate"],
      sessionTainted: false,
    };
    const taintedNoExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["reads_private_data"],
      sessionTainted: true,
    };
    const taintedExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["can_exfiltrate"],
      sessionTainted: true,
    };

    assert.equal(engine.evaluate(notTaintedExfil).action, "allow");
    assert.equal(engine.evaluate(taintedNoExfil).action, "allow");
    assert.equal(engine.evaluate(taintedExfil).action, "confirm");
  });

  it("rule with no when never matches", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "empty when",
        action: "block",
        when: undefined,
      },
    ]));
    assert.equal(engine.evaluate(baseCtx).action, "allow");
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyEngine } from "../../src/policy/engine.js";
import type { ToolCallEvent } from "../../src/types/mcp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY = path.resolve(__dirname, "../../../policies/default.yaml");

let counter = 0;
function writeTmp(content: string): string {
  const p = path.join(os.tmpdir(), `portcullis-engine-test-${Date.now()}-${counter++}.yaml`);
  fs.writeFileSync(p, content);
  return p;
}

// Loads an engine from inline YAML, cleaning up the tmp file afterward.
function engineFrom(yaml: string): PolicyEngine {
  const tmp = writeTmp(yaml);
  try {
    const engine = new PolicyEngine();
    engine.load(tmp);
    return engine;
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function event(over: Partial<ToolCallEvent> = {}): ToolCallEvent {
  return {
    tool: "read_file",
    server: "filesystem",
    capabilities: [],
    sessionTrifecta: false,
    ...over,
  };
}

describe("PolicyEngine.load", () => {
  it("loads the real default.yaml without error", () => {
    const engine = new PolicyEngine();
    assert.doesNotThrow(() => engine.load(DEFAULT_POLICY));
  });

  it("throws a clear error on malformed YAML at load time", () => {
    const tmp = writeTmp("rules: [ this: is: not: valid: yaml");
    try {
      assert.throws(
        () => new PolicyEngine().load(tmp),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.match(err.message, /Malformed YAML/);
          return true;
        }
      );
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  });

  it("throws on a non-existent file", () => {
    assert.throws(() => new PolicyEngine().load("/does/not/exist.yaml"));
  });

  it("rejects an unknown action at load time, not evaluation", () => {
    assert.throws(
      () => engineFrom(`rules:\n  - name: bad\n    action: nuke\n`),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /Invalid policy rules/);
        return true;
      }
    );
  });

  it("rejects an unknown `when` condition key at load time", () => {
    assert.throws(
      () =>
        engineFrom(
          `rules:\n  - name: bad\n    when:\n      not_a_condition: true\n    action: allow\n`
        ),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /Invalid policy rules/);
        return true;
      }
    );
  });

  it("rejects a malformed condition shape at load time", () => {
    // session_trifecta must be a boolean, not a string.
    assert.throws(
      () =>
        engineFrom(
          `rules:\n  - name: bad\n    when:\n      session_trifecta: "yes"\n    action: allow\n`
        ),
      /Invalid policy rules/
    );
  });
});

describe("PolicyEngine.evaluate", () => {
  it("throws if called before load (fail loud, not open)", () => {
    assert.throws(() => new PolicyEngine().evaluate(event()), /before load/);
  });

  it("returns an explicit allow when a rule matches with action allow", () => {
    const engine = engineFrom(
      `rules:\n  - name: allow-fs\n    when:\n      server: "filesystem"\n    action: allow\n`
    );
    const decision = engine.evaluate(event({ server: "filesystem" }));
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule?.name, "allow-fs");
  });

  it("returns block when a block rule matches", () => {
    const engine = engineFrom(
      `rules:\n  - name: block-exfil\n    when:\n      capabilities:\n        any: [can_exfiltrate]\n    action: block\n`
    );
    const decision = engine.evaluate(event({ capabilities: ["can_exfiltrate"] }));
    assert.equal(decision.action, "block");
    assert.equal(decision.matchedRule?.name, "block-exfil");
  });

  it("returns warn when a warn rule matches", () => {
    const engine = engineFrom(
      `rules:\n  - name: warn-write\n    when:\n      capabilities:\n        all: [can_modify_files]\n    action: warn\n`
    );
    const decision = engine.evaluate(event({ capabilities: ["can_modify_files"] }));
    assert.equal(decision.action, "warn");
    assert.equal(decision.matchedRule?.name, "warn-write");
  });

  it("returns confirm when a confirm rule matches", () => {
    const engine = engineFrom(
      `rules:\n  - name: confirm-exec\n    when:\n      capabilities:\n        any: [can_execute_code]\n    action: confirm\n`
    );
    const decision = engine.evaluate(event({ capabilities: ["can_execute_code"] }));
    assert.equal(decision.action, "confirm");
    assert.equal(decision.matchedRule?.name, "confirm-exec");
  });

  it("default-allows with no matched rule when nothing matches", () => {
    const engine = engineFrom(
      `rules:\n  - name: block-gmail\n    when:\n      server: "gmail"\n    action: block\n`
    );
    const decision = engine.evaluate(event({ server: "filesystem" }));
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("is first-match-wins: a later matching rule is not evaluated", () => {
    // Both rules match the event; the first (confirm) must win over the
    // second (block), proving the walk stops at the first match.
    const engine = engineFrom(
      `rules:\n` +
        `  - name: first\n    when:\n      capabilities:\n        any: [can_exfiltrate]\n    action: confirm\n` +
        `  - name: second\n    when:\n      capabilities:\n        any: [can_exfiltrate]\n    action: block\n`
    );
    const decision = engine.evaluate(event({ capabilities: ["can_exfiltrate"] }));
    assert.equal(decision.action, "confirm");
    assert.equal(decision.matchedRule?.name, "first");
  });

  it("matches the lethal-trifecta rule in default.yaml via session_trifecta", () => {
    const engine = new PolicyEngine();
    engine.load(DEFAULT_POLICY);
    const decision = engine.evaluate(event({ sessionTrifecta: true }));
    assert.equal(decision.action, "block");
    assert.match(decision.matchedRule?.name ?? "", /trifecta/i);
  });

  it("AND-combines conditions: all must hold to match", () => {
    const engine = engineFrom(
      `rules:\n  - name: gmail-exfil\n    when:\n      server: "gmail"\n      capabilities:\n        any: [can_exfiltrate]\n    action: block\n`
    );
    // server matches but capability does not -> no match -> default allow.
    const miss = engine.evaluate(event({ server: "gmail", capabilities: [] }));
    assert.equal(miss.action, "allow");
    // both hold -> block.
    const hit = engine.evaluate(event({ server: "gmail", capabilities: ["can_exfiltrate"] }));
    assert.equal(hit.action, "block");
  });

  it("treats glob wildcards in tool/server conditions", () => {
    const engine = engineFrom(
      `rules:\n  - name: any-read\n    when:\n      tool: "read*"\n    action: warn\n`
    );
    assert.equal(engine.evaluate(event({ tool: "read_file" })).action, "warn");
    assert.equal(engine.evaluate(event({ tool: "write_file" })).action, "allow");
  });

  it("treats an empty `when` as match-all", () => {
    const engine = engineFrom(`rules:\n  - name: catch-all\n    action: block\n`);
    assert.equal(engine.evaluate(event()).action, "block");
  });
});
