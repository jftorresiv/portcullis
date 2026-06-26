import { describe, it } from "node:test";
import assert from "node:assert/strict";
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
