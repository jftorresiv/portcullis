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

describe("PolicyEngine server_is_new", () => {
  const newServerRule =
    `rules:\n` +
    `  - name: confirm-new-server\n` +
    `    when:\n` +
    `      server_is_new: true\n` +
    `    action: confirm\n`;

  it("fires when serverIsNew is true", () => {
    const engine = engineFrom(newServerRule);
    const decision = engine.evaluate(event({ serverIsNew: true }));
    assert.equal(decision.action, "confirm");
    assert.equal(decision.matchedRule?.name, "confirm-new-server");
  });

  it("does not fire when serverIsNew is false", () => {
    const engine = engineFrom(newServerRule);
    const decision = engine.evaluate(event({ serverIsNew: false }));
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("does not fire when serverIsNew is absent (treated as false)", () => {
    const engine = engineFrom(newServerRule);
    // event() sets no `serverIsNew`; the engine defaults it to false.
    const decision = engine.evaluate(event());
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });
});

describe("PolicyEngine arguments_match", () => {
  // A rule that blocks whenever the serialized arguments contain "sk-<hex>".
  const secretRule =
    `rules:\n` +
    `  - name: block-secret\n` +
    `    when:\n` +
    `      arguments_match:\n` +
    `        - 'sk-[a-zA-Z0-9]{16,}'\n` +
    `    action: block\n`;

  it("fires when a pattern matches the serialized arguments", () => {
    const engine = engineFrom(secretRule);
    const decision = engine.evaluate(
      event({ arguments: { note: "token is sk-abcdef0123456789abcdef" } })
    );
    assert.equal(decision.action, "block");
    assert.equal(decision.matchedRule?.name, "block-secret");
  });

  it("does not fire when no pattern matches", () => {
    const engine = engineFrom(secretRule);
    const decision = engine.evaluate(
      event({ arguments: { note: "nothing sensitive here" } })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("treats absent arguments as {} (no match)", () => {
    const engine = engineFrom(secretRule);
    // event() sets no `arguments`; the engine serializes it as {}.
    assert.equal(engine.evaluate(event()).action, "allow");
  });

  it("is case-insensitive (compiled with the `i` flag)", () => {
    const engine = engineFrom(
      `rules:\n` +
        `  - name: block-secret-word\n` +
        `    when:\n` +
        `      arguments_match:\n` +
        `        - 'password'\n` +
        `    action: block\n`
    );
    assert.equal(
      engine.evaluate(event({ arguments: { field: "PASSWORD=hunter2" } })).action,
      "block"
    );
  });

  it("fails loud at load on an invalid regex, not at evaluate", () => {
    // `(?i)` inline-flag groups are invalid in a JS RegExp; this must throw at
    // load() so a broken pattern can never silently pass at evaluate().
    assert.throws(
      () =>
        engineFrom(
          `rules:\n  - name: bad\n    when:\n      arguments_match:\n        - '(?i)oops'\n    action: block\n`
        ),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /Invalid arguments_match pattern/);
        assert.match(err.message, /rule "bad"/);
        return true;
      }
    );
  });

  it("truncates the subject to 5000 chars BEFORE matching", () => {
    // The needle sits past char 5000 in the serialized arguments, so truncation
    // must cut it off and the rule must NOT fire. A control with the needle
    // early confirms the pattern itself works.
    const engine = engineFrom(
      `rules:\n` +
        `  - name: block-needle\n` +
        `    when:\n` +
        `      arguments_match:\n` +
        `        - 'NEEDLE'\n` +
        `    action: block\n`
    );

    const buried = engine.evaluate(
      event({ arguments: { pad: "x".repeat(6000), tail: "NEEDLE" } })
    );
    assert.equal(buried.action, "allow", "needle past char 5000 must be truncated away");

    const early = engine.evaluate(event({ arguments: { tail: "NEEDLE" } }));
    assert.equal(early.action, "block", "control: needle within 5000 chars must match");
  });

  it("does not hang on a catastrophic-backtracking pattern (truncation caps input)", () => {
    // `(a+)+$` is exponential when it must fail. The full 100k-char subject ends
    // in "!" (forcing failure) and WITHOUT truncation would backtrack forever.
    // Truncation to 5000 chars cuts the trailing "!", leaving a run of 'a' that
    // matches immediately — so evaluate() returns near-instantly. If truncation
    // were removed, this test would hang, which is exactly what it guards.
    const engine = engineFrom(
      `rules:\n` +
        `  - name: catastrophic\n` +
        `    when:\n` +
        `      arguments_match:\n` +
        `        - '(a+)+$'\n` +
        `    action: block\n`
    );

    const subject = "a".repeat(100000) + "!";
    assert.ok(subject.length > 5000);

    const start = Date.now();
    const decision = engine.evaluate(event({ arguments: { blob: subject } }));
    const elapsed = Date.now() - start;

    // Truncated subject ends mid-run of 'a', so `(a+)+$` matches -> block.
    assert.equal(decision.action, "block");
    // Generous bound: a real hang is effectively unbounded; this cleanly clears.
    assert.ok(elapsed < 2000, `evaluate took ${elapsed}ms — truncation likely broken`);
  });
});

describe("default.yaml arguments_match rules", () => {
  function defaultEngine(): PolicyEngine {
    const engine = new PolicyEngine();
    engine.load(DEFAULT_POLICY);
    return engine;
  }

  describe("Credential exfiltration patterns", () => {
    it("blocks arguments containing a credential-shaped string (positive)", () => {
      const engine = defaultEngine();
      const decision = engine.evaluate(
        event({
          server: "filesystem",
          tool: "write_file",
          arguments: {
            path: "/tmp/out.txt",
            content: "aws key AKIAIOSFODNN7EXAMPLE for the deploy",
          },
        })
      );
      assert.equal(decision.action, "block");
      assert.match(decision.matchedRule?.name ?? "", /Credential exfiltration/);
    });

    it("allows benign arguments with no credential (negative)", () => {
      const engine = defaultEngine();
      const decision = engine.evaluate(
        event({
          server: "filesystem",
          tool: "write_file",
          arguments: { path: "/tmp/notes.txt", content: "grocery list: milk, eggs" },
        })
      );
      assert.equal(decision.action, "allow");
      assert.equal(decision.matchedRule, undefined);
    });
  });

  describe("Suspicious fetch targets", () => {
    it("confirms a fetch to a suspicious target (positive)", () => {
      const engine = defaultEngine();
      const decision = engine.evaluate(
        event({
          server: "fetch",
          tool: "fetch",
          arguments: { url: "http://1.2.3.4/collect" },
        })
      );
      assert.equal(decision.action, "confirm");
      assert.match(decision.matchedRule?.name ?? "", /Suspicious fetch/);
    });

    it("allows a fetch to an ordinary target (negative)", () => {
      const engine = defaultEngine();
      const decision = engine.evaluate(
        event({
          server: "fetch",
          tool: "fetch",
          arguments: { url: "https://example.com/docs/getting-started" },
        })
      );
      assert.equal(decision.action, "allow");
      assert.equal(decision.matchedRule, undefined);
    });
  });
});
