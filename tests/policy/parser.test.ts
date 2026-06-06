import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { loadPolicy } from "../../src/policy/parser.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY = path.resolve(__dirname, "../../../policies/default.yaml");

function writeTmp(content: string): string {
  const p = path.join(os.tmpdir(), `portcullis-policy-test-${Date.now()}.yaml`);
  fs.writeFileSync(p, content);
  return p;
}

describe("loadPolicy", () => {
  it("loads default.yaml without error", () => {
    const policy = loadPolicy(DEFAULT_POLICY);
    assert.equal(typeof policy.version, "number");
    assert.equal(typeof policy.name, "string");
  });

  it("parses all seven known capabilities", () => {
    const policy = loadPolicy(DEFAULT_POLICY);
    const caps = policy.capabilities;
    assert.ok(caps.includes("reads_private_data"));
    assert.ok(caps.includes("sees_untrusted_content"));
    assert.ok(caps.includes("can_exfiltrate"));
    assert.ok(caps.includes("can_execute_code"));
    assert.ok(caps.includes("can_modify_files"));
    assert.ok(caps.includes("can_send_messages"));
    assert.ok(caps.includes("touches_credentials"));
  });

  it("parses tools array with match and tags", () => {
    const policy = loadPolicy(DEFAULT_POLICY);
    assert.ok(policy.tools.length > 0);
    for (const tool of policy.tools) {
      assert.equal(typeof tool.match, "string");
      assert.ok(Array.isArray(tool.tags));
    }
  });

  it("produces correct tags for gmail.read* entry", () => {
    const policy = loadPolicy(DEFAULT_POLICY);
    const entry = policy.tools.find((t) => t.match === "gmail.read*");
    assert.ok(entry, "gmail.read* entry should exist");
    assert.deepEqual(
      [...entry.tags].sort(),
      ["reads_private_data", "sees_untrusted_content"].sort()
    );
  });

  it("throws on non-existent file", () => {
    assert.throws(() => loadPolicy("/does/not/exist.yaml"));
  });

  it("throws with clear message on unknown capability name", () => {
    const tmp = writeTmp(`
version: 1
name: test
capabilities: [reads_private_data]
tools:
  - match: "test.*"
    tags: [not_a_real_capability]
`);
    try {
      assert.throws(
        () => loadPolicy(tmp),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(err.message.includes("Invalid policy"), err.message);
          return true;
        }
      );
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  });

  it("throws with clear message on malformed YAML (missing required field)", () => {
    const tmp = writeTmp(`
version: 1
name: test
capabilities: [reads_private_data]
`);
    try {
      assert.throws(
        () => loadPolicy(tmp),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(err.message.includes("Invalid policy"), err.message);
          return true;
        }
      );
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  });
});
