import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { CapabilityRegistry } from "../../src/capabilities/registry.js";
import { loadPolicy } from "../../src/policy/parser.js";
import { init as initTagger, tagTool } from "../../src/capabilities/tagger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY = path.resolve(__dirname, "../../../policies/default.yaml");

describe("CapabilityRegistry (manual patterns)", () => {
  it("returns tags for an exact prefix match", () => {
    const registry = new CapabilityRegistry([
      { match: "gmail.read*", tags: ["reads_private_data", "sees_untrusted_content"] },
    ]);
    assert.deepEqual(
      registry.tag("gmail", "read_message").sort(),
      ["reads_private_data", "sees_untrusted_content"].sort()
    );
  });

  it("returns empty array when no pattern matches", () => {
    const registry = new CapabilityRegistry([
      { match: "gmail.read*", tags: ["reads_private_data"] },
    ]);
    assert.deepEqual(registry.tag("calculator", "add"), []);
  });

  it("first-match-wins — more specific pattern must precede glob", () => {
    const registry = new CapabilityRegistry([
      { match: "gmail.read*", tags: ["reads_private_data"] },
      { match: "gmail.*", tags: ["can_exfiltrate"] },
    ]);
    // gmail.read_message matches the first rule
    assert.deepEqual(registry.tag("gmail", "read_message"), ["reads_private_data"]);
    // gmail.send_message matches the second rule
    assert.deepEqual(registry.tag("gmail", "send_message"), ["can_exfiltrate"]);
  });

  it("server wildcard pattern *.execute* matches any server", () => {
    const registry = new CapabilityRegistry([
      { match: "*.execute*", tags: ["can_execute_code", "can_modify_files", "can_exfiltrate"] },
    ]);
    assert.deepEqual(
      registry.tag("shell", "execute_command").sort(),
      ["can_execute_code", "can_exfiltrate", "can_modify_files"].sort()
    );
    assert.deepEqual(
      registry.tag("bash", "execute").sort(),
      ["can_execute_code", "can_exfiltrate", "can_modify_files"].sort()
    );
  });

  it("returns empty array for explicitly empty tags", () => {
    const registry = new CapabilityRegistry([
      { match: "calculator.*", tags: [] },
    ]);
    assert.deepEqual(registry.tag("calculator", "add"), []);
  });

  it("fetch.* pattern matches any fetch tool", () => {
    const registry = new CapabilityRegistry([
      { match: "fetch.*", tags: ["sees_untrusted_content", "can_exfiltrate"] },
    ]);
    assert.deepEqual(
      registry.tag("fetch", "get").sort(),
      ["can_exfiltrate", "sees_untrusted_content"].sort()
    );
    assert.deepEqual(registry.tag("prefetch", "get"), []);
  });
});

describe("tagTool (module-level singleton) — default.yaml", () => {
  before(() => {
    const policy = loadPolicy(DEFAULT_POLICY);
    initTagger(new CapabilityRegistry(policy.tools));
  });

  it("gmail read_message → reads_private_data, sees_untrusted_content", () => {
    assert.deepEqual(
      tagTool("gmail", "read_message").sort(),
      ["reads_private_data", "sees_untrusted_content"].sort()
    );
  });

  it("calculator add → empty", () => {
    assert.deepEqual(tagTool("calculator", "add"), []);
  });

  it("filesystem read_file → reads_private_data", () => {
    assert.deepEqual(tagTool("filesystem", "read_file"), ["reads_private_data"]);
  });

  it("fetch get → sees_untrusted_content, can_exfiltrate", () => {
    assert.deepEqual(
      tagTool("fetch", "get").sort(),
      ["can_exfiltrate", "sees_untrusted_content"].sort()
    );
  });

  it("unknown server/tool → empty", () => {
    assert.deepEqual(tagTool("unknown_server", "unknown_tool"), []);
  });
});
