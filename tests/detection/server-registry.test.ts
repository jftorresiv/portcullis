import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ServerRegistry } from "../../src/detection/server-registry.js";

let counter = 0;
// A unique, non-existent path under a fresh temp dir. The dir itself is not
// created — save() is responsible for creating parent dirs.
function tmpPath(): string {
  return path.join(
    os.tmpdir(),
    `portcullis-registry-test-${Date.now()}-${counter++}`,
    "known-servers.json"
  );
}

describe("ServerRegistry", () => {
  it("starts empty when the file does not exist", () => {
    const p = tmpPath();
    const reg = new ServerRegistry();
    reg.load(p);
    assert.equal(reg.isNew("gmail"), true);
    assert.equal(reg.isNew("filesystem"), true);
    assert.equal(fs.existsSync(p), false); // load() must not create the file
  });

  it("load() on a missing file does not throw", () => {
    const reg = new ServerRegistry();
    assert.doesNotThrow(() => reg.load(tmpPath()));
  });

  it("isNew() returns true for an unseen server and false after markSeen()", () => {
    const reg = new ServerRegistry();
    reg.load(tmpPath());
    assert.equal(reg.isNew("gmail"), true);
    reg.markSeen("gmail");
    assert.equal(reg.isNew("gmail"), false);
    // Unrelated servers stay new.
    assert.equal(reg.isNew("github"), true);
  });

  it("markSeen() is idempotent — re-adding does not duplicate", () => {
    const p = tmpPath();
    const reg = new ServerRegistry();
    reg.load(p);
    reg.markSeen("gmail");
    reg.markSeen("gmail");
    reg.save();

    const onDisk = JSON.parse(fs.readFileSync(p, "utf8")) as { servers: string[] };
    assert.deepEqual(onDisk.servers, ["gmail"]);
    fs.rmSync(path.dirname(p), { recursive: true, force: true });
  });

  it("save() + load() round-trips the server set", () => {
    const p = tmpPath();
    const writer = new ServerRegistry();
    writer.load(p);
    writer.markSeen("gmail");
    writer.markSeen("github");
    writer.markSeen("filesystem");
    writer.save();

    const reader = new ServerRegistry();
    reader.load(p);
    assert.equal(reader.isNew("gmail"), false);
    assert.equal(reader.isNew("github"), false);
    assert.equal(reader.isNew("filesystem"), false);
    assert.equal(reader.isNew("fetch"), true);

    fs.rmSync(path.dirname(p), { recursive: true, force: true });
  });

  it("save() writes the documented { servers: [...] } shape and creates parent dirs", () => {
    const p = tmpPath();
    const reg = new ServerRegistry();
    reg.load(p);
    reg.markSeen("gmail");
    reg.save();

    assert.equal(fs.existsSync(p), true);
    const parsed = JSON.parse(fs.readFileSync(p, "utf8")) as unknown;
    assert.ok(
      parsed !== null &&
        typeof parsed === "object" &&
        Array.isArray((parsed as { servers?: unknown }).servers)
    );
    fs.rmSync(path.dirname(p), { recursive: true, force: true });
  });
});
