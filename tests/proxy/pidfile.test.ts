import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import {
  resolvePidPath,
  writePidFile,
  readPidFile,
  removePidFile,
} from "../../src/proxy/pidfile.js";

function tmpPidPath(): string {
  return path.join(os.tmpdir(), `portcullis-pidfile-test-${randomUUID()}.pid`);
}

describe("pidfile", () => {
  const created: string[] = [];

  afterEach(() => {
    for (const p of created.splice(0)) {
      fs.rmSync(p, { force: true });
    }
  });

  it("writePidFile then readPidFile round-trips the pid", () => {
    const p = tmpPidPath();
    created.push(p);
    writePidFile(p, 12345);
    assert.equal(readPidFile(p), 12345);
  });

  it("writePidFile defaults to process.pid", () => {
    const p = tmpPidPath();
    created.push(p);
    writePidFile(p);
    assert.equal(readPidFile(p), process.pid);
  });

  it("readPidFile returns null when the file does not exist", () => {
    const p = tmpPidPath();
    assert.equal(readPidFile(p), null);
  });

  it("readPidFile returns null for malformed content", () => {
    const p = tmpPidPath();
    created.push(p);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "not-a-pid", "utf8");
    assert.equal(readPidFile(p), null);
  });

  it("removePidFile deletes the file and is a no-op if already gone", () => {
    const p = tmpPidPath();
    writePidFile(p, 1);
    assert.ok(fs.existsSync(p));
    removePidFile(p);
    assert.ok(!fs.existsSync(p));
    assert.doesNotThrow(() => removePidFile(p));
  });

  it("writePidFile creates parent directories as needed", () => {
    const dir = path.join(os.tmpdir(), `portcullis-pidfile-dir-${randomUUID()}`);
    const p = path.join(dir, "nested", "proxy.pid");
    created.push(p);
    writePidFile(p, 42);
    assert.equal(readPidFile(p), 42);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("resolvePidPath expands a leading ~ to the home directory", () => {
    const resolved = resolvePidPath("~/.portcullis/proxy.pid");
    assert.equal(resolved, path.join(os.homedir(), ".portcullis/proxy.pid"));
  });

  it("resolvePidPath falls back to PORTCULLIS_PID_PATH env var", () => {
    const prev = process.env["PORTCULLIS_PID_PATH"];
    process.env["PORTCULLIS_PID_PATH"] = "/tmp/custom-proxy.pid";
    try {
      assert.equal(resolvePidPath(), "/tmp/custom-proxy.pid");
    } finally {
      if (prev === undefined) delete process.env["PORTCULLIS_PID_PATH"];
      else process.env["PORTCULLIS_PID_PATH"] = prev;
    }
  });

  it("resolvePidPath defaults to ~/.portcullis/proxy.pid", () => {
    const prev = process.env["PORTCULLIS_PID_PATH"];
    delete process.env["PORTCULLIS_PID_PATH"];
    try {
      assert.equal(resolvePidPath(), path.join(os.homedir(), ".portcullis/proxy.pid"));
    } finally {
      if (prev !== undefined) process.env["PORTCULLIS_PID_PATH"] = prev;
    }
  });
});
