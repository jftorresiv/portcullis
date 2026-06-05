import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import { AuditEventSchema } from "./audit/logger.js";
import type { Store } from "./audit/store.js";

function resolvePath(p: string): string {
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

/**
 * Rebuilds the SQLite mirror from a JSONL audit file.
 *
 * Truncates the events table, then inserts every valid line from the JSONL
 * file inside a single transaction.  Idempotent: calling it twice leaves
 * SQLite in the same state as calling it once.
 *
 * @returns The number of events replayed.
 */
export function replayFromJsonl(jsonlPath: string, store: Store): number {
  const resolved = resolvePath(jsonlPath);
  const content = fs.readFileSync(resolved, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);

  const events = lines.map((line) =>
    AuditEventSchema.parse(JSON.parse(line) as unknown)
  );

  store.replay(events);
  return events.length;
}

// ---------------------------------------------------------------------------
// CLI entry — only runs when this file is the main module.
// ---------------------------------------------------------------------------

const isMain =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  const [, , cmd, ...rest] = process.argv;

  if (cmd === "replay-from-jsonl") {
    const { Store } = await import("./audit/store.js");

    const jsonlPath =
      rest[0] ??
      process.env["PORTCULLIS_AUDIT_LOG"] ??
      "~/.portcullis/audit.jsonl";
    const dbPath =
      rest[1] ??
      process.env["PORTCULLIS_DB_PATH"] ??
      "~/.portcullis/audit.db";

    const store = new Store(dbPath);
    try {
      const count = replayFromJsonl(jsonlPath, store);
      process.stdout.write(`[portcullis] replayed ${count} events\n`);
    } finally {
      store.close();
    }
  } else {
    process.stderr.write(
      `[portcullis] unknown command: ${cmd ?? "(none)"}\n` +
        `Usage: portcullis replay-from-jsonl [<jsonl-path> [<db-path>]]\n`
    );
    process.exit(1);
  }
}
