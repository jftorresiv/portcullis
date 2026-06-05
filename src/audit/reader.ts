import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import * as os from "node:os";
import * as path from "node:path";
import { AuditEventSchema, type AuditEvent } from "./logger.js";

export async function readAuditLog(logPath: string): Promise<AuditEvent[]> {
  const resolved = logPath.startsWith("~")
    ? path.join(os.homedir(), logPath.slice(1))
    : logPath;

  const events: AuditEvent[] = [];

  try {
    const rl = createInterface({
      input: createReadStream(resolved, { encoding: "utf8" }),
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      if (!line.trim()) continue;
      try {
        const parsed: unknown = JSON.parse(line);
        const result = AuditEventSchema.safeParse(parsed);
        if (result.success) events.push(result.data);
      } catch {
        // skip malformed lines — log is append-only, a bad line should never block reads
      }
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }

  return events;
}
