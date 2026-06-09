import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { z } from "zod";
import type { Store } from "./store.js";

export const AuditEventSchema = z.object({
  timestamp: z.string().datetime(),
  session_id: z.string().uuid(),
  direction: z.enum(["client_to_server", "server_to_client"]),
  server: z.string().min(1),
  method: z.string().min(1),
  message: z.record(z.string(), z.unknown()),
  decision: z.enum(["allowed", "blocked", "warned", "confirmed"]).optional(),
  capabilities: z.array(z.string()).optional(),
});

export type AuditEvent = z.infer<typeof AuditEventSchema>;

export class Logger {
  private readonly stream: fs.WriteStream;
  private readonly ready: Promise<void>;
  // Serialises concurrent append() calls so lines never interleave.
  private writeQueue: Promise<void> = Promise.resolve();
  private readonly store: Store | null;

  constructor(logPath: string, store?: Store) {
    const resolved = logPath.startsWith("~")
      ? path.join(os.homedir(), logPath.slice(1))
      : logPath;

    fs.mkdirSync(path.dirname(resolved), { recursive: true });

    // O_APPEND is set by the 'a' flag — never truncates on open.
    this.stream = fs.createWriteStream(resolved, { flags: "a", encoding: "utf8" });

    this.ready = new Promise((resolve, reject) => {
      this.stream.once("open", resolve);
      this.stream.once("error", reject);
    });

    this.store = store ?? null;
  }

  async append(event: AuditEvent): Promise<void> {
    // Validate before touching the file — throws ZodError on bad input.
    // async so the synchronous throw becomes a rejected Promise, not an uncaught throw.
    AuditEventSchema.parse(event);

    const line = JSON.stringify(event) + "\n";

    // Chain onto the queue; propagate errors to the caller but keep the
    // queue moving so one bad write doesn't block subsequent appends.
    const next = this.writeQueue.then(() => this.doWrite(line, event));
    this.writeQueue = next.catch(() => {});
    return next;
  }

  private doWrite(line: string, event: AuditEvent): Promise<void> {
    return this.ready.then(
      () =>
        new Promise<void>((resolve, reject) => {
          this.stream.write(line, (writeErr) => {
            if (writeErr) {
              reject(writeErr);
              return;
            }
            // fsync so a crash after write() doesn't silently lose the event.
            const fd = (this.stream as unknown as { fd: number }).fd;
            fs.fsync(fd, (syncErr) => {
              if (syncErr) {
                reject(syncErr);
                return;
              }
              // JSONL write is durable — now mirror to SQLite.
              // SQLite failures are logged as warnings and never propagated:
              // a failed mirror is recoverable via replay-from-jsonl; a
              // failed audit write is not.
              if (this.store !== null) {
                try {
                  this.store.insert(event);
                } catch (err) {
                  process.stderr.write(
                    `[portcullis] SQLite mirror write failed: ${err}\n`
                  );
                }
              }
              resolve();
            });
          });
        })
    );
  }

  close(): Promise<void> {
    return this.writeQueue.then(
      () => new Promise<void>((resolve) => this.stream.end(resolve))
    );
  }
}
