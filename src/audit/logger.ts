import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { z } from "zod";

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

  constructor(logPath: string) {
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
  }

  async append(event: AuditEvent): Promise<void> {
    // Validate before touching the file — throws ZodError on bad input.
    // async so the synchronous throw becomes a rejected Promise, not an uncaught throw.
    AuditEventSchema.parse(event);

    const line = JSON.stringify(event) + "\n";

    // Chain onto the queue; propagate errors to the caller but keep the
    // queue moving so one bad write doesn't block subsequent appends.
    const next = this.writeQueue.then(() => this.doWrite(line));
    this.writeQueue = next.catch(() => {});
    return next;
  }

  private doWrite(line: string): Promise<void> {
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
              if (syncErr) reject(syncErr);
              else resolve();
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
