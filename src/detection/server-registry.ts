import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// Tracks which MCP servers have been seen before, persisted to
// ~/.portcullis/known-servers.json. A server is "new" until markSeen() records
// it; the on-disk set makes that first-seen fact survive across processes so a
// server counts as new only the very first time it is ever encountered.
//
// Pure class in the trifecta.ts mould: no Logger dependency and no I/O beyond
// its own JSON file. The proxy owns audit logging for the new_server_seen event.
//
// File format: { "servers": ["name1", "name2", ...] }
export class ServerRegistry {
  private readonly seen = new Set<string>();
  // Resolved (~ expanded) path captured by load(), reused by save() so callers
  // never have to pass the path twice.
  private resolvedPath: string | null = null;

  // Reads the known-servers file into the in-memory set. Expands a leading ~.
  // Never throws on a missing file — an absent file simply means no server has
  // been seen yet. A corrupt or unreadable file is tolerated the same way: the
  // registry starts empty rather than crashing the proxy at startup.
  load(filePath: string): void {
    this.resolvedPath = expandHome(filePath);

    let raw: string;
    try {
      raw = fs.readFileSync(this.resolvedPath, "utf8");
    } catch {
      // Missing (or unreadable) file: start empty.
      return;
    }

    try {
      const parsed = JSON.parse(raw) as unknown;
      const servers =
        parsed !== null &&
        typeof parsed === "object" &&
        Array.isArray((parsed as { servers?: unknown }).servers)
          ? (parsed as { servers: unknown[] }).servers
          : [];
      for (const name of servers) {
        if (typeof name === "string") this.seen.add(name);
      }
    } catch {
      // Corrupt JSON: start empty rather than throw.
      return;
    }
  }

  // True if this server name has NOT been recorded yet.
  isNew(name: string): boolean {
    return !this.seen.has(name);
  }

  // Records a server as seen. Idempotent — the backing Set dedupes.
  markSeen(name: string): void {
    this.seen.add(name);
  }

  // Persists the current set to the JSON file, creating parent dirs as needed.
  // Uses the path captured by load(); throws if save() is called before load()
  // so a missing load() is a loud programming error, not a silent no-op write.
  save(): void {
    if (this.resolvedPath === null) {
      throw new Error("ServerRegistry.save() called before load()");
    }
    fs.mkdirSync(path.dirname(this.resolvedPath), { recursive: true });
    const body = JSON.stringify({ servers: [...this.seen] }, null, 2);
    fs.writeFileSync(this.resolvedPath, body + "\n", "utf8");
  }
}

// Expands a leading ~ to the user's home directory; leaves other paths intact.
function expandHome(filePath: string): string {
  return filePath.startsWith("~")
    ? path.join(os.homedir(), filePath.slice(1))
    : filePath;
}
