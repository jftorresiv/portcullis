import Database from "better-sqlite3";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { AuditEvent } from "./logger.js";

export interface QueryFilters {
  session_id?: string;
  /** ISO 8601 lower bound (inclusive) */
  from?: string;
  /** ISO 8601 upper bound (inclusive) */
  to?: string;
  server?: string;
  method?: string;
  type?: string;
}

interface Row {
  id: number;
  timestamp: string;
  session_id: string;
  direction: string;
  server: string;
  method: string;
  message_json: string;
  decision: string | null;
  type: string | null;
  capabilities_json: string | null;
}

type InsertParams = {
  timestamp: string;
  session_id: string;
  direction: string;
  server: string;
  method: string;
  message_json: string;
  decision: string | null;
  type: string | null;
  capabilities_json: string | null;
};

function resolvePath(p: string): string {
  if (p === ":memory:") return p;
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

function rowToEvent(row: Row): AuditEvent {
  const event: AuditEvent = {
    timestamp: row.timestamp,
    session_id: row.session_id,
    direction: row.direction as AuditEvent["direction"],
    server: row.server,
    method: row.method,
    message: JSON.parse(row.message_json) as Record<string, unknown>,
  };
  if (row.decision != null) {
    event.decision = row.decision as AuditEvent["decision"];
  }
  if (row.type != null) {
    event.type = row.type;
  }
  if (row.capabilities_json != null) {
    event.capabilities = JSON.parse(row.capabilities_json) as string[];
  }
  return event;
}

export class Store {
  private readonly db: Database.Database;
  private readonly insertStmt: Database.Statement<InsertParams>;
  private readonly truncateStmt: Database.Statement<[]>;
  private readonly stmtCache = new Map<
    string,
    Database.Statement<[Record<string, string | null>], Row>
  >();

  constructor(dbPath: string) {
    const resolved = resolvePath(dbPath);
    if (resolved !== ":memory:") {
      fs.mkdirSync(path.dirname(resolved), { recursive: true });
    }

    this.db = new Database(resolved);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT NOT NULL,
        session_id TEXT NOT NULL,
        direction  TEXT NOT NULL,
        server     TEXT NOT NULL,
        method     TEXT NOT NULL,
        message_json TEXT NOT NULL,
        decision   TEXT,
        type       TEXT,
        capabilities_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_session       ON events(session_id);
      CREATE INDEX IF NOT EXISTS idx_timestamp     ON events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_server_method ON events(server, method);
    `);

    // Columns added after the initial release. Existing on-disk DBs won't
    // have these yet — ALTER TABLE ADD COLUMN is a no-op-safe upgrade path
    // that avoids forcing anyone to delete their DB file.
    const existingColumns = new Set(
      (this.db.pragma("table_info(events)") as Array<{ name: string }>).map(
        (c) => c.name
      )
    );
    if (!existingColumns.has("type")) {
      this.db.exec("ALTER TABLE events ADD COLUMN type TEXT");
    }
    if (!existingColumns.has("capabilities_json")) {
      this.db.exec("ALTER TABLE events ADD COLUMN capabilities_json TEXT");
    }
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_type ON events(type);");

    this.insertStmt = this.db.prepare<InsertParams>(
      "INSERT INTO events (timestamp, session_id, direction, server, method, message_json, decision, type, capabilities_json) " +
        "VALUES (@timestamp, @session_id, @direction, @server, @method, @message_json, @decision, @type, @capabilities_json)"
    );

    this.truncateStmt = this.db.prepare<[]>("DELETE FROM events");
  }

  insert(event: AuditEvent): void {
    this.insertStmt.run({
      timestamp: event.timestamp,
      session_id: event.session_id,
      direction: event.direction,
      server: event.server,
      method: event.method,
      message_json: JSON.stringify(event.message),
      decision: event.decision ?? null,
      type: event.type ?? null,
      capabilities_json:
        event.capabilities !== undefined
          ? JSON.stringify(event.capabilities)
          : null,
    });
  }

  query(filters: QueryFilters = {}): AuditEvent[] {
    const conditions: string[] = [];
    const params: Record<string, string | null> = {};

    if (filters.session_id !== undefined) {
      conditions.push("session_id = @session_id");
      params["session_id"] = filters.session_id;
    }
    if (filters.from !== undefined) {
      conditions.push("timestamp >= @from");
      params["from"] = filters.from;
    }
    if (filters.to !== undefined) {
      conditions.push("timestamp <= @to");
      params["to"] = filters.to;
    }
    if (filters.server !== undefined) {
      conditions.push("server = @server");
      params["server"] = filters.server;
    }
    if (filters.method !== undefined) {
      conditions.push("method = @method");
      params["method"] = filters.method;
    }
    if (filters.type !== undefined) {
      conditions.push("type = @type");
      params["type"] = filters.type;
    }

    const where =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const sql = `SELECT * FROM events ${where} ORDER BY timestamp ASC`;

    return this.cachedPrepare(sql).all(params).map(rowToEvent);
  }

  /** Truncates the events table and inserts all provided events in one transaction. */
  replay(events: AuditEvent[]): void {
    const run = this.db.transaction(() => {
      this.truncateStmt.run();
      for (const event of events) {
        this.insert(event);
      }
    });
    run();
  }

  /** Wraps a callback in a single SQLite transaction — useful for bulk inserts in tests/benchmarks. */
  runInTransaction(fn: () => void): void {
    this.db.transaction(fn)();
  }

  close(): void {
    this.db.close();
  }

  private cachedPrepare(
    sql: string
  ): Database.Statement<[Record<string, string | null>], Row> {
    const hit = this.stmtCache.get(sql);
    if (hit !== undefined) return hit;
    const stmt = this.db.prepare<
      Record<string, string | null>,
      Row
    >(sql);
    this.stmtCache.set(sql, stmt);
    return stmt;
  }
}
