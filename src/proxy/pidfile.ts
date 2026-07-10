import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

/**
 * Lets the dashboard (a separate process from the proxy) locate the proxy's
 * PID so it can signal it — e.g. SIGUSR1 for the kill switch. Written by the
 * proxy on startup, read by the dashboard, removed by the proxy on exit.
 */
export function resolvePidPath(p?: string): string {
  const raw = p ?? process.env["PORTCULLIS_PID_PATH"] ?? "~/.portcullis/proxy.pid";
  return raw.startsWith("~") ? path.join(os.homedir(), raw.slice(1)) : raw;
}

export function writePidFile(pidPath: string, pid: number = process.pid): void {
  fs.mkdirSync(path.dirname(pidPath), { recursive: true });
  fs.writeFileSync(pidPath, String(pid), "utf8");
}

export function readPidFile(pidPath: string): number | null {
  try {
    const raw = fs.readFileSync(pidPath, "utf8").trim();
    const pid = parseInt(raw, 10);
    return Number.isNaN(pid) ? null : pid;
  } catch {
    return null;
  }
}

export function removePidFile(pidPath: string): void {
  try {
    fs.unlinkSync(pidPath);
  } catch {
    // already gone — fine
  }
}
