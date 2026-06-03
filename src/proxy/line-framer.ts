import { EventEmitter } from "node:events";
import type { Readable } from "node:stream";

export class LineFramer extends EventEmitter {
  private buffer = "";

  attach(stream: Readable): void {
    stream.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf8");
      const lines = this.buffer.split("\n");
      this.buffer = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length > 0) {
          this.emit("line", trimmed);
        }
      }
    });

    stream.on("end", () => {
      if (this.buffer.trim().length > 0) {
        this.emit("line", this.buffer.trim());
        this.buffer = "";
      }
      this.emit("end");
    });
  }
}
