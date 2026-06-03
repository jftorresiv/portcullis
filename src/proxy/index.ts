import { startProxy } from "./proxy.js";
import type { InterceptedMessage } from "../types/mcp.js";

function onMessage(msg: InterceptedMessage): void {
  process.stderr.write(
    `[portcullis] ${msg.timestamp} ${msg.direction} ${JSON.stringify(msg.parsed).slice(0, 120)}\n`
  );
}

startProxy({
  serverCommand: [
    "npx", "-y", "@modelcontextprotocol/server-filesystem",
    `${process.env["HOME"]}/projects/mcp-walkthrough/sandbox`
  ],
  onMessage,
});
