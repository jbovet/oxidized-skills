import { readFileSync } from "fs";
import * as path from "path";

// Safely read a config file from the skill directory.
export function loadConfig(configPath: string): Record<string, unknown> {
  const resolved = path.resolve(configPath);
  const raw = readFileSync(resolved, "utf8");
  return JSON.parse(raw);
}

// Regex exec — must NOT be flagged (this is a property call, not eval()).
export function extractVersion(text: string): string | null {
  const match = /v(\d+\.\d+\.\d+)/.exec(text);
  return match ? match[1] : null;
}

// String method — must NOT be flagged (ends with .eval, excluded by regex).
const obj = { evalStr: (s: string) => s.trim() };
const result = obj.evalStr("  hello  ");

export { result };
