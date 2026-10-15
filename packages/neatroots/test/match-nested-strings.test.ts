import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/store/db.js";
import { loadTrace } from "../src/engine/trace.js";
import { evaluateRule } from "../src/checks/rules.js";
import { parseChecks } from "../src/checks/registry.js";
import type { RuleCheck } from "../src/checks/types.js";
import { batch, hex, tmpHome, toolSpan } from "./helpers.js";

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});
const library = parseChecks(fs.readFileSync(new URL("../library/rules.yaml", import.meta.url), "utf8")).checks;
const softFailure = library.find((c) => c.id === "soft-tool-failure") as RuleCheck;

/** An MCP tools/call result: the tool's own output is a string inside content[].text. */
const mcp = (text: string, isError = false) => JSON.stringify({ content: [{ type: "text", text }], isError });

function fires(rule: RuleCheck, output: string): boolean {
  const h = tmpHome();
  homes.push(h);
  const st = new Store(path.join(h, "data"));
  const t = hex(16);
  st.ingest([batch([toolSpan(t, hex(8), "get_weather", '{"city":"Lagos"}', output)])]);
  return evaluateRule(rule, loadTrace(st, t), false)?.firing === true;
}

describe("match rules read strings nested in a field", () => {
  it("fires soft-tool-failure on a failure wrapped in an MCP result, as it does unwrapped", () => {
    const fails = [
      '{"error":"city not found","code":"NOT_FOUND"}',
      '{"status":404,"message":"no such city"}',
      '{"errors":["invalid api key"]}',
      "Error: city not found",
    ];
    for (const out of fails) {
      expect(fires(softFailure, out), out).toBe(true);
      expect(fires(softFailure, mcp(out)), `mcp ${out}`).toBe(true);
    }
  });

  it("stays quiet on normal output wrapped in an MCP result", () => {
    const clean = ['{"temp_c":31,"sky":"sunny"}', '{"error":null}', '{"errors":[]}', '{"status":200}', "no errors found", "Error handling guide for developers"];
    for (const out of clean) expect(fires(softFailure, mcp(out)), `mcp ${out}`).toBe(false);
  });
});
