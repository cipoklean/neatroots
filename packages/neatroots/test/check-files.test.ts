import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { checkFiles } from "../src/checks/offline.js";
import { hex } from "./helpers.js";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "check-files-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

const kv = (key: string, v: string | number) => ({ key, value: { stringValue: String(v) } });

type Step = { kind: "tool" | "llm"; name: string; ok?: boolean; input?: string; out?: string };
const tool = (name: string, ok = true, input = '{"q":1}'): Step => ({ kind: "tool", name, ok, input, out: "ok" });
const llm = (out = "fine"): Step => ({ kind: "llm", name: "chat", out });

function trace(steps: Step[]): string {
  const t = hex(16);
  const root = hex(8);
  const n = 1_700_000_000_000_000_000;
  const spans = steps.map((s, i) => {
    const attrs =
      s.kind === "tool"
        ? [kv("neatlogs.span.kind", "tool"), kv("neatlogs.tool.name", s.name), kv("neatlogs.tool.input", s.input ?? "{}"), ...(s.ok ? [kv("neatlogs.tool.output", s.out ?? "")] : [])]
        : [kv("neatlogs.span.kind", "llm"), kv("neatlogs.llm.output_messages.0.role", "assistant"), kv("neatlogs.llm.output_messages.0.content", s.out ?? ""), kv("neatlogs.llm.token_count.prompt", 100), kv("neatlogs.llm.token_count.completion", 20)];
    const start = n + i * 300_000_000;
    return { traceId: t, spanId: hex(8), parentSpanId: root, name: s.name, kind: 1, startTimeUnixNano: String(start), endTimeUnixNano: String(start + 200_000_000), attributes: attrs, status: s.ok === false ? { code: 2, message: "HTTP 500" } : {} };
  });
  spans.push({ traceId: t, spanId: root, parentSpanId: "" as string, name: "agent", kind: 1, startTimeUnixNano: String(n - 100_000_000), endTimeUnixNano: String(n + 5_000_000_000), attributes: [kv("neatlogs.span.kind", "workflow"), kv("neatlogs.workflow.output", "Done.")], status: {} });
  return JSON.stringify({ resourceSpans: [{ resource: { attributes: [kv("service.name", "check-demo")] }, scopeSpans: [{ scope: { name: "t" }, spans }] }] });
}

const same = (name: string, n: number) => Array.from({ length: n }, () => tool(name, true, '{"q":"x"}'));
const BAD: Step[][] = [
  same("search", 3),
  [tool("a", false), tool("b", false), tool("c", false)],
  [llm("key sk-proj-abcdefghijklmnopqrstuvwx")],
  Array.from({ length: 25 }, () => llm()),
];
const GOOD: Step[][] = [
  [tool("s", true, '{"q":"1"}'), tool("s", true, '{"q":"2"}'), tool("s", true, '{"q":"3"}')],
  [tool("a", false), tool("a"), tool("b", false), tool("b")],
  [llm("all fine")],
  Array.from({ length: 5 }, () => llm()),
];

let seq = 0;
const write = (steps: Step[]) => {
  const p = path.join(dir, `t${seq++}.json`);
  fs.writeFileSync(p, trace(steps));
  return p;
};

describe("checkFiles", () => {
  it("flags a bad run and passes a good one", () => {
    const r = checkFiles([write(BAD[0]), write(GOOD[0])]);
    expect(r.runs.map((x) => x.findings.length > 0)).toEqual([true, false]);
    expect(r.runs[0].findings[0].check_id).toBe("repeated-tool-call");
  });

  it("limits to the rules asked for", () => {
    const r = checkFiles([write(BAD[1])], { only: ["secret-in-output"] });
    expect(r.rules).toEqual(["secret-in-output"]);
    expect(r.runs[0].findings).toEqual([]);
  });

  it("rejects an unknown rule id", () => {
    expect(() => checkFiles([write(GOOD[0])], { only: ["nope"] })).toThrow(/no rule check named nope/);
  });

  it("rejects an empty rule list instead of checking nothing", () => {
    expect(() => checkFiles([write(BAD[0])], { only: [] })).toThrow(/names no rule ids/);
  });
  
  it("fails on a file that is not a trace", () => {
    const p = path.join(dir, "junk.json");
    fs.writeFileSync(p, "{oops");
    expect(() => checkFiles([p])).toThrow();
  });

  it("labeled smoke: 120 saved runs, 60 bad and 60 good, every verdict matches", () => {
    const files: [string, boolean][] = [];
    for (let i = 0; i < 120; i++) {
      const bad = i % 2 === 0;
      files.push([write((bad ? BAD : GOOD)[(i >> 1) % 4]), bad]);
    }
    const r = checkFiles(files.map((f) => f[0]));
    let tp = 0, fn = 0, fp = 0, tn = 0;
    r.runs.forEach((run, i) => {
      const fired = run.findings.length > 0;
      if (files[i][1] && fired) tp++;
      else if (files[i][1]) fn++;
      else if (fired) fp++;
      else tn++;
    });
    expect({ tp, fn, fp, tn }).toEqual({ tp: 60, fn: 0, fp: 0, tn: 60 });
  });
});
